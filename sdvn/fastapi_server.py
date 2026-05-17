import uuid
import time
import json
import uvicorn
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel
from typing import Dict, Any

from ca import CertificateAuthority
from crypto_utils import (
    generate_keypair, pub_to_pem, pub_to_hex, pem_to_pub, derive_session_key,
    ecdh_shared_secret_x, aes_gcm_encrypt, aes_gcm_decrypt, ecdsa_sign,
    ecdsa_verify, fresh_timestamp, canonical_json
)

app = FastAPI(title="SDVN Secure Communication - API Backend")

# ─────────────────────────────────────────────
# GLOBAL STATE & INITIALIZATION
# ─────────────────────────────────────────────
print("Initializing CA and Server Identity...")
ca = CertificateAuthority()
ca_pub = ca.get_ca_pub_key_for_party()

srv_lt_priv, srv_lt_pub = generate_keypair()
srv_cert = ca.issue_certificate("MONITORING-SERVER-01", "server", pub_to_pem(srv_lt_pub))

vehicle_log: Dict[str, dict] = {}
ch2_sessions: Dict[str, dict] = {}
ch3_sessions: Dict[str, dict] = {}


# ─────────────────────────────────────────────
# CHANNEL 2 ROUTES (Direct Monitoring)
# ─────────────────────────────────────────────

class Ch2HelloReq(BaseModel):
    entity_id: str
    certificate: dict
    ephemeral_pub: str
    timestamp: float
    signature: str

@app.post("/ch2/hello")
def ch2_hello(req: Ch2HelloReq):
    print(f"[SERVER/CH2] RECV HELLO from entity_id={req.entity_id}")
    
    # CHECK-A: CA signature on C1 certificate
    cert_body = {k: v for k, v in req.certificate.items() if k != "ca_signature"}
    body_bytes = canonical_json(cert_body)
    if not ecdsa_verify(ca_pub, body_bytes, req.certificate["ca_signature"]):
        raise HTTPException(status_code=400, detail="C1 certificate CA signature invalid")

    # CHECK-B & C: Extract pub key and verify signature on HELLO
    c1_lt_pub = pem_to_pub(req.certificate["public_key"])
    hello_body = canonical_json({
        "entity_id": req.entity_id,
        "ephemeral_pub": req.ephemeral_pub,
        "timestamp": req.timestamp,
    })
    if not ecdsa_verify(c1_lt_pub, hello_body, req.signature):
        raise HTTPException(status_code=400, detail="C1 HELLO signature invalid")

    # CHECK-D: Freshness
    if not fresh_timestamp(req.timestamp):
        raise HTTPException(status_code=400, detail="C1 HELLO timestamp stale")

    # Generate ephemeral keypair
    s_eph_priv, s_eph_pub = generate_keypair()
    s_eph_pub_pem = pub_to_pem(s_eph_pub)
    now = int(time.time())

    ack_body = canonical_json({
        "ephemeral_pub": s_eph_pub_pem,
        "timestamp": now,
    })
    ack_sig = ecdsa_sign(srv_lt_priv, ack_body)

    # Derive session key
    c1_eph_pub = pem_to_pub(req.ephemeral_pub)
    aes_key = derive_session_key(s_eph_priv, c1_eph_pub, "Monitoring-Ch2", "monitor")

    session_id = str(uuid.uuid4())
    ch2_sessions[session_id] = {
        "aes_key": aes_key,
        "entity_id": req.entity_id,
        "c1_lt_pub": c1_lt_pub
    }

    return {
        "session_id": session_id,
        "certificate": srv_cert,
        "ephemeral_pub": s_eph_pub_pem,
        "timestamp": now,
        "signature": ack_sig
    }

class Ch2FinishedReq(BaseModel):
    session_id: str
    proof: dict

@app.post("/ch2/finished")
def ch2_finished(req: Ch2FinishedReq):
    session = ch2_sessions.get(req.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    decrypted = aes_gcm_decrypt(session["aes_key"], req.proof)
    if decrypted != b"CLIENT_FINISHED":
        raise HTTPException(status_code=400, detail="CLIENT_FINISHED proof failed")
        
    print(f"[SERVER/CH2] SECURE CHANNEL ESTABLISHED with {session['entity_id']}")
    return {"status": "channel_established"}

class Ch2DataReq(BaseModel):
    session_id: str
    encrypted_payload: dict

@app.post("/ch2/data")
def ch2_data(req: Ch2DataReq):
    session = ch2_sessions.get(req.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
        
    plain = aes_gcm_decrypt(session["aes_key"], req.encrypted_payload)
    payload = json.loads(plain.decode())
    stats = payload["stats"]
    data_sig = payload["signature"]

    stats_bytes = canonical_json(stats)
    if not ecdsa_verify(session["c1_lt_pub"], stats_bytes, data_sig):
        raise HTTPException(status_code=400, detail="C1 data signature invalid")

    entity_id = session["entity_id"]
    vehicle_log[entity_id] = stats
    print(f"[SERVER/CH2] Logged stats for {entity_id}: speed={stats['speed']}, direction={stats['direction']}")
    
    return {"status": "ok"}


# ─────────────────────────────────────────────
# CHANNEL 3 ROUTES (Relay)
# ─────────────────────────────────────────────

class Ch3AnonHelloReq(BaseModel):
    relay_id: str
    relay_certificate: dict
    payload: dict
    relay_sig: str
    timestamp: float

@app.post("/ch3/relay_anon_hello")
def ch3_anon_hello(req: Ch3AnonHelloReq):
    # Verify C1 relay certificate
    cert_body = {k: v for k, v in req.relay_certificate.items() if k != "ca_signature"}
    body_bytes = canonical_json(cert_body)
    if not ecdsa_verify(ca_pub, body_bytes, req.relay_certificate["ca_signature"]):
        raise HTTPException(status_code=400, detail="C1 relay certificate invalid")

    c1_lt_pub = pem_to_pub(req.relay_certificate["public_key"])
    relay_body = canonical_json({
        "payload": req.payload,
        "relay_id": req.relay_id,
        "timestamp": req.timestamp,
    })
    if not ecdsa_verify(c1_lt_pub, relay_body, req.relay_sig):
        raise HTTPException(status_code=400, detail="C1 relay signature invalid")

    anon_hello = req.payload
    if not fresh_timestamp(anon_hello["timestamp"]):
        raise HTTPException(status_code=400, detail="C2 Anon Hello timestamp stale")

    c2_eph_pub = pem_to_pub(anon_hello["ephemeral_pub"])
    nonce_echo = anon_hello["nonce"]

    # Server ephemeral keypair
    s_eph_priv2, s_eph_pub2 = generate_keypair()
    s_eph_pub2_pem = pub_to_pem(s_eph_pub2)
    now = int(time.time())

    ack_body = canonical_json({
        "ephemeral_pub": s_eph_pub2_pem,
        "nonce_echo": nonce_echo,
        "timestamp": now,
    })
    ack_sig = ecdsa_sign(srv_lt_priv, ack_body)

    # Derive AES session key (does not know C2 identity yet)
    aes_key = derive_session_key(s_eph_priv2, c2_eph_pub, "Monitoring-Ch3-Relay", "relay")

    session_id = str(uuid.uuid4())
    ch3_sessions[session_id] = {
        "aes_key": aes_key
    }

    return {
        "session_id": session_id,
        "certificate": srv_cert,
        "ephemeral_pub": s_eph_pub2_pem,
        "timestamp": now,
        "nonce_echo": nonce_echo,
        "signature": ack_sig
    }

class Ch3FinishedReq(BaseModel):
    session_id: str
    sealed: dict

@app.post("/ch3/relay_finished")
def ch3_finished(req: Ch3FinishedReq):
    session = ch3_sessions.get(req.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    plain = aes_gcm_decrypt(session["aes_key"], req.sealed)
    identity_payload = json.loads(plain.decode())
    
    c2_entity_id = identity_payload["entity_id"]
    c2_cert = identity_payload["certificate"]
    proof = identity_payload["proof"]

    c2_cert_body = {k: v for k, v in c2_cert.items() if k != "ca_signature"}
    c2_body_bytes = canonical_json(c2_cert_body)
    if not ecdsa_verify(ca_pub, c2_body_bytes, c2_cert["ca_signature"]):
        raise HTTPException(status_code=400, detail="C2 certificate invalid")

    if proof != "CLIENT_FINISHED":
        raise HTTPException(status_code=400, detail="C2 CLIENT_FINISHED proof failed")

    session["c2_entity_id"] = c2_entity_id
    session["c2_lt_pub"] = pem_to_pub(c2_cert["public_key"])
    print(f"[SERVER/CH3] C2↔Server SECURE CHANNEL ESTABLISHED (end-to-end) for {c2_entity_id}")

    return {"status": "c2_channel_established"}

class Ch3DataReq(BaseModel):
    session_id: str
    sealed: dict

@app.post("/ch3/relay_data")
def ch3_data(req: Ch3DataReq):
    session = ch3_sessions.get(req.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    plain = aes_gcm_decrypt(session["aes_key"], req.sealed)
    payload = json.loads(plain.decode())
    stats = payload["stats"]
    data_sig = payload["signature"]

    stats_bytes = canonical_json(stats)
    if not ecdsa_verify(session["c2_lt_pub"], stats_bytes, data_sig):
        raise HTTPException(status_code=400, detail="C2 data signature invalid")

    c2_entity_id = session["c2_entity_id"]
    vehicle_log[c2_entity_id] = stats
    print(f"[SERVER/CH3] Stats logged for {c2_entity_id} [via relay]: speed={stats['speed']}")

    return {"status": "ok"}

@app.get("/logs")
def get_logs():
    return {"logs": vehicle_log}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
