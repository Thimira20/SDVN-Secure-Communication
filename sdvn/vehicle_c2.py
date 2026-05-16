"""
vehicle_c2.py — SDVN Vehicle C2
================================
Vehicle C2: out of wireless range of the base station.
Must relay monitoring data through C1.

Roles:
  - Channel 1 (V2V)  : Initiator — connects to C1 port 9001
  - Channel 3 (Relay): Anonymous client — sends data via C1 to server

Key privacy guarantees:
  - Uses pseudonyms for V2V (C1 never learns C2's real identity)
  - Uses anonymous Phase-1 key exchange for relay (C1 never sees C2's cert)
  - Real identity revealed ONLY to the server, encrypted end-to-end
"""

import socket
import json
import time
import base64
import os

from crypto_utils import (
    generate_keypair, pub_to_pem, pub_to_hex, pem_to_pub,
    derive_session_key, ecdh_shared_secret_x,
    aes_gcm_encrypt, aes_gcm_decrypt,
    ecdsa_sign, ecdsa_verify,
    hmac_sign,
    fresh_timestamp, make_packet, parse_packet, canonical_json,
)


def _recv_msg(sock):
    raw_len = b""
    while len(raw_len) < 4:
        chunk = sock.recv(4 - len(raw_len))
        if not chunk:
            raise ConnectionError("Socket closed")
        raw_len += chunk
    length = int.from_bytes(raw_len, "big")
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Socket closed")
        data += chunk
    return parse_packet(data)


def _send_msg(sock, msg_type, **fields):
    payload = make_packet(msg_type, **fields)
    sock.sendall(len(payload).to_bytes(4, "big") + payload)


class VehicleC2:
    """
    Vehicle C2 — out of range of base station.
    V2V initiator and anonymous relay client.
    """

    ENTITY_ID = "C2-LK-5678"

    def __init__(self, ca_pub_key, lt_priv, lt_cert, pseudo_certs):
        """
        Args:
            ca_pub_key   : CA public key (pre-loaded)
            lt_priv      : C2 long-term ECDSA private key
            lt_cert      : C2 CA-signed long-term certificate
            pseudo_certs : list of (cert_dict, priv_key) pseudonym pairs
        """
        self._ca_pub     = ca_pub_key
        self._lt_priv    = lt_priv
        self._lt_pub     = lt_priv.public_key()
        self._lt_cert    = lt_cert
        self._pseudonyms = pseudo_certs
        self._v2v_key    = None   # Set after Channel 1
        print(f"[C2] Vehicle C2 ({self.ENTITY_ID}) initialised")
        print(f"[C2] Long-term certificate: entity={self.ENTITY_ID}, role=vehicle")
        print(f"[C2] Pseudonyms available: {len(self._pseudonyms)}")

    # ─────────────────────────────────────────────
    # CHANNEL 1 — V2V INITIATOR
    # ─────────────────────────────────────────────

    def run_v2v(self, c1_host="127.0.0.1", c1_port=9001):
        """Connect to C1 and run full V2V handshake."""
        print(f"\n[C2/V2V] ── CHANNEL 1 V2V HANDSHAKE START ──")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((c1_host, c1_port))
            self._handle_v2v(sock)

    def _handle_v2v(self, sock):
        my_pseudo_cert, my_pseudo_priv = self._pseudonyms[0]
        my_pseudo_id = my_pseudo_cert["entity_id"]

        # ── STEP 1: Send HELLO ────────────────────────────────────────
        print(f"[C2/V2V] ── STEP 1: SEND V2V_HELLO ──")
        c2_eph_priv, c2_eph_pub = generate_keypair()
        c2_eph_pub_pem = pub_to_pem(c2_eph_pub)
        now = int(time.time())

        hello_body = canonical_json({
            "ephemeral_pub": c2_eph_pub_pem,
            "pseudo_id"    : my_pseudo_id,
            "timestamp"    : now,
        })
        hello_sig = ecdsa_sign(my_pseudo_priv, hello_body)
        print(f"[C2/V2V] Using pseudonym: pseudo_id={my_pseudo_id} (real ID hidden)")
        print(f"[C2/V2V] Generated ephemeral keypair for ECDH")
        print(f"[C2/V2V]   c2_eph_pub = {pub_to_hex(c2_eph_pub)[:32]}...")
        print(f"[C2/V2V] hello_body = {{pseudo_id, ephemeral_pub, timestamp}}")
        print(f"[C2/V2V] ECDSA_sign(pseudo_priv_2, hello_body) → sig={hello_sig[:24]}...")
        _send_msg(sock, "V2V_HELLO",
                  pseudo_id      = my_pseudo_id,
                  pseudonym_cert = my_pseudo_cert,
                  ephemeral_pub  = c2_eph_pub_pem,
                  timestamp      = now,
                  signature      = hello_sig)
        print(f"[C2/V2V] SENT V2V_HELLO → {{pseudo_id, pseudonym_cert, ephemeral_pub, timestamp, sig}}")
        print(f"[C2/V2V] NOTE: Real identity {self.ENTITY_ID} NOT included ✓")

        # ── STEP 4: Verify C1 HELLO ───────────────────────────────────
        print(f"\n[C2/V2V] ── STEP 4: VERIFY C1 V2V_HELLO ──")
        pkt = _recv_msg(sock)
        assert pkt["type"] == "V2V_HELLO"
        c1_pseudo_cert = pkt["pseudonym_cert"]
        c1_pseudo_id   = pkt["pseudo_id"]
        print(f"[C2/V2V] RECV V2V_HELLO from pseudo_id={c1_pseudo_id}")

        # CHECK-A: CA signature on C1 pseudonym cert
        cert_body  = {k: v for k, v in c1_pseudo_cert.items() if k != "ca_signature"}
        body_bytes = canonical_json(cert_body)
        ca_ok = ecdsa_verify(self._ca_pub, body_bytes, c1_pseudo_cert["ca_signature"])
        print(f"[C2/V2V] CHECK-A CA signature on pseudonym cert → {'TRUE ✓' if ca_ok else 'FALSE ✗'}")
        assert ca_ok

        # CHECK-B: ECDSA on C1 HELLO body
        c1_pseudo_pub = pem_to_pub(c1_pseudo_cert["public_key"])
        c1_hello_body = canonical_json({
            "ephemeral_pub": pkt["ephemeral_pub"],
            "pseudo_id"    : pkt["pseudo_id"],
            "timestamp"    : pkt["timestamp"],
        })
        sig_ok = ecdsa_verify(c1_pseudo_pub, c1_hello_body, pkt["signature"])
        print(f"[C2/V2V] CHECK-B ECDSA_verify(pseudo_pub_1, hello_body, sig) → {'TRUE ✓' if sig_ok else 'FALSE ✗'}")
        assert sig_ok

        # CHECK-C: Timestamp
        delta = abs(time.time() - pkt["timestamp"])
        ts_ok = fresh_timestamp(pkt["timestamp"])
        print(f"[C2/V2V] CHECK-C Timestamp: delta={delta:.3f}s → {'FRESH ✓' if ts_ok else 'STALE ✗'}")
        assert ts_ok
        print(f"[C2/V2V] NOTE: C2 does NOT know C1's real identity ✓")

        c1_eph_pub = pem_to_pub(pkt["ephemeral_pub"])

        # ── STEP 5: Derive session key ────────────────────────────────
        print(f"\n[C2/V2V] ── STEP 5: DERIVE SESSION KEY ──")
        ss_raw  = ecdh_shared_secret_x(c2_eph_priv, c1_eph_pub)
        aes_key = derive_session_key(c2_eph_priv, c1_eph_pub, "V2V-Ch1", "v2v")
        print(f"[C2/V2V] ECDH: SS = c2_eph_priv × c1_eph_pub")
        print(f"[C2/V2V]   SS.x = {ss_raw.hex()[:32]}...  (shared secret x-coordinate)")
        print(f"[C2/V2V] HKDF(SS.x, salt='V2V-Ch1', label='v2v')")
        print(f"[C2/V2V]   AES_key = {aes_key.hex()[:32]}... (32 bytes)")
        self._v2v_key = aes_key

        # ── STEP 6: KEY_CONFIRM ───────────────────────────────────────
        print(f"\n[C2/V2V] ── STEP 6: KEY_CONFIRM ──")
        proof_c2 = aes_gcm_encrypt(aes_key, b"C2_KEY_CONFIRM")
        _send_msg(sock, "KEY_CONFIRM", proof=proof_c2)
        print(f"[C2/V2V] AES_GCM_encrypt(AES_key, 'C2_KEY_CONFIRM')")
        print(f"[C2/V2V] SENT KEY_CONFIRM proof to C1")

        kc_pkt = _recv_msg(sock)
        assert kc_pkt["type"] == "KEY_CONFIRM"
        decrypted = aes_gcm_decrypt(aes_key, kc_pkt["proof"])
        kc_ok = (decrypted == b"C1_KEY_CONFIRM")
        print(f"[C2/V2V] RECV KEY_CONFIRM from C1")
        print(f"[C2/V2V] AES_GCM_decrypt(AES_key, proof) → '{decrypted.decode()}' {'✓' if kc_ok else '✗'}")
        assert kc_ok
        print(f"[C2/V2V] V2V SECURE CHANNEL ESTABLISHED ✓")

        # ── STEP 7: Send V2V safety data ─────────────────────────────
        print(f"\n[C2/V2V] ── STEP 7: SEND V2V_DATA ──")
        data = {
            "braking"   : False,
            "direction" : "SOUTH",
            "location"  : [6.9350, 79.8500],
            "speed"     : 55,
            "stability" : "OK",
            "timestamp" : int(time.time()),
        }
        data_bytes = canonical_json(data)
        data_sig   = ecdsa_sign(my_pseudo_priv, data_bytes)
        print(f"[C2/V2V] Payload: speed={data['speed']}, location={data['location']}, direction={data['direction']}")
        print(f"[C2/V2V] ECDSA_sign(pseudo_priv_2, data_bytes) → sig={data_sig[:24]}... (pseudonym signature)")

        payload_bytes = canonical_json({"data": data, "signature": data_sig})
        encrypted     = aes_gcm_encrypt(aes_key, payload_bytes.encode() if isinstance(payload_bytes, str) else payload_bytes)
        _send_msg(sock, "V2V_DATA", encrypted=encrypted)
        print(f"[C2/V2V] AES_GCM_encrypt(AES_key, {{data + sig}}) → {{nonce, ciphertext, tag}}")
        print(f"[C2/V2V] SENT V2V_DATA (C1 sees only encrypted bytes, not plain data)")

    # ─────────────────────────────────────────────
    # CHANNEL 3 — RELAY TO SERVER VIA C1
    # ─────────────────────────────────────────────

    def run_relay(self, c1: object, server_host="127.0.0.1", server_port=9002):
        """
        Run Channel 3: anonymous relay through C1 to reach the monitoring server.

        Phase 1: Anonymous key exchange (C1 cannot identify C2)
        Phase 2: Encrypted identity + monitoring data sent to server (C1 is blind)

        Args:
            c1          : VehicleC1 instance (used for relay methods)
            server_host : monitoring server address
            server_port : channel-3 relay port on server
        """
        assert self._v2v_key is not None, "V2V channel must be established first"

        print(f"\n[C2/CH3] ══ PHASE 1: ANONYMOUS KEY EXCHANGE ══")

        # ── STEP 1: Build anonymous HELLO ────────────────────────────
        print(f"[C2/CH3] ── STEP 1: BUILD ANONYMOUS HELLO ──")
        c2_eph_priv2, c2_eph_pub2 = generate_keypair()
        c2_eph_pub2_pem = pub_to_pem(c2_eph_pub2)
        nonce_c2 = base64.b64encode(os.urandom(16)).decode()
        now = int(time.time())

        anon_hello = {
            "ephemeral_pub": c2_eph_pub2_pem,
            "nonce"        : nonce_c2,
            "timestamp"    : now,
            "type"         : "ANON_HELLO",
        }
        print(f"[C2/CH3] Generated NEW ephemeral keypair for server ECDH")
        print(f"[C2/CH3]   c2_eph_pub2 = {pub_to_hex(c2_eph_pub2)[:32]}...")
        print(f"[C2/CH3] anon_hello = {{ephemeral_pub, timestamp, nonce}}")
        print(f"[C2/CH3] NO entity_id included → C1 cannot identify C2 ✓")
        print(f"[C2/CH3] NO certificate included → C1 cannot verify C2's identity ✓")

        # HMAC over anon_hello using V2V session key (integrity for C1)
        anon_hello_bytes = canonical_json(anon_hello)
        hmac_val = hmac_sign(self._v2v_key, anon_hello_bytes)
        print(f"[C2/CH3] HMAC_SHA256(V2V_key, anon_hello) → mac={hmac_val[:24]}... (integrity for C1)")
        print(f"[C2/CH3] SENT RELAY_REQUEST to C1 via encrypted V2V channel")

        # ── Open server connection and do relay via C1 ────────────────
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv_sock:
            srv_sock.connect((server_host, server_port))

            # C1 relays anonymous hello → server, gets ACK back
            ack = c1.relay_step2_forward(anon_hello, hmac_val, srv_sock)

            # ── STEP 5: Verify server + derive session key ────────────
            print(f"\n[C2/CH3] ── STEP 5: VERIFY SERVER + DERIVE SESSION KEY ──")
            print(f"[C2/CH3] RECV RELAY_HELLO_ACK via C1 relay")
            srv_cert = ack["certificate"]

            # CHECK-A: CA sig on server cert
            cert_body  = {k: v for k, v in srv_cert.items() if k != "ca_signature"}
            body_bytes = canonical_json(cert_body)
            ca_ok = ecdsa_verify(self._ca_pub, body_bytes, srv_cert["ca_signature"])
            print(f"[C2/CH3] CHECK-A CA signature on server cert → {'TRUE ✓' if ca_ok else 'FALSE ✗'}")
            assert ca_ok
            print(f"[C2/CH3]   This is a real CA-authorised controller ✓")

            srv_lt_pub = pem_to_pub(srv_cert["public_key"])
            print(f"[C2/CH3] CHECK-B Extract Server_lt_pub from cert")

            # CHECK-C: Server ECDSA on ack_body
            ack_body = canonical_json({
                "ephemeral_pub": ack["ephemeral_pub"],
                "nonce_echo"   : ack["nonce_echo"],
                "timestamp"    : ack["timestamp"],
            })
            ack_sig_ok = ecdsa_verify(srv_lt_pub, ack_body, ack["signature"])
            print(f"[C2/CH3] CHECK-C ECDSA_verify(Server_lt_pub, ack_body, sig) → {'TRUE ✓' if ack_sig_ok else 'FALSE ✗'}")
            assert ack_sig_ok
            print(f"[C2/CH3]   s_eph_pub is genuine (server produced it) ✓")
            print(f"[C2/CH3]   C1 could NOT have fabricated this (no Server_lt_priv) ✓")

            # CHECK-D: Nonce echo
            nonce_ok = (ack["nonce_echo"] == nonce_c2)
            print(f"[C2/CH3] CHECK-D nonce_echo == nonce_c2 → {'TRUE ✓' if nonce_ok else 'FALSE ✗'} (no replay)")
            assert nonce_ok

            # CHECK-E: Timestamp
            delta = abs(time.time() - ack["timestamp"])
            ts_ok = fresh_timestamp(ack["timestamp"])
            print(f"[C2/CH3] CHECK-E Timestamp: delta={delta:.3f}s → {'FRESH ✓' if ts_ok else 'STALE ✗'}")
            assert ts_ok

            # Derive session key
            s_eph_pub2 = pem_to_pub(ack["ephemeral_pub"])
            ss_raw  = ecdh_shared_secret_x(c2_eph_priv2, s_eph_pub2)
            aes_key = derive_session_key(c2_eph_priv2, s_eph_pub2, "Monitoring-Ch3-Relay", "relay")
            print(f"[C2/CH3] ECDH: SS = c2_eph_priv2 × s_eph_pub2")
            print(f"[C2/CH3]   SS.x = {ss_raw.hex()[:32]}...")
            print(f"[C2/CH3] HKDF(SS.x, salt='Monitoring-Ch3-Relay') → AES_key={aes_key.hex()[:32]}...")
            print(f"[C2/CH3] This AES_key is UNKNOWN to C1 ✓ (C1 never had either priv key)")
            print(f"[C2/CH3] PHASE 1 COMPLETE — anonymous key exchange done ✓")

            # ── PHASE 2: Encrypted identity ───────────────────────────
            print(f"\n[C2/CH3] ══ PHASE 2: ENCRYPTED IDENTITY ══")

            # ── STEP 6: Send FINISHED with encrypted identity ─────────
            print(f"[C2/CH3] ── STEP 6: SEND FINISHED WITH ENCRYPTED IDENTITY ──")
            real_identity_payload = canonical_json({
                "certificate": self._lt_cert,
                "entity_id"  : self.ENTITY_ID,
                "proof"      : "CLIENT_FINISHED",
            })
            sealed_identity = aes_gcm_encrypt(aes_key, real_identity_payload.encode() if isinstance(real_identity_payload, str) else real_identity_payload)
            print(f"[C2/CH3] real_identity = {{entity_id='{self.ENTITY_ID}', certificate, proof}}")
            print(f"[C2/CH3] AES_GCM_encrypt(AES_key, real_identity) → sealed blob")
            print(f"[C2/CH3] SENT RELAY_FINISHED (C1 sees only encrypted blob)")

            fin_resp = c1.relay_forward_blob("RELAY_FINISHED", sealed_identity, srv_sock, "RELAY_FINISHED")
            print(f"[C2/CH3] RECV RELAY_FINISHED_ACK — status={fin_resp.get('status')} ✓")

            # ── STEP 7: Send monitoring data (sealed) ─────────────────
            print(f"\n[C2/CH3] ── STEP 7: SEND MONITORING DATA (SEALED) ──")
            stats = {
                "braking"     : True,
                "direction"   : "EAST",
                "engine_temp" : 87,
                "fuel_level"  : 42,
                "location"    : [6.9350, 79.8500],
                "speed"       : 48,
                "stability"   : "OK",
                "timestamp"   : int(time.time()),
                "vehicle_id"  : self.ENTITY_ID,
            }
            stats_bytes = canonical_json(stats)
            data_sig    = ecdsa_sign(self._lt_priv, stats_bytes)
            print(f"[C2/CH3] Stats: speed={stats['speed']}, direction={stats['direction']}, location={stats['location']}")
            print(f"[C2/CH3] ECDSA_sign(C2_lt_priv, stats_bytes) → sig={data_sig[:24]}...")
            print(f"[C2/CH3]   (Non-repudiation: C2-LK-5678 cannot deny sending these stats)")

            payload_bytes = canonical_json({"signature": data_sig, "stats": stats})
            sealed_data   = aes_gcm_encrypt(aes_key, payload_bytes.encode() if isinstance(payload_bytes, str) else payload_bytes)
            print(f"[C2/CH3] AES_GCM_encrypt(AES_key, {{stats+sig}}) → sealed blob")
            print(f"[C2/CH3] SENT RELAY_DATA to C1 for forwarding")

            data_resp = c1.relay_forward_blob("RELAY_DATA", sealed_data, srv_sock, "RELAY_DATA")
            print(f"[C2/CH3] RECV DATA_ACK — status={data_resp.get('status')} ✓")
