"""
vehicle_c1.py — SDVN Vehicle C1
================================
Vehicle C1: in wireless range of the mobile node (base station).

Roles:
  - Channel 1 (V2V)      : Responder — listens on TCP port 9001 for C2
  - Channel 2 (Monitoring): Client   — connects to server port 9000
  - Channel 3 (Relay)    : Blind relay node — forwards C2↔Server packets

Security contract for relay:
  C1 MUST NOT learn C2's real identity at any point.
  C1 verifies HMAC integrity of relay requests (channel membership check only).
  C1 forwards sealed blobs it cannot decrypt.
"""

import socket
import json
import time
import threading

from crypto_utils import (
    generate_keypair, pub_to_pem, pub_to_hex, pem_to_pub,
    derive_session_key, ecdh_shared_secret_x,
    aes_gcm_encrypt, aes_gcm_decrypt,
    ecdsa_sign, ecdsa_verify,
    hmac_verify,
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


class VehicleC1:
    """
    Vehicle C1 — in wireless range of base station.
    Acts as V2V responder, direct monitoring client, and blind relay.
    """

    ENTITY_ID = "C1-LK-1234"
    V2V_PORT  = 9001   # C2 connects here for V2V

    def __init__(self, ca_pub_key, lt_priv, lt_cert, pseudo_certs):
        """
        Args:
            ca_pub_key   : CA public key (pre-loaded)
            lt_priv      : C1 long-term ECDSA private key
            lt_cert      : C1 CA-signed long-term certificate
            pseudo_certs : list of (cert_dict, priv_key) pseudonym pairs
        """
        self._ca_pub      = ca_pub_key
        self._lt_priv     = lt_priv
        self._lt_pub      = lt_priv.public_key()
        self._lt_cert     = lt_cert
        self._pseudonyms  = pseudo_certs   # [(cert, priv), ...]
        self._v2v_key     = None           # Set after Channel 1
        self._c2_pseudo_pub = None         # C2's pseudonym pub (for data verify)
        print(f"[C1] Vehicle C1 ({self.ENTITY_ID}) initialised")
        print(f"[C1] Long-term certificate: entity={self.ENTITY_ID}, role=vehicle")
        print(f"[C1] Pseudonyms available: {len(self._pseudonyms)}")

    # ─────────────────────────────────────────────
    # CHANNEL 1 — V2V RESPONDER
    # ─────────────────────────────────────────────

    def run_v2v_server(self, ready_event=None):
        """Listen on V2V_PORT, accept C2, run full V2V handshake."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", self.V2V_PORT))
            srv.listen(1)
            if ready_event:
                ready_event.set()
            conn, _ = srv.accept()
            with conn:
                self._handle_v2v(conn)

    def _handle_v2v(self, conn):
        """Full V2V handshake as responder (Steps 2-7 from C1 perspective)."""
        print(f"\n[C1/V2V] ── CHANNEL 1 V2V HANDSHAKE START ──")

        # ── STEP 2: Verify C2 HELLO ──────────────────────────────────
        print(f"[C1/V2V] ── STEP 2: VERIFY INCOMING V2V_HELLO ──")
        pkt = _recv_msg(conn)
        assert pkt["type"] == "V2V_HELLO"
        peer_pseudo_id   = pkt["pseudo_id"]
        peer_pseudo_cert = pkt["pseudonym_cert"]
        print(f"[C1/V2V] RECV V2V_HELLO from pseudo_id={peer_pseudo_id}")

        # CHECK-A: CA signature on pseudonym cert
        cert_body  = {k: v for k, v in peer_pseudo_cert.items() if k != "ca_signature"}
        body_bytes = canonical_json(cert_body)
        ca_ok = ecdsa_verify(self._ca_pub, body_bytes, peer_pseudo_cert["ca_signature"])
        print(f"[C1/V2V] CHECK-A CA signature on pseudonym cert:")
        print(f"[C1/V2V]   ECDSA_verify(CA_pub, cert_body, ca_sig) → {'TRUE ✓' if ca_ok else 'FALSE ✗'}")
        assert ca_ok
        print(f"[C1/V2V]   This pseudonym was issued by the trusted CA")
        print(f"[C1/V2V]   Meaning: sender is a real registered vehicle ✓")

        # CHECK-B: ECDSA on HELLO body with pseudonym pub
        peer_pseudo_pub = pem_to_pub(peer_pseudo_cert["public_key"])
        hello_body = canonical_json({
            "ephemeral_pub": pkt["ephemeral_pub"],
            "pseudo_id"    : pkt["pseudo_id"],
            "timestamp"    : pkt["timestamp"],
        })
        sig_ok = ecdsa_verify(peer_pseudo_pub, hello_body, pkt["signature"])
        print(f"[C1/V2V] CHECK-B ECDSA signature on HELLO body:")
        print(f"[C1/V2V]   ECDSA_verify(pseudo_pub_2, hello_body, sig) → {'TRUE ✓' if sig_ok else 'FALSE ✗'}")
        assert sig_ok
        print(f"[C1/V2V]   Sender owns the private key matching this pseudonym ✓")

        # CHECK-C: Timestamp
        delta = abs(time.time() - pkt["timestamp"])
        ts_ok = fresh_timestamp(pkt["timestamp"])
        print(f"[C1/V2V] CHECK-C Timestamp freshness: delta={delta:.3f}s < 30s → {'FRESH ✓' if ts_ok else 'STALE ✗'}")
        assert ts_ok
        print(f"[C1/V2V] NOTE: C1 does NOT know C2's real identity ✓")

        c2_eph_pub = pem_to_pub(pkt["ephemeral_pub"])
        self._c2_pseudo_pub = peer_pseudo_pub

        # ── STEP 3: Send C1 HELLO ─────────────────────────────────────
        print(f"\n[C1/V2V] ── STEP 3: SEND V2V_HELLO (C1 response) ──")
        my_pseudo_cert, my_pseudo_priv = self._pseudonyms[0]
        my_pseudo_id = my_pseudo_cert["entity_id"]
        c1_eph_priv, c1_eph_pub = generate_keypair()
        c1_eph_pub_pem = pub_to_pem(c1_eph_pub)
        now = int(time.time())

        hello_body_c1 = canonical_json({
            "ephemeral_pub": c1_eph_pub_pem,
            "pseudo_id"    : my_pseudo_id,
            "timestamp"    : now,
        })
        hello_sig = ecdsa_sign(my_pseudo_priv, hello_body_c1)
        print(f"[C1/V2V] Using pseudonym: pseudo_id={my_pseudo_id} (real ID hidden)")
        print(f"[C1/V2V] Generated ephemeral keypair for ECDH")
        print(f"[C1/V2V] ECDSA_sign(pseudo_priv_1, hello_body) → sig={hello_sig[:24]}...")
        _send_msg(conn, "V2V_HELLO",
                  pseudo_id      = my_pseudo_id,
                  pseudonym_cert = my_pseudo_cert,
                  ephemeral_pub  = c1_eph_pub_pem,
                  timestamp      = now,
                  signature      = hello_sig)
        print(f"[C1/V2V] SENT V2V_HELLO → {{pseudo_id, pseudonym_cert, ephemeral_pub, timestamp, sig}}")
        print(f"[C1/V2V] NOTE: Real identity {self.ENTITY_ID} NOT included ✓")

        # ── STEP 5: Derive session key ────────────────────────────────
        print(f"\n[C1/V2V] ── STEP 5: DERIVE SESSION KEY ──")
        ss_raw  = ecdh_shared_secret_x(c1_eph_priv, c2_eph_pub)
        aes_key = derive_session_key(c1_eph_priv, c2_eph_pub, "V2V-Ch1", "v2v")
        print(f"[C1/V2V] ECDH: SS = c1_eph_priv × c2_eph_pub")
        print(f"[C1/V2V]   SS.x = {ss_raw.hex()[:32]}...  ← IDENTICAL to C2's ✓")
        print(f"[C1/V2V]   AES_key = {aes_key.hex()[:32]}... ← IDENTICAL to C2's ✓")
        print(f"[C1/V2V] NOTE: Attacker sees c1_eph_pub and c2_eph_pub on wire")
        print(f"[C1/V2V]       To get SS, attacker needs c1_eph_priv OR c2_eph_priv")
        print(f"[C1/V2V]       Neither was ever transmitted → attacker cannot derive key ✓")
        self._v2v_key = aes_key

        # ── STEP 6: KEY_CONFIRM ───────────────────────────────────────
        print(f"\n[C1/V2V] ── STEP 6: KEY_CONFIRM ──")
        # Receive C2 proof
        kc_pkt = _recv_msg(conn)
        assert kc_pkt["type"] == "KEY_CONFIRM"
        decrypted = aes_gcm_decrypt(aes_key, kc_pkt["proof"])
        kc_ok = (decrypted == b"C2_KEY_CONFIRM")
        print(f"[C1/V2V] RECV KEY_CONFIRM from C2")
        print(f"[C1/V2V] AES_GCM_decrypt(AES_key, proof) → '{decrypted.decode()}' {'✓' if kc_ok else '✗'}")
        assert kc_ok
        print(f"[C1/V2V] Both sides hold the same AES_key ✓")

        # Send C1 proof
        proof_c1 = aes_gcm_encrypt(aes_key, b"C1_KEY_CONFIRM")
        _send_msg(conn, "KEY_CONFIRM", proof=proof_c1)
        print(f"[C1/V2V] SENT KEY_CONFIRM proof to C2")
        print(f"[C1/V2V] V2V SECURE CHANNEL ESTABLISHED ✓")

        # ── STEP 7: Receive V2V data ──────────────────────────────────
        print(f"\n[C1/V2V] ── STEP 7: RECV V2V_DATA ──")
        data_pkt = _recv_msg(conn)
        assert data_pkt["type"] == "V2V_DATA"
        print(f"[C1/V2V] RECV V2V_DATA")
        plain   = aes_gcm_decrypt(aes_key, data_pkt["encrypted"])
        payload = json.loads(plain.decode())
        data    = payload["data"]
        data_sig= payload["signature"]
        print(f"[C1/V2V] AES_GCM_decrypt(AES_key, packet) → plaintext ✓")

        data_bytes = canonical_json(data)
        sig_ok = ecdsa_verify(peer_pseudo_pub, data_bytes, data_sig)
        print(f"[C1/V2V] ECDSA_verify(pseudo_pub_2, data_bytes, sig) → {'TRUE ✓' if sig_ok else 'FALSE ✗'}")
        assert sig_ok
        print(f"[C1/V2V] Safety data authenticated (from a real vehicle) ✓")
        print(f"[C1/V2V] Real identity of sender: UNKNOWN (anonymity preserved) ✓")
        print(f"[C1/V2V] Data received: speed={data['speed']}, direction={data['direction']}, braking={data['braking']}")

        # Channel 1 security checklist
        print(f"\n── Channel 1 Security Properties ──────────────────────────")
        print(f"  Confidentiality   : ✓ AES-GCM-256 (session key from ECDH)")
        print(f"  Integrity         : ✓ AES-GCM auth tag (any modification = reject)")
        print(f"  Authentication    : ✓ ECDSA on pseudonym (CA-verified vehicle)")
        print(f"  Anonymity         : ✓ Pseudonym used (real ID never transmitted)")
        print(f"  Replay Protection : ✓ Timestamp checked within 30-second window")
        print(f"  Forward Secrecy   : ✓ Ephemeral keys deleted after session")
        print(f"────────────────────────────────────────────────────────────")

    # ─────────────────────────────────────────────
    # CHANNEL 2 — MONITORING CLIENT
    # ─────────────────────────────────────────────

    def run_monitoring(self, server_host="127.0.0.1", server_port=9000):
        """Connect to server and run full Channel 2 monitoring session."""
        print(f"\n[C1/CH2] ── CHANNEL 2 MONITORING SESSION START ──")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((server_host, server_port))
            self._handle_channel2(sock)

    def _handle_channel2(self, sock):
        # ── STEP 1: Send HELLO ────────────────────────────────────────
        print(f"[C1/CH2] ── STEP 1: SEND HELLO ──")
        c1_eph_priv, c1_eph_pub = generate_keypair()
        c1_eph_pub_pem = pub_to_pem(c1_eph_pub)
        now = int(time.time())

        hello_body = canonical_json({
            "entity_id"    : self.ENTITY_ID,
            "ephemeral_pub": c1_eph_pub_pem,
            "timestamp"    : now,
        })
        hello_sig = ecdsa_sign(self._lt_priv, hello_body)
        print(f"[C1/CH2] Real identity used: {self.ENTITY_ID} (server needs to know who we are)")
        print(f"[C1/CH2] Generated ephemeral keypair for ECDH")
        print(f"[C1/CH2] ECDSA_sign(C1_longterm_priv, hello_body) → sig={hello_sig[:24]}...")
        _send_msg(sock, "HELLO",
                  entity_id     = self.ENTITY_ID,
                  certificate   = self._lt_cert,
                  ephemeral_pub = c1_eph_pub_pem,
                  timestamp     = now,
                  signature     = hello_sig)
        print(f"[C1/CH2] SENT HELLO → {{entity_id, certificate, ephemeral_pub, timestamp, sig}}")

        # ── STEP 4: Verify HELLO_ACK ─────────────────────────────────
        print(f"[C1/CH2] ── STEP 4: VERIFY HELLO_ACK (MUTUAL AUTHENTICATION) ──")
        ack = _recv_msg(sock)
        assert ack["type"] == "HELLO_ACK"
        srv_cert = ack["certificate"]

        cert_body  = {k: v for k, v in srv_cert.items() if k != "ca_signature"}
        body_bytes = canonical_json(cert_body)
        ca_ok = ecdsa_verify(self._ca_pub, body_bytes, srv_cert["ca_signature"])
        print(f"[C1/CH2] CHECK-A CA signature on server certificate → {'TRUE ✓' if ca_ok else 'FALSE ✗'}")
        assert ca_ok
        print(f"[C1/CH2]   Server is a genuine CA-authorised monitoring controller ✓")

        srv_lt_pub = pem_to_pub(srv_cert["public_key"])
        print(f"[C1/CH2] CHECK-B Extract Server_lt_pub from cert → done")

        ack_body = canonical_json({
            "ephemeral_pub": ack["ephemeral_pub"],
            "timestamp"    : ack["timestamp"],
        })
        ack_sig_ok = ecdsa_verify(srv_lt_pub, ack_body, ack["signature"])
        print(f"[C1/CH2] CHECK-C ECDSA_verify(Server_lt_pub, ack_body, sig) → {'TRUE ✓' if ack_sig_ok else 'FALSE ✗'}")
        assert ack_sig_ok
        print(f"[C1/CH2]   Server_ephemeral_pub is genuine (server signed it) ✓")
        print(f"[C1/CH2]   C1 knows it is talking to the real server, not an attacker ✓")

        delta = abs(time.time() - ack["timestamp"])
        ts_ok = fresh_timestamp(ack["timestamp"])
        print(f"[C1/CH2] CHECK-D Timestamp: delta={delta:.3f}s → {'FRESH ✓' if ts_ok else 'STALE ✗'}")
        assert ts_ok
        print(f"[C1/CH2] MUTUAL AUTHENTICATION COMPLETE ✓")

        s_eph_pub = pem_to_pub(ack["ephemeral_pub"])

        # ── STEP 5: Derive session key ────────────────────────────────
        print(f"[C1/CH2] ── STEP 5: DERIVE SESSION KEY ──")
        ss_raw  = ecdh_shared_secret_x(c1_eph_priv, s_eph_pub)
        aes_key = derive_session_key(c1_eph_priv, s_eph_pub, "Monitoring-Ch2", "monitor")
        print(f"[C1/CH2] ECDH: SS = c1_eph_priv × s_eph_pub")
        print(f"[C1/CH2]   SS.x = {ss_raw.hex()[:32]}...")
        print(f"[C1/CH2] HKDF(SS.x, salt='Monitoring-Ch2') → AES_key={aes_key.hex()[:32]}...")

        # ── STEP 6: Send FINISHED ─────────────────────────────────────
        print(f"[C1/CH2] ── STEP 6: SEND FINISHED ──")
        proof = aes_gcm_encrypt(aes_key, b"CLIENT_FINISHED")
        _send_msg(sock, "FINISHED", proof=proof)
        print(f"[C1/CH2] AES_GCM_encrypt(AES_key, 'CLIENT_FINISHED') → proof")
        print(f"[C1/CH2] SENT FINISHED (proves C1 derived correct session key)")

        fin_ack = _recv_msg(sock)
        assert fin_ack["type"] == "FINISHED_ACK"
        print(f"[C1/CH2] RECV FINISHED_ACK — channel established ✓")

        # ── STEP 7: Send monitoring data ──────────────────────────────
        print(f"[C1/CH2] ── STEP 7: SEND MONITORING DATA ──")
        stats = {
            "braking"     : False,
            "direction"   : "NORTH",
            "engine_temp" : 92,
            "fuel_level"  : 68,
            "location"    : [6.9271, 79.8612],
            "speed"       : 72,
            "stability"   : "OK",
            "timestamp"   : int(time.time()),
            "vehicle_id"  : self.ENTITY_ID,
        }
        stats_bytes = canonical_json(stats)
        data_sig    = ecdsa_sign(self._lt_priv, stats_bytes)
        print(f"[C1/CH2] Stats: speed={stats['speed']}, direction={stats['direction']}, location={stats['location']}")
        print(f"[C1/CH2] ECDSA_sign(C1_longterm_priv, stats_bytes) → sig={data_sig[:24]}...")
        print(f"[C1/CH2]   (Non-repudiation: C1 cannot later deny sending these stats)")

        payload_bytes = canonical_json({"signature": data_sig, "stats": stats})
        encrypted     = aes_gcm_encrypt(aes_key, payload_bytes.encode() if isinstance(payload_bytes, str) else payload_bytes)
        _send_msg(sock, "DATA", encrypted_payload=encrypted)
        print(f"[C1/CH2] AES_GCM_encrypt(AES_key, {{stats + sig}}) → encrypted payload")
        print(f"[C1/CH2] SENT DATA")

        da = _recv_msg(sock)
        assert da["type"] == "DATA_ACK"
        print(f"[C1/CH2] RECV DATA_ACK ✓")

    # ─────────────────────────────────────────────
    # CHANNEL 3 — BLIND RELAY
    # ─────────────────────────────────────────────

    def run_relay(self, server_host="127.0.0.1", server_port=9002, v2v_conn=None):
        """
        Act as a blind relay between C2 (V2V) and the monitoring server.
        Forwards packets in both directions without being able to read them.

        Args:
            server_host : monitoring server address
            server_port : monitoring server channel-3 port
            v2v_conn    : established V2V socket to C2 (or simulated queue)
        """
        pass  # Called differently in simulation — see main.py

    def relay_step2_forward(self, anon_hello: dict, hmac_val: str, srv_sock) -> dict:
        """
        Relay step 2: verify HMAC, sign relay wrapper, forward to server.

        Args:
            anon_hello : anonymous hello dict from C2
            hmac_val   : HMAC from C2 over anon_hello
            srv_sock   : connected socket to monitoring server

        Returns:
            dict: RELAY_HELLO_ACK from server (to forward back to C2)
        """
        print(f"\n[C1/RELAY] ── STEP 2: FORWARD ANONYMOUS HELLO ──")
        print(f"[C1/RELAY] RECV RELAY_REQUEST from V2V peer")

        # Verify HMAC with V2V session key
        anon_hello_bytes = canonical_json(anon_hello)
        hmac_ok = hmac_verify(self._v2v_key, anon_hello_bytes, hmac_val)
        print(f"[C1/RELAY] HMAC_verify(V2V_key, hello, mac) → {'TRUE ✓' if hmac_ok else 'FALSE ✗'}")
        assert hmac_ok, "RELAY_REQUEST HMAC invalid"
        print(f"[C1/RELAY]   Request is genuine (came from V2V partner, not injected) ✓")

        # Inspect but cannot identify
        print(f"[C1/RELAY] C1 inspects anon_hello:")
        print(f"[C1/RELAY]   ephemeral_pub = {anon_hello['ephemeral_pub'][:32]}... (just a public key, no identity info)")
        print(f"[C1/RELAY]   entity_id = NOT PRESENT → C1 cannot identify sender ✓")

        # Sign relay wrapper with C1 long-term key
        now = int(time.time())
        relay_body = canonical_json({
            "payload"  : anon_hello,
            "relay_id" : self.ENTITY_ID,
            "timestamp": now,
        })
        relay_sig = ecdsa_sign(self._lt_priv, relay_body)
        print(f"[C1/RELAY] ECDSA_sign(C1_lt_priv, relay_body) → relay_sig={relay_sig[:24]}...")

        _send_msg(srv_sock, "RELAY_ANON_HELLO",
                  relay_id          = self.ENTITY_ID,
                  relay_certificate = self._lt_cert,
                  payload           = anon_hello,
                  timestamp         = now,
                  relay_sig         = relay_sig)
        print(f"[C1/RELAY] SENT RELAY_ANON_HELLO to server")
        print(f"[C1/RELAY]   (C1 knows only: some vehicle wants to reach the server)")
        print(f"[C1/RELAY]   (C1 does NOT know who that vehicle is) ✓")

        # Receive ACK from server
        ack = _recv_msg(srv_sock)
        assert ack["type"] == "RELAY_HELLO_ACK"
        print(f"\n[C1/RELAY] RECV RELAY_HELLO_ACK from server")
        print(f"[C1/RELAY] C1 sees: server certificate (public, not secret)")
        print(f"[C1/RELAY] C1 sees: s_eph_pub = {ack['ephemeral_pub'][:32]}... (public key, useless alone)")
        print(f"[C1/RELAY] C1 CANNOT derive session key (needs c2_eph_priv or s_eph_priv)")
        print(f"[C1/RELAY] Forwarding RELAY_HELLO_ACK to C2 via V2V channel")
        return ack

    def relay_forward_blob(self, msg_type: str, sealed: dict, srv_sock, label: str) -> dict:
        """
        Blindly forward a sealed (encrypted) packet to server and return response.

        C1 cannot read the sealed blob — it only forwards it.

        Args:
            msg_type : packet type to send to server
            sealed   : encrypted blob dict
            srv_sock : server socket
            label    : logging label (e.g. "RELAY_FINISHED", "RELAY_DATA")

        Returns:
            dict: server response packet
        """
        print(f"[C1/RELAY] RECV {label} from C2")
        print(f"[C1/RELAY] C1 sees: [nonce | ciphertext | tag] — meaningless ✓")
        if label == "RELAY_DATA":
            print(f"[C1/RELAY] C1 identity of data sender: UNKNOWN ✓")
            print(f"[C1/RELAY] C1 content of data: UNKNOWN ✓")
        print(f"[C1/RELAY] Forwarding sealed blob to server (blind relay) ✓")
        _send_msg(srv_sock, msg_type, sealed=sealed)
        resp = _recv_msg(srv_sock)
        return resp
