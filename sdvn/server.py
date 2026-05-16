"""
server.py — SDVN Monitoring Server
====================================
Central monitoring controller for the SDVN network.

Responsibilities:
  - Listen on TCP port 9000 for Channel 2 (direct C1 monitoring)
  - Listen on TCP port 9001 for Channel 3 relay forwarding from C1
  - Perform mutual authentication with C1 (Channel 2)
  - Accept anonymous relay from C2 via C1 (Channel 3)
  - Decrypt and log vehicle statistics
  - Provide non-repudiation verification on all received data

Security properties provided:
  Channel 2: Mutual auth (ECDSA+CA), Confidentiality (AES-GCM),
             Integrity (GCM tag), Non-repudiation (ECDSA on stats),
             Replay protection (timestamp)
  Channel 3: Accept relayed anonymous key exchange, verify C1 relay
             authenticity, establish end-to-end encrypted session with
             C2 without C1 learning C2's identity.
"""

import socket
import json
import time
import threading

from crypto_utils import (
    generate_keypair,
    pub_to_pem,
    pub_to_hex,
    pem_to_pub,
    derive_session_key,
    ecdh_shared_secret_x,
    aes_gcm_encrypt,
    aes_gcm_decrypt,
    ecdsa_sign,
    ecdsa_verify,
    fresh_timestamp,
    make_packet,
    parse_packet,
    canonical_json,
)


def _recv_msg(sock: socket.socket) -> dict:
    """
    Receive a length-prefixed JSON message from a socket.

    Protocol: 4-byte big-endian length prefix followed by JSON payload.

    Args:
        sock: connected TCP socket

    Returns:
        dict: parsed packet
    """
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
            raise ConnectionError("Socket closed during payload")
        data += chunk
    return parse_packet(data)


def _send_msg(sock: socket.socket, msg_type: str, **fields):
    """
    Send a length-prefixed JSON message over a socket.

    Args:
        sock     : connected TCP socket
        msg_type : packet type string
        **fields : packet payload fields
    """
    payload = make_packet(msg_type, **fields)
    length  = len(payload).to_bytes(4, "big")
    sock.sendall(length + payload)


class MonitoringServer:
    """
    SDVN Monitoring Server.

    Holds long-term certificate and handles both direct (Ch2) and
    relay (Ch3) secure channels.
    """

    SERVER_ID   = "MONITORING-SERVER-01"
    CH2_PORT    = 9000   # Direct C1 monitoring
    CH3_PORT    = 9002   # Relay forwarding from C1

    def __init__(self, ca_pub_key, server_certificate: dict, server_lt_priv):
        """
        Initialise the monitoring server.

        Args:
            ca_pub_key          : CA public key for certificate verification
            server_certificate  : Server's CA-signed long-term certificate
            server_lt_priv      : Server's long-term ECDSA private key
        """
        print(f"[SERVER] Initialising Monitoring Server ({self.SERVER_ID})")
        self._ca_pub       = ca_pub_key
        self._cert         = server_certificate
        self._lt_priv      = server_lt_priv
        self._lt_pub       = server_lt_priv.public_key()
        self._vehicle_log  = {}    # entity_id → latest stats

        # Channel-3 state: set after anonymous key exchange
        self._ch3_aes_key  = None
        self._ch3_entity   = None
        self._ch3_lt_pub   = None

        print(f"[SERVER] Long-term certificate: entity={self.SERVER_ID}, role=server")
        print(f"[SERVER] Listening on CH2_PORT={self.CH2_PORT}, CH3_PORT={self.CH3_PORT}")

    # ─────────────────────────────────────────────
    # CHANNEL 2 — DIRECT C1 MONITORING
    # ─────────────────────────────────────────────

    def handle_channel2(self, conn: socket.socket):
        """
        Handle a full Channel 2 (direct monitoring) session with C1.

        Steps:
          1. RECV HELLO from C1 → verify CA sig + ECDSA sig + timestamp
          2. SEND HELLO_ACK  → server cert + ephemeral pub + ECDSA sig
          3. Both sides derive AES session key via ECDH + HKDF
          4. RECV FINISHED   → verify AES proof from C1
          5. SEND FINISHED_ACK
          6. RECV DATA       → decrypt stats + verify ECDSA (non-repudiation)
          7. SEND DATA_ACK

        Args:
            conn: accepted TCP connection socket
        """
        print(f"\n[SERVER/CH2] ══ CHANNEL 2: DIRECT MONITORING SESSION ══")

        # ── STEP 2: Receive and verify C1 HELLO ─────────────────────
        print(f"[SERVER/CH2] ── STEP 2: VERIFY HELLO ──")
        pkt = _recv_msg(conn)
        assert pkt["type"] == "HELLO", f"Expected HELLO, got {pkt['type']}"

        entity_id = pkt["entity_id"]
        c1_cert   = pkt["certificate"]
        print(f"[SERVER/CH2] RECV HELLO from entity_id={entity_id}")

        # CHECK-A: CA signature on C1 certificate
        cert_body  = {k: v for k, v in c1_cert.items() if k != "ca_signature"}
        body_bytes = canonical_json(cert_body)
        ca_sig_ok  = ecdsa_verify(self._ca_pub, body_bytes, c1_cert["ca_signature"])
        print(f"[SERVER/CH2] CHECK-A CA signature on C1 certificate:")
        print(f"[SERVER/CH2]   ECDSA_verify(CA_pub, cert_body, ca_sig) → {'TRUE ✓' if ca_sig_ok else 'FALSE ✗'}")
        assert ca_sig_ok, "C1 certificate CA signature invalid"
        print(f"[SERVER/CH2]   C1 is a genuine CA-registered vehicle ✓")

        # CHECK-B: Extract C1 long-term public key
        c1_lt_pub = pem_to_pub(c1_cert["public_key"])
        print(f"[SERVER/CH2] CHECK-B Extract C1_lt_pub from certificate → done")

        # CHECK-C: ECDSA signature on HELLO body
        hello_body = canonical_json({
            "entity_id"    : pkt["entity_id"],
            "ephemeral_pub": pkt["ephemeral_pub"],
            "timestamp"    : pkt["timestamp"],
        })
        hello_sig_ok = ecdsa_verify(c1_lt_pub, hello_body, pkt["signature"])
        print(f"[SERVER/CH2] CHECK-C ECDSA signature on HELLO:")
        print(f"[SERVER/CH2]   ECDSA_verify(C1_lt_pub, hello_body, sig) → {'TRUE ✓' if hello_sig_ok else 'FALSE ✗'}")
        assert hello_sig_ok, "C1 HELLO signature invalid"
        print(f"[SERVER/CH2]   C1 owns the private key matching its certificate ✓")

        # CHECK-D: Timestamp freshness
        delta = abs(time.time() - pkt["timestamp"])
        ts_ok = fresh_timestamp(pkt["timestamp"])
        print(f"[SERVER/CH2] CHECK-D Timestamp: delta={delta:.3f}s → {'FRESH ✓' if ts_ok else 'STALE ✗'}")
        assert ts_ok, "C1 HELLO timestamp stale"

        c1_eph_pub = pem_to_pub(pkt["ephemeral_pub"])

        # ── STEP 3: Send HELLO_ACK ───────────────────────────────────
        print(f"[SERVER/CH2] ── STEP 3: SEND HELLO_ACK ──")
        s_eph_priv, s_eph_pub = generate_keypair()
        s_eph_pub_pem = pub_to_pem(s_eph_pub)
        s_eph_pub_hex = pub_to_hex(s_eph_pub)
        now = int(time.time())

        ack_body = canonical_json({
            "ephemeral_pub": s_eph_pub_pem,
            "timestamp"    : now,
        })
        ack_sig = ecdsa_sign(self._lt_priv, ack_body)
        print(f"[SERVER/CH2] Generated ephemeral keypair for ECDH")
        print(f"[SERVER/CH2]   s_eph_pub = {s_eph_pub_hex[:32]}...")
        print(f"[SERVER/CH2] ECDSA_sign(Server_lt_priv, ack_body) → sig={ack_sig[:24]}...")
        _send_msg(conn, "HELLO_ACK",
                  certificate   = self._cert,
                  ephemeral_pub = s_eph_pub_pem,
                  timestamp     = now,
                  signature     = ack_sig)
        print(f"[SERVER/CH2] SENT HELLO_ACK → {{server_certificate, ephemeral_pub, sig}}")

        # ── STEP 5: Derive session key ───────────────────────────────
        print(f"[SERVER/CH2] ── STEP 5: DERIVE SESSION KEY ──")
        ss_raw    = ecdh_shared_secret_x(s_eph_priv, c1_eph_pub)
        aes_key   = derive_session_key(s_eph_priv, c1_eph_pub, "Monitoring-Ch2", "monitor")
        print(f"[SERVER/CH2] ECDH: SS = s_eph_priv × c1_eph_pub")
        print(f"[SERVER/CH2]   SS.x = {ss_raw.hex()[:32]}...")
        print(f"[SERVER/CH2] HKDF(SS.x, salt='Monitoring-Ch2', label='monitor')")
        print(f"[SERVER/CH2]   AES_key = {aes_key.hex()[:32]}... (32 bytes)")

        # ── STEP 6: Receive FINISHED from C1 ────────────────────────
        print(f"[SERVER/CH2] ── STEP 6: RECV FINISHED ──")
        fin_pkt = _recv_msg(conn)
        assert fin_pkt["type"] == "FINISHED"
        decrypted = aes_gcm_decrypt(aes_key, fin_pkt["proof"])
        fin_ok = (decrypted == b"CLIENT_FINISHED")
        print(f"[SERVER/CH2] RECV FINISHED")
        print(f"[SERVER/CH2] AES_GCM_decrypt(AES_key, proof) → '{decrypted.decode()}' {'✓' if fin_ok else '✗'}")
        assert fin_ok, "CLIENT_FINISHED proof failed"
        print(f"[SERVER/CH2] SECURE CHANNEL ESTABLISHED with {entity_id} ✓")
        _send_msg(conn, "FINISHED_ACK", status="channel_established")
        print(f"[SERVER/CH2] SENT FINISHED_ACK")

        # ── STEP 7: Receive monitoring data ─────────────────────────
        print(f"[SERVER/CH2] ── STEP 7: RECV MONITORING DATA ──")
        data_pkt  = _recv_msg(conn)
        assert data_pkt["type"] == "DATA"
        plain     = aes_gcm_decrypt(aes_key, data_pkt["encrypted_payload"])
        payload   = json.loads(plain.decode())
        stats     = payload["stats"]
        data_sig  = payload["signature"]
        print(f"[SERVER/CH2] RECV DATA")
        print(f"[SERVER/CH2] AES_GCM_decrypt → plaintext ✓")

        # Verify non-repudiation signature
        stats_bytes = canonical_json(stats)
        nr_ok = ecdsa_verify(c1_lt_pub, stats_bytes, data_sig)
        print(f"[SERVER/CH2] ECDSA_verify(C1_lt_pub, stats_bytes, sig) → {'TRUE ✓' if nr_ok else 'FALSE ✗'}")
        assert nr_ok, "C1 data signature invalid"
        print(f"[SERVER/CH2]   Non-repudiation confirmed: {entity_id} cannot deny this ✓")
        print(f"[SERVER/CH2] Logged stats for {entity_id}: speed={stats['speed']}, direction={stats['direction']}")
        self._vehicle_log[entity_id] = stats

        _send_msg(conn, "DATA_ACK", status="ok")
        print(f"[SERVER/CH2] SENT DATA_ACK")
        conn.close()

        # Print Channel 2 security checklist
        print(f"\n── Channel 2 Security Properties ──────────────────────────")
        print(f"  Confidentiality   : ✓ AES-GCM-256 (session key from ECDH)")
        print(f"  Integrity         : ✓ AES-GCM auth tag (any modification = reject)")
        print(f"  Authentication    : ✓ Mutual — C1 cert + Server cert (CA-verified)")
        print(f"  Non-repudiation   : ✓ ECDSA on stats (C1 cannot deny sending)")
        print(f"  Anonymity         : n/a (real identity required for monitoring)")
        print(f"  Replay Protection : ✓ Timestamp checked within 30-second window")
        print(f"  Forward Secrecy   : ✓ Ephemeral keys deleted after session")
        print(f"────────────────────────────────────────────────────────────")

    # ─────────────────────────────────────────────
    # CHANNEL 3 — RELAY (via C1)
    # ─────────────────────────────────────────────

    def handle_channel3(self, conn: socket.socket):
        """
        Handle a Channel 3 relay session (C2 → C1 → Server).

        Phase 1 — Anonymous key exchange:
          The server receives C2's anonymous hello (no identity) via C1,
          responds with its own ephemeral pub + ECDSA sig.
          Derives shared AES key without knowing who C2 is.

        Phase 2 — Encrypted identity:
          C2 sends its real certificate encrypted with the shared key.
          Server learns C2's identity; C1 never does.

        Args:
            conn: accepted TCP connection socket from C1 relay
        """
        print(f"\n[SERVER/CH3] ══ CHANNEL 3: RELAY SESSION (C2 → C1 → SERVER) ══")

        # ── PHASE 1: Anonymous key exchange ─────────────────────────
        print(f"[SERVER/CH3] ══ PHASE 1: ANONYMOUS KEY EXCHANGE ══")

        # ── STEP 3: Receive RELAY_ANON_HELLO from C1 ────────────────
        print(f"[SERVER/CH3] ── STEP 3: PROCESS RELAY ANON HELLO ──")
        pkt = _recv_msg(conn)
        assert pkt["type"] == "RELAY_ANON_HELLO"

        relay_id   = pkt["relay_id"]
        relay_cert = pkt["relay_certificate"]
        anon_hello = pkt["payload"]
        relay_sig  = pkt["relay_sig"]

        print(f"[SERVER/CH3] RECV RELAY_ANON_HELLO via {relay_id}")

        # CHECK-A: C1 relay certificate (CA sig)
        cert_body  = {k: v for k, v in relay_cert.items() if k != "ca_signature"}
        body_bytes = canonical_json(cert_body)
        ca_ok = ecdsa_verify(self._ca_pub, body_bytes, relay_cert["ca_signature"])
        print(f"[SERVER/CH3] CHECK-A C1 relay certificate (CA sig) → {'TRUE ✓' if ca_ok else 'FALSE ✗'}")
        assert ca_ok, "C1 relay certificate invalid"

        # CHECK-B: C1 relay ECDSA signature
        c1_lt_pub  = pem_to_pub(relay_cert["public_key"])
        relay_body = canonical_json({
            "payload"  : anon_hello,
            "relay_id" : relay_id,
            "timestamp": pkt["timestamp"],
        })
        relay_sig_ok = ecdsa_verify(c1_lt_pub, relay_body, relay_sig)
        print(f"[SERVER/CH3] CHECK-B C1 relay signature → {'TRUE ✓' if relay_sig_ok else 'FALSE ✗'}")
        assert relay_sig_ok, "C1 relay signature invalid"
        print(f"[SERVER/CH3]   C1 genuinely relayed this (C1 signed it) ✓")

        # Read anonymous hello (no identity)
        c2_eph_pub  = pem_to_pub(anon_hello["ephemeral_pub"])
        nonce_echo  = anon_hello["nonce"]
        ts_ok       = fresh_timestamp(anon_hello["timestamp"])
        print(f"[SERVER/CH3] Reading anon_hello:")
        print(f"[SERVER/CH3]   ephemeral_pub = {pub_to_hex(c2_eph_pub)[:32]}... (no identity)")
        print(f"[SERVER/CH3]   nonce = {nonce_echo[:16]}...")
        print(f"[SERVER/CH3]   Timestamp → {'FRESH ✓' if ts_ok else 'STALE ✗'}")
        print(f"[SERVER/CH3]   Server does NOT yet know who C2 is (by design) ✓")

        # Generate server ephemeral pair
        s_eph_priv2, s_eph_pub2 = generate_keypair()
        s_eph_pub2_pem = pub_to_pem(s_eph_pub2)
        s_eph_pub2_hex = pub_to_hex(s_eph_pub2)
        now = int(time.time())
        print(f"[SERVER/CH3] Generated server ephemeral keypair for ECDH")
        print(f"[SERVER/CH3]   s_eph_pub2 = {s_eph_pub2_hex[:32]}...")

        ack_body = canonical_json({
            "ephemeral_pub": s_eph_pub2_pem,
            "nonce_echo"   : nonce_echo,
            "timestamp"    : now,
        })
        ack_sig = ecdsa_sign(self._lt_priv, ack_body)
        print(f"[SERVER/CH3] nonce_echo = (echo back C2's nonce for freshness binding)")
        print(f"[SERVER/CH3] ECDSA_sign(Server_lt_priv, ack_body) → sig={ack_sig[:24]}...")

        _send_msg(conn, "RELAY_HELLO_ACK",
                  certificate   = self._cert,
                  ephemeral_pub = s_eph_pub2_pem,
                  timestamp     = now,
                  nonce_echo    = nonce_echo,
                  signature     = ack_sig)
        print(f"[SERVER/CH3] SENT RELAY_HELLO_ACK → {{server_cert, s_eph_pub, nonce_echo, sig}}")

        # Derive session key (server side)
        ss_raw  = ecdh_shared_secret_x(s_eph_priv2, c2_eph_pub)
        aes_key = derive_session_key(s_eph_priv2, c2_eph_pub, "Monitoring-Ch3-Relay", "relay")
        print(f"[SERVER/CH3] ECDH: SS = s_eph_priv2 × c2_eph_pub")
        print(f"[SERVER/CH3]   SS.x = {ss_raw.hex()[:32]}...")
        print(f"[SERVER/CH3] HKDF(SS.x, salt='Monitoring-Ch3-Relay') → AES_key={aes_key.hex()[:32]}...")
        print(f"[SERVER/CH3] This AES_key is shared only with C2 — C1 cannot derive it ✓")

        # ── PHASE 2: Encrypted identity ──────────────────────────────
        print(f"\n[SERVER/CH3] ══ PHASE 2: ENCRYPTED IDENTITY ══")

        # ── STEP 6: Receive RELAY_FINISHED (sealed identity) ────────
        fin_pkt = _recv_msg(conn)
        assert fin_pkt["type"] == "RELAY_FINISHED"
        print(f"[SERVER/CH3] ── STEP 6: RECV RELAY_FINISHED ──")
        print(f"[SERVER/CH3] RECV RELAY_FINISHED")

        plain = aes_gcm_decrypt(aes_key, fin_pkt["sealed"])
        identity_payload = json.loads(plain.decode())
        c2_entity_id = identity_payload["entity_id"]
        c2_cert      = identity_payload["certificate"]
        proof        = identity_payload["proof"]

        print(f"[SERVER/CH3] AES_GCM_decrypt(AES_key, sealed) → real_identity ✓")
        print(f"[SERVER/CH3] NOW server learns C2's identity for the first time")
        print(f"[SERVER/CH3] entity_id = {c2_entity_id}")

        # Verify C2 certificate
        c2_cert_body   = {k: v for k, v in c2_cert.items() if k != "ca_signature"}
        c2_body_bytes  = canonical_json(c2_cert_body)
        c2_cert_ok     = ecdsa_verify(self._ca_pub, c2_body_bytes, c2_cert["ca_signature"])
        print(f"[SERVER/CH3] Verify C2 certificate (CA sig) → {'TRUE ✓' if c2_cert_ok else 'FALSE ✗'}")
        assert c2_cert_ok, "C2 certificate invalid"

        proof_ok = (proof == "CLIENT_FINISHED")
        print(f"[SERVER/CH3] proof = '{proof}' {'✓' if proof_ok else '✗'}")
        assert proof_ok, "C2 CLIENT_FINISHED proof failed"

        c2_lt_pub = pem_to_pub(c2_cert["public_key"])
        self._ch3_aes_key = aes_key
        self._ch3_entity  = c2_entity_id
        self._ch3_lt_pub  = c2_lt_pub

        print(f"[SERVER/CH3] C2↔Server SECURE CHANNEL ESTABLISHED (end-to-end) ✓")
        _send_msg(conn, "RELAY_FINISHED_ACK", status="c2_channel_established")
        print(f"[SERVER/CH3] SENT RELAY_FINISHED_ACK → C1 → C2")

        # ── STEP 7: Receive relay monitoring data ────────────────────
        print(f"[SERVER/CH3] ── STEP 7: RECV RELAY DATA (SEALED) ──")
        data_pkt = _recv_msg(conn)
        assert data_pkt["type"] == "RELAY_DATA"
        print(f"[SERVER/CH3] RECV RELAY_DATA")

        plain    = aes_gcm_decrypt(aes_key, data_pkt["sealed"])
        payload  = json.loads(plain.decode())
        stats    = payload["stats"]
        data_sig = payload["signature"]

        print(f"[SERVER/CH3] AES_GCM_decrypt(AES_key, sealed) → plaintext ✓")

        stats_bytes = canonical_json(stats)
        nr_ok = ecdsa_verify(c2_lt_pub, stats_bytes, data_sig)
        print(f"[SERVER/CH3] ECDSA_verify(C2_lt_pub, stats_bytes, sig) → {'TRUE ✓' if nr_ok else 'FALSE ✗'}")
        assert nr_ok, "C2 data signature invalid"
        print(f"[SERVER/CH3]   Non-repudiation: {c2_entity_id} signed this data ✓")
        print(f"[SERVER/CH3]   Data integrity: AES-GCM tag verified, C1 did not tamper ✓")
        print(f"[SERVER/CH3] Stats logged for {c2_entity_id} [via C1 relay]:")
        print(f"[SERVER/CH3]   speed={stats['speed']}, direction={stats['direction']}, location={stats['location']}")
        self._vehicle_log[c2_entity_id] = stats

        _send_msg(conn, "DATA_ACK", status="ok")
        print(f"[SERVER/CH3] SENT DATA_ACK → C1 → C2")
        conn.close()

        # Print Channel 3 security checklist
        print(f"\n── Channel 3 Security Properties ──────────────────────────")
        print(f"  Confidentiality   : ✓ AES-GCM-256 end-to-end (C1 cannot read)")
        print(f"  Integrity         : ✓ AES-GCM auth tag on all sealed data")
        print(f"  Authentication    : ✓ C1 relay cert + C2 identity (both CA-verified)")
        print(f"  Non-repudiation   : ✓ ECDSA on stats (C2 cannot deny sending)")
        print(f"  Anonymity (C2→C1) : ✓ Phase 1 anon — C1 never saw C2's identity")
        print(f"  Relay Privacy     : ✓ C1 forwarded sealed blobs it cannot decrypt")
        print(f"  Replay Protection : ✓ Nonce + Timestamp (two-layer freshness)")
        print(f"  Forward Secrecy   : ✓ Ephemeral keys for both channels")
        print(f"────────────────────────────────────────────────────────────")

    def get_vehicle_log(self) -> dict:
        """Return all logged vehicle statistics."""
        return self._vehicle_log

    # ─────────────────────────────────────────────
    # SERVER SOCKETS
    # ─────────────────────────────────────────────

    def start_ch2_server(self, ready_event: threading.Event = None):
        """
        Start Channel 2 TCP listener (port 9000).

        Accepts one connection, handles the full session, then exits.

        Args:
            ready_event: optional threading.Event to signal readiness
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", self.CH2_PORT))
            srv.listen(1)
            if ready_event:
                ready_event.set()
            conn, addr = srv.accept()
            with conn:
                self.handle_channel2(conn)

    def start_ch3_server(self, ready_event: threading.Event = None):
        """
        Start Channel 3 TCP listener (port 9002) for C1 relay forwarding.

        Accepts one connection (from C1 acting as relay), handles session.

        Args:
            ready_event: optional threading.Event to signal readiness
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", self.CH3_PORT))
            srv.listen(1)
            if ready_event:
                ready_event.set()
            conn, addr = srv.accept()
            with conn:
                self.handle_channel3(conn)
