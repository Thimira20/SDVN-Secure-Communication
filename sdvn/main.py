"""
main.py — SDVN Secure Communication Simulation Runner
======================================================
Orchestrates all three secure channels:
  Channel 1 — V2V         : C1 <-> C2  (pseudonym anonymity)
  Channel 2 — Monitoring  : C1 -> Server (real identity, non-repudiation)
  Channel 3 — Relay       : C2 -> C1 -> Server (C1 is blind relay)

Run with: python main.py
Requires: pip install cryptography
"""
import io

import sys
# Force UTF-8 output on Windows to support box-drawing/check-mark characters
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
else:
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
import time
import threading

# Ensure local imports work when run from project root
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ca            import CertificateAuthority
from crypto_utils  import generate_keypair, pub_to_pem, pub_to_hex
from server        import MonitoringServer
from vehicle_c1    import VehicleC1
from vehicle_c2    import VehicleC2


# ─────────────────────────────────────────────
# BANNER HELPERS
# ─────────────────────────────────────────────

def print_banner():
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║     SDVN SECURE COMMUNICATION PROTOCOL — FULL SIMULATION        ║")
    print("╠══════════════════════════════════════════════════════════════════╣")
    print("║  Three channels built from scratch. No SSL. No TLS.             ║")
    print("║  All crypto manual: ECDH, AES-GCM, ECDSA, HKDF, HMAC          ║")
    print("╠══════════════════════════════════════════════════════════════════╣")
    print("║  PARTIES:                                                        ║")
    print("║    Vehicle C1   — in range of mobile node                       ║")
    print("║    Vehicle C2   — out of range, relays via C1                   ║")
    print("║    Controller   — monitoring server                             ║")
    print("║  CHANNELS:                                                       ║")
    print("║    Ch1 V2V     : C1 ↔ C2              (pseudonym anonymity)     ║")
    print("║    Ch2 Monitor : C1 → Server          (real identity)           ║")
    print("║    Ch3 Relay   : C2 → C1 → Server    (C1 is blind relay)       ║")
    print("╚══════════════════════════════════════════════════════════════════╝")


def print_ch1_banner():
    print("\n" + "═" * 68)
    print("CHANNEL 1 — V2V SECURE COMMUNICATION")
    print("Parties   : Vehicle C1 (responder) ↔ Vehicle C2 (initiator)")
    print("Crypto    : ECDH + HKDF + AES-GCM-256 + ECDSA + Pseudonyms")
    print("Properties: Confidentiality, Integrity, Auth, Anonymity, Replay-Protect")
    print("═" * 68)


def print_ch2_banner():
    print("\n" + "═" * 68)
    print("CHANNEL 2 — MONITORING SECURE COMMUNICATION")
    print("Parties   : Vehicle C1 (client) → Monitoring Server")
    print("Crypto    : ECDH + HKDF + AES-GCM-256 + ECDSA (long-term certs)")
    print("Properties: Confidentiality, Integrity, Mutual-Auth, Non-Repudiation")
    print("═" * 68)


def print_ch3_banner():
    print("\n" + "═" * 68)
    print("CHANNEL 3 — ANONYMOUS RELAY COMMUNICATION")
    print("Parties   : Vehicle C2 → C1 (blind relay) → Monitoring Server")
    print("Crypto    : ECDH + HKDF + AES-GCM-256 + ECDSA + HMAC")
    print("Properties: E2E Confidentiality, Anonymity to C1, Non-Repudiation")
    print("═" * 68)


def print_summary(server: MonitoringServer):
    log = server.get_vehicle_log()
    print("\n" + "═" * 68)
    print("SIMULATION COMPLETE — FINAL SUMMARY")
    print("═" * 68)

    print("\n╔══════════════════════╦══════════════╦══════════════╦══════════════════════╗")
    print("║ Security Property    ║ Ch1 V2V      ║ Ch2 Monitor  ║ Ch3 Relay            ║")
    print("╠══════════════════════╬══════════════╬══════════════╬══════════════════════╣")
    print("║ Confidentiality      ║ ✓ AES-GCM   ║ ✓ AES-GCM   ║ ✓ AES-GCM E2E       ║")
    print("║ Integrity            ║ ✓ GCM tag   ║ ✓ GCM tag   ║ ✓ GCM tag            ║")
    print("║ Authentication       ║ ✓ ECDSA+CA  ║ ✓ ECDSA+CA  ║ ✓ C1+C2 both auth   ║")
    print("║ Non-repudiation      ║ ✓ ECDSA sig ║ ✓ ECDSA sig ║ ✓ ECDSA sig          ║")
    print("║ Anonymity (C2 to C1) ║ ✓ Pseudonym ║ n/a         ║ ✓ Anon Phase 1       ║")
    print("║ Replay Protection    ║ ✓ Timestamp ║ ✓ Timestamp ║ ✓ Nonce+Timestamp    ║")
    print("║ Forward Secrecy      ║ ✓ Ephemeral ║ ✓ Ephemeral ║ ✓ Ephemeral          ║")
    print("║ Relay Privacy        ║ n/a         ║ n/a         ║ ✓ C1 cannot read     ║")
    print("╚══════════════════════╩══════════════╩══════════════╩══════════════════════╝")

    print(f"\nServer vehicle log:")
    c1_stats = log.get("C1-LK-1234", {})
    c2_stats = log.get("C2-LK-5678", {})
    print(f"  C1-LK-1234 [direct channel 2]  : speed={c1_stats.get('speed','?')}, direction={c1_stats.get('direction','?')}")
    print(f"  C2-LK-5678 [relay via C1]      : speed={c2_stats.get('speed','?')}, direction={c2_stats.get('direction','?')}")
    print()


# ─────────────────────────────────────────────
# MAIN SIMULATION
# ─────────────────────────────────────────────

def main():
    print_banner()

    # ── SETUP: Certificate Authority ──────────────────────────────────
    print("\n" + "─" * 68)
    print("SETUP — CERTIFICATE AUTHORITY & ENTITY INITIALISATION")
    print("─" * 68)

    ca = CertificateAuthority()

    # Generate long-term key pairs for all parties
    srv_lt_priv,  srv_lt_pub  = generate_keypair()
    c1_lt_priv,   c1_lt_pub   = generate_keypair()
    c2_lt_priv,   c2_lt_pub   = generate_keypair()

    # Issue long-term certificates
    srv_cert = ca.issue_certificate("MONITORING-SERVER-01", "server",  pub_to_pem(srv_lt_pub))
    c1_cert  = ca.issue_certificate("C1-LK-1234",          "vehicle", pub_to_pem(c1_lt_pub))
    c2_cert  = ca.issue_certificate("C2-LK-5678",          "vehicle", pub_to_pem(c2_lt_pub))

    # Issue pseudonym certificates (2 per vehicle for rotation support)
    c1_pseudo0_cert, c1_pseudo0_priv = ca.issue_pseudonym("C1-LK-1234")
    c1_pseudo1_cert, c1_pseudo1_priv = ca.issue_pseudonym("C1-LK-1234")
    c2_pseudo0_cert, c2_pseudo0_priv = ca.issue_pseudonym("C2-LK-5678")

    ca_pub = ca.get_ca_pub_key_for_party()

    # ── Instantiate parties ───────────────────────────────────────────
    server = MonitoringServer(ca_pub, srv_cert, srv_lt_priv)

    c1 = VehicleC1(
        ca_pub_key   = ca_pub,
        lt_priv      = c1_lt_priv,
        lt_cert      = c1_cert,
        pseudo_certs = [(c1_pseudo0_cert, c1_pseudo0_priv),
                        (c1_pseudo1_cert, c1_pseudo1_priv)],
    )

    c2 = VehicleC2(
        ca_pub_key   = ca_pub,
        lt_priv      = c2_lt_priv,
        lt_cert      = c2_cert,
        pseudo_certs = [(c2_pseudo0_cert, c2_pseudo0_priv)],
    )

    # ─────────────────────────────────────────────────────────────────
    # CHANNEL 1 — V2V
    # ─────────────────────────────────────────────────────────────────
    print_ch1_banner()

    v2v_ready = threading.Event()

    def run_c1_v2v():
        c1.run_v2v_server(ready_event=v2v_ready)

    def run_c2_v2v():
        v2v_ready.wait()
        time.sleep(0.05)  # Small delay to ensure server is accepting
        c2.run_v2v(c1_host="127.0.0.1", c1_port=9001)

    t_c1_v2v = threading.Thread(target=run_c1_v2v, daemon=True)
    t_c2_v2v = threading.Thread(target=run_c2_v2v, daemon=True)

    t_c1_v2v.start()
    t_c2_v2v.start()
    t_c1_v2v.join(timeout=15)
    t_c2_v2v.join(timeout=15)

    # ─────────────────────────────────────────────────────────────────
    # CHANNEL 2 — C1 DIRECT MONITORING
    # ─────────────────────────────────────────────────────────────────
    print_ch2_banner()

    ch2_ready = threading.Event()

    def run_server_ch2():
        server.start_ch2_server(ready_event=ch2_ready)

    def run_c1_monitor():
        ch2_ready.wait()
        time.sleep(0.05)
        c1.run_monitoring(server_host="127.0.0.1", server_port=9000)

    t_srv_ch2 = threading.Thread(target=run_server_ch2, daemon=True)
    t_c1_mon  = threading.Thread(target=run_c1_monitor,  daemon=True)

    t_srv_ch2.start()
    t_c1_mon.start()
    t_srv_ch2.join(timeout=15)
    t_c1_mon.join(timeout=15)

    # ─────────────────────────────────────────────────────────────────
    # CHANNEL 3 — C2 RELAY VIA C1
    # ─────────────────────────────────────────────────────────────────
    print_ch3_banner()

    ch3_ready = threading.Event()

    def run_server_ch3():
        server.start_ch3_server(ready_event=ch3_ready)

    def run_c2_relay():
        ch3_ready.wait()
        time.sleep(0.05)
        c2.run_relay(c1=c1, server_host="127.0.0.1", server_port=9002)

    t_srv_ch3 = threading.Thread(target=run_server_ch3, daemon=True)
    t_c2_relay = threading.Thread(target=run_c2_relay,   daemon=True)

    t_srv_ch3.start()
    t_c2_relay.start()
    t_srv_ch3.join(timeout=15)
    t_c2_relay.join(timeout=15)

    # ─────────────────────────────────────────────────────────────────
    # FINAL SUMMARY
    # ─────────────────────────────────────────────────────────────────
    print_summary(server)


if __name__ == "__main__":
    main()
