"use client";
import { useState } from "react";
import styles from "./page.module.css";

type Step = {
  id: string;
  channel: string;
  channelColor: string;
  from: string;
  to: string;
  type: string;
  desc: string;
  checks: { label: string; result: string; ok: boolean }[];
  code: string;
};

const STEPS: Step[] = [
  // === SETUP ===
  {
    id: "setup-ca",
    channel: "SETUP",
    channelColor: "#f59e0b",
    from: "CA",
    to: "All Parties",
    type: "CA INIT",
    desc: "Certificate Authority generates its key pair and issues long-term certificates for all parties (Server, C1, C2) plus pseudonym certificates for V2V anonymity.",
    checks: [
      { label: "CA key pair generated (secp256k1)", result: "✓ Done", ok: true },
      { label: "srv_cert issued (role=server, valid=24h)", result: "✓ Issued", ok: true },
      { label: "c1_cert issued (role=vehicle, valid=24h)", result: "✓ Issued", ok: true },
      { label: "c2_cert issued (role=vehicle, valid=24h)", result: "✓ Issued", ok: true },
      { label: "c1_pseudo0, c1_pseudo1 issued (valid=5min)", result: "✓ Issued", ok: true },
      { label: "c2_pseudo0 issued (valid=5min)", result: "✓ Issued", ok: true },
    ],
    code: `ca = CertificateAuthority()
srv_cert = ca.issue_certificate("MONITORING-SERVER-01", "server", pub_to_pem(srv_lt_pub))
c1_cert  = ca.issue_certificate("C1-LK-1234", "vehicle", pub_to_pem(c1_lt_pub))
c1_pseudo0_cert, c1_pseudo0_priv = ca.issue_pseudonym("C1-LK-1234")`,
  },
  // === CH1 V2V ===
  {
    id: "ch1-hello",
    channel: "Ch1 V2V",
    channelColor: "#00d4ff",
    from: "C2",
    to: "C1",
    type: "V2V_HELLO",
    desc: "C2 sends a V2V HELLO using its pseudonym certificate. Real identity 'C2-LK-5678' is hidden — only the opaque pseudo_id is transmitted.",
    checks: [
      { label: "Pseudonym cert selected (not long-term cert)", result: "✓ Anonymous", ok: true },
      { label: "Ephemeral keypair generated for ECDH", result: "✓ Generated", ok: true },
      { label: "ECDSA_sign(pseudo_priv, hello_body)", result: "✓ Signed", ok: true },
    ],
    code: `V2V_HELLO → {
  "type": "V2V_HELLO",
  "pseudo_cert": { "entity_id": "<random_token>", "role": "pseudonym", ... },
  "ephemeral_pub": "-----BEGIN PUBLIC KEY-----...",
  "signature": "base64(ECDSA_sig)",
  "timestamp": 1716000000
}`,
  },
  {
    id: "ch1-verify",
    channel: "Ch1 V2V",
    channelColor: "#00d4ff",
    from: "C1",
    to: "C1 (self)",
    type: "VERIFY HELLO",
    desc: "C1 performs three security checks on the received HELLO before trusting the peer.",
    checks: [
      { label: "CHECK-A: CA sig on pseudonym cert valid", result: "TRUE ✓", ok: true },
      { label: "CHECK-B: ECDSA(pseudo_pub, hello_body, sig) valid", result: "TRUE ✓", ok: true },
      { label: "CHECK-C: Timestamp freshness (delta < 30s)", result: "FRESH ✓", ok: true },
    ],
    code: `# CHECK-A
ca_sig_ok = ecdsa_verify(ca_pub, canonical_json(cert_body), cert["ca_signature"])
# CHECK-B
hello_body = canonical_json({"ephemeral_pub": ..., "timestamp": ...})
sig_ok = ecdsa_verify(pseudo_pub, hello_body, pkt["signature"])
# CHECK-C
ts_ok = abs(time.time() - pkt["timestamp"]) < 30`,
  },
  {
    id: "ch1-ack",
    channel: "Ch1 V2V",
    channelColor: "#00d4ff",
    from: "C1",
    to: "C2",
    type: "V2V_ACK",
    desc: "C1 replies with its own pseudonym certificate and ephemeral public key. Both parties now have each other's ephemeral public keys for ECDH.",
    checks: [
      { label: "C1 pseudonym cert included (real ID hidden)", result: "✓ Anonymous", ok: true },
      { label: "ECDSA_sign(c1_pseudo_priv, ack_body)", result: "✓ Signed", ok: true },
    ],
    code: `V2V_ACK → {
  "type": "V2V_ACK",
  "pseudo_cert": c1_pseudo_cert,
  "ephemeral_pub": c1_eph_pub_pem,
  "signature": ecdsa_sign(c1_pseudo_priv, ack_body),
  "timestamp": now
}`,
  },
  {
    id: "ch1-key",
    channel: "Ch1 V2V",
    channelColor: "#00d4ff",
    from: "Both",
    to: "Both",
    type: "KEY DERIVATION",
    desc: "Both parties independently perform ECDH with their private ephemeral key and the peer's public ephemeral key. HKDF produces identical 32-byte AES keys on both sides without transmitting the secret.",
    checks: [
      { label: "ECDH: SS = eph_priv × peer_eph_pub", result: "✓ Same SS", ok: true },
      { label: "HKDF(SS.x, salt='V2V-Ch1', label='v2v')", result: "32 bytes ✓", ok: true },
      { label: "Both keys identical (verified)", result: "✓ Match", ok: true },
    ],
    code: `# C2 side
SS = c2_eph_priv.exchange(ECDH(), c1_eph_pub)
AES_key = HKDF(SS, salt="V2V-Ch1", label="v2v", length=32)

# C1 side (computes SAME key)
SS = c1_eph_priv.exchange(ECDH(), c2_eph_pub)
AES_key = HKDF(SS, salt="V2V-Ch1", label="v2v", length=32)`,
  },
  {
    id: "ch1-done",
    channel: "Ch1 V2V",
    channelColor: "#00d4ff",
    from: "C2",
    to: "C1",
    type: "FINISHED + DATA",
    desc: "C2 sends AES-GCM encrypted proof. Channel is established. Encrypted vehicle data is exchanged with ECDSA non-repudiation.",
    checks: [
      { label: "CLIENT_FINISHED proof decrypted correctly", result: "✓ Verified", ok: true },
      { label: "Secure V2V channel established", result: "✓ Active", ok: true },
      { label: "Stats signed + encrypted exchanged", result: "✓ Done", ok: true },
    ],
    code: `# C2 sends
proof = aes_gcm_encrypt(AES_key, b"CLIENT_FINISHED")
FINISHED → { "proof": proof }

# C1 verifies
decrypted = aes_gcm_decrypt(AES_key, fin_pkt["proof"])
assert decrypted == b"CLIENT_FINISHED"  # ✓`,
  },
  // === CH2 MONITOR ===
  {
    id: "ch2-hello",
    channel: "Ch2 Monitor",
    channelColor: "#a855f7",
    from: "C1",
    to: "Server",
    type: "HELLO",
    desc: "C1 initiates the monitoring channel with its long-term certificate (not pseudonym). Real identity 'C1-LK-1234' is transmitted for accountability.",
    checks: [
      { label: "Long-term cert used (not pseudonym)", result: "✓ Real ID", ok: true },
      { label: "ECDSA_sign(c1_lt_priv, hello_body)", result: "✓ Signed", ok: true },
      { label: "TCP connection to port 9000", result: "✓ Connected", ok: true },
    ],
    code: `HELLO → {
  "entity_id": "C1-LK-1234",
  "certificate": c1_lt_cert,  # real identity
  "ephemeral_pub": c1_eph_pub_pem,
  "signature": ecdsa_sign(c1_lt_priv, hello_body),
  "timestamp": now
}`,
  },
  {
    id: "ch2-server-verify",
    channel: "Ch2 Monitor",
    channelColor: "#a855f7",
    from: "Server",
    to: "Server (self)",
    type: "4-CHECK VERIFY",
    desc: "Server performs four rigorous checks before trusting C1's hello.",
    checks: [
      { label: "CHECK-A: CA sig on C1 long-term cert", result: "TRUE ✓", ok: true },
      { label: "CHECK-B: Extract C1_lt_pub from cert", result: "✓ Extracted", ok: true },
      { label: "CHECK-C: ECDSA(C1_lt_pub, hello_body, sig)", result: "TRUE ✓", ok: true },
      { label: "CHECK-D: Timestamp freshness", result: "FRESH ✓", ok: true },
    ],
    code: `# CHECK-A: CA sig
ca_sig_ok = ecdsa_verify(ca_pub, canonical_json(cert_body), cert["ca_signature"])
# CHECK-B: pub key
c1_lt_pub = pem_to_pub(c1_cert["public_key"])
# CHECK-C: hello sig
hello_sig_ok = ecdsa_verify(c1_lt_pub, hello_body, pkt["signature"])
# CHECK-D: timestamp
ts_ok = fresh_timestamp(pkt["timestamp"])  # within 30s`,
  },
  {
    id: "ch2-data",
    channel: "Ch2 Monitor",
    channelColor: "#a855f7",
    from: "C1",
    to: "Server",
    type: "DATA + NON-REPUDIATION",
    desc: "C1 signs its vehicle statistics with its long-term private key and encrypts the signed payload with the AES session key. Server verifies the ECDSA signature to confirm non-repudiation.",
    checks: [
      { label: "stats signed with C1 long-term key", result: "✓ Signed", ok: true },
      { label: "AES_GCM_encrypt(AES_key, {stats, signature})", result: "✓ Encrypted", ok: true },
      { label: "Server: ECDSA_verify(c1_lt_pub, stats, sig)", result: "TRUE ✓", ok: true },
      { label: "Non-repudiation confirmed", result: "✓ C1 cannot deny", ok: true },
    ],
    code: `stats = {"speed": 72, "direction": "N", "location": "6.927, 79.861"}
data_sig = ecdsa_sign(c1_lt_priv, canonical_json(stats))
payload = {"stats": stats, "signature": data_sig}
encrypted = aes_gcm_encrypt(AES_key, json.dumps(payload).encode())
DATA → { "encrypted_payload": encrypted }`,
  },
  // === CH3 RELAY ===
  {
    id: "ch3-anon",
    channel: "Ch3 Relay",
    channelColor: "#10b981",
    from: "C2",
    to: "C1",
    type: "ANON_HELLO (via V2V)",
    desc: "C2 sends an anonymous hello (no identity!) to C1 over the existing V2V session. The hello includes only C2's ephemeral pub and nonce. HMAC ensures C1 knows it came from its V2V partner.",
    checks: [
      { label: "No entity_id in anon_hello — fully anonymous", result: "✓ Anonymous", ok: true },
      { label: "HMAC(v2v_aes_key, anon_hello_bytes)", result: "✓ MACed", ok: true },
      { label: "Nonce generated for freshness binding", result: "✓ Random nonce", ok: true },
    ],
    code: `anon_hello = {
  "ephemeral_pub": c2_eph_pub2_pem,  # No identity
  "nonce": base64(urandom(16)),
  "timestamp": now
}
mac = hmac_sign(v2v_aes_key, canonical_json(anon_hello))`,
  },
  {
    id: "ch3-relay",
    channel: "Ch3 Relay",
    channelColor: "#10b981",
    from: "C1",
    to: "Server",
    type: "RELAY_ANON_HELLO",
    desc: "C1 verifies the HMAC from its V2V partner, then wraps the anonymous hello in its own certificate + ECDSA signature and forwards to the server. C1 cannot read the content being relayed.",
    checks: [
      { label: "HMAC_verify(v2v_key, anon_hello, mac)", result: "TRUE ✓", ok: true },
      { label: "C1 wraps with relay_cert + relay_sig", result: "✓ Signed", ok: true },
      { label: "C1 does NOT know who C2 is", result: "✓ Blind relay", ok: true },
    ],
    code: `RELAY_ANON_HELLO → {
  "relay_id": "C1-LK-1234",
  "relay_certificate": c1_lt_cert,
  "payload": anon_hello,  # ← C1 cannot decrypt this
  "relay_sig": ecdsa_sign(c1_lt_priv, relay_body),
  "timestamp": now
}`,
  },
  {
    id: "ch3-e2e",
    channel: "Ch3 Relay",
    channelColor: "#10b981",
    from: "C2",
    to: "Server",
    type: "E2E KEY + IDENTITY",
    desc: "Server replies with its ephemeral pub and nonce_echo. C2 and Server independently derive the same E2E session key. Then C2 sends its real identity encrypted with the E2E key — C1 cannot read it.",
    checks: [
      { label: "E2E AES_key derived (C1 cannot compute it)", result: "✓ Exclusive", ok: true },
      { label: "sealed = AES_GCM_encrypt(E2E_key, {entity_id, cert, proof})", result: "✓ Sealed", ok: true },
      { label: "Server decrypts and learns C2='C2-LK-5678'", result: "✓ Revealed", ok: true },
      { label: "C2 CA cert verified by server", result: "TRUE ✓", ok: true },
    ],
    code: `# E2E key (C2 ↔ Server — C1 excluded)
AES_key_e2e = HKDF(ECDH(c2_eph_priv2, s_eph_pub2), salt="Monitoring-Ch3-Relay")

# Identity reveal (sealed)
sealed = aes_gcm_encrypt(AES_key_e2e, json.dumps({
  "entity_id": "C2-LK-5678",
  "certificate": c2_lt_cert,
  "proof": "CLIENT_FINISHED"
}).encode())
RELAY_FINISHED → { "sealed": sealed }  # C1 forwards blindly`,
  },
];

const CHANNEL_COLORS: Record<string, string> = {
  "SETUP": "#f59e0b",
  "Ch1 V2V": "#00d4ff",
  "Ch2 Monitor": "#a855f7",
  "Ch3 Relay": "#10b981",
};

export default function SimulationPage() {
  const [current, setCurrent] = useState(0);
  const [completed, setCompleted] = useState<Set<number>>(new Set());

  const step = STEPS[current];

  const handleNext = () => {
    setCompleted((prev) => new Set([...prev, current]));
    if (current < STEPS.length - 1) setCurrent(current + 1);
  };
  const handlePrev = () => { if (current > 0) setCurrent(current - 1); };
  const handleReset = () => { setCurrent(0); setCompleted(new Set()); };

  return (
    <div className={styles.page}>
      <div className="container">
        <div className={styles.header}>
          <p className="section-label">Interactive Demo</p>
          <h1 className="section-title">Protocol <span className="gradient-text">Simulation</span></h1>
          <p className="section-subtitle">
            Step through the complete SDVN simulation — from CA setup through all three secure channels.
          </p>
        </div>

        <div className={styles.layout}>
          {/* Sidebar: step list */}
          <aside className={styles.sidebar}>
            <div className={styles.sidebarTitle}>Simulation Steps</div>
            {STEPS.map((s, i) => (
              <button
                key={s.id}
                className={`${styles.stepBtn} ${i === current ? styles.stepBtnActive : ""} ${completed.has(i) ? styles.stepBtnDone : ""}`}
                style={{ borderLeftColor: CHANNEL_COLORS[s.channel] }}
                onClick={() => setCurrent(i)}
              >
                <span className={styles.stepBtnNum}>{i + 1}</span>
                <div>
                  <div className={styles.stepBtnChannel} style={{ color: CHANNEL_COLORS[s.channel] }}>{s.channel}</div>
                  <div className={styles.stepBtnLabel}>{s.type}</div>
                </div>
                {completed.has(i) && <span className={styles.checkMark}>✓</span>}
              </button>
            ))}
          </aside>

          {/* Main panel */}
          <div className={styles.main}>
            {/* Channel badge */}
            <div className={styles.stepMeta}>
              <span className={styles.stepChannel} style={{ background: step.channelColor + "20", color: step.channelColor, borderColor: step.channelColor + "50" }}>
                {step.channel}
              </span>
              <span className={styles.stepProgress}>Step {current + 1} of {STEPS.length}</span>
            </div>

            {/* Message type */}
            <h2 className={styles.stepType}>{step.type}</h2>

            {/* From → To */}
            <div className={styles.flow}>
              <span className={styles.flowNode} style={{ borderColor: step.channelColor + "60", color: step.channelColor }}>{step.from}</span>
              <span className={styles.flowArrow} style={{ color: step.channelColor }}>——→</span>
              <span className={styles.flowNode} style={{ borderColor: step.channelColor + "60", color: step.channelColor }}>{step.to}</span>
            </div>

            {/* Description */}
            <p className={styles.stepDesc}>{step.desc}</p>

            {/* Security checks */}
            <div className={styles.checks}>
              <div className={styles.checksTitle}>Security Checks</div>
              {step.checks.map((c, i) => (
                <div key={i} className={`${styles.check} ${c.ok ? styles.checkOk : styles.checkFail}`}>
                  <span className={styles.checkIcon}>{c.ok ? "✓" : "✗"}</span>
                  <span className={styles.checkLabel}>{c.label}</span>
                  <span className={styles.checkResult} style={{ color: c.ok ? "#10b981" : "#ef4444" }}>{c.result}</span>
                </div>
              ))}
            </div>

            {/* Code */}
            <div className={styles.codeSection}>
              <div className={styles.checksTitle}>Implementation (Python)</div>
              <div className="code-block">{step.code}</div>
            </div>

            {/* Navigation */}
            <div className={styles.nav}>
              <button className="btn btn-secondary btn-sm" onClick={handlePrev} disabled={current === 0}>← Previous</button>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn btn-secondary btn-sm" onClick={handleReset}>↺ Reset</button>
                {current < STEPS.length - 1 ? (
                  <button className="btn btn-primary btn-sm" onClick={handleNext}>Next Step →</button>
                ) : (
                  <button className="btn btn-primary btn-sm" onClick={handleReset}>🎉 Restart</button>
                )}
              </div>
            </div>

            {/* Progress bar */}
            <div className={styles.progressBar}>
              <div className={styles.progressFill} style={{ width: `${((current + 1) / STEPS.length) * 100}%`, background: step.channelColor }} />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
