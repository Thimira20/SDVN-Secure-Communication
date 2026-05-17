import styles from "./page.module.css";

const CHANNELS = [
  {
    id: "v2v",
    name: "Channel 1 — V2V Secure Communication",
    parties: "Vehicle C1 (responder) ↔ Vehicle C2 (initiator)",
    color: "#00d4ff",
    icon: "🚗",
    badge: "Pseudonym Anonymity",
    badgeClass: "badge-teal",
    description:
      "The V2V channel enables two vehicles to communicate securely without revealing their real identities. Each vehicle uses a short-lived pseudonym certificate issued by the CA instead of its long-term identity. The V2V peer cannot link the pseudonym to the real vehicle.",
    steps: [
      { step: 1, party: "C2", label: "V2V HELLO", desc: "C2 sends ephemeral pub, pseudonym cert, ECDSA signature, and timestamp to C1.", code: 'V2V_HELLO → { pseudo_cert, ephemeral_pub, signature, timestamp }' },
      { step: 2, party: "C1", label: "Verify HELLO", desc: "C1 verifies CA sig on pseudonym cert, ECDSA sig on hello body, and timestamp freshness (±30s).", code: 'ECDSA_verify(CA_pub, cert_body, ca_sig) → TRUE\nECDSA_verify(pseudo_pub, hello_body, sig) → TRUE\nabs(now - timestamp) < 30s → FRESH' },
      { step: 3, party: "C1", label: "V2V ACK", desc: "C1 replies with its own pseudonym cert, ephemeral pub, and ECDSA signature.", code: 'V2V_ACK → { pseudo_cert, ephemeral_pub, signature, timestamp }' },
      { step: 4, party: "Both", label: "Derive Session Key", desc: "Both sides perform ECDH to get a shared secret, then use HKDF to derive the AES-256 session key.", code: 'SS = ECDH(my_eph_priv, peer_eph_pub)\nAES_key = HKDF(SS.x, salt="V2V-Ch1", label="v2v") → 32 bytes' },
      { step: 5, party: "C2", label: "FINISHED", desc: "C2 encrypts the proof 'CLIENT_FINISHED' with the session key and sends to C1.", code: 'FINISHED → { proof: AES_GCM_encrypt(AES_key, "CLIENT_FINISHED") }' },
      { step: 6, party: "C1", label: "Channel Ready + Data Exchange", desc: "C1 decrypts proof, confirms channel establishment. Encrypted vehicle data is then exchanged.", code: 'AES_GCM_decrypt(AES_key, proof) → "CLIENT_FINISHED" ✓\nSecure channel established ✓' },
    ],
    props: [
      { name: "Confidentiality", detail: "AES-GCM-256 — ciphertext reveals nothing" },
      { name: "Integrity", detail: "GCM 128-bit auth tag — any modification fails" },
      { name: "Authentication", detail: "ECDSA + CA-verified pseudonym certs" },
      { name: "Anonymity", detail: "Pseudonym ID — real identity never transmitted" },
      { name: "Replay Protection", detail: "Timestamp checked within ±30 second window" },
      { name: "Forward Secrecy", detail: "Ephemeral ECDH keys deleted after session" },
      { name: "Non-Repudiation", detail: "ECDSA on data payloads" },
    ],
  },
  {
    id: "monitor",
    name: "Channel 2 — Monitoring (C1 → Server)",
    parties: "Vehicle C1 (client) → Monitoring Server",
    color: "#a855f7",
    icon: "📡",
    badge: "Mutual Authentication",
    badgeClass: "badge-purple",
    description:
      "The monitoring channel sends C1's real vehicle statistics to the central controller. Both parties authenticate with their long-term CA-issued certificates, providing mutual authentication and non-repudiation. The server can hold C1 accountable for signed data.",
    steps: [
      { step: 1, party: "C1", label: "HELLO", desc: "C1 sends its long-term cert, ephemeral pub, and ECDSA sig to the server.", code: 'HELLO → { lt_cert, ephemeral_pub, signature, timestamp }' },
      { step: 2, party: "Server", label: "Verify HELLO (4 checks)", desc: "CHECK-A: CA sig on cert. CHECK-B: Extract C1_lt_pub. CHECK-C: ECDSA on hello body. CHECK-D: Timestamp freshness.", code: 'CHECK-A: ECDSA_verify(CA_pub, cert_body, ca_sig) → TRUE\nCHECK-B: c1_lt_pub = cert["public_key"]\nCHECK-C: ECDSA_verify(c1_lt_pub, hello_body, sig) → TRUE\nCHECK-D: timestamp_fresh → TRUE' },
      { step: 3, party: "Server", label: "HELLO_ACK", desc: "Server replies with its certificate, ephemeral pub, and ECDSA signature.", code: 'HELLO_ACK → { server_cert, ephemeral_pub, signature, timestamp }' },
      { step: 4, party: "Both", label: "Derive Session Key", desc: "ECDH + HKDF with channel-specific salt 'Monitoring-Ch2'.", code: 'AES_key = HKDF(ECDH(eph_priv, peer_eph_pub), salt="Monitoring-Ch2", label="monitor")' },
      { step: 5, party: "C1", label: "FINISHED", desc: "C1 sends AES-encrypted CLIENT_FINISHED proof.", code: 'FINISHED → { proof: AES_GCM_encrypt(AES_key, "CLIENT_FINISHED") }' },
      { step: 6, party: "Server", label: "FINISHED_ACK", desc: "Server decrypts proof and confirms channel establishment.", code: 'AES_GCM_decrypt(AES_key, proof) → "CLIENT_FINISHED" ✓\nSEND FINISHED_ACK → { status: "channel_established" }' },
      { step: 7, party: "C1 → Server", label: "DATA + Non-Repudiation", desc: "C1 signs stats with long-term key, encrypts with session key. Server verifies ECDSA to confirm non-repudiation.", code: 'payload = { stats, signature: ECDSA_sign(c1_lt_priv, stats) }\nDATA → { encrypted_payload: AES_GCM_encrypt(AES_key, payload) }\nServer: ECDSA_verify(c1_lt_pub, stats, sig) → TRUE ✓' },
    ],
    props: [
      { name: "Confidentiality", detail: "AES-GCM-256 session key" },
      { name: "Integrity", detail: "GCM auth tag on all payloads" },
      { name: "Mutual Authentication", detail: "Both parties verify CA-signed long-term certs" },
      { name: "Non-Repudiation", detail: "C1 signs stats — cannot deny sending later" },
      { name: "Replay Protection", detail: "Timestamp within ±30 second freshness window" },
      { name: "Forward Secrecy", detail: "Ephemeral ECDH — session key never reused" },
    ],
  },
  {
    id: "relay",
    name: "Channel 3 — Anonymous Relay (C2 → C1 → Server)",
    parties: "Vehicle C2 → C1 (blind relay) → Monitoring Server",
    color: "#10b981",
    icon: "🔁",
    badge: "E2E + Relay Privacy",
    badgeClass: "badge-green",
    description:
      "C2 is out of range of the server. It uses C1 as a blind relay — C1 forwards encrypted blobs without being able to read C2's identity or data. The end-to-end encrypted channel between C2 and the server is built in two phases: anonymous key exchange then encrypted identity reveal.",
    steps: [
      { step: 1, party: "C2 → C1", label: "Relay Request (V2V Ch1)", desc: "C2 asks C1 to act as relay. Sends an ANON_HELLO (no identity) over the V2V session key with HMAC integrity.", code: 'ANON_HELLO (sealed in V2V channel):\n  { ephemeral_pub, nonce, timestamp }\n  + HMAC(v2v_aes_key, anon_hello_bytes)' },
      { step: 2, party: "C1", label: "Verify HMAC + Forward", desc: "C1 verifies HMAC to confirm the relay request came from its V2V partner. C1 wraps with its own certificate and ECDSA signature and forwards to server.", code: 'HMAC_verify(v2v_key, anon_hello, mac) → TRUE ✓\nRELAY_ANON_HELLO → { relay_cert, payload: anon_hello, relay_sig }' },
      { step: 3, party: "Server", label: "Verify Relay (CHECK-A + B)", desc: "Server checks C1's relay certificate (CA sig) and C1's relay ECDSA signature. Reads anonymous hello — no identity known yet.", code: 'CHECK-A: ECDSA_verify(CA_pub, relay_cert_body, ca_sig) → TRUE\nCHECK-B: ECDSA_verify(c1_lt_pub, relay_body, relay_sig) → TRUE\nNOTE: Server does NOT know who C2 is yet ✓' },
      { step: 4, party: "Server → C2", label: "RELAY_HELLO_ACK", desc: "Server sends its ephemeral pub and ECDSA sig, echoes C2's nonce for freshness binding.", code: 'RELAY_HELLO_ACK → { server_cert, ephemeral_pub, nonce_echo, signature }\nAES_key = HKDF(ECDH(s_eph_priv, c2_eph_pub), salt="Monitoring-Ch3-Relay")' },
      { step: 5, party: "C2 → Server", label: "RELAY_FINISHED (Phase 2)", desc: "C2 encrypts its real identity, certificate, and proof with the E2E session key. C1 forwards blindly.", code: 'sealed = AES_GCM_encrypt(AES_key, {\n  entity_id, certificate, proof: "CLIENT_FINISHED"\n})\nRELAY_FINISHED → { sealed }  ← C1 cannot read this' },
      { step: 6, party: "Server", label: "Identity Reveal + Verify", desc: "Server decrypts sealed payload and learns C2's real identity for the first time. Verifies C2's CA-signed certificate.", code: 'AES_GCM_decrypt(AES_key, sealed) → { entity_id: "C2-LK-5678", cert, proof }\nECDSA_verify(CA_pub, c2_cert_body, c2_ca_sig) → TRUE ✓\nNow server knows C2 — C1 never found out ✓' },
      { step: 7, party: "C2 → Server", label: "RELAY_DATA (Non-Repudiation)", desc: "C2 signs stats, encrypts E2E. Server verifies signature for non-repudiation.", code: 'sealed = AES_GCM_encrypt(AES_key, { stats, signature: ECDSA_sign(c2_lt_priv, stats) })\nServer: ECDSA_verify(c2_lt_pub, stats, sig) → TRUE ✓' },
    ],
    props: [
      { name: "E2E Confidentiality", detail: "AES-GCM — C1 cannot read C2↔Server data" },
      { name: "Integrity", detail: "GCM auth tag on all sealed payloads" },
      { name: "Relay Authentication", detail: "C1 relay cert + C2 identity (CA-verified)" },
      { name: "Non-Repudiation", detail: "C2 ECDSA signature on stats" },
      { name: "Anonymity to Relay", detail: "Phase 1 anonymous — C1 never sees C2 identity" },
      { name: "Relay Privacy", detail: "C1 forwards sealed blobs it cannot decrypt" },
      { name: "Replay Protection", detail: "Nonce + Timestamp (two-layer freshness)" },
      { name: "Forward Secrecy", detail: "Ephemeral ECDH for both V2V and relay channels" },
    ],
  },
];

export default function ChannelsPage() {
  return (
    <div className={styles.page}>
      <div className="container">
        <div className={styles.header}>
          <p className="section-label">Protocol Design</p>
          <h1 className="section-title">
            Three <span className="gradient-text">Secure Channels</span>
          </h1>
          <p className="section-subtitle">
            Each channel is independently designed with its own cryptographic handshake,
            security goals, and threat model.
          </p>
        </div>

        {CHANNELS.map((ch) => (
          <section key={ch.id} id={ch.id} className={styles.channelSection}>
            {/* Channel header */}
            <div className={styles.chHeader} style={{ borderLeftColor: ch.color }}>
              <div className={styles.chIcon}>{ch.icon}</div>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 12, marginBottom: 6 }}>
                  <h2 className={styles.chName}>{ch.name}</h2>
                  <span className={`badge ${ch.badgeClass}`}>{ch.badge}</span>
                </div>
                <p className={styles.chParties} style={{ color: ch.color }}>
                  ⟶ {ch.parties}
                </p>
                <p className={styles.chDesc}>{ch.description}</p>
              </div>
            </div>

            <div className={styles.chBody}>
              {/* Handshake Steps */}
              <div className={styles.stepsCol}>
                <h3 className={styles.colTitle}>Handshake Protocol</h3>
                <div className={styles.steps}>
                  {ch.steps.map((s) => (
                    <div key={s.step} className={styles.step}>
                      <div className={styles.stepNum} style={{ background: ch.color + "20", borderColor: ch.color + "60", color: ch.color }}>
                        {s.step}
                      </div>
                      <div className={styles.stepContent}>
                        <div className={styles.stepHeader}>
                          <span className={styles.stepParty} style={{ color: ch.color }}>[{s.party}]</span>
                          <span className={styles.stepLabel}>{s.label}</span>
                        </div>
                        <p className={styles.stepDesc}>{s.desc}</p>
                        <div className="code-block" style={{ marginTop: 8, fontSize: 12 }}>
                          {s.code}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Security Properties */}
              <div className={styles.propsCol}>
                <h3 className={styles.colTitle}>Security Properties</h3>
                <div className={styles.propsList}>
                  {ch.props.map((p) => (
                    <div key={p.name} className={styles.propItem} style={{ borderColor: ch.color + "30" }}>
                      <span className={styles.propCheck} style={{ color: ch.color }}>✓</span>
                      <div>
                        <div className={styles.propName}>{p.name}</div>
                        <div className={styles.propDetail}>{p.detail}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}
