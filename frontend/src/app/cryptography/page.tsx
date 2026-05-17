import styles from "./page.module.css";

const PRIMITIVES = [
  {
    name: "ECDH — Key Agreement",
    short: "Elliptic Curve Diffie-Hellman",
    curve: "secp256k1",
    color: "#00d4ff",
    icon: "🔑",
    purpose: "Establishes a shared secret between two parties without transmitting the secret over the network.",
    howItWorks: [
      "Both parties generate ephemeral key pairs: (priv, pub)",
      "Exchange public keys over the network",
      "Each computes SS = ECDH(my_priv, peer_pub)",
      "Both get identical SS.x (x-coordinate of shared point)",
      "SS is never transmitted — impossible to derive from pub keys alone",
    ],
    securityBits: 128,
    usedIn: ["Channel 1 V2V handshake", "Channel 2 Monitor handshake", "Channel 3 Relay E2E"],
    code: `# ECDH shared secret
shared_secret = my_ephemeral_priv.exchange(ECDH(), peer_ephemeral_pub)
# Both sides compute identical shared_secret`,
  },
  {
    name: "HKDF — Key Derivation",
    short: "HMAC-based Key Derivation Function",
    curve: "SHA-256",
    color: "#a855f7",
    icon: "🧮",
    purpose: "Converts raw ECDH shared secret (non-uniform) into cryptographically strong 32-byte AES key material.",
    howItWorks: [
      "Extract: PRK = HMAC(salt, IKM) — concentrates entropy",
      "Expand: OKM = HMAC(PRK, info) — stretches to desired length",
      "Channel-specific salt isolates keys across channels",
      "Label differentiates purpose (v2v / monitor / relay)",
      "Output: exactly 32 bytes of uniform key material",
    ],
    securityBits: 256,
    usedIn: ["After every ECDH exchange to derive AES-256 key"],
    code: `HKDF(
  algorithm = SHA-256,
  length    = 32,
  salt      = "V2V-Ch1".encode(),   # channel-specific
  info      = "v2v".encode(),       # purpose label
).derive(ecdh_shared_secret)
# → 32-byte AES-256 key`,
  },
  {
    name: "AES-GCM — Authenticated Encryption",
    short: "Advanced Encryption Standard — Galois/Counter Mode",
    curve: "256-bit",
    color: "#10b981",
    icon: "🔒",
    purpose: "Provides both confidentiality (encryption) and integrity (authentication tag) in one operation.",
    howItWorks: [
      "Generates random 96-bit nonce per encryption",
      "CTR mode encrypts plaintext → ciphertext",
      "GHASH authenticates ciphertext + optional AAD",
      "Produces 128-bit authentication tag",
      "Decryption verifies tag FIRST — rejects tampered data",
    ],
    securityBits: 256,
    usedIn: ["All encrypted payloads on all three channels"],
    code: `# Encrypt
nonce      = os.urandom(12)      # 96-bit random nonce
ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
# ciphertext includes 16-byte GCM auth tag

# Decrypt (tag verified before returning plaintext)
plaintext  = AESGCM(key).decrypt(nonce, ciphertext, aad)
# raises InvalidTag if modified`,
  },
  {
    name: "ECDSA — Digital Signatures",
    short: "Elliptic Curve Digital Signature Algorithm",
    curve: "secp256k1 + SHA-256",
    color: "#f59e0b",
    icon: "✍️",
    purpose: "Proves a message was created by the holder of a specific private key. Provides authentication and non-repudiation.",
    howItWorks: [
      "Signer: sig = ECDSA_sign(priv_key, SHA-256(message))",
      "sig is a DER-encoded (r, s) point pair",
      "Verifier: ECDSA_verify(pub_key, message, sig)",
      "Verification fails if message was modified",
      "Non-repudiation: only private key holder can produce valid sig",
    ],
    securityBits: 128,
    usedIn: ["CA certificate signatures", "Handshake body signatures", "Vehicle data non-repudiation"],
    code: `# Sign
sig = priv_key.sign(data_bytes, ECDSA(SHA256()))
sig_b64 = base64.b64encode(sig).decode()

# Verify
pub_key.verify(base64.b64decode(sig_b64), data_bytes, ECDSA(SHA256()))
# raises InvalidSignature if not authentic`,
  },
  {
    name: "HMAC — Message Authentication",
    short: "Hash-based Message Authentication Code",
    curve: "SHA-256",
    color: "#ec4899",
    icon: "🔐",
    purpose: "Verifies that a message came from a party sharing the same secret key. Used in Channel 3 relay to prevent injection attacks.",
    howItWorks: [
      "MAC = HMAC-SHA256(shared_key, message)",
      "Only parties knowing the key can produce valid MAC",
      "Constant-time comparison prevents timing attacks",
      "Does NOT prove identity — only channel membership",
      "C1 verifies C2's relay request came from its V2V partner",
    ],
    securityBits: 256,
    usedIn: ["Channel 3: C2 → C1 relay request integrity"],
    code: `# MAC relay request
mac = hmac.new(v2v_aes_key, anon_hello_bytes, sha256).digest()
mac_b64 = base64.b64encode(mac).decode()

# Verify (constant-time)
expected = hmac.new(v2v_aes_key, data, sha256).digest()
hmac.compare_digest(expected, base64.b64decode(mac_b64))`,
  },
];

export default function CryptographyPage() {
  return (
    <div className={styles.page}>
      <div className="container">
        <div className={styles.header}>
          <p className="section-label">Implementation Details</p>
          <h1 className="section-title">
            Cryptographic <span className="gradient-text">Primitives</span>
          </h1>
          <p className="section-subtitle">
            All cryptographic operations are implemented from scratch using only
            the Python <code className="font-mono" style={{ color: "var(--teal)", fontSize: 15 }}>cryptography</code> library.
            No SSL, no TLS, no shortcuts.
          </p>
        </div>

        <div className={styles.grid}>
          {PRIMITIVES.map((p) => (
            <div key={p.name} className={styles.card} style={{ borderTopColor: p.color }}>
              <div className={styles.cardHeader}>
                <span className={styles.icon}>{p.icon}</span>
                <div>
                  <h2 className={styles.primName} style={{ color: p.color }}>{p.name}</h2>
                  <p className={styles.primShort}>{p.short}</p>
                </div>
                <div className={styles.secBits} style={{ borderColor: p.color + "50", color: p.color }}>
                  {p.securityBits}-bit
                </div>
              </div>

              <p className={styles.purpose}>{p.purpose}</p>

              <div className={styles.howItWorks}>
                <div className={styles.subTitle}>How It Works</div>
                <ol className={styles.steps}>
                  {p.howItWorks.map((s, i) => (
                    <li key={i} className={styles.stepItem}>
                      <span className={styles.stepNum} style={{ background: p.color + "20", color: p.color }}>{i + 1}</span>
                      <span>{s}</span>
                    </li>
                  ))}
                </ol>
              </div>

              <div className={styles.usedIn}>
                <div className={styles.subTitle}>Used In</div>
                <div className={styles.usedList}>
                  {p.usedIn.map((u) => (
                    <span key={u} className={styles.useTag} style={{ background: p.color + "15", color: p.color, borderColor: p.color + "40" }}>{u}</span>
                  ))}
                </div>
              </div>

              <div>
                <div className={styles.subTitle}>Implementation</div>
                <div className="code-block">{p.code}</div>
              </div>
            </div>
          ))}
        </div>

        {/* Curve Info */}
        <div className={styles.curveInfo}>
          <h2 className={styles.curveTitle}>Why secp256k1?</h2>
          <div className={styles.curveGrid}>
            {[
              ["Curve", "secp256k1 (same as Bitcoin/Ethereum)"],
              ["Security Level", "128-bit equivalent security"],
              ["Key Size", "256-bit private keys, 512-bit public keys"],
              ["Signature Size", "64–72 bytes DER-encoded"],
              ["Operations", "ECDH key agreement + ECDSA signatures"],
              ["Library", "cryptography.hazmat.primitives.asymmetric.ec"],
            ].map(([label, val]) => (
              <div key={label} className={styles.curveRow}>
                <span className={styles.curveLabel}>{label}</span>
                <span className={styles.curveVal}>{val}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
