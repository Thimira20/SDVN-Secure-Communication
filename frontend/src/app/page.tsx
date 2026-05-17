import NetworkTopology from "@/components/NetworkTopology";
import SecurityMatrix from "@/components/SecurityMatrix";
import styles from "./page.module.css";
import Link from "next/link";

const CHANNELS = [
  {
    id: "ch1",
    name: "Channel 1 — V2V",
    short: "C1 ↔ C2",
    description: "Vehicle-to-vehicle secure communication using pseudonym certificates for complete anonymity.",
    crypto: ["ECDH", "AES-GCM", "ECDSA", "HKDF"],
    color: "teal",
    icon: "🚗",
    props: ["Confidentiality", "Integrity", "Authentication", "Anonymity"],
    href: "/channels#v2v",
  },
  {
    id: "ch2",
    name: "Channel 2 — Monitor",
    short: "C1 → Server",
    description: "Direct vehicle-to-monitoring-server channel using real identity certificates for full accountability.",
    crypto: ["ECDH", "AES-GCM", "ECDSA", "HKDF"],
    color: "purple",
    icon: "📡",
    props: ["Confidentiality", "Mutual Auth", "Non-Repudiation", "Replay Protection"],
    href: "/channels#monitor",
  },
  {
    id: "ch3",
    name: "Channel 3 — Relay",
    short: "C2 → C1 → Server",
    description: "Anonymous relay where C1 forwards C2's encrypted data to the server without learning C2's identity.",
    crypto: ["ECDH", "AES-GCM", "ECDSA", "HMAC"],
    color: "amber",
    icon: "🔁",
    props: ["E2E Confidentiality", "Anonymity to Relay", "Forward Secrecy", "Non-Repudiation"],
    href: "/channels#relay",
  },
];

const STATS = [
  { label: "Security Properties", value: "8", sub: "per channel" },
  { label: "Crypto Primitives", value: "5", sub: "manual impl." },
  { label: "Secure Channels", value: "3", sub: "independent" },
  { label: "Key Bits", value: "256", sub: "AES-GCM + ECDH" },
];

export default function HomePage() {
  return (
    <div className={styles.page}>
      {/* Hero */}
      <section className={styles.hero}>
        <div className={styles.heroBg}>
          <div className={styles.heroBgOrb1} />
          <div className={styles.heroBgOrb2} />
          <div className={styles.grid} />
        </div>
        <div className="container">
          <div className={styles.heroContent}>
            <div className="animate-fade-up">
              <span className="badge badge-teal">
                <span className="pulse-dot" style={{ width: 6, height: 6 }} />
                No SSL · No TLS · Manual Cryptography
              </span>
            </div>
            <h1 className={`${styles.heroTitle} animate-fade-up delay-100`}>
              SDVN Secure<br />
              <span className="gradient-text">Communication</span><br />
              Protocol
            </h1>
            <p className={`${styles.heroSubtitle} animate-fade-up delay-200`}>
              A complete from-scratch cryptographic protocol for Software-Defined Vehicular Networks.
              Three independent secure channels — V2V, Monitoring, and Anonymous Relay —
              built using ECDH, AES-GCM-256, ECDSA, HKDF, and HMAC.
            </p>
            <div className={`${styles.heroActions} animate-fade-up delay-300`}>
              <Link href="/simulation" className="btn btn-primary">
                ▶ Run Simulation
              </Link>
              <Link href="/channels" className="btn btn-secondary">
                Explore Channels →
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Stats bar */}
      <section className={styles.statsBar}>
        <div className="container">
          <div className={styles.statsGrid}>
            {STATS.map((s, i) => (
              <div key={i} className={styles.statItem}>
                <div className={styles.statValue}>{s.value}</div>
                <div className={styles.statLabel}>{s.label}</div>
                <div className={styles.statSub}>{s.sub}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <div className="container">
        {/* Network Topology */}
        <section style={{ marginBottom: 80 }}>
          <div style={{ textAlign: "center", marginBottom: 40 }}>
            <p className="section-label">Architecture</p>
            <h2 className="section-title">Network <span className="gradient-text">Topology</span></h2>
            <p className="section-subtitle" style={{ margin: "0 auto" }}>
              Three parties connected across three independent secure channels.
              The CA is the single root of trust for the entire network.
            </p>
          </div>
          <NetworkTopology />
        </section>

        <div className="glow-divider" />

        {/* Channels */}
        <section style={{ marginBottom: 80 }}>
          <div style={{ marginBottom: 48 }}>
            <p className="section-label">Protocol Channels</p>
            <h2 className="section-title">Three <span className="gradient-text">Secure Channels</span></h2>
            <p className="section-subtitle">
              Each channel is independently designed with its own security goals,
              handshake protocol, and cryptographic guarantees.
            </p>
          </div>
          <div className={styles.channelsGrid}>
            {CHANNELS.map((ch, i) => (
              <Link href={ch.href} key={ch.id} className={`${styles.channelCard} animate-fade-up delay-${(i + 1) * 100}`}>
                <div className={styles.channelIcon}>{ch.icon}</div>
                <div className={styles.channelHeader}>
                  <h3 className={styles.channelName}>{ch.name}</h3>
                  <span className={`badge badge-${ch.color === "teal" ? "teal" : ch.color === "purple" ? "purple" : "amber"}`}>
                    {ch.short}
                  </span>
                </div>
                <p className={styles.channelDesc}>{ch.description}</p>
                <div className={styles.cryptoTags}>
                  {ch.crypto.map((c) => (
                    <span key={c} className={styles.cryptoTag}>{c}</span>
                  ))}
                </div>
                <ul className={styles.propsList}>
                  {ch.props.map((p) => (
                    <li key={p}>
                      <span className="check-icon">✓</span>
                      {p}
                    </li>
                  ))}
                </ul>
                <div className={styles.channelArrow}>Explore →</div>
              </Link>
            ))}
          </div>
        </section>

        <div className="glow-divider" />

        {/* Security Matrix */}
        <section style={{ marginBottom: 80 }}>
          <div style={{ textAlign: "center", marginBottom: 48 }}>
            <p className="section-label">Security Analysis</p>
            <h2 className="section-title">Security <span className="gradient-text">Properties Matrix</span></h2>
            <p className="section-subtitle" style={{ margin: "0 auto" }}>
              Comprehensive mapping of security properties across all three channels.
            </p>
          </div>
          <SecurityMatrix />
        </section>
      </div>
    </div>
  );
}
