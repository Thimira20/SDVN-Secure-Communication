import SecurityMatrix from "@/components/SecurityMatrix";
import styles from "./page.module.css";

const VEHICLE_STATS = [
  { vehicle: "C1-LK-1234", channel: "Ch2 Direct", speed: "72 km/h", direction: "North", location: "6.927, 79.861", method: "ECDSA + mutual auth" },
  { vehicle: "C2-LK-5678", channel: "Ch3 Relay", speed: "65 km/h", direction: "East", location: "6.914, 79.852", method: "E2E encrypted + ECDSA" },
];

const ATTACK_MITIGATIONS = [
  { attack: "Eavesdropping", description: "Passive interception of network traffic", mitigation: "AES-GCM-256 encryption on all channels — ciphertext reveals nothing", allChannels: true },
  { attack: "Man-in-the-Middle", description: "Attacker intercepts and modifies messages", mitigation: "ECDSA signatures verified by CA — any modification fails", allChannels: true },
  { attack: "Replay Attack", description: "Reuse of captured valid packets", mitigation: "Timestamp freshness check (±30s) + random nonces on Ch3", allChannels: true },
  { attack: "Identity Linkability", description: "Tracking a vehicle across V2V sessions", mitigation: "Pseudonym certificates (5 min lifetime, random opaque ID)", allChannels: false },
  { attack: "Relay Deanonymization", description: "C1 learning C2's identity while relaying", mitigation: "Phase 1 anonymous key exchange — C2 identity sealed E2E", allChannels: false },
  { attack: "Repudiation", description: "Vehicle denying it sent specific data", mitigation: "ECDSA over vehicle stats with long-term key — irrefutable", allChannels: true },
  { attack: "Impersonation", description: "Attacker pretending to be a registered vehicle", mitigation: "CA-signed certificates — forged certs rejected by all parties", allChannels: true },
  { attack: "Key Compromise (past)", description: "Compromised key revealing past sessions", mitigation: "Ephemeral ECDH keys — forward secrecy guaranteed", allChannels: true },
];

export default function SecurityPage() {
  return (
    <div className={styles.page}>
      <div className="container">
        <div className={styles.header}>
          <p className="section-label">Security Analysis</p>
          <h1 className="section-title">Security <span className="gradient-text">Report</span></h1>
          <p className="section-subtitle">
            Comprehensive security analysis of all three channels, threat model,
            attack mitigations, and final vehicle log.
          </p>
        </div>

        {/* Security Matrix */}
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>Properties Matrix</h2>
          <SecurityMatrix />
        </section>

        {/* Vehicle Log */}
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>Server Vehicle Log (Post-Simulation)</h2>
          <div className={styles.vehicleLog}>
            {VEHICLE_STATS.map((v) => (
              <div key={v.vehicle} className={styles.vehicleCard}>
                <div className={styles.vehicleHeader}>
                  <span className={styles.vehicleId}>🚗 {v.vehicle}</span>
                  <span className="badge badge-teal">{v.channel}</span>
                </div>
                <div className={styles.vehicleStats}>
                  <div className={styles.stat}><span className={styles.statKey}>Speed</span><span className={styles.statVal}>{v.speed}</span></div>
                  <div className={styles.stat}><span className={styles.statKey}>Direction</span><span className={styles.statVal}>{v.direction}</span></div>
                  <div className={styles.stat}><span className={styles.statKey}>Location</span><span className={styles.statVal}>{v.location}</span></div>
                  <div className={styles.stat}><span className={styles.statKey}>Auth Method</span><span className={styles.statVal} style={{ color: "var(--green)" }}>{v.method}</span></div>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Attack Mitigation Table */}
        <section className={styles.section}>
          <h2 className={styles.sectionTitle}>Threat Model & Attack Mitigations</h2>
          <div className={styles.tableWrap}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Attack Vector</th>
                  <th>Description</th>
                  <th>Mitigation</th>
                  <th>All Channels</th>
                </tr>
              </thead>
              <tbody>
                {ATTACK_MITIGATIONS.map((a) => (
                  <tr key={a.attack}>
                    <td><span className={styles.attackName}>{a.attack}</span></td>
                    <td style={{ color: "var(--text-secondary)", fontSize: 13 }}>{a.description}</td>
                    <td style={{ fontSize: 13 }}>{a.mitigation}</td>
                    <td>
                      <span style={{ color: a.allChannels ? "var(--green)" : "var(--amber)", fontWeight: 700 }}>
                        {a.allChannels ? "✓ All" : "◉ Specific"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Final Summary Banner */}
        <section className={styles.summaryBanner}>
          <div className={styles.summaryTitle}>✅ Simulation Complete — All Security Properties Verified</div>
          <p className={styles.summaryText}>
            All three channels successfully demonstrated confidentiality, integrity, authentication,
            and non-repudiation. No SSL or TLS was used — every cryptographic primitive was implemented manually.
          </p>
          <div className={styles.summaryGrid}>
            {[
              ["8", "Security Properties", "Verified per channel"],
              ["256-bit", "Encryption Strength", "AES-GCM key size"],
              ["3", "Secure Channels", "All operational"],
              ["0", "SSL/TLS Deps", "Pure manual crypto"],
            ].map(([val, label, sub]) => (
              <div key={label} className={styles.summaryItem}>
                <div className={styles.summaryVal}>{val}</div>
                <div className={styles.summaryLabel}>{label}</div>
                <div className={styles.summarySub}>{sub}</div>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
