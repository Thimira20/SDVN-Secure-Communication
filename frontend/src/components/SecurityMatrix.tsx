import styles from "./SecurityMatrix.module.css";

const PROPERTIES = [
  "Confidentiality",
  "Integrity",
  "Authentication",
  "Non-Repudiation",
  "Anonymity",
  "Replay Protection",
  "Forward Secrecy",
  "Relay Privacy",
];

const CHANNELS = ["Ch1 V2V", "Ch2 Monitor", "Ch3 Relay"];

type CellVal = { ok: boolean; detail: string };

const MATRIX: CellVal[][] = [
  // Confidentiality
  [
    { ok: true,  detail: "AES-GCM-256" },
    { ok: true,  detail: "AES-GCM-256" },
    { ok: true,  detail: "AES-GCM E2E" },
  ],
  // Integrity
  [
    { ok: true,  detail: "GCM auth tag" },
    { ok: true,  detail: "GCM auth tag" },
    { ok: true,  detail: "GCM tag" },
  ],
  // Authentication
  [
    { ok: true,  detail: "ECDSA + CA" },
    { ok: true,  detail: "Mutual + CA" },
    { ok: true,  detail: "C1 + C2 auth" },
  ],
  // Non-Repudiation
  [
    { ok: true,  detail: "ECDSA on stats" },
    { ok: true,  detail: "ECDSA on stats" },
    { ok: true,  detail: "ECDSA sig" },
  ],
  // Anonymity
  [
    { ok: true,  detail: "Pseudonym cert" },
    { ok: false, detail: "Real ID required" },
    { ok: true,  detail: "Anon Phase 1" },
  ],
  // Replay Protection
  [
    { ok: true,  detail: "Timestamp ±30s" },
    { ok: true,  detail: "Timestamp ±30s" },
    { ok: true,  detail: "Nonce + Timestamp" },
  ],
  // Forward Secrecy
  [
    { ok: true,  detail: "Ephemeral ECDH" },
    { ok: true,  detail: "Ephemeral ECDH" },
    { ok: true,  detail: "Ephemeral ECDH" },
  ],
  // Relay Privacy
  [
    { ok: false, detail: "N/A" },
    { ok: false, detail: "N/A" },
    { ok: true,  detail: "C1 cannot read" },
  ],
];

export default function SecurityMatrix() {
  return (
    <div className={styles.wrapper}>
      <div className={styles.tableWrap}>
        <table className={styles.table}>
          <thead>
            <tr>
              <th className={styles.propHeader}>Security Property</th>
              <th className={styles.chHeader} style={{ color: "#00d4ff" }}>Ch1 V2V</th>
              <th className={styles.chHeader} style={{ color: "#a855f7" }}>Ch2 Monitor</th>
              <th className={styles.chHeader} style={{ color: "#10b981" }}>Ch3 Relay</th>
            </tr>
          </thead>
          <tbody>
            {PROPERTIES.map((prop, pi) => (
              <tr key={prop} className={styles.row}>
                <td className={styles.propCell}>{prop}</td>
                {CHANNELS.map((_, ci) => {
                  const cell = MATRIX[pi][ci];
                  return (
                    <td key={ci} className={styles.cell}>
                      <div className={`${styles.cellInner} ${cell.ok ? styles.ok : styles.na}`}>
                        <span className={styles.icon}>{cell.ok ? "✓" : "—"}</span>
                        <span className={styles.detail}>{cell.detail}</span>
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
