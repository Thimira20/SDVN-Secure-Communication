import type { Metadata } from "next";
import "./globals.css";
import Navbar from "@/components/Navbar";

export const metadata: Metadata = {
  title: "SDVN Secure Communication — Protocol Visualizer",
  description: "Interactive visualization of the SDVN secure vehicular communication protocol featuring ECDH, AES-GCM, ECDSA, and pseudonym anonymity across three secure channels.",
  keywords: ["SDVN", "secure communication", "vehicular network", "ECDH", "AES-GCM", "cryptography"],
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <Navbar />
        <main>{children}</main>
        <footer style={{
          borderTop: '1px solid var(--border)',
          padding: '32px 0',
          marginTop: '80px',
          textAlign: 'center',
          color: 'var(--text-muted)',
          fontSize: '14px',
        }}>
          <div className="container">
            <p>SDVN Secure Communication Protocol — Built with ECDH · AES-GCM-256 · ECDSA · HKDF · HMAC</p>
            <p style={{ marginTop: 8, fontSize: 12 }}>No SSL. No TLS. Manual cryptography from scratch.</p>
          </div>
        </footer>
      </body>
    </html>
  );
}
