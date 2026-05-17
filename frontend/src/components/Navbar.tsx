"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import styles from "./Navbar.module.css";

const links = [
  { href: "/", label: "Overview" },
  { href: "/channels", label: "Channels" },
  { href: "/simulation", label: "Simulation" },
  { href: "/security", label: "Security Report" },
  { href: "/cryptography", label: "Cryptography" },
];

export default function Navbar() {
  const pathname = usePathname();
  return (
    <nav className={styles.nav}>
      <div className={styles.inner}>
        <Link href="/" className={styles.logo}>
          <span className={styles.logoIcon}>⬡</span>
          <span>SDVN<span className={styles.logoAccent}>.sec</span></span>
        </Link>
        <ul className={styles.links}>
          {links.map((l) => (
            <li key={l.href}>
              <Link
                href={l.href}
                className={`${styles.link} ${pathname === l.href ? styles.active : ""}`}
              >
                {l.label}
              </Link>
            </li>
          ))}
        </ul>
        <div className={styles.status}>
          <span className="pulse-dot" />
          <span className={styles.statusText}>Protocol Active</span>
        </div>
      </div>
    </nav>
  );
}
