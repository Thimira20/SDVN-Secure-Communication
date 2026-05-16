"""
ca.py — SDVN Certificate Authority
====================================
The root of all trust in the SDVN network.

Responsibilities:
  - Generate and hold the CA key pair (never shared)
  - Issue signed long-term certificates for: server, C1, C2
  - Issue short-lived pseudonym certificates for V2V anonymity
  - Provide verify_certificate() used by all parties

Certificate structure (Python dict):
  {
    "entity_id"   : str   — identity (or opaque token for pseudonyms)
    "role"        : str   — "vehicle" | "server" | "pseudonym"
    "public_key"  : str   — PEM-encoded public key
    "issued_at"   : int   — Unix timestamp
    "expires_at"  : int   — Unix timestamp
    "issuer"      : str   — "SDVN-Root-CA"
    "ca_signature": str   — base64(ECDSA(CA_priv, cert_body_bytes))
  }
"""

import json
import time
import base64
import os

from crypto_utils import (
    generate_keypair,
    pub_to_pem,
    pub_to_hex,
    ecdsa_sign,
    ecdsa_verify,
    pem_to_pub,
    canonical_json,
)


class CertificateAuthority:
    """
    SDVN Root Certificate Authority.

    The CA is the single trust anchor. Its public key is pre-loaded
    into every vehicle at manufacture time (like a root CA certificate
    in a browser). The CA private key is never transmitted.
    """

    ISSUER_NAME = "SDVN-Root-CA"
    LONG_TERM_VALIDITY  = 86400      # 24 hours in seconds
    PSEUDONYM_VALIDITY  = 300        # 5 minutes in seconds

    def __init__(self):
        print("[CA] Initialising SDVN Root Certificate Authority")
        self._ca_priv, self._ca_pub = generate_keypair()
        self._ca_pub_hex = pub_to_hex(self._ca_pub)
        self._ca_pub_pem = pub_to_pem(self._ca_pub)
        print("[CA] CA key pair generated (secp256k1)")
        print("[CA] CA public key (pre-loaded into all vehicles at manufacture):")
        print(f"[CA]   pub = {self._ca_pub_hex[:64]}...")

        # Track pseudonym mappings (CA secret — never disclosed)
        self._pseudonym_map = {}   # pseudo_id → real entity_id
        self._pseudo_counters = {} # entity_id → count issued

    # ─────────────────────────────────────────────
    # PUBLIC KEY ACCESS
    # ─────────────────────────────────────────────

    @property
    def ca_public_key(self):
        """Return CA public key object (distributed to all parties at setup)."""
        return self._ca_pub

    @property
    def ca_public_key_pem(self) -> str:
        """Return CA public key as PEM string."""
        return self._ca_pub_pem

    # ─────────────────────────────────────────────
    # CERTIFICATE ISSUANCE
    # ─────────────────────────────────────────────

    def _sign_cert_body(self, cert_body: dict) -> str:
        """
        Produce a CA signature over a certificate body.

        The cert_body is JSON-serialised with sorted keys to ensure
        deterministic signing. The ca_signature field must NOT be
        included in the body before signing.

        Args:
            cert_body: dict of all cert fields except ca_signature

        Returns:
            str: base64-encoded ECDSA signature
        """
        body_bytes = canonical_json(cert_body)
        return ecdsa_sign(self._ca_priv, body_bytes)

    def issue_certificate(
        self,
        entity_id: str,
        role: str,
        public_key_pem: str,
        validity_seconds: int = None,
    ) -> dict:
        """
        Issue a signed long-term certificate for a network entity.

        Args:
            entity_id        : unique entity identifier (e.g. "C1-LK-1234")
            role             : "vehicle" or "server"
            public_key_pem   : PEM string of the entity's public key
            validity_seconds : how long the cert is valid (default 24h)

        Returns:
            dict: complete certificate including ca_signature
        """
        if validity_seconds is None:
            validity_seconds = self.LONG_TERM_VALIDITY

        now = int(time.time())
        cert_body = {
            "entity_id" : entity_id,
            "expires_at": now + validity_seconds,
            "issued_at" : now,
            "issuer"    : self.ISSUER_NAME,
            "public_key": public_key_pem,
            "role"      : role,
        }
        ca_sig = self._sign_cert_body(cert_body)
        cert = dict(cert_body)
        cert["ca_signature"] = ca_sig

        validity_label = f"{validity_seconds // 3600}h" if validity_seconds >= 3600 else f"{validity_seconds}s"
        print(f"[CA] Certificate issued → entity={entity_id}, role={role}, valid={validity_label}")
        return cert

    def issue_pseudonym(self, real_entity_id: str, pseudo_priv=None) -> tuple:
        """
        Issue an anonymous short-lived pseudonym certificate for V2V use.

        The pseudonym's entity_id is a random opaque token — NOT the
        vehicle's real identity. Only the CA maintains the mapping.
        All other parties (including V2V peers) cannot link pseudonym
        to real identity.

        Args:
            real_entity_id : real identity of the vehicle (CA internal only)
            pseudo_priv    : optional pre-generated private key (generated here if None)

        Returns:
            tuple: (pseudonym_certificate dict, pseudo_private_key)
        """
        # Generate fresh key pair for this pseudonym
        if pseudo_priv is None:
            pseudo_priv, pseudo_pub = generate_keypair()
        else:
            pseudo_pub = pseudo_priv.public_key()

        # Opaque random pseudo_id — NOT derived from real identity
        pseudo_id = base64.b64encode(os.urandom(8)).decode()

        count = self._pseudo_counters.get(real_entity_id, 0)
        self._pseudo_counters[real_entity_id] = count + 1

        now = int(time.time())
        cert_body = {
            "entity_id" : pseudo_id,
            "expires_at": now + self.PSEUDONYM_VALIDITY,
            "issued_at" : now,
            "issuer"    : self.ISSUER_NAME,
            "public_key": pub_to_pem(pseudo_pub),
            "role"      : "pseudonym",
        }
        ca_sig = self._sign_cert_body(cert_body)
        cert = dict(cert_body)
        cert["ca_signature"] = ca_sig

        # Record CA secret mapping
        self._pseudonym_map[pseudo_id] = real_entity_id

        print(f"[CA] Pseudonym #{count} issued for {real_entity_id} → pseudo_id={pseudo_id}, valid=5min")
        if role := "pseudonym":
            print(f"[CA] NOTE: CA secret mapping → {pseudo_id} belongs to {real_entity_id}")
            print(f"[CA]        (Only CA knows this. V2V peers cannot find out.)")

        return cert, pseudo_priv

    # ─────────────────────────────────────────────
    # CERTIFICATE VERIFICATION
    # ─────────────────────────────────────────────

    def verify_certificate(self, cert: dict) -> bool:
        """
        Verify a certificate's CA signature and validity period.

        Verification steps:
          1. Extract cert body (all fields except ca_signature)
          2. Verify ECDSA(CA_pub, cert_body_bytes, ca_signature)
          3. Check issued_at <= now <= expires_at

        Args:
            cert: certificate dict (must include ca_signature)

        Returns:
            bool: True if certificate is valid and not expired

        Used by:
            All parties — server, C1, C2 — to validate received certificates
        """
        try:
            cert_body = {k: v for k, v in cert.items() if k != "ca_signature"}
            body_bytes = canonical_json(cert_body)
            sig_valid = ecdsa_verify(self._ca_pub, body_bytes, cert["ca_signature"])
            now = time.time()
            time_valid = cert["issued_at"] <= now <= cert["expires_at"]
            return sig_valid and time_valid
        except Exception:
            return False

    def get_ca_pub_key_for_party(self):
        """
        Return the CA public key to be distributed to network parties.

        In a real deployment this would be embedded in firmware.
        Here it is passed directly at initialisation.

        Returns:
            EllipticCurvePublicKey: CA public key
        """
        return self._ca_pub
