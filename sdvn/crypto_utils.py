"""
crypto_utils.py — SDVN Cryptographic Primitives
================================================
All cryptographic building blocks for the SDVN secure communication protocol.
NO SSL. NO TLS. Manual implementation using only the `cryptography` library.

Security primitives used:
  ECDH   secp256k1  — key agreement
  HKDF   SHA-256    — session key derivation
  AES-GCM 256-bit   — authenticated encryption
  ECDSA  secp256k1  — digital signatures
  HMAC   SHA-256    — relay integrity checking
"""

import os
import json
import time
import base64
import hmac as _hmac
import hashlib

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256K1, generate_private_key, ECDH,
    EllipticCurvePublicKey, EllipticCurvePrivateKey,
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# ─────────────────────────────────────────────
# KEY GENERATION
# ─────────────────────────────────────────────

def generate_keypair():
    """
    Generate an ECDSA/ECDH key pair on the secp256k1 curve.

    Security role:
        - Used for both long-term identity keys (ECDSA signing) and
          ephemeral session keys (ECDH key agreement).
        - secp256k1 is the same curve used in Bitcoin; provides 128-bit
          security level.

    Returns:
        tuple: (private_key, public_key)
            private_key : EllipticCurvePrivateKey (secp256k1)
            public_key  : EllipticCurvePublicKey  (secp256k1)
    """
    private_key = generate_private_key(SECP256K1(), default_backend())
    public_key  = private_key.public_key()
    return private_key, public_key


# ─────────────────────────────────────────────
# KEY SERIALISATION
# ─────────────────────────────────────────────

def pub_to_pem(pub_key: EllipticCurvePublicKey) -> str:
    """
    Serialise an EllipticCurvePublicKey to a PEM string for network transmission.

    Security role:
        - Public keys must be shared during handshakes (ephemeral ECDH pub,
          pseudonym pub, long-term cert pub).
        - PEM is a standard, unambiguous wire format.

    Args:
        pub_key: EllipticCurvePublicKey object

    Returns:
        str: PEM-encoded public key (SubjectPublicKeyInfo format)
    """
    return pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def pem_to_pub(pem_str: str) -> EllipticCurvePublicKey:
    """
    Deserialise a PEM string back to an EllipticCurvePublicKey object.

    Security role:
        - Reconstruct the peer's public key received over the network
          before performing ECDH or ECDSA verification.

    Args:
        pem_str: PEM-encoded public key string

    Returns:
        EllipticCurvePublicKey object
    """
    return serialization.load_pem_public_key(
        pem_str.encode("utf-8"),
        backend=default_backend(),
    )


def pub_to_hex(pub_key: EllipticCurvePublicKey) -> str:
    """
    Return uncompressed hex representation of a public key (04 || x || y).

    Security role:
        - Used for logging/display. The 04 prefix indicates uncompressed point.

    Args:
        pub_key: EllipticCurvePublicKey object

    Returns:
        str: hex string starting with "04..."
    """
    raw = pub_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    return raw.hex()


# ─────────────────────────────────────────────
# SESSION KEY DERIVATION (ECDH + HKDF)
# ─────────────────────────────────────────────

def derive_session_key(
    my_priv: EllipticCurvePrivateKey,
    peer_pub: EllipticCurvePublicKey,
    salt: str,
    label: str,
) -> bytes:
    """
    Derive a 256-bit AES session key via ECDH + HKDF(SHA-256).

    Security role:
        - ECDH (Elliptic Curve Diffie-Hellman):
            Produces a shared secret from one private key and one public key.
            Both sides compute the same shared secret without transmitting it.
            Provides Perfect Forward Secrecy when ephemeral keys are used.
        - HKDF (HMAC-based Key Derivation Function):
            Extracts entropy from the raw ECDH output (which is not uniform)
            and expands it to exactly 32 bytes of cryptographically strong
            key material. The salt differentiates keys across channels.

    Args:
        my_priv  : My ECDH private key (ephemeral)
        peer_pub : Peer's ECDH public key (received during handshake)
        salt     : Channel-specific salt string (e.g. "V2V-Ch1")
        label    : HKDF info/label string (e.g. "v2v")

    Returns:
        bytes: 32-byte AES-256 key
    """
    # ECDH exchange — raw shared secret bytes (x-coordinate of shared point)
    shared_secret = my_priv.exchange(ECDH(), peer_pub)

    # HKDF extraction + expansion
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode("utf-8"),
        info=label.encode("utf-8"),
        backend=default_backend(),
    )
    return hkdf.derive(shared_secret)


def ecdh_shared_secret_x(
    my_priv: EllipticCurvePrivateKey,
    peer_pub: EllipticCurvePublicKey,
) -> bytes:
    """
    Return raw ECDH shared secret bytes (x-coordinate) for logging.

    Security role:
        - Used ONLY for display/logging purposes to show that both sides
          computed the same x-coordinate.
        - Never used directly as a key (use derive_session_key for that).

    Args:
        my_priv  : My ECDH private key
        peer_pub : Peer's ECDH public key

    Returns:
        bytes: raw shared secret x-coordinate
    """
    return my_priv.exchange(ECDH(), peer_pub)


# ─────────────────────────────────────────────
# AUTHENTICATED ENCRYPTION (AES-GCM)
# ─────────────────────────────────────────────

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> dict:
    """
    Encrypt plaintext with AES-256-GCM authenticated encryption.

    Security role:
        - Confidentiality : AES-GCM cipher hides the plaintext.
        - Integrity       : GCM produces a 128-bit authentication tag.
                            Any modification to the ciphertext or AAD
                            will cause decryption to fail (InvalidTag).
        - AAD (Additional Authenticated Data): integrity-protected but
          NOT encrypted (e.g. packet headers that need to be readable
          but must not be tampered with).
        - Nonce: 96-bit random value — MUST be unique per encryption.

    Args:
        key       : 32-byte AES-256 key
        plaintext : bytes to encrypt
        aad       : additional authenticated data (default empty)

    Returns:
        dict: {
            "nonce"      : base64-encoded 12-byte nonce,
            "ciphertext" : base64-encoded ciphertext (includes GCM tag),
            "aad"        : base64-encoded AAD,
        }
    """
    nonce = os.urandom(12)          # 96-bit random nonce
    aesgcm = AESGCM(key)
    # AESGCM.encrypt appends the 16-byte auth tag to ciphertext automatically
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad if aad else None)
    return {
        "nonce"      : base64.b64encode(nonce).decode(),
        "ciphertext" : base64.b64encode(ciphertext).decode(),
        "aad"        : base64.b64encode(aad).decode(),
    }


def aes_gcm_decrypt(key: bytes, packet_dict: dict) -> bytes:
    """
    Decrypt an AES-256-GCM packet and verify its authentication tag.

    Security role:
        - Verifies the GCM authentication tag BEFORE returning any plaintext.
        - If ciphertext or AAD was tampered with, raises InvalidTag.
        - This provides both integrity and confidentiality guarantees.

    Args:
        key         : 32-byte AES-256 key
        packet_dict : dict from aes_gcm_encrypt

    Returns:
        bytes: decrypted plaintext

    Raises:
        cryptography.exceptions.InvalidTag: if authentication fails
    """
    nonce      = base64.b64decode(packet_dict["nonce"])
    ciphertext = base64.b64decode(packet_dict["ciphertext"])
    aad_bytes  = base64.b64decode(packet_dict["aad"])
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, aad_bytes if aad_bytes else None)


# ─────────────────────────────────────────────
# DIGITAL SIGNATURES (ECDSA)
# ─────────────────────────────────────────────

def ecdsa_sign(priv_key: EllipticCurvePrivateKey, data_bytes: bytes) -> str:
    """
    Sign data with ECDSA using SHA-256 on secp256k1.

    Security role:
        - Authentication    : Proves the signer holds the private key.
        - Non-repudiation   : Signer cannot later deny signing the data.
        - Integrity         : Any modification to data invalidates the signature.
        - Used for: certificate signing (CA), handshake body signing,
                    data payload signing.

    Args:
        priv_key   : EllipticCurvePrivateKey (signer's private key)
        data_bytes : bytes to sign

    Returns:
        str: base64-encoded DER-encoded ECDSA signature
    """
    sig = priv_key.sign(data_bytes, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(sig).decode()


def ecdsa_verify(pub_key: EllipticCurvePublicKey, data_bytes: bytes, sig_b64: str) -> bool:
    """
    Verify an ECDSA signature.

    Security role:
        - Confirms the message was produced by the holder of the private key
          corresponding to pub_key.
        - Returns False (not exception) on invalid signature for safe handling.

    Args:
        pub_key  : EllipticCurvePublicKey (signer's public key)
        data_bytes: bytes that were signed
        sig_b64  : base64-encoded DER ECDSA signature

    Returns:
        bool: True if valid, False if invalid or tampered
    """
    try:
        sig = base64.b64decode(sig_b64)
        pub_key.verify(sig, data_bytes, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False


# ─────────────────────────────────────────────
# HMAC (Relay Integrity)
# ─────────────────────────────────────────────

def hmac_sign(key_bytes: bytes, data_bytes: bytes) -> str:
    """
    Compute HMAC-SHA256 over data_bytes using key_bytes.

    Security role:
        - Used in Channel 3 (relay) for C2 → C1 relay request integrity.
        - C2 uses the shared V2V session key to MAC the anonymous hello.
        - C1 verifies the MAC to confirm the relay request came from
          its V2V partner (not injected by an attacker).
        - Does NOT authenticate identity — only channel membership.

    Args:
        key_bytes  : HMAC key (e.g. AES session key from V2V channel)
        data_bytes : data to authenticate

    Returns:
        str: base64-encoded HMAC-SHA256
    """
    mac = _hmac.new(key_bytes, data_bytes, hashlib.sha256).digest()
    return base64.b64encode(mac).decode()


def hmac_verify(key_bytes: bytes, data_bytes: bytes, mac_b64: str) -> bool:
    """
    Verify an HMAC-SHA256 value.

    Security role:
        - Constant-time comparison prevents timing attacks.
        - Returns bool for safe conditional checking.

    Args:
        key_bytes : HMAC key
        data_bytes: data that was authenticated
        mac_b64   : base64-encoded expected HMAC

    Returns:
        bool: True if MAC is valid, False otherwise
    """
    try:
        expected = _hmac.new(key_bytes, data_bytes, hashlib.sha256).digest()
        received = base64.b64decode(mac_b64)
        return _hmac.compare_digest(expected, received)
    except Exception:
        return False


# ─────────────────────────────────────────────
# REPLAY PROTECTION
# ─────────────────────────────────────────────

def fresh_timestamp(ts: float, window_seconds: float = 30.0) -> bool:
    """
    Check whether a timestamp is within the acceptable freshness window.

    Security role:
        - Prevents replay attacks: an attacker who captures a valid packet
          cannot replay it more than `window_seconds` later.
        - Uses absolute difference to handle minor clock skew between parties.

    Args:
        ts             : Unix timestamp from received packet
        window_seconds : Maximum allowed age of message (default 30s)

    Returns:
        bool: True if timestamp is fresh, False if stale (replay suspected)
    """
    return abs(time.time() - ts) < window_seconds


# ─────────────────────────────────────────────
# PACKET SERIALISATION
# ─────────────────────────────────────────────

def make_packet(msg_type: str, **fields) -> bytes:
    """
    Serialise a packet to JSON bytes for network transmission.

    Security role:
        - Deterministic serialisation ensures signatures over packet fields
          can be reliably verified by the receiver.
        - The "type" field allows receivers to dispatch packet handling.

    Args:
        msg_type : packet type string (e.g. "V2V_HELLO", "HELLO_ACK")
        **fields : key-value pairs to include in packet

    Returns:
        bytes: JSON-encoded packet (UTF-8)
    """
    packet = {"type": msg_type}
    packet.update(fields)
    return json.dumps(packet, sort_keys=True).encode("utf-8")


def parse_packet(raw_bytes: bytes) -> dict:
    """
    Deserialise a received JSON packet.

    Security role:
        - All received packets MUST be parsed and then individually
          validated (signature check, timestamp check) before trusting
          any field. Parsing alone does NOT imply trust.

    Args:
        raw_bytes: JSON bytes received from socket

    Returns:
        dict: parsed packet fields

    Raises:
        json.JSONDecodeError: if packet is malformed
    """
    return json.loads(raw_bytes.decode("utf-8"))


# ─────────────────────────────────────────────
# HELPER: canonical JSON bytes for signing
# ─────────────────────────────────────────────

def canonical_json(obj: dict) -> bytes:
    """
    Produce deterministic, sorted-key JSON bytes suitable for signing.

    Security role:
        - Both signer and verifier must produce IDENTICAL bytes.
        - sort_keys=True ensures field order is deterministic regardless
          of insertion order (Python dict ordering varies).

    Args:
        obj: dict to serialise

    Returns:
        bytes: sorted-key JSON (UTF-8)
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
