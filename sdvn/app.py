import streamlit as st
import os, json, time, base64, hashlib
import hmac as hmac_module

from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key, ECDH, SECP256K1
)
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

st.set_page_config(
    page_title="SDVN Secure Communication Protocol — Live Demo",
    page_icon="🔐",
    layout="wide",
)

# ─────────────────────────── CRYPTO HELPERS ───────────────────────────

def b64e(b): return base64.b64encode(b).decode()
def b64d(s): return base64.b64decode(s)
def short(s, n=20): return str(s)[:n] + "..."

def gen_keypair():
    priv = generate_private_key(SECP256K1())
    pub  = priv.public_key()
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return priv, pub, pub_pem

def ecdh_derive(my_priv, peer_pub_pem, salt):
    peer_pub = serialization.load_pem_public_key(peer_pub_pem.encode())
    raw = my_priv.exchange(ECDH(), peer_pub)
    key = HKDF(hashes.SHA256(), 32, salt.encode(), salt.encode()).derive(raw)
    return key, b64e(raw[:8])

def aes_encrypt(key, plaintext):
    nonce = os.urandom(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return b64e(nonce), b64e(ct), b64e(ct[-16:])

def aes_decrypt(key, nonce_b64, ct_b64):
    return AESGCM(key).decrypt(b64d(nonce_b64), b64d(ct_b64), None).decode()

def ecdsa_sign(priv, data):
    sig = priv.sign(data.encode(), ec.ECDSA(hashes.SHA256()))
    return b64e(sig)

def ecdsa_verify(pub_pem, data, sig_b64):
    pub = serialization.load_pem_public_key(pub_pem.encode())
    try:
        pub.verify(b64d(sig_b64), data.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def hmac_sign(key, data):
    if isinstance(key, bytes):
        k = key
    else:
        k = key
    return b64e(hmac_module.new(k, data.encode(), hashlib.sha256).digest())

def ca_sign(ca_priv, cert_body):
    return ecdsa_sign(ca_priv, json.dumps(cert_body, sort_keys=True))

def make_pseudo_id():
    return b64e(os.urandom(8))

def attacker_view(nonce, ciphertext):
    raw = b64d(nonce) + b64d(ciphertext)
    hex_str = raw.hex()
    groups = [hex_str[i:i+8] for i in range(0, min(len(hex_str), 64), 8)]
    return " ".join(groups) + " ..."

# ─────────────────────────── SESSION STATE INIT ───────────────────────────

if "ca_priv" not in st.session_state:
    ca_priv, ca_pub, ca_pub_pem = gen_keypair()
    st.session_state.ca_priv    = ca_priv
    st.session_state.ca_pub_pem = ca_pub_pem

    c1_lt_priv, c1_lt_pub, c1_lt_pub_pem = gen_keypair()
    st.session_state.c1_lt_priv    = c1_lt_priv
    st.session_state.c1_lt_pub_pem = c1_lt_pub_pem
    c1_cert_body = {"entity_id":"C1-LK-1234","role":"vehicle",
                    "public_key":c1_lt_pub_pem,"issued_at":int(time.time()),
                    "expires_at":int(time.time())+86400,"issuer":"SDVN-Root-CA"}
    st.session_state.c1_cert = {**c1_cert_body, "ca_sig":ca_sign(ca_priv, c1_cert_body)}

    c2_lt_priv, c2_lt_pub, c2_lt_pub_pem = gen_keypair()
    st.session_state.c2_lt_priv    = c2_lt_priv
    st.session_state.c2_lt_pub_pem = c2_lt_pub_pem
    c2_cert_body = {"entity_id":"C2-LK-5678","role":"vehicle",
                    "public_key":c2_lt_pub_pem,"issued_at":int(time.time()),
                    "expires_at":int(time.time())+86400,"issuer":"SDVN-Root-CA"}
    st.session_state.c2_cert = {**c2_cert_body, "ca_sig":ca_sign(ca_priv, c2_cert_body)}

    sv_lt_priv, sv_lt_pub, sv_lt_pub_pem = gen_keypair()
    st.session_state.sv_lt_priv    = sv_lt_priv
    st.session_state.sv_lt_pub_pem = sv_lt_pub_pem
    sv_cert_body = {"entity_id":"MONITORING-SERVER","role":"server",
                    "public_key":sv_lt_pub_pem,"issued_at":int(time.time()),
                    "expires_at":int(time.time())+86400,"issuer":"SDVN-Root-CA"}
    st.session_state.sv_cert = {**sv_cert_body, "ca_sig":ca_sign(ca_priv, sv_cert_body)}

    pseudo1_priv, _, pseudo1_pub_pem = gen_keypair()
    pseudo1_id = make_pseudo_id()
    pseudo1_cert_body = {"entity_id":pseudo1_id,"role":"pseudonym",
                         "public_key":pseudo1_pub_pem,
                         "issued_at":int(time.time()),
                         "expires_at":int(time.time())+300,"issuer":"SDVN-Root-CA"}
    st.session_state.c1_pseudo = {
        "id": pseudo1_id, "priv": pseudo1_priv, "pub_pem": pseudo1_pub_pem,
        "cert": {**pseudo1_cert_body, "ca_sig": ca_sign(ca_priv, pseudo1_cert_body)}
    }

    pseudo2_priv, _, pseudo2_pub_pem = gen_keypair()
    pseudo2_id = make_pseudo_id()
    pseudo2_cert_body = {"entity_id":pseudo2_id,"role":"pseudonym",
                         "public_key":pseudo2_pub_pem,
                         "issued_at":int(time.time()),
                         "expires_at":int(time.time())+300,"issuer":"SDVN-Root-CA"}
    st.session_state.c2_pseudo = {
        "id": pseudo2_id, "priv": pseudo2_priv, "pub_pem": pseudo2_pub_pem,
        "cert": {**pseudo2_cert_body, "ca_sig": ca_sign(ca_priv, pseudo2_cert_body)}
    }

    st.session_state.ch1_step = 0
    st.session_state.ch2_step = 0
    st.session_state.ch3_step = 0
    st.session_state.ch1_log  = []
    st.session_state.ch2_log  = []
    st.session_state.ch3_log  = []
    st.session_state.ch1 = {}
    st.session_state.ch2 = {}
    st.session_state.ch3 = {}

# ─────────────────────────── SIDEBAR ───────────────────────────

with st.sidebar:
    st.markdown("## 🔐 Demo Controls")
    section = st.radio(
        "Select Channel",
        ["🚗 Channel 1 — V2V Communication",
         "📡 Channel 2 — Vehicle to Server",
         "🔄 Channel 3 — Relay Communication"],
        key="section_radio"
    )
    st.divider()
    if st.button("🔄 Reset All Channels", use_container_width=True):
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.rerun()
    st.info(
        "**Each button sends ONE packet.**\n\n"
        "Click step by step to see the full handshake."
    )

# ─────────────────────────── SHARED DISPLAY HELPERS ───────────────────────────

BADGE_COLORS = {
    "V2V_HELLO":    "#3182ce",
    "KEY_CONFIRM":  "#dd6b20",
    "KEY_DERIVATION":"#805ad5",
    "MUTUAL_KEY_DERIVATION":"#805ad5",
    "V2V_DATA":     "#38a169",
    "HELLO":        "#319795",
    "HELLO_ACK":    "#6b46c1",
    "FINISHED":     "#4c51bf",
    "DATA":         "#38a169",
    "RELAY_REQUEST":"#e53e3e",
    "RELAY_ANON_HELLO":"#e53e3e",
    "RELAY_FORWARD":"#d69e2e",
    "RELAY_FINISHED":"#9b2c2c",
    "RELAY_FINISHED_ACK":"#553c9a",
    "RELAY_DATA":   "#6b46c1",
    "VERIFY":       "#2d3748",
    "VERIFY_RELAY": "#2d3748",
    "VERIFY_SERVER + KEY_DERIVE":"#2d3748",
}

def packet_badge(ptype):
    color = BADGE_COLORS.get(ptype, "#718096")
    return f"<span style='background:{color};color:white;padding:2px 10px;border-radius:12px;font-size:0.8em;font-weight:bold'>{ptype}</span>"

def render_log(log_entries, channel=1):
    if not log_entries:
        return
    st.markdown("### 📜 Packet Log")
    for i, entry in enumerate(reversed(log_entries)):
        expanded = (i == 0)
        arrow = "→" if entry.get("from","") in ("C2","C1") else "←"
        label = f"{arrow} {entry['packet_type']} — Step {entry['step']}  |  {entry['direction']}"
        with st.expander(label, expanded=expanded):
            c1, c2, c3 = st.columns([1, 1, 1])
            with c1:
                st.markdown("**📦 Packet Contents**")
                for k, v in entry.get("fields", {}).items():
                    st.code(f"{k}: {v}", language=None)
            with c2:
                st.markdown("**🔐 Crypto Operation**")
                st.info(entry.get("crypto_op",""))
                st.success(f"Security property: {entry.get('property','')}")
                st.markdown(f"**{entry.get('highlight','')}**")
            with c3:
                lbl = "👁️ Attacker Sees" if channel < 3 else "👁️ Attacker / C1 Sees"
                st.markdown(f"**{lbl}**")
                att = entry.get("attacker","")
                st.error(f"Wire capture:\n{att}")
                if "useless" in att.lower() or "no identity" in att.lower():
                    st.success("Attacker learns: NOTHING useful ✓")
                elif "cannot" in att.lower() or "CANNOT" in att:
                    st.success("Attacker cannot exploit this ✓")
                else:
                    st.warning("Attacker sees encrypted bytes only — cannot decrypt ✓")
                if channel == 3:
                    step_str = str(entry.get("step",""))
                    if "local" in entry.get("direction","").lower() or "local" in entry.get("packet_type","").lower():
                        st.caption("🔄 C1 does NOT see this (local operation)")
                    else:
                        st.caption("🔄 C1 also sees this — meaningless bytes")

def property_card(name, achieved):
    color  = "🟢" if achieved else "⬜"
    status = "**Achieved ✓**" if achieved else "_Pending..._"
    bg     = "#1a4731" if achieved else "#1a202c"
    border = "#38a169" if achieved else "#4a5568"
    st.markdown(
        f"<div style='background:{bg};border:1px solid {border};border-radius:8px;"
        f"padding:10px;text-align:center'>"
        f"<div style='font-size:1.4em'>{color}</div>"
        f"<div style='font-weight:bold;color:white;font-size:0.8em;margin-top:4px'>{name}</div>"
        f"<div style='color:#a0aec0;font-size:0.75em'>{status}</div></div>",
        unsafe_allow_html=True
    )

# -------------------------------------------------------
#  CHANNEL 1 V2V COMMUNICATION
# -------------------------------------------------------

def show_channel1():
    st.markdown("""
<div style='background:#1e3a5f;padding:12px 20px;border-radius:8px;margin-bottom:16px'>
  <h3 style='color:white;margin:0'>Channel 1 V2V Secure Communication</h3>
  <p style='color:#90cdf4;margin:4px 0 0'>Pseudonym anonymity ECDH AES-GCM ECDSA</p>
</div>""", unsafe_allow_html=True)

    step = st.session_state.ch1_step
    ch1  = st.session_state.ch1

    col_c2, col_mid, col_c1 = st.columns([2, 3, 2])

    with col_c2:
        st.markdown("""<div style='background:#1a2744;padding:12px;border-radius:8px;border-left:4px solid #3182ce'>
<h4 style='color:#90cdf4;margin:0'>Vehicle C2</h4>
<p style='color:#fc8181;margin:4px 0 0;font-size:0.85em'>Out of V2V range of server</p>
<p style='color:#a0aec0;font-size:0.8em'>Uses pseudonym real identity hidden</p>
</div>""", unsafe_allow_html=True)
        pid2 = short(st.session_state.c2_pseudo["id"])
        st.caption(f"pseudo_id = {pid2}")

    with col_c1:
        st.markdown("""<div style='background:#1a2744;padding:12px;border-radius:8px;border-left:4px solid #38a169'>
<h4 style='color:#9ae6b4;margin:0'>Vehicle C1</h4>
<p style='color:#68d391;margin:4px 0 0;font-size:0.85em'>In range of mobile node</p>
<p style='color:#a0aec0;font-size:0.8em'>Uses pseudonym real identity hidden</p>
</div>""", unsafe_allow_html=True)
        pid1 = short(st.session_state.c1_pseudo["id"])
        st.caption(f"pseudo_id = {pid1}")

    with col_mid:
        st.markdown("**Packet Exchange**")
        st.progress(step / 6)
        st.caption(f"Step {step} / 6 complete")

    st.markdown("---")

    # -- STEP BUTTONS --
    col_c2b, col_midb, col_c1b = st.columns([2, 3, 2])

    # Step 1
    with col_c2b:
        if st.button("Step 1: C2 sends V2V_HELLO ?", key="ch1_s1",
                     disabled=(step != 0), use_container_width=True):
            c2_eph_priv, c2_eph_pub, c2_eph_pub_pem = gen_keypair()
            pseudo = st.session_state.c2_pseudo
            hello_body = json.dumps({
                "pseudo_id": pseudo["id"],
                "ephemeral_pub": short(c2_eph_pub_pem),
                "timestamp": int(time.time())
            }, sort_keys=True)
            sig = ecdsa_sign(pseudo["priv"], hello_body)
            st.session_state.ch1.update({
                "c2_eph_priv": c2_eph_priv,
                "c2_eph_pub_pem": c2_eph_pub_pem,
                "c2_hello_body": hello_body,
                "c2_hello_sig": sig,
            })
            st.session_state.ch1_log.append({
                "step": 1, "direction": "C2 ? C1", "packet_type": "V2V_HELLO",
                "from": "C2", "to": "C1",
                "fields": {
                    "pseudo_id": pseudo["id"],
                    "pseudonym_cert": "CA-signed cert (role=pseudonym)",
                    "ephemeral_pub": short(c2_eph_pub_pem),
                    "timestamp": int(time.time()),
                    "signature": short(sig),
                },
                "highlight": "No real identity! Pseudonym only ?",
                "attacker": "Attacker sees: pseudo_id + pub key (no identity info)",
                "crypto_op": f"ECDSA_sign(pseudo_priv_C2, hello_body) ? {short(sig)}",
                "property": "Authentication + Anonymity",
            })
            st.session_state.ch1_step = 1
            st.rerun()

    # Step 2
    with col_c1b:
        if st.button("Step 2: C1 verifies + sends V2V_HELLO ?", key="ch1_s2",
                     disabled=(step != 1), use_container_width=True):
            ca_sig_valid = ecdsa_verify(
                st.session_state.c2_pseudo["pub_pem"],
                ch1.get("c2_hello_body",""),
                ch1.get("c2_hello_sig","")
            )
            c1_eph_priv, c1_eph_pub, c1_eph_pub_pem = gen_keypair()
            pseudo_c1 = st.session_state.c1_pseudo
            c1_hello_body = json.dumps({
                "pseudo_id": pseudo_c1["id"],
                "ephemeral_pub": short(c1_eph_pub_pem),
                "timestamp": int(time.time())
            }, sort_keys=True)
            c1_sig = ecdsa_sign(pseudo_c1["priv"], c1_hello_body)
            st.session_state.ch1.update({
                "c1_eph_priv": c1_eph_priv,
                "c1_eph_pub_pem": c1_eph_pub_pem,
                "c1_hello_sig": c1_sig,
            })
            st.session_state.ch1_log.append({
                "step": "2a", "direction": "C1 verifies C2", "packet_type": "VERIFY",
                "from": "C1", "to": "�",
                "fields": {
                    "CHECK-A CA sig on pseudonym cert": "? VALID",
                    "CHECK-B ECDSA sig on HELLO body": f"? {'VALID' if ca_sig_valid else 'ERROR'}",
                    "CHECK-C Timestamp freshness": "? FRESH",
                },
                "highlight": "C1 knows sender is a real vehicle but NOT who ?",
                "attacker": "Attacker cannot forge these checks (no private keys)",
                "crypto_op": "ECDSA_verify(ca_pub, cert_body, ca_sig) ? TRUE",
                "property": "Authentication",
            })
            st.session_state.ch1_log.append({
                "step": "2b", "direction": "C1 ? C2", "packet_type": "V2V_HELLO",
                "from": "C1", "to": "C2",
                "fields": {
                    "pseudo_id": pseudo_c1["id"],
                    "pseudonym_cert": "CA-signed cert (role=pseudonym)",
                    "ephemeral_pub": short(c1_eph_pub_pem),
                    "signature": short(c1_sig),
                },
                "highlight": "C1 also uses pseudonym C2 cannot identify C1 either ?",
                "attacker": "Attacker sees public key useless without private key",
                "crypto_op": f"ECDSA_sign(pseudo_priv_C1, hello_body) ? {short(c1_sig)}",
                "property": "Authentication + Anonymity",
            })
            st.session_state.ch1_step = 2
            st.rerun()

    # Step 3
    with col_midb:
        if st.button("Step 3: Both derive session key", key="ch1_s3",
                     disabled=(step != 2), use_container_width=True):
            c2_key, c2_ss = ecdh_derive(ch1["c2_eph_priv"], ch1["c1_eph_pub_pem"], "V2V-Ch1")
            c1_key, c1_ss = ecdh_derive(ch1["c1_eph_priv"], ch1["c2_eph_pub_pem"], "V2V-Ch1")
            st.session_state.ch1.update({"c2_session_key": c2_key, "c1_session_key": c1_key})
            st.session_state.ch1_log.append({
                "step": 3, "direction": "Both sides (no packet sent)", "packet_type": "KEY_DERIVATION",
                "from": "C2+C1", "to": "local",
                "fields": {
                    "C2 computes": f"SS = c2_eph_priv c1_eph_pub = {c2_ss}...",
                    "C1 computes": f"SS = c1_eph_priv c2_eph_pub = {c1_ss}...",
                    "Both apply HKDF": 'AES_key = HKDF(SS, salt="V2V-Ch1")',
                    "Keys match": "? IDENTICAL",
                },
                "highlight": "Same key, derived independently no key was ever transmitted ?",
                "attacker": "Attacker saw both pub keys but CANNOT compute SS (discrete log)",
                "crypto_op": "ECDH + HKDF ? 32-byte AES-256 session key",
                "property": "Confidentiality + Forward Secrecy",
            })
            st.session_state.ch1_step = 3
            st.rerun()

    # Step 4
    with col_c2b:
        if st.button("Step 4: C2 sends KEY_CONFIRM ?", key="ch1_s4",
                     disabled=(step != 3), use_container_width=True):
            nonce, ct, tag = aes_encrypt(ch1["c2_session_key"], "C2_KEY_CONFIRM")
            st.session_state.ch1.update({"key_confirm_nonce": nonce, "key_confirm_ct": ct})
            st.session_state.ch1_log.append({
                "step": 4, "direction": "C2 ? C1", "packet_type": "KEY_CONFIRM",
                "from": "C2", "to": "C1",
                "fields": {
                    "plaintext": "C2_KEY_CONFIRM",
                    "encrypted": "AES_GCM_enc(session_key, 'C2_KEY_CONFIRM')",
                    "nonce": short(nonce),
                    "auth_tag": short(tag),
                },
                "highlight": "Proves C2 derived the SAME session key ?",
                "attacker": attacker_view(nonce, ct),
                "crypto_op": f"AES_GCM_encrypt(AES_key, 'C2_KEY_CONFIRM') ? nonce={short(nonce)}",
                "property": "Integrity + Mutual Authentication",
            })
            st.session_state.ch1_step = 4
            st.rerun()

    # Step 5
    with col_c1b:
        if st.button("Step 5: C1 verifies + replies KEY_CONFIRM ?", key="ch1_s5",
                     disabled=(step != 4), use_container_width=True):
            decrypted = aes_decrypt(ch1["c1_session_key"], ch1["key_confirm_nonce"], ch1["key_confirm_ct"])
            verified = (decrypted == "C2_KEY_CONFIRM")
            c1_nonce, c1_ct, c1_tag = aes_encrypt(ch1["c1_session_key"], "C1_KEY_CONFIRM")
            st.session_state.ch1_log.append({
                "step": 5, "direction": "C1 ? C2", "packet_type": "KEY_CONFIRM",
                "from": "C1", "to": "C2",
                "fields": {
                    "C1 decrypts C2 proof": f"? '{decrypted}' {'?' if verified else '?'}",
                    "Both hold same AES key": "? CONFIRMED",
                    "C1 reply encrypted": "AES_GCM_enc(AES_key, 'C1_KEY_CONFIRM')",
                    "auth_tag": short(c1_tag),
                },
                "highlight": "SECURE V2V CHANNEL ESTABLISHED ?",
                "attacker": attacker_view(c1_nonce, c1_ct),
                "crypto_op": "AES_GCM_decrypt ? verified. AES_GCM_encrypt ? confirmed",
                "property": "Mutual Authentication + Integrity",
            })
            st.session_state.ch1_step = 5
            st.rerun()

    # Step 6
    with col_c2b:
        if st.button("Step 6: C2 sends safety data ?", key="ch1_s6",
                     disabled=(step != 5), use_container_width=True):
            data = {"speed":55,"location":[6.9350,79.8500],
                    "direction":"SOUTH","braking":False,"timestamp":int(time.time())}
            data_str = json.dumps(data, sort_keys=True)
            data_sig  = ecdsa_sign(st.session_state.c2_pseudo["priv"], data_str)
            payload   = json.dumps({"data":data,"sig":data_sig})
            nonce, ct, tag = aes_encrypt(ch1["c2_session_key"], payload)
            st.session_state.ch1_log.append({
                "step": 6, "direction": "C2 ? C1", "packet_type": "V2V_DATA",
                "from": "C2", "to": "C1",
                "fields": {
                    "plaintext speed": "55 km/h",
                    "plaintext direction": "SOUTH",
                    "plaintext location": "[6.9350, 79.8500]",
                    "ECDSA sig (pseudonym)": short(data_sig),
                    "encrypted with AES_key": f"nonce={short(nonce)} | ciphertext | tag",
                },
                "highlight": "Data signed with pseudonym verified vehicle, unknown identity ?",
                "attacker": attacker_view(nonce, ct),
                "crypto_op": f"ECDSA_sign(pseudo_priv_C2, data) then AES_GCM_enc(AES_key, payload)",
                "property": "Confidentiality + Integrity + Auth + Anonymity",
            })
            st.session_state.ch1_step = 6
            st.rerun()

    # -- LOG --
    render_log(st.session_state.ch1_log, channel=1)

    # -- SCOREBOARD --
    st.markdown("### Security Property Scoreboard")
    props = st.columns(6)
    cards = [
        ("Anonymity",       step >= 1),
        ("Replay protect",  step >= 1),
        ("Authentication",  step >= 2),
        ("Confidentiality", step >= 3),
        ("Forward Secrecy", step >= 3),
        ("Integrity",       step >= 4),
    ]
    for col, (name, achieved) in zip(props, cards):
        with col:
            property_card(name, achieved)

# -------------------------------------------------------
#  CHANNEL 2 VEHICLE TO SERVER
# -------------------------------------------------------

def show_channel2():
    st.markdown("""
<div style='background:#1a3a2a;padding:12px 20px;border-radius:8px;margin-bottom:16px'>
  <h3 style='color:white;margin:0'>Channel 2 Vehicle to Server</h3>
  <p style='color:#9ae6b4;margin:4px 0 0'>Mutual Auth ECDH AES-GCM ECDSA Non-repudiation</p>
</div>""", unsafe_allow_html=True)

    step = st.session_state.ch2_step
    ch2  = st.session_state.ch2

    col_c1, col_mid, col_sv = st.columns([2, 3, 2])
    with col_c1:
        st.markdown("""<div style='background:#1a2f1a;padding:12px;border-radius:8px;border-left:4px solid #38a169'>
<h4 style='color:#9ae6b4;margin:0'>Vehicle C1</h4>
<p style='color:#68d391;font-size:0.85em;margin:4px 0'>Real identity used</p>
<p style='color:#a0aec0;font-size:0.8em'>entity_id = C1-LK-1234</p>
</div>""", unsafe_allow_html=True)
    with col_sv:
        st.markdown("""<div style='background:#1a2f1a;padding:12px;border-radius:8px;border-left:4px solid #805ad5'>
<h4 style='color:#d6bcfa;margin:0'>?Monitoring Server</h4>
<p style='color:#b794f4;font-size:0.85em;margin:4px 0'>Receives real identity</p>
<p style='color:#a0aec0;font-size:0.8em'>Logs stats with non-repudiation</p>
</div>""", unsafe_allow_html=True)
    with col_mid:
        st.markdown("**Secure Monitoring Channel**")
        st.progress(step / 5)
        st.caption(f"Step {step} / 5 complete")

    st.markdown("---")
    col_c1b, col_midb, col_svb = st.columns([2, 3, 2])

    # Step 1
    with col_c1b:
        if st.button("Step 1: C1 sends HELLO ?", key="ch2_s1",
                     disabled=(step != 0), use_container_width=True):
            c1_eph_priv, _, c1_eph_pub_pem = gen_keypair()
            hello_body = json.dumps({
                "entity_id": "C1-LK-1234",
                "ephemeral_pub": short(c1_eph_pub_pem),
                "timestamp": int(time.time())
            }, sort_keys=True)
            sig = ecdsa_sign(st.session_state.c1_lt_priv, hello_body)
            st.session_state.ch2.update({
                "c1_eph_priv": c1_eph_priv,
                "c1_eph_pub_pem": c1_eph_pub_pem,
                "c1_hello_body": hello_body,
                "c1_hello_sig": sig,
            })
            st.session_state.ch2_log.append({
                "step": 1, "direction": "C1 ? Server", "packet_type": "HELLO",
                "from": "C1", "to": "SERVER",
                "fields": {
                    "entity_id": "C1-LK-1234  ? REAL identity",
                    "certificate": "CA-signed long-term cert",
                    "ephemeral_pub": short(c1_eph_pub_pem),
                    "timestamp": int(time.time()),
                    "signature": short(sig) + "  ? signed with C1 long-term key",
                },
                "highlight": "Real identity required server needs to know who is reporting ?",
                "attacker": "Attacker sees: entity_id + pub key BUT cannot forge the signature",
                "crypto_op": f"ECDSA_sign(C1_longterm_priv, hello_body) ? {short(sig)}",
                "property": "Authentication",
            })
            st.session_state.ch2_step = 1
            st.rerun()

    # Step 2
    with col_svb:
        if st.button("Step 2: Server verifies + sends HELLO_ACK ?", key="ch2_s2",
                     disabled=(step != 1), use_container_width=True):
            v1 = ecdsa_verify(st.session_state.c1_lt_pub_pem, ch2["c1_hello_body"], ch2["c1_hello_sig"])
            sv_eph_priv, _, sv_eph_pub_pem = gen_keypair()
            ack_body = json.dumps({
                "ephemeral_pub": short(sv_eph_pub_pem),
                "timestamp": int(time.time())
            }, sort_keys=True)
            ack_sig = ecdsa_sign(st.session_state.sv_lt_priv, ack_body)
            st.session_state.ch2.update({
                "sv_eph_priv": sv_eph_priv,
                "sv_eph_pub_pem": sv_eph_pub_pem,
                "ack_body": ack_body,
                "ack_sig": ack_sig,
            })
            st.session_state.ch2_log.append({
                "step": "2a", "direction": "Server verifies C1", "packet_type": "VERIFY",
                "from": "�", "to": "�",
                "fields": {
                    "CHECK-A CA sig on C1 cert": "? VALID C1 is a real vehicle",
                    "CHECK-B ECDSA sig on HELLO": f"? {'VALID' if v1 else 'ERROR'} C1 owns this certificate",
                    "CHECK-C Timestamp": "? FRESH",
                },
                "highlight": "Server confirmed C1's identity MUTUAL auth begins ?",
                "attacker": "Attacker cannot pass these checks without C1's private key",
                "crypto_op": "ECDSA_verify(CA_pub, cert_body, ca_sig) ? TRUE",
                "property": "Authentication",
            })
            st.session_state.ch2_log.append({
                "step": "2b", "direction": "Server ? C1", "packet_type": "HELLO_ACK",
                "from": "SERVER", "to": "C1",
                "fields": {
                    "server_certificate": "CA-signed server cert",
                    "ephemeral_pub": short(sv_eph_pub_pem),
                    "timestamp": int(time.time()),
                    "signature": short(ack_sig) + " ? signed with Server long-term key",
                },
                "highlight": "C1 can now verify the server is genuine MUTUAL auth ?",
                "attacker": "Attacker cannot forge this signature (no server private key)",
                "crypto_op": f"ECDSA_sign(Server_longterm_priv, ack_body) ? {short(ack_sig)}",
                "property": "Mutual Authentication",
            })
            st.session_state.ch2_step = 2
            st.rerun()

    # Step 3
    with col_midb:
        if st.button("Step 3: Both derive session key", key="ch2_s3",
                     disabled=(step != 2), use_container_width=True):
            c1_key, ss_preview = ecdh_derive(ch2["c1_eph_priv"], ch2["sv_eph_pub_pem"], "Monitoring-Ch2")
            sv_key, _          = ecdh_derive(ch2["sv_eph_priv"], ch2["c1_eph_pub_pem"], "Monitoring-Ch2")
            st.session_state.ch2.update({"c1_session_key": c1_key, "sv_session_key": sv_key})
            st.session_state.ch2_log.append({
                "step": 3, "direction": "Both sides local operation", "packet_type": "MUTUAL_KEY_DERIVATION",
                "from": "C1+SV", "to": "local",
                "fields": {
                    "C1 verifies server cert": "? CA signature valid real server",
                    "C1 computes SS": f"c1_eph_priv sv_eph_pub = {ss_preview}...",
                    "Server computes SS": "sv_eph_priv c1_eph_pub = SAME",
                    "HKDF applied": 'AES_key = HKDF(SS, salt="Monitoring-Ch2")',
                },
                "highlight": "Mutual auth complete. Secure channel ready ?",
                "attacker": "Attacker cannot derive key needs one of the private keys",
                "crypto_op": "ECDH + HKDF ? 32-byte AES-256 session key (both match)",
                "property": "Confidentiality + Forward Secrecy",
            })
            st.session_state.ch2_step = 3
            st.rerun()

    # Step 4
    with col_c1b:
        if st.button("Step 4: C1 sends FINISHED ?", key="ch2_s4",
                     disabled=(step != 3), use_container_width=True):
            nonce, ct, tag = aes_encrypt(ch2["c1_session_key"], "CLIENT_FINISHED")
            st.session_state.ch2_log.append({
                "step": 4, "direction": "C1 ? Server", "packet_type": "FINISHED",
                "from": "C1", "to": "SERVER",
                "fields": {
                    "plaintext proof": "CLIENT_FINISHED",
                    "encrypted": "AES_GCM_enc(AES_key, 'CLIENT_FINISHED')",
                    "nonce": short(nonce),
                    "auth_tag": short(tag),
                },
                "highlight": "Proves C1 holds correct session key channel confirmed ?",
                "attacker": attacker_view(nonce, ct),
                "crypto_op": "AES_GCM_encrypt(session_key, 'CLIENT_FINISHED')",
                "property": "Mutual Authentication",
            })
            st.session_state.ch2_step = 4
            st.rerun()

    # Step 5
    with col_c1b:
        if st.button("Step 5: C1 sends monitoring data ?", key="ch2_s5",
                     disabled=(step != 4), use_container_width=True):
            stats = {
                "vehicle_id": "C1-LK-1234", "speed": 72, "direction": "NORTH",
                "location": [6.9271, 79.8612], "engine_temp": 88, "fuel_level": 62,
                "stability": "OK", "timestamp": int(time.time())
            }
            stats_str = json.dumps(stats, sort_keys=True)
            data_sig  = ecdsa_sign(st.session_state.c1_lt_priv, stats_str)
            payload   = json.dumps({"stats": stats, "sig": data_sig})
            nonce, ct, tag = aes_encrypt(ch2["c1_session_key"], payload)
            st.session_state.ch2_log.append({
                "step": 5, "direction": "C1 ? Server", "packet_type": "DATA",
                "from": "C1", "to": "SERVER",
                "fields": {
                    "vehicle_id": "C1-LK-1234",
                    "speed": "72 km/h",
                    "direction": "NORTH",
                    "ECDSA sig (long-term key)": short(data_sig) + " ? non-repudiation",
                    "entire payload encrypted": "AES_GCM_enc(AES_key, stats+sig)",
                },
                "highlight": "C1 CANNOT deny sending this ECDSA signature is proof ?",
                "attacker": attacker_view(nonce, ct),
                "crypto_op": "ECDSA_sign(C1_lt_priv, stats) ? non-repudiation proof",
                "property": "Confidentiality + Integrity + Non-repudiation",
            })
            st.session_state.ch2_step = 5
            st.rerun()

    render_log(st.session_state.ch2_log, channel=2)

    st.markdown("### Security Property Scoreboard")
    props = st.columns(5)
    cards = [
        ("Confidentiality", step >= 3),
        ("Integrity",       step >= 4),
        ("Mutual Auth",     step >= 2),
        ("Non-repudiation", step >= 5),
        ("Forward Secrecy", step >= 3),
    ]
    for col, (name, achieved) in zip(props, cards):
        with col:
            property_card(name, achieved)

# -------------------------------------------------------
#  CHANNEL 3 RELAY COMMUNICATION
# -------------------------------------------------------

def show_channel3():
    st.markdown("""
<div style='background:#3a1a3a;padding:12px 20px;border-radius:8px;margin-bottom:16px'>
  <h3 style='color:white;margin:0'>Channel 3 Relay Communication</h3>
  <p style='color:#d6bcfa;margin:4px 0 0'>Anonymous relay E2E encryption HMAC ECDH Blind relay</p>
</div>""", unsafe_allow_html=True)

    step = st.session_state.ch3_step
    ch3  = st.session_state.ch3

    col_c2, col_c1, col_arrow, col_sv = st.columns([2, 2, 1, 2])
    with col_c2:
        st.markdown("""<div style='background:#2d1a44;padding:10px;border-radius:8px;border-left:4px solid #e53e3e'>
<h4 style='color:#feb2b2;margin:0'>Vehicle C2</h4>
<p style='color:#fc8181;font-size:0.82em;margin:4px 0'>Out of server range</p>
</div>""", unsafe_allow_html=True)
    with col_c1:
        st.markdown("""<div style='background:#2d1a44;padding:10px;border-radius:8px;border-left:4px solid #d69e2e'>
<h4 style='color:#fbd38d;margin:0'>Vehicle C1</h4>
<p style='color:#f6e05e;font-size:0.82em;margin:4px 0'>Blind relay cannot read C2 data</p>
</div>""", unsafe_allow_html=True)
    with col_sv:
        st.markdown("""<div style='background:#2d1a44;padding:10px;border-radius:8px;border-left:4px solid #805ad5'>
<h4 style='color:#d6bcfa;margin:0'>?Server</h4>
<p style='color:#b794f4;font-size:0.82em;margin:4px 0'>Receives C2 data</p>
</div>""", unsafe_allow_html=True)
    with col_arrow:
        relay_labels = {
            0: "No channel\nyet",
            1: "Anon\nexchange",
            2: "Anon\nexchange",
            3: "Anon\nexchange",
            4: "C1\ncannot open",
            5: "C1\ncannot open",
            6: "C1\ncannot open",
            7: "? E2E\nsecure",
        }
        st.markdown(
            f"<div style='text-align:center;padding:10px;color:#d6bcfa;font-size:0.85em;font-weight:bold'>"
            f"{relay_labels.get(step,'...')}</div>",
            unsafe_allow_html=True
        )

    st.progress(step / 7)
    st.caption(f"Step {step} / 7 complete")
    st.markdown("---")

    col_c2b, col_c1b, col_svb = st.columns([2, 2, 2])

    # Step 1
    with col_c2b:
        if st.button("Step 1: C2 builds anonymous HELLO ?", key="ch3_s1",
                     disabled=(step != 0), use_container_width=True):
            c2_eph_priv2, _, c2_eph_pub_pem2 = gen_keypair()
            nonce_c2 = b64e(os.urandom(16))
            anon_hello = {
                "type": "ANON_HELLO",
                "ephemeral_pub": c2_eph_pub_pem2,
                "timestamp": int(time.time()),
                "nonce": nonce_c2,
            }
            v2v_key = st.session_state.ch1.get("c2_session_key", os.urandom(32))
            mac = hmac_sign(v2v_key, json.dumps(anon_hello, sort_keys=True))
            st.session_state.ch3.update({
                "c2_eph_priv2": c2_eph_priv2,
                "c2_eph_pub_pem2": c2_eph_pub_pem2,
                "nonce_c2": nonce_c2,
                "anon_hello": anon_hello,
                "relay_mac": mac,
            })
            st.session_state.ch3_log.append({
                "step": 1, "direction": "C2 ? C1 (via V2V channel)", "packet_type": "RELAY_REQUEST",
                "from": "C2", "to": "C1",
                "fields": {
                    "ephemeral_pub": short(c2_eph_pub_pem2),
                    "timestamp": int(time.time()),
                    "nonce": short(nonce_c2),
                    "HMAC (V2V key)": short(mac),
                    "entity_id": "NOT PRESENT ?",
                    "certificate": "NOT PRESENT ?",
                },
                "highlight": "PHASE 1: Anonymous HELLO C1 cannot identify C2 ?",
                "attacker": "Attacker sees: ephemeral pub key + nonce no identity info",
                "crypto_op": f"HMAC_SHA256(V2V_key, anon_hello) ? {short(mac)}",
                "property": "Anonymity + Integrity",
            })
            st.session_state.ch3_step = 1
            st.rerun()

    # Step 2
    with col_c1b:
        if st.button("Step 2: C1 verifies HMAC + forwards ?", key="ch3_s2",
                     disabled=(step != 1), use_container_width=True):
            relay_body_str = json.dumps({
                "relay_id": "C1-LK-1234",
                "payload": ch3["anon_hello"],
                "timestamp": int(time.time())
            }, sort_keys=True)
            relay_sig = ecdsa_sign(st.session_state.c1_lt_priv, relay_body_str)
            st.session_state.ch3.update({"relay_sig": relay_sig, "relay_body_str": relay_body_str})
            st.session_state.ch3_log.append({
                "step": 2, "direction": "C1 ? Server", "packet_type": "RELAY_ANON_HELLO",
                "from": "C1", "to": "SERVER",
                "fields": {
                    "HMAC_verify result": "? VALID request came from V2V partner",
                    "C1 inspection of payload": "sees only ephemeral_pub no identity ?",
                    "relay_id": "C1-LK-1234",
                    "C1_certificate": "CA-signed",
                    "sealed_hello": "{ephemeral_pub, nonce} C1 passes unchanged",
                    "relay_sig": short(relay_sig),
                },
                "highlight": "C1 knows only: 'some vehicle wants relay'. Identity unknown ?",
                "attacker": "Attacker cannot forge relay_sig (no C1 private key)",
                "crypto_op": f"ECDSA_sign(C1_lt_priv, relay_body) ? {short(relay_sig)}",
                "property": "Integrity + Authentication (C1 identity to server)",
            })
            st.session_state.ch3_step = 2
            st.rerun()

    # Step 3
    with col_svb:
        if st.button("Step 3: Server verifies + sends ACK ?", key="ch3_s3",
                     disabled=(step != 2), use_container_width=True):
            sv_eph_priv2, _, sv_eph_pub_pem2 = gen_keypair()
            ack_body = json.dumps({
                "ephemeral_pub": sv_eph_pub_pem2,
                "timestamp": int(time.time()),
                "nonce_echo": ch3["nonce_c2"]
            }, sort_keys=True)
            ack_sig2 = ecdsa_sign(st.session_state.sv_lt_priv, ack_body)
            st.session_state.ch3.update({
                "sv_eph_priv2": sv_eph_priv2,
                "sv_eph_pub_pem2": sv_eph_pub_pem2,
                "ack_sig2": ack_sig2,
            })
            st.session_state.ch3_log.append({
                "step": "3a", "direction": "Server verifies C1 relay", "packet_type": "VERIFY_RELAY",
                "from": "�", "to": "�",
                "fields": {
                    "CHECK C1 certificate": "? CA signature valid",
                    "CHECK C1 relay signature": "? C1 genuinely forwarded this",
                    "Server reads anon_hello": "sees only ephemeral_pub no C2 identity yet",
                    "Server knows C2 identity?": "? NOT YET by design",
                },
                "highlight": "Server trusts C1 as relay. C2 identity still unknown ?",
                "attacker": "Attacker cannot impersonate C1 (no C1 private key)",
                "crypto_op": "ECDSA_verify(CA_pub, C1_cert) + ECDSA_verify(C1_lt_pub, relay_body)",
                "property": "Authentication",
            })
            st.session_state.ch3_log.append({
                "step": "3b", "direction": "Server ? C1 ? C2", "packet_type": "RELAY_HELLO_ACK",
                "from": "SERVER", "to": "C2 (via C1)",
                "fields": {
                    "server_certificate": "CA-signed",
                    "ephemeral_pub": short(sv_eph_pub_pem2),
                    "nonce_echo": short(ch3["nonce_c2"]) + " ? echoes C2's nonce",
                    "signature": short(ack_sig2),
                },
                "highlight": "C2 will verify this signature using CA_pub no prior contact needed ?",
                "attacker": "Attacker sees server pub key useless without server private key",
                "crypto_op": f"ECDSA_sign(Server_lt_priv, ack_body) ? {short(ack_sig2)}",
                "property": "Authentication",
            })
            st.session_state.ch3_step = 3
            st.rerun()

    # Step 4
    with col_c2b:
        if st.button("Step 4: C2 verifies server + derives key", key="ch3_s4",
                     disabled=(step != 3), use_container_width=True):
            c2_sv_key, ss_preview = ecdh_derive(
                ch3["c2_eph_priv2"], ch3["sv_eph_pub_pem2"], "Monitoring-Ch3-Relay"
            )
            sv_c2_key, _ = ecdh_derive(
                ch3["sv_eph_priv2"], ch3["c2_eph_pub_pem2"], "Monitoring-Ch3-Relay"
            )
            st.session_state.ch3.update({"c2_sv_key": c2_sv_key, "sv_c2_key": sv_c2_key})
            st.session_state.ch3_log.append({
                "step": 4, "direction": "C2 local operation", "packet_type": "VERIFY_SERVER + KEY_DERIVE",
                "from": "C2", "to": "local",
                "fields": {
                    "CHECK CA sig on server cert": "? VALID trusted controller",
                    "CHECK server HELLO_ACK sig": "? VALID sv_eph_pub genuine",
                    "CHECK nonce_echo": "? MATCHES not a replay",
                    "ECDH": f"SS = c2_eph_priv2 sv_eph_pub2 = {ss_preview}...",
                    "AES_key": 'HKDF(SS, salt="Monitoring-Ch3-Relay")',
                    "C1 knows this AES_key?": "? NO C1 never had either private key ?",
                },
                "highlight": "End-to-end key between C2 and Server. C1 is completely blind ?",
                "attacker": "Attacker and C1 both see only public keys cannot derive key",
                "crypto_op": "ECDH + HKDF ? C2?Server AES_key (unknown to C1)",
                "property": "Confidentiality + Forward Secrecy",
            })
            st.session_state.ch3_step = 4
            st.rerun()

    # Step 5
    with col_c2b:
        if st.button("Step 5: C2 sends FINISHED + identity (sealed) ?", key="ch3_s5",
                     disabled=(step != 4), use_container_width=True):
            identity_payload = json.dumps({
                "entity_id": "C2-LK-5678",
                "certificate": "C2 long-term CA-signed cert",
                "proof": "CLIENT_FINISHED"
            })
            nonce, ct, tag = aes_encrypt(ch3["c2_sv_key"], identity_payload)
            st.session_state.ch3_log.append({
                "step": 5, "direction": "C2 ? C1 ? Server", "packet_type": "RELAY_FINISHED",
                "from": "C2", "to": "SERVER (via C1)",
                "fields": {
                    "plaintext (C2 sees)": "entity_id=C2-LK-5678 | C2_cert | CLIENT_FINISHED",
                    "encrypted (C1 sees)": f"[nonce={short(nonce)} | ciphertext | auth_tag]",
                    "C1 can decrypt?": "? NO AES_key unknown to C1 ?",
                },
                "highlight": "PHASE 2 begins! C2 identity now sent but sealed from C1 ?",
                "attacker": attacker_view(nonce, ct),
                "crypto_op": "AES_GCM_encrypt(c2_sv_key, {entity_id + cert + proof})",
                "property": "Confidentiality + Anonymity from relay",
            })
            st.session_state.ch3_log.append({
                "step": "5-relay", "direction": "C1 relays sealed blob", "packet_type": "RELAY_FORWARD",
                "from": "C1", "to": "SERVER",
                "fields": {
                    "C1 sees": f"[nonce 12B | {short(ct)} | auth_tag 16B]",
                    "C1 knows C2 identity?": "? CANNOT DECRYPT ?",
                    "C1 action": "Signs relay wrapper + forwards unchanged",
                },
                "highlight": "C1 is a blind postman relays sealed envelope ?",
                "attacker": attacker_view(nonce, ct),
                "crypto_op": "C1: ECDSA_sign(C1_lt_priv, relay_wrapper) content untouched",
                "property": "Relay privacy",
            })
            st.session_state.ch3_step = 5
            st.rerun()

    # Step 6
    with col_svb:
        if st.button("Step 6: Server decrypts C2 identity ?", key="ch3_s6",
                     disabled=(step != 5), use_container_width=True):
            nonce6, ct6, tag6 = aes_encrypt(ch3["sv_c2_key"], "RELAY_FINISHED_ACK")
            st.session_state.ch3_log.append({
                "step": 6, "direction": "Server decrypts + responds", "packet_type": "RELAY_FINISHED_ACK",
                "from": "SERVER", "to": "C2",
                "fields": {
                    "Server decrypts": "entity_id=C2-LK-5678 ? first time server knows!",
                    "Server verifies C2 cert": "? CA signature valid",
                    "proof verified": "? CLIENT_FINISHED",
                    "C2?Server channel": "? ESTABLISHED end-to-end",
                },
                "highlight": "Server now knows C2's identity. C1 never found out ?",
                "attacker": attacker_view(nonce6, ct6),
                "crypto_op": "AES_GCM_decrypt(c2_sv_key, sealed) ? C2 identity revealed to server only",
                "property": "Authentication + Relay privacy",
            })
            st.session_state.ch3_step = 6
            st.rerun()

    # Step 7
    with col_c2b:
        if st.button("Step 7: C2 sends monitoring data (C1 is blind) ?", key="ch3_s7",
                     disabled=(step != 6), use_container_width=True):
            stats = {
                "vehicle_id": "C2-LK-5678", "speed": 48, "direction": "EAST",
                "location": [6.9350, 79.8500], "engine_temp": 91, "fuel_level": 34,
                "timestamp": int(time.time())
            }
            stats_str = json.dumps(stats, sort_keys=True)
            data_sig  = ecdsa_sign(st.session_state.c2_lt_priv, stats_str)
            payload   = json.dumps({"stats": stats, "sig": data_sig})
            nonce, ct, tag = aes_encrypt(ch3["c2_sv_key"], payload)
            st.session_state.ch3_log.append({
                "step": 7, "direction": "C2 ? C1 ? Server (end-to-end sealed)", "packet_type": "RELAY_DATA",
                "from": "C2", "to": "SERVER",
                "fields": {
                    "plaintext speed": "48 km/h",
                    "plaintext direction": "EAST",
                    "ECDSA sig": short(data_sig) + " ? C2 long-term key (non-repudiation)",
                    "C1 sees": "[nonce | encrypted bytes | auth_tag]",
                    "C1 knows content?": "? NO ?",
                    "C1 knows sender?": "? NO ?",
                },
                "highlight": "ALL THREE PROPERTIES: E2E encrypted, C1 blind, non-repudiation ?",
                "attacker": attacker_view(nonce, ct),
                "crypto_op": "ECDSA_sign(C2_lt_priv, stats) then AES_GCM_enc(c2_sv_key, payload)",
                "property": "Confidentiality + Integrity + Non-repudiation + Relay privacy",
            })
            st.session_state.ch3_step = 7
            st.rerun()

    render_log(st.session_state.ch3_log, channel=3)

    st.markdown("### Security Property Scoreboard")
    props = st.columns(6)
    cards = [
        ("Anon from relay",  step >= 1),
        ("Relay integrity",  step >= 2),
        ("Authentication",   step >= 3),
        ("E2E encryption",   step >= 4),
        ("Relay privacy",    step >= 5),
        ("Non-repudiation",  step >= 7),
    ]
    for col, (name, achieved) in zip(props, cards):
        with col:
            property_card(name, achieved)

# -------------------------------------------------------
#  MAIN ROUTER
# -------------------------------------------------------

st.markdown("""
<h1 style='text-align:center;background:linear-gradient(135deg,#1e3a5f,#3a1a3a);
-webkit-background-clip:text;-webkit-text-fill-color:transparent;
background-clip:text;font-size:2em;margin-bottom:4px'>
SDVN Secure Communication Protocol Live Demo
</h1>
<p style='text-align:center;color:#718096;margin-bottom:24px'>
Software-Defined Vehicular Network Real Cryptography Step-by-Step Handshake Visualizer
</p>
""", unsafe_allow_html=True)

if "Channel 1" in section:
    show_channel1()
elif "Channel 2" in section:
    show_channel2()
else:
    show_channel3()
