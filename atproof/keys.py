"""Signing keys and identity history (atproto.com/specs/cryptography, did:plc audit log).

Multikey = 'z' + base58btc(multicodec prefix + 33-byte compressed point); prefixes 0xE7 0x01
(secp256k1) and 0x80 0x24 (P-256). Signatures are 64-byte compact r||s, low-S, ECDSA over SHA-256.
"""
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
CURVES = {
    b"\xe7\x01": ("secp256k1", ec.SECP256K1(),
                  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141),
    b"\x80\x24": ("p256", ec.SECP256R1(),
                  0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551),
}
_TID = "234567abcdefghijklmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + raw


def b58encode(b: bytes) -> str:
    n, out = int.from_bytes(b, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(b) - len(b.lstrip(b"\x00"))) + out


def parse_multikey(mk: str):
    """'did:key:z...' or 'z...' -> (curve_name, public_key, order)."""
    mk = mk.removeprefix("did:key:")
    if not mk.startswith("z"):
        raise ValueError("expected a base58btc multikey starting with 'z'")
    raw = b58decode(mk[1:])
    for prefix, (name, curve, order) in CURVES.items():
        if raw.startswith(prefix):
            return name, ec.EllipticCurvePublicKey.from_encoded_point(curve, raw[len(prefix):]), order
    raise ValueError(f"unsupported key type prefix {raw[:2].hex()}")


def verify(multikey: str, message: bytes, sig: bytes) -> tuple[bool, str]:
    """Check an atproto signature. Returns (ok, reason)."""
    name, pub, order = parse_multikey(multikey)
    if len(sig) != 64:
        return False, f"signature is {len(sig)} bytes, expected 64 (compact r||s)"
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if s > order // 2:
        return False, "high-S signature (atproto requires low-S)"
    try:
        pub.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        return True, f"valid {name} signature"
    except InvalidSignature:
        return False, f"{name} signature does not verify"


def tid_time(tid: str) -> str:
    """TID (rev, record key) -> claimed creation time, ISO-8601 UTC. Top 53 bits after bit 63: microseconds."""
    n = 0
    for ch in tid:
        n = n * 32 + _TID.index(ch)
    us = (n >> 10) & ((1 << 53) - 1)
    return datetime.fromtimestamp(us / 1e6, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def key_history(doc) -> list[dict]:
    """Signing keys over time from a did:plc audit log (list) or a DID document (dict, current key only)."""
    if isinstance(doc, dict):
        for vm in doc.get("verificationMethod", []):
            if vm.get("id", "").endswith("#atproto") and vm.get("publicKeyMultibase"):
                return [{"from": None, "key": vm["publicKeyMultibase"], "source": "DID document (current only)"}]
        raise ValueError("DID document has no #atproto verification method")
    hist = []
    for entry in doc:
        if entry.get("nullified"):
            continue
        op = entry.get("operation", {})
        key = (op.get("verificationMethods") or {}).get("atproto") or op.get("signingKey")
        if op.get("type") == "plc_tombstone":
            key = None
        hist.append({"from": entry.get("createdAt"), "key": key, "source": f"plc op {entry.get('cid')}"})
    return hist


def key_at(hist: list[dict], when_iso: str):
    """The history entry in force at `when_iso` (last one starting at or before it)."""
    best = None
    for h in hist:
        if h["from"] is None or h["from"] <= when_iso:
            best = h
    return best
