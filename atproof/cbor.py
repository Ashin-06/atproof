"""Strict DRISL / DAG-CBOR codec, CIDs and CAR v1, as used by atproto (atproto.com/specs/data-model).

Decoding rejects what atproto forbids (floats, indefinite lengths, tags other than 42, non-string map
keys) instead of guessing. Encoding is canonical (minimal heads, map keys sorted by length then bytes),
so a decoded object re-encodes to the identical bytes and therefore the identical CID.
"""
import base64
import hashlib

DAG_CBOR, RAW, SHA256 = 0x71, 0x55, 0x12


def read_varint(data: bytes, off: int) -> tuple[int, int]:
    n = shift = 0
    while True:
        if off >= len(data):
            raise ValueError("truncated varint")
        b = data[off]
        off += 1
        n |= (b & 0x7F) << shift
        if b < 0x80:
            return n, off
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


class CID(bytes):
    """Binary CIDv1 (version, codec, multihash). str() gives the base32 'b...' form."""

    @property
    def codec(self) -> int:
        return read_varint(self, read_varint(self, 0)[1])[0]

    @property
    def digest(self) -> tuple[int, bytes]:
        _, o = read_varint(self, 0)
        _, o = read_varint(self, o)
        code, o = read_varint(self, o)
        ln, o = read_varint(self, o)
        return code, bytes(self[o:o + ln])

    def __str__(self) -> str:
        return "b" + base64.b32encode(self).decode().lower().rstrip("=")

    __repr__ = __str__

    @classmethod
    def parse(cls, s: str) -> "CID":
        if not s.startswith("b"):
            raise ValueError("only base32 ('b') CIDv1 strings are supported")
        body = s[1:].upper()
        return cls(base64.b32decode(body + "=" * (-len(body) % 8)))

    @classmethod
    def of(cls, block: bytes, codec: int = DAG_CBOR) -> "CID":
        return cls(b"\x01" + varint(codec) + bytes([SHA256, 32]) + hashlib.sha256(block).digest())

    def matches(self, block: bytes) -> bool:
        code, dig = self.digest
        return code == SHA256 and hashlib.sha256(block).digest() == dig


def cid_length(data: bytes, off: int) -> int:
    start = off
    _, off = read_varint(data, off)       # version
    _, off = read_varint(data, off)       # codec
    _, off = read_varint(data, off)       # multihash code
    ln, off = read_varint(data, off)      # digest length
    return off + ln - start


# ---- CBOR decode -----------------------------------------------------------------------------
def _head(data: bytes, off: int) -> tuple[int, int, int]:
    if off >= len(data):
        raise ValueError("truncated CBOR")
    b = data[off]
    major, info, off = b >> 5, b & 31, off + 1
    if info < 24:
        return major, info, off
    if info in (24, 25, 26, 27):
        size = 1 << (info - 24)
        if off + size > len(data):
            raise ValueError("truncated CBOR")
        return major, int.from_bytes(data[off:off + size], "big"), off + size
    raise ValueError(f"unsupported CBOR additional info {info} (indefinite length or reserved)")


MAX_DEPTH = 128  # atproto records are shallow; deep nesting is hostile input


def _decode(data: bytes, off: int, depth: int = 0):
    if depth > MAX_DEPTH:
        raise ValueError("CBOR nesting too deep")
    if off >= len(data):
        raise ValueError("truncated CBOR")
    if data[off] in (0xF9, 0xFA, 0xFB):
        raise ValueError("floats are not allowed in atproto data")
    major, n, off = _head(data, off)
    if major == 0:
        return n, off
    if major == 1:
        return -1 - n, off
    if major in (2, 3):
        if off + n > len(data):
            raise ValueError("truncated CBOR")
        raw = bytes(data[off:off + n])
        return (raw if major == 2 else raw.decode("utf-8")), off + n
    if major == 4:
        out = []
        for _ in range(n):
            v, off = _decode(data, off, depth + 1)
            out.append(v)
        return out, off
    if major == 5:
        out = {}
        for _ in range(n):
            k, off = _decode(data, off, depth + 1)
            if not isinstance(k, str):
                raise ValueError("map keys must be strings")
            if k in out:
                raise ValueError(f"duplicate CBOR map key: {k!r}")
            out[k], off = _decode(data, off, depth + 1)
        return out, off
    if major == 6:
        if n != 42:
            raise ValueError(f"CBOR tag {n} not allowed (only 42)")
        raw, off = _decode(data, off, depth + 1)
        if not isinstance(raw, bytes) or not raw.startswith(b"\x00"):
            raise ValueError("bad CID link")
        return CID(raw[1:]), off
    if n == 20:
        return False, off
    if n == 21:
        return True, off
    if n == 22:
        return None, off
    raise ValueError(f"unsupported CBOR simple value {n}")


def decode(data: bytes):
    obj, off = _decode(data, 0)
    if off != len(data):
        raise ValueError(f"{len(data) - off} trailing bytes after CBOR object")
    return obj


# ---- CBOR encode (canonical) -------------------------------------------------------------------
def _ehead(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    raise ValueError("integer too large")


def encode(obj) -> bytes:
    if obj is None:
        return b"\xf6"
    if obj is True:
        return b"\xf5"
    if obj is False:
        return b"\xf4"
    if isinstance(obj, CID):
        raw = b"\x00" + bytes(obj)
        return b"\xd8\x2a" + _ehead(2, len(raw)) + raw
    if isinstance(obj, int):
        return _ehead(0, obj) if obj >= 0 else _ehead(1, -1 - obj)
    if isinstance(obj, (bytes, bytearray)):
        return _ehead(2, len(obj)) + bytes(obj)
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _ehead(3, len(raw)) + raw
    if isinstance(obj, (list, tuple)):
        return _ehead(4, len(obj)) + b"".join(encode(v) for v in obj)
    if isinstance(obj, dict):
        keys = sorted(obj, key=lambda k: (len(k.encode()), k.encode()))
        return _ehead(5, len(obj)) + b"".join(encode(k) + encode(obj[k]) for k in keys)
    raise TypeError(f"cannot encode {type(obj).__name__} in atproto data")


# ---- CAR v1 -----------------------------------------------------------------------------------
def read_car(data: bytes) -> tuple[list[CID], dict[CID, bytes]]:
    """Roots and blocks of a CAR v1 file. Block integrity is checked separately (verify_blocks)."""
    hlen, off = read_varint(data, 0)
    header = decode(data[off:off + hlen])
    if not isinstance(header, dict):
        raise ValueError("CAR header must be a map")
    if header.get("version") != 1:
        raise ValueError(f"unsupported CAR version {header.get('version')}")
    roots = header.get("roots", [])
    if not isinstance(roots, list) or any(not isinstance(root, CID) for root in roots):
        raise ValueError("CAR roots must be a list of CID links")
    off += hlen
    blocks = {}
    while off < len(data):
        slen, off = read_varint(data, off)
        end = off + slen
        if end > len(data):
            raise ValueError("truncated CAR section")
        clen = cid_length(data, off)
        blocks[CID(data[off:off + clen])] = bytes(data[off + clen:end])
        off = end
    return roots, blocks


def write_car(roots: list[CID], blocks: dict[CID, bytes]) -> bytes:
    header = encode({"version": 1, "roots": list(roots)})
    out = [varint(len(header)), header]
    for cid, block in blocks.items():
        out += [varint(len(cid) + len(block)), bytes(cid), block]
    return b"".join(out)


def verify_blocks(blocks: dict[CID, bytes]) -> list[str]:
    """CIDs whose block does not hash to the CID (tampering or corruption)."""
    return [str(c) for c, b in blocks.items() if not c.matches(b)]
