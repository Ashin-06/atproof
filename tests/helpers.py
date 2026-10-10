"""Test-only builders: signing keys, a reference MST builder, and signed repo CARs."""
import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from atproof import keys, mst
from atproof.cbor import CID, encode, write_car

PREFIX = {"secp256k1": (b"\xe7\x01", ec.SECP256K1()), "p256": (b"\x80\x24", ec.SECP256R1())}


def new_key(curve="secp256k1"):
    prefix, c = PREFIX[curve]
    priv = ec.generate_private_key(c)
    point = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    return priv, "did:key:z" + keys.b58encode(prefix + point)


def sign(priv, message: bytes, low_s=True) -> bytes:
    r, s = decode_dss_signature(priv.sign(message, ec.ECDSA(hashes.SHA256())))
    order = next(o for _, (_, c, o) in keys.CURVES.items() if c.name == priv.curve.name)
    if low_s and s > order // 2:
        s = order - s
    elif not low_s and s <= order // 2:
        s = order - s  # force high-S
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def build_mst(items: dict[bytes, CID], blocks: dict) -> CID:
    """Reference MST construction: top layer holds the highest-layer keys, gaps recurse one layer down."""
    if not items:
        node = {"l": None, "e": []}
        blk = encode(node)
        blocks[CID.of(blk)] = blk
        return CID.of(blk)
    top = max(mst.key_layer(k) for k in items)

    def build(keys_sorted, layer):
        if not keys_sorted:
            return None
        here = [k for k in keys_sorted if mst.key_layer(k) == layer]
        if not here:  # empty intermediate node, keeps links one layer apart
            child = build(keys_sorted, layer - 1)
            blk = encode({"l": child, "e": []})
        else:
            gaps, cur = [], []
            for k in keys_sorted:
                if mst.key_layer(k) == layer:
                    gaps.append(cur)
                    cur = []
                else:
                    cur.append(k)
            gaps.append(cur)
            entries, prev = [], b""
            for i, k in enumerate(here):
                p = 0
                while p < min(len(prev), len(k)) and prev[p] == k[p]:
                    p += 1
                entries.append({"p": p, "k": k[p:], "v": items[k], "t": build(gaps[i + 1], layer - 1)})
                prev = k
            blk = encode({"l": build(gaps[0], layer - 1), "e": entries})
        cid = CID.of(blk)
        blocks[cid] = blk
        return cid

    return build(sorted(items), top)


def signed_repo(priv, did: str, records: dict[str, dict], rev: str) -> tuple[CID, dict]:
    """A complete signed repo as (commit CID, blocks)."""
    blocks, items = {}, {}
    for path, rec in records.items():
        blk = encode(rec)
        cid = CID.of(blk)
        blocks[cid] = blk
        items[path.encode()] = cid
    root = build_mst(items, blocks)
    unsigned = {"did": did, "version": 3, "data": root, "rev": rev, "prev": None}
    commit = {**unsigned, "sig": sign(priv, encode(unsigned))}
    blk = encode(commit)
    cid = CID.of(blk)
    blocks[cid] = blk
    return cid, blocks


def car(commit: CID, blocks: dict) -> bytes:
    ordered = {commit: blocks[commit], **{c: b for c, b in blocks.items() if c != commit}}
    return write_car([commit], ordered)


def tid(us: int, clock: int = 0) -> str:
    n = (us << 10) | clock
    return "".join("234567abcdefghijklmnopqrstuvwxyz"[(n >> (5 * i)) & 31] for i in range(12, -1, -1))


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
