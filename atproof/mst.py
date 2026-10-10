"""Merkle Search Tree lookup with an explicit proof path (atproto.com/specs/repository).

Node: {l: CID|null, e: [{p: prefixlen, k: keysuffix, v: record CID, t: subtree CID|null}]}.
A key's layer is (leading zero bits of sha256(key)) // 2. Every node on the path is checked for
sorted keys and a single layer, because an absence proof is only as good as the tree's order.
"""
import hashlib

from atproof.cbor import decode


def key_layer(key: bytes) -> int:
    h = hashlib.sha256(key).digest()
    zeros = 0
    for b in h:
        if b == 0:
            zeros += 8
            continue
        zeros += 8 - b.bit_length()
        break
    return zeros // 2


def _entries(node: dict) -> list[tuple[bytes, dict]]:
    keys, prev = [], b""
    for e in node.get("e", []):
        k = prev[:e["p"]] + e["k"]
        keys.append((k, e))
        prev = k
    return keys


def find(blocks: dict, root, key: str) -> dict:
    """Look `key` ("collection/rkey") up from MST root `root`.

    status: "present" (value = record CID), "absent" (proven by the walked path), or "unproven"
    (a node needed for the walk is not in the blocks). `problems` lists ordering/layer violations.
    """
    target = key.encode()
    path, problems, cid, parent_layer = [], [], root, None
    while cid is not None:
        if cid not in blocks:
            return {"status": "unproven", "missing_node": str(cid), "path": path, "problems": problems}
        path.append(str(cid))
        node = decode(blocks[cid])
        ents = _entries(node)
        keys = [k for k, _ in ents]
        if any(a >= b for a, b in zip(keys, keys[1:])):
            problems.append(f"{cid}: keys not strictly sorted")
        layers = {key_layer(k) for k in keys}
        if len(layers) > 1:
            problems.append(f"{cid}: entries from different layers {sorted(layers)}")
        layer = layers.pop() if len(layers) == 1 else None
        if layer is not None and parent_layer is not None and layer >= parent_layer:
            problems.append(f"{cid}: layer {layer} not below parent layer {parent_layer}")
        if layer is not None:
            parent_layer = layer
        elif parent_layer is not None:
            parent_layer -= 1  # empty intermediate node sits one layer down
        nxt = node.get("l")
        for k, e in ents:
            if k == target:
                return {"status": "present", "value": e["v"], "path": path, "problems": problems}
            if k < target:
                nxt = e.get("t")
            else:
                break
        cid = nxt
    return {"status": "absent", "path": path, "problems": problems}
