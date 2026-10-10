import json
from pathlib import Path

import pytest
from helpers import car, new_key, sign, signed_repo, tid

from atproof import cbor, keys, mst
from atproof.cbor import CID

FIX = Path(__file__).parent / "fixtures"
POST = FIX / "bsky-app-post-3mxhdhodv222n.car"
ABSENT = FIX / "bsky-app-absent-3zzzzzzzzzzzz.car"
EXPECTED = json.loads((FIX / "bsky-app-post-expected.json").read_text())
AUDIT = json.loads((FIX / "bsky-app-plc-audit.json").read_text())


# ---- real network data (official @bsky.app account) -----------------------------------------
def test_real_inclusion_proof_end_to_end():
    roots, blocks = cbor.read_car(POST.read_bytes())
    assert cbor.verify_blocks(blocks) == []
    assert all(cbor.encode(cbor.decode(b)) == b for b in blocks.values())  # canonical encoder
    commit = cbor.decode(blocks[roots[0]])
    assert list(commit) == ["did", "rev", "sig", "data", "prev", "version"]  # length-first key order
    k = keys.key_at(keys.key_history(AUDIT), keys.tid_time(commit["rev"]))
    ok, why = keys.verify(k["key"], cbor.encode({x: v for x, v in commit.items() if x != "sig"}), commit["sig"])
    assert ok, why
    r = mst.find(blocks, commit["data"], "app.bsky.feed.post/3mxhdhodv222n")
    assert r["status"] == "present" and r["problems"] == [] and str(r["value"]) == EXPECTED["cid"]
    rec = cbor.decode(blocks[r["value"]])
    assert rec["text"] == EXPECTED["text"]
    assert keys.tid_time("3mxhdhodv222n") == EXPECTED["createdAt"].replace("Z", "000Z")


def test_real_absence_proof():
    roots, blocks = cbor.read_car(ABSENT.read_bytes())
    commit = cbor.decode(blocks[roots[0]])
    k = keys.key_at(keys.key_history(AUDIT), keys.tid_time(commit["rev"]))
    assert keys.verify(k["key"], cbor.encode({x: v for x, v in commit.items() if x != "sig"}), commit["sig"])[0]
    assert mst.find(blocks, commit["data"], "app.bsky.feed.post/3zzzzzzzzzzzz")["status"] == "absent"


def test_real_did_document_matches_audit_log():
    doc = json.loads((FIX / "bsky-app-did.json").read_text())
    current = keys.key_history(doc)[0]["key"]
    assert "did:key:" + current == keys.key_history(AUDIT)[-1]["key"]


# ---- CBOR / CID / CAR -----------------------------------------------------------------------
def test_cbor_roundtrip_and_strictness():
    cid = CID.of(b"x")
    obj = {"text": "hi", "n": -5, "big": 2**40, "b": b"\x00\x01", "l": [None, True, False], "link": cid}
    raw = cbor.encode(obj)
    assert cbor.decode(raw) == obj and cbor.encode(cbor.decode(raw)) == raw
    assert list(cbor.decode(cbor.encode({"bb": 1, "a": 2, "ccc": 3}))) == ["a", "bb", "ccc"]
    for bad, why in [(b"\xfb" + bytes(8), "floats"), (b"\x9f\xff", "indefinite"), (b"\xc1\x00", "tag"),
                     (b"\x01\x01", "trailing"), (b"\xa1\x01\x02", "keys"), (b"\x62a", "truncated")]:
        with pytest.raises(ValueError, match=why):
            cbor.decode(bad)


def test_cid_string_and_tamper_detection():
    real = CID.parse(EXPECTED["cid"])
    assert str(real) == EXPECTED["cid"] and real.codec == cbor.DAG_CBOR
    roots, blocks = cbor.read_car(POST.read_bytes())
    victim = next(c for c in blocks if c != roots[0])
    blocks[victim] = blocks[victim][:-1] + bytes([blocks[victim][-1] ^ 1])
    assert cbor.verify_blocks(blocks) == [str(victim)]


def test_car_write_read_roundtrip():
    roots, blocks = cbor.read_car(POST.read_bytes())
    again = cbor.read_car(cbor.write_car(roots, blocks))
    assert again == (roots, blocks)
    with pytest.raises(ValueError):
        cbor.read_car(POST.read_bytes()[:-3])


# ---- keys, signatures, identity history ------------------------------------------------------
@pytest.mark.parametrize("curve", ["secp256k1", "p256"])
def test_signatures_both_curves(curve):
    priv, mk = new_key(curve)
    msg = b"unsigned commit bytes"
    assert keys.verify(mk, msg, sign(priv, msg)) == (True, f"valid {curve} signature")
    assert keys.verify(mk, msg + b"!", sign(priv, msg))[0] is False
    assert "high-S" in keys.verify(mk, msg, sign(priv, msg, low_s=False))[1]
    assert "64" in keys.verify(mk, msg, sign(priv, msg)[:63])[1]
    other_priv, _ = new_key(curve)
    assert keys.verify(mk, msg, sign(other_priv, msg))[0] is False


def test_base58_and_multikey():
    for b in (b"", b"\x00\x00ab", bytes(range(40))):
        assert keys.b58decode(keys.b58encode(b)) == b
    with pytest.raises(ValueError):
        keys.parse_multikey("zQ" + "1" * 10)
    with pytest.raises(ValueError):
        keys.parse_multikey("uABC")


def test_key_history_picks_key_in_force():
    hist = [{"from": "2024-01-01T00:00:00Z", "key": "A", "source": "op1"},
            {"from": "2025-06-01T00:00:00Z", "key": "B", "source": "op2"}]
    assert keys.key_at(hist, "2025-01-01T00:00:00Z")["key"] == "A"
    assert keys.key_at(hist, "2026-01-01T00:00:00Z")["key"] == "B"
    assert keys.key_at(hist, "2023-01-01T00:00:00Z") is None
    log = [{"createdAt": "2024", "cid": "x", "nullified": True, "operation": {"verificationMethods": {"atproto": "N"}}},
           {"createdAt": "2025", "cid": "y", "operation": {"type": "plc_tombstone"}}]
    assert keys.key_history(log) == [{"from": "2025", "key": None, "source": "plc op y"}]


def test_tid_time():
    assert keys.tid_time(tid(1_760_000_000_000_000)) == "2025-10-09T08:53:20.000000Z"


# ---- MST: reference-built trees ---------------------------------------------------------------
def test_mst_present_absent_and_layers():
    priv, _ = new_key()
    recs = {f"app.bsky.feed.post/{tid(1_760_000_000_000_000 + i * 7919)}": {"text": f"post {i}"} for i in range(300)}
    commit, blocks = signed_repo(priv, "did:plc:test", recs, tid(1_760_000_100_000_000))
    root = cbor.decode(blocks[commit])["data"]
    depths = set()
    for path, rec in recs.items():
        r = mst.find(blocks, root, path)
        assert r["status"] == "present" and r["problems"] == [], path
        assert cbor.decode(blocks[r["value"]]) == rec
        depths.add(len(r["path"]))
    assert max(depths) > 1  # multi-layer tree actually exercised
    for missing in ("app.bsky.feed.post/2222222222222", "app.bsky.feed.post/zzzzzzzzzzzzz", "a/b", "zzz/zzz"):
        assert mst.find(blocks, root, missing)["status"] == "absent"


def test_mst_unproven_when_node_missing_and_flags_disorder():
    priv, _ = new_key()
    recs = {f"app.bsky.feed.post/{tid(1_760_000_000_000_000 + i * 104729)}": {"i": i} for i in range(200)}
    commit, blocks = signed_repo(priv, "did:plc:test", recs, tid(1_760_000_100_000_000))
    root = cbor.decode(blocks[commit])["data"]
    path = next(p for p in recs if len(mst.find(blocks, root, p)["path"]) > 1)
    deep = CID.parse(mst.find(blocks, root, path)["path"][-1])
    del blocks[deep]
    assert mst.find(blocks, root, path)["status"] == "unproven"
    bad = cbor.encode({"l": None, "e": [{"p": 0, "k": b"b/b", "v": CID.of(b"1"), "t": None},
                                        {"p": 0, "k": b"a/a", "v": CID.of(b"2"), "t": None}]})
    r = mst.find({CID.of(bad): bad}, CID.of(bad), "a/a")
    assert any("not strictly sorted" in p for p in r["problems"])


def test_signed_repo_car_verifies():
    priv, mk = new_key("p256")
    commit, blocks = signed_repo(priv, "did:plc:test", {"app.bsky.feed.post/3aaaaaaaaaaaa": {"text": "x"}},
                                 tid(1_760_000_000_000_000))
    roots, back = cbor.read_car(car(commit, blocks))
    c = cbor.decode(back[roots[0]])
    assert keys.verify(mk, cbor.encode({x: v for x, v in c.items() if x != "sig"}), c["sig"])[0]
