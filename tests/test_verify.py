import json
from pathlib import Path

import pytest
from helpers import car, new_key, signed_repo, tid

from atproof import verify

FIX = Path(__file__).parent / "fixtures"
REAL_POST = (FIX / "bsky-app-post-3mxhdhodv222n.car").read_bytes()
REAL_ABSENT = (FIX / "bsky-app-absent-3zzzzzzzzzzzz.car").read_bytes()
AUDIT = json.loads((FIX / "bsky-app-plc-audit.json").read_text())
DID = "did:plc:testaccount0000000000000"
PATH = "app.bsky.feed.post/3lpostpostpos"
T1, T2 = 1_760_000_000_000_000, 1_760_000_900_000_000


def plc(did, *ops):
    return [{"did": did, "cid": f"op{i}", "nullified": False, "createdAt": when,
             "operation": {"type": "plc_operation", "verificationMethods": {"atproto": key}}}
            for i, (when, key) in enumerate(ops)]


def scenario(curve="secp256k1"):
    priv, mk = new_key(curve)
    other = {"app.bsky.feed.post/3lotherotherr": {"text": "stays"}}
    c1, b1 = signed_repo(priv, DID, {PATH: {"text": "the post that gets deleted", "createdAt": "2025"}, **other},
                         tid(T1))
    c2, b2 = signed_repo(priv, DID, other, tid(T2))
    return priv, mk, car(c1, b1), car(c2, b2)


def test_real_proofs():
    r = verify.verify_proof(REAL_POST, AUDIT, "app.bsky.feed.post/3mxhdhodv222n")
    assert r["verdict"] == "present" and r["record"]["value"]["text"] == "a masterclass in alt text"
    assert r["signature"]["ok"] and r["mst"]["depth"] == 6
    assert verify.verify_proof(REAL_ABSENT, AUDIT, "app.bsky.feed.post/3zzzzzzzzzzzz")["verdict"] == "absent"
    assert verify.parse_uri("at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/3mxhdhodv222n") == \
        ("did:plc:z72i7hdynmk6r22z27h6tvur", "app.bsky.feed.post/3mxhdhodv222n")


@pytest.mark.parametrize("curve", ["secp256k1", "p256"])
def test_deleted_post_proven(curve):
    _, mk, inc, ab = scenario(curve)
    rep = verify.verify_deleted(inc, ab, plc(DID, ("2025-01-01T00:00:00.000Z", mk)), PATH)
    assert rep["verdict"] == "proven", rep["reasons"]
    assert rep["inclusion"]["record"]["value"]["text"] == "the post that gets deleted"
    assert rep["limits"] == verify.LIMITS


def test_deleted_rejections():
    priv, mk, inc, ab = scenario()
    ident = plc(DID, ("2025-01-01T00:00:00.000Z", mk))
    assert verify.verify_deleted(ab, inc, ident, PATH)["verdict"] == "not proven"            # order swapped
    assert verify.verify_deleted(inc, inc, ident, PATH)["verdict"] == "not proven"           # never removed
    wrong = plc("did:plc:someoneelse00000000000000", ("2025-01-01T00:00:00.000Z", mk))
    r = verify.verify_proof(inc, wrong, PATH)
    assert r["verdict"] == "failed" and any("identity is for" in f for f in r["failures"])
    _, stranger = new_key()
    r = verify.verify_proof(inc, plc(DID, ("2025-01-01T00:00:00.000Z", stranger)), PATH)
    assert r["verdict"] == "failed" and not r["signature"]["ok"]
    tampered = bytearray(inc)
    i = tampered.find(b"the post that gets deleted")
    tampered[i] ^= 0x20
    r = verify.verify_proof(bytes(tampered), ident, PATH)
    assert r["verdict"] == "failed" and any("do not match their CID" in f for f in r["failures"])


def test_key_rotation_handling():
    priv_old, mk_old, inc, _ = scenario()
    _, mk_new = new_key()
    # Old key until just before the commit, new key from then on: commit time falls under the NEW key.
    ident = plc(DID, ("2024-01-01T00:00:00.000Z", mk_old), ("2025-10-09T08:00:00.000Z", mk_new))
    r = verify.verify_proof(inc, ident, PATH)
    assert r["verdict"] == "failed" and "earlier/later key" in r["signature"]["detail"]
    # Rotation after the commit: the old key was in force, so it verifies.
    ident = plc(DID, ("2024-01-01T00:00:00.000Z", mk_old), ("2026-01-01T00:00:00.000Z", mk_new))
    assert verify.verify_proof(inc, ident, PATH)["verdict"] == "present"


def _files(tmp_path, inc, ab, ident):
    (tmp_path / "in").mkdir()
    for name, data in (("inc.car", inc), ("ab.car", ab)):
        (tmp_path / "in" / name).write_bytes(data)
    (tmp_path / "in" / "id.json").write_text(json.dumps(ident))
    return [str(tmp_path / "in" / n) for n in ("id.json", "inc.car", "ab.car")]


def test_package_build_and_check(tmp_path):
    _, mk, inc, ab = scenario()
    idf, incf, abf = _files(tmp_path, inc, ab, plc(DID, ("2025-01-01T00:00:00.000Z", mk)))
    pkg = tmp_path / "pkg"
    rep = verify.build_package(str(pkg), PATH, idf, incf, abf, note="case 42")
    assert rep["verdict"] == "proven"
    assert {p.name for p in pkg.iterdir()} == {"identity.json", "inclusion.car", "absence.car", "report.json",
                                               "report.html", "MANIFEST.sha256"}
    assert verify.check_package(str(pkg)) == {"package": str(pkg), "manifest_ok": True, "problems": [],
                                               "verdict": "proven"}
    assert "What this does not show" in (pkg / "report.html").read_text(encoding="utf-8")
    with pytest.raises(FileExistsError):
        verify.build_package(str(pkg), PATH, idf, incf, abf)
    data = bytearray((pkg / "inclusion.car").read_bytes())
    data[-1] ^= 1
    (pkg / "inclusion.car").write_bytes(bytes(data))
    (pkg / "extra.txt").write_text("x")
    chk = verify.check_package(str(pkg))
    assert chk["verdict"] == "package invalid"
    assert any("hash mismatch inclusion.car" in p for p in chk["problems"])
    assert any("not in manifest" in p for p in chk["problems"])


def test_html_escapes_record_text(tmp_path):
    priv, mk = new_key()
    c, b = signed_repo(priv, DID, {PATH: {"text": "<script>alert(1)</script>"}}, tid(T1))
    rep = {"claim": "x", "verdict": "proven", "inclusion": verify.verify_proof(car(c, b),
           plc(DID, ("2025-01-01T00:00:00.000Z", mk)), PATH), "limits": verify.LIMITS}
    h = verify.to_html(rep)
    assert "&lt;script&gt;" in h and "<script>alert" not in h


def test_corrupt_input_never_raises():
    _, mk, inc, _ = scenario()
    ident = plc(DID, ("2025-01-01T00:00:00.000Z", mk))
    for bad in (b"", b"\x00", inc[:40], inc[:-1] + bytes([inc[-1] ^ 1]), b"\xff" * 100, REAL_POST[: len(REAL_POST) // 2]):
        r = verify.verify_proof(bad, ident, PATH)
        assert r["verdict"] == "failed" and r["failures"], bad[:10]
