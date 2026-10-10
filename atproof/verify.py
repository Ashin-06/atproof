"""Verify record proofs and build/check evidence packages (method: research/03).

Every report carries LIMITS: what a passing result does not show. Callers must not drop them.
"""
import base64
import hashlib
import html
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from atproof import __version__, cbor, keys, mst

LIMITS = [
    "On hosted accounts the server holds the signing key: a valid signature shows the account's host "
    "published this under the account, not which person wrote it.",
    "Revision and record times (TIDs, createdAt) are claims by the server and client, not a trusted clock. "
    "Add an independent timestamp (e.g. RFC 3161) over the manifest if timing matters.",
    "Each proof binds the content at its own revision only; edits in between are not excluded.",
    "If the signing key was compromised, signatures prove nothing; check the identity history for "
    "unexpected rotations.",
    "did:web identities have no public key history; old signatures need an independently saved DID document.",
]


def parse_uri(uri: str) -> tuple[str, str]:
    """'at://did/collection/rkey' -> (did, 'collection/rkey')."""
    parts = uri.removeprefix("at://").split("/")
    if len(parts) != 3 or not parts[0].startswith("did:"):
        raise ValueError(f"expected at://<did>/<collection>/<rkey>, got {uri!r}")
    return parts[0], f"{parts[1]}/{parts[2]}"


def _plain(v):
    """Record data as JSON-safe values (CIDs as strings, bytes as base64)."""
    if isinstance(v, cbor.CID):
        return {"$link": str(v)}
    if isinstance(v, bytes):
        return {"$bytes": base64.b64encode(v).decode()}
    if isinstance(v, dict):
        return {k: _plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_plain(x) for x in v]
    return v


def _identity_did(identity) -> str | None:
    if isinstance(identity, dict):
        return identity.get("id")
    return next((e.get("did") for e in identity if e.get("did")), None)


def verify_proof(car_bytes: bytes, identity, path: str) -> dict:
    """Check one getRecord / export CAR for `path`. verdict: present, absent, unproven or failed.

    Corrupt or hostile input never raises: it ends as verdict "failed" with the reason recorded.
    """
    rep = {"path": path, "car_sha256": hashlib.sha256(car_bytes).hexdigest(), "failures": []}
    try:
        return _verify(rep, car_bytes, identity, path)
    except (ValueError, KeyError, TypeError, IndexError) as e:
        rep["failures"].append(f"undecodable or malformed data: {type(e).__name__}: {e}")
        rep["verdict"] = "failed"
        return rep


def _verify(rep: dict, car_bytes: bytes, identity, path: str) -> dict:
    fail = rep["failures"].append
    try:
        roots, blocks = cbor.read_car(car_bytes)
    except ValueError as e:
        fail(f"CAR unreadable: {e}")
        rep["verdict"] = "failed"
        return rep
    rep["blocks"] = len(blocks)
    bad = cbor.verify_blocks(blocks)
    if bad:
        fail(f"{len(bad)} block(s) do not match their CID: {bad[:5]}")
    if not roots or roots[0] not in blocks:
        fail("first root (the commit) is not in the CAR")
        rep["verdict"] = "failed"
        return rep
    commit = cbor.decode(blocks[roots[0]])
    if not isinstance(commit, dict) or not {"did", "data", "rev", "sig"} <= set(commit):
        fail("first root is not a signed commit")
        rep["verdict"] = "failed"
        return rep
    rev_time = keys.tid_time(commit["rev"])
    rep["commit"] = {"cid": str(roots[0]), "did": commit["did"], "rev": commit["rev"], "rev_time": rev_time,
                     "version": commit.get("version"), "mst_root": str(commit["data"])}

    id_did = _identity_did(identity)
    if id_did and id_did != commit["did"]:
        fail(f"identity is for {id_did}, commit is for {commit['did']}")
    hist = keys.key_history(identity)
    in_force = keys.key_at(hist, rev_time)
    unsigned = cbor.encode({k: v for k, v in commit.items() if k != "sig"})
    sig = {"key_in_force": in_force}
    if in_force and in_force["key"]:
        sig["ok"], sig["detail"] = keys.verify(in_force["key"], unsigned, commit["sig"])
    else:
        sig["ok"], sig["detail"] = False, "no signing key in force at the commit's time"
    if not sig["ok"]:
        other = next((h for h in hist if h["key"] and h is not in_force
                      and keys.verify(h["key"], unsigned, commit["sig"])[0]), None)
        if other:
            sig["detail"] += f"; it does verify with an earlier/later key from {other['source']}"
        fail(f"signature: {sig['detail']}")
    rep["signature"] = sig

    found = mst.find(blocks, commit["data"], path)
    rep["mst"] = {"status": found["status"], "depth": len(found["path"]), "path": found["path"],
                  "problems": found["problems"]}
    if found["problems"]:
        fail(f"MST structure problems: {found['problems']}")
    if found["status"] == "present":
        rcid = found["value"]
        if rcid not in blocks:
            fail(f"record block {rcid} missing")
        else:
            rep["record"] = {"cid": str(rcid), "value": _plain(cbor.decode(blocks[rcid]))}
    rep["verdict"] = "failed" if rep["failures"] else found["status"]
    return rep


def verify_deleted(inclusion: bytes, absence: bytes, identity, path: str) -> dict:
    inc, ab = verify_proof(inclusion, identity, path), verify_proof(absence, identity, path)
    reasons = []
    if inc["verdict"] != "present":
        reasons.append(f"inclusion proof: {inc['verdict']} {inc['failures']}")
    if ab.get("mst", {}).get("status") == "present":
        reasons.append("the record is still present in the later revision (not deleted)")
    elif ab["verdict"] != "absent":
        reasons.append(f"absence proof: {ab['verdict']} {ab['failures']}")
    if inc.get("commit") and ab.get("commit"):
        if inc["commit"]["did"] != ab["commit"]["did"]:
            reasons.append("the two proofs are for different accounts")
        if ab["commit"]["rev"] <= inc["commit"]["rev"]:  # TIDs sort by time
            reasons.append("absence revision is not later than the inclusion revision")
    return {"claim": f"{path} existed and was later removed", "verdict": "proven" if not reasons else "not proven",
            "reasons": reasons, "inclusion": inc, "absence": ab, "limits": LIMITS}


# ---- evidence packages -------------------------------------------------------------------------
def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def build_package(out: str, path: str, identity_file: str, inclusion_file: str, absence_file: str | None = None,
                  note: str = "") -> dict:
    d = Path(out)
    d.mkdir(parents=True, exist_ok=False)  # never overwrite an existing package
    names = {"identity": "identity.json", "inclusion": "inclusion.car", "absence": "absence.car"}
    shutil.copyfile(identity_file, d / names["identity"])
    shutil.copyfile(inclusion_file, d / names["inclusion"])
    if absence_file:
        shutil.copyfile(absence_file, d / names["absence"])
    identity = json.loads((d / names["identity"]).read_text(encoding="utf-8"))
    inc = (d / names["inclusion"]).read_bytes()
    if absence_file:
        report = verify_deleted(inc, (d / names["absence"]).read_bytes(), identity, path)
    else:
        report = {"claim": f"{path} existed", "verdict": None, "inclusion": verify_proof(inc, identity, path),
                  "limits": LIMITS}
        report["verdict"] = "proven" if report["inclusion"]["verdict"] == "present" else "not proven"
    report["package"] = {"path": path, "built_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                         "tool": f"atproof {__version__}", "note": note}
    (d / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    (d / "report.html").write_text(to_html(report), encoding="utf-8")
    files = sorted(p for p in d.iterdir() if p.name != "MANIFEST.sha256")
    (d / "MANIFEST.sha256").write_text("".join(f"{_sha(p)}  {p.name}\n" for p in files), encoding="utf-8")
    return report


def check_package(directory: str) -> dict:
    """Re-check a package from scratch: manifest hashes, then the proofs themselves."""
    d = Path(directory)
    problems = []
    listed = {}
    for line in (d / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        if Path(name).name != name or name in ("", ".", ".."):
            problems.append(f"unsafe name in manifest: {name!r}")
            continue
        listed[name] = digest
        f = d / name
        if not f.exists():
            problems.append(f"missing {name}")
        elif _sha(f) != digest:
            problems.append(f"hash mismatch {name}")
    extra = sorted(p.name for p in d.iterdir() if p.name not in listed and p.name != "MANIFEST.sha256")
    if extra:
        problems.append(f"files not in manifest: {extra}")
    stored = json.loads((d / "report.json").read_text(encoding="utf-8"))
    path = stored["package"]["path"]
    identity = json.loads((d / "identity.json").read_text(encoding="utf-8"))
    inc = (d / "inclusion.car").read_bytes()
    if (d / "absence.car").exists():
        fresh = verify_deleted(inc, (d / "absence.car").read_bytes(), identity, path)
    else:
        fresh = {"verdict": "proven" if verify_proof(inc, identity, path)["verdict"] == "present" else "not proven"}
    if fresh["verdict"] != stored["verdict"]:
        problems.append(f"re-verification gives {fresh['verdict']!r}, report says {stored['verdict']!r}")
    return {"package": str(d), "manifest_ok": not problems, "problems": problems,
            "verdict": fresh["verdict"] if not problems else "package invalid"}


def to_html(rep: dict) -> str:
    e = lambda v: html.escape("" if v is None else str(v))

    def proof(name, p):
        if not p:
            return ""
        c, s, m = p.get("commit", {}), p.get("signature", {}), p.get("mst", {})
        rec = p.get("record", {}).get("value", {})
        rows = [("verdict", p.get("verdict")), ("account", c.get("did")), ("revision", c.get("rev")),
                ("revision time (claimed)", c.get("rev_time")), ("signature", s.get("detail")),
                ("key in force from", (s.get("key_in_force") or {}).get("from")),
                ("tree lookup", f"{m.get('status')} (depth {m.get('depth')})"),
                ("record CID", p.get("record", {}).get("cid")), ("text", rec.get("text") if isinstance(rec, dict) else None),
                ("createdAt (claimed)", rec.get("createdAt") if isinstance(rec, dict) else None),
                ("CAR SHA-256", p.get("car_sha256")), ("failures", "; ".join(p.get("failures", [])) or "none")]
        return f"<h2>{e(name)}</h2><table>" + "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in rows) \
            + "</table>"

    return ("<!doctype html><meta charset=utf-8><title>atproof report</title>"
            "<style>body{font:14px system-ui;margin:1rem;max-width:60rem}table{border-collapse:collapse;width:100%;"
            "margin-bottom:1rem}td,th{border:1px solid #ccc;padding:4px 8px;text-align:left;vertical-align:top}"
            "th{background:#f0f0f0;width:14rem}.v{font-size:1.2rem;font-weight:600}</style>"
            f"<h1>{e(rep.get('claim'))}</h1><p class=v>Verdict: {e(rep.get('verdict'))}</p>"
            + ("<p>Reasons: " + e("; ".join(rep["reasons"])) + "</p>" if rep.get("reasons") else "")
            + proof("Inclusion proof", rep.get("inclusion")) + proof("Absence proof", rep.get("absence"))
            + "<h2>What this does not show</h2><ul>" + "".join(f"<li>{e(x)}</li>" for x in rep.get("limits", []))
            + "</ul>")
