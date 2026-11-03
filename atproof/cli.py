"""atproof command line. Every command only reads its inputs."""
import argparse
import json
import sys
from pathlib import Path

from atproof import capture, cbor, keys, verify


def _dump(obj):
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def inspect(path: str) -> dict:
    roots, blocks = cbor.read_car(Path(path).read_bytes())
    out = {"roots": [str(r) for r in roots], "blocks": len(blocks), "bad_blocks": cbor.verify_blocks(blocks)}
    if roots and roots[0] in blocks:
        c = cbor.decode(blocks[roots[0]])
        if isinstance(c, dict) and "sig" in c:
            out["commit"] = {"did": c.get("did"), "version": c.get("version"), "rev": c.get("rev"),
                             "rev_time": keys.tid_time(c["rev"]) if c.get("rev") else None,
                             "data": str(c.get("data")), "sig_bytes": len(c["sig"])}
    return out


def main(argv=None):
    p = argparse.ArgumentParser(prog="atproof", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("inspect", help="summarise a CAR file: roots, block integrity, commit").add_argument("car")
    v = sub.add_parser("verify", help="verify one proof CAR for a record path")
    v.add_argument("car")
    v.add_argument("--identity", required=True, help="did:plc audit log JSON (or DID document)")
    v.add_argument("--uri", required=True, help="at://<did>/<collection>/<rkey>")
    d = sub.add_parser("deleted", help="verify that a record existed and was later removed")
    d.add_argument("--inclusion", required=True)
    d.add_argument("--absence", required=True)
    d.add_argument("--identity", required=True)
    d.add_argument("--uri", required=True)
    pk = sub.add_parser("package", help="build an evidence package folder (inputs, reports, SHA-256 manifest)")
    pk.add_argument("--out", required=True, help="new folder (must not exist)")
    pk.add_argument("--inclusion", required=True)
    pk.add_argument("--absence")
    pk.add_argument("--identity", required=True)
    pk.add_argument("--uri", required=True)
    pk.add_argument("--note", default="", help="case reference / purpose, stored in the report")
    sub.add_parser("check-package", help="re-verify a package from scratch").add_argument("dir")
    cp = sub.add_parser("capture", help="preserve ONE record's proof + identity history from the network")
    cp.add_argument("--uri", required=True, help="at://<did>/<collection>/<rkey> (a DID, not a handle)")
    cp.add_argument("--out", required=True, help="new folder (must not exist)")
    sv = sub.add_parser("serve", help="verification API (settings: ATPROOF_* environment variables)")
    sv.add_argument("--host", help="default ATPROOF_HOST or 127.0.0.1; any other address needs API keys")
    sv.add_argument("--port", type=int, help="default ATPROOF_PORT or 8104")
    sub.add_parser("migrate", help="apply database migrations to ATPROOF_DATABASE_URL")
    a = p.parse_args(argv)
    if a.cmd in ("serve", "migrate"):
        return _service(a)
    try:
        if a.cmd == "inspect":
            _dump(inspect(a.car))
        elif a.cmd == "verify":
            _, path = verify.parse_uri(a.uri)
            ident = json.loads(Path(a.identity).read_text(encoding="utf-8"))
            _dump({**verify.verify_proof(Path(a.car).read_bytes(), ident, path), "limits": verify.LIMITS})
        elif a.cmd == "deleted":
            _, path = verify.parse_uri(a.uri)
            ident = json.loads(Path(a.identity).read_text(encoding="utf-8"))
            _dump(verify.verify_deleted(Path(a.inclusion).read_bytes(), Path(a.absence).read_bytes(), ident, path))
        elif a.cmd == "package":
            _, path = verify.parse_uri(a.uri)
            rep = verify.build_package(a.out, path, a.identity, a.inclusion, a.absence, a.note)
            print(f"{rep['verdict']}: package written to {a.out}")
        elif a.cmd == "check-package":
            _dump(verify.check_package(a.dir))
        elif a.cmd == "capture":
            _dump(capture.capture(a.uri, a.out))
    except (OSError, ValueError, KeyError) as e:  # incl. urllib errors (OSError subclasses)
        p.error(f"{a.cmd}: {type(e).__name__}: {e}")


def _service(a) -> int:
    import os

    from atproof import db, ops

    if a.cmd == "serve":
        for flag, var in (("host", "ATPROOF_HOST"), ("port", "ATPROOF_PORT")):
            if getattr(a, flag) is not None:
                os.environ[var] = str(getattr(a, flag))
    try:
        settings = ops.load_settings()  # fail here, before uvicorn, with a readable message
    except ops.ConfigError as e:
        print(f"configuration error: {e}", file=sys.stderr)
        return 1
    if a.cmd == "migrate":
        print(*(db.migrate(db.engine(settings.database_url)) or ["up to date"]), sep="\n")
        return 0
    import uvicorn

    ops.setup_logging(settings.log_level)
    try:
        uvicorn.run("atproof.api:app", host=settings.host, port=settings.port, log_config=None, access_log=False)
    except ops.ConfigError as e:  # checks the API module makes when it loads
        print(f"configuration error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
