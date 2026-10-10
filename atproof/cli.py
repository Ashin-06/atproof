"""atproof command line. Every command only reads its inputs."""
import argparse
import json
import sys
from pathlib import Path

from atproof import cbor, keys


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
    a = p.parse_args(argv)
    try:
        if a.cmd == "inspect":
            _dump(inspect(a.car))
    except (OSError, ValueError, KeyError) as e:
        p.error(f"{a.cmd}: {type(e).__name__}: {e}")


if __name__ == "__main__":
    sys.exit(main())
