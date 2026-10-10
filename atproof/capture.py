"""Preserve ONE record's proof and the account's identity history, with capture metadata.

Targeted by design (research/04): one at:// URI per call, no listing, no bulk or firehose mode.
Network access goes through `get(url) -> (body, headers)` so it can be replaced in tests.
"""
import hashlib
import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from atproof import __version__, verify

PLC = "https://plc.directory"
UA = f"atproof/{__version__} (targeted evidence preservation)"


MAX_BYTES = 64 << 20  # one record proof is kilobytes; refuse runaway responses


def http_get(url: str, timeout: float = 30, limit: int = MAX_BYTES) -> tuple[bytes, dict]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (https URLs built below)
        body = r.read(limit + 1)
        if len(body) > limit:
            raise ValueError(f"response from {url} exceeds {limit} bytes")
        return body, dict(r.headers)


def identity_urls(did: str) -> dict:
    if did.startswith("did:plc:"):
        return {"document": f"{PLC}/{did}", "history": f"{PLC}/{did}/log/audit"}
    if did.startswith("did:web:"):
        rest = did.removeprefix("did:web:")
        if ":" in rest:  # path-based did:web is not used by atproto; a port is encoded as %3A
            raise ValueError("did:web with a path is not supported")
        return {"document": f"https://{urllib.parse.unquote(rest)}/.well-known/did.json", "history": None}
    raise ValueError(f"unsupported DID method: {did}")


def pds_endpoint(doc: dict) -> str:
    for s in doc.get("service", []):
        if s.get("id", "").endswith("#atproto_pds") and s.get("serviceEndpoint", "").startswith("https://"):
            return s["serviceEndpoint"].rstrip("/")
    raise ValueError("DID document has no https #atproto_pds service")


def capture(uri: str, out: str, get=http_get) -> dict:
    """Write proof.car, identity.json, did-document.json and capture.json into a new folder `out`."""
    did, path = verify.parse_uri(uri)
    collection, rkey = path.split("/")
    d = Path(out)
    d.mkdir(parents=True, exist_ok=False)
    log, urls = [], identity_urls(did)

    def fetch(name, url):
        when = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        body, headers = get(url)
        (d / name).write_bytes(body)
        log.append({"file": name, "url": url, "fetched_utc": when, "server_date": headers.get("Date"),
                    "sha256": hashlib.sha256(body).hexdigest(), "bytes": len(body)})
        return body

    doc = json.loads(fetch("did-document.json", urls["document"]))
    if doc.get("id") != did:
        raise ValueError(f"DID document is for {doc.get('id')}, expected {did}")
    if urls["history"]:
        fetch("identity.json", urls["history"])
    else:  # did:web: the current document is all there is
        (d / "identity.json").write_bytes((d / "did-document.json").read_bytes())
    q = urllib.parse.urlencode({"did": did, "collection": collection, "rkey": rkey})
    car = fetch("proof.car", f"{pds_endpoint(doc)}/xrpc/com.atproto.sync.getRecord?{q}")
    identity = json.loads((d / "identity.json").read_text(encoding="utf-8"))
    result = verify.verify_proof(car, identity, path)
    meta = {"uri": uri, "tool": f"atproof {__version__}", "fetches": log,
            "verdict_at_capture": result["verdict"], "commit": result.get("commit"),
            "record_cid": result.get("record", {}).get("cid"),
            "note": "fetched_utc is this machine's clock; server_date is the server's HTTP Date header. "
                    "Neither is a trusted timestamp."}
    (d / "capture.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta
