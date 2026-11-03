import json
import os
from pathlib import Path

import pytest

from atproof import capture

FIX = Path(__file__).parent / "fixtures"
DID = "did:plc:z72i7hdynmk6r22z27h6tvur"
URI = f"at://{DID}/app.bsky.feed.post/3mxhdhodv222n"


def fake_get(url):
    """Serve the saved real responses instead of the network."""
    if url == f"https://plc.directory/{DID}":
        return (FIX / "bsky-app-did.json").read_bytes(), {"Date": "Fri, 10 Oct 2026 02:05:00 GMT"}
    if url == f"https://plc.directory/{DID}/log/audit":
        return (FIX / "bsky-app-plc-audit.json").read_bytes(), {}
    if "com.atproto.sync.getRecord" in url and "rkey=3mxhdhodv222n" in url:
        assert url.startswith("https://puffball.us-east.host.bsky.network/xrpc/")
        return (FIX / "bsky-app-post-3mxhdhodv222n.car").read_bytes(), {"Date": "Fri, 10 Oct 2026 02:05:01 GMT"}
    raise AssertionError(f"unexpected URL {url}")


def test_capture_offline(tmp_path):
    meta = capture.capture(URI, str(tmp_path / "cap"), get=fake_get)
    assert meta["verdict_at_capture"] == "present"
    assert meta["record_cid"] == "bafyreiguowippsvmump7jfcfqtghlwd6rftalwndc2ctl7wknwtnnh5ddq"
    assert {f["file"] for f in meta["fetches"]} == {"did-document.json", "identity.json", "proof.car"}
    assert all(len(f["sha256"]) == 64 for f in meta["fetches"])
    assert json.loads((tmp_path / "cap" / "capture.json").read_text())["uri"] == URI
    with pytest.raises(FileExistsError):  # never overwrite a capture
        capture.capture(URI, str(tmp_path / "cap"), get=fake_get)


def test_identity_urls_and_guards():
    assert capture.identity_urls("did:web:example.com") == {
        "document": "https://example.com/.well-known/did.json", "history": None}
    assert capture.identity_urls("did:web:localhost%3A8443")["document"] == \
        "https://localhost:8443/.well-known/did.json"
    for bad in ("did:web:example.com:user:alice", "did:key:zabc"):
        with pytest.raises(ValueError):
            capture.identity_urls(bad)
    with pytest.raises(ValueError):
        capture.pds_endpoint({"service": [{"id": "#atproto_pds", "serviceEndpoint": "http://insecure"}]})


def test_wrong_did_document_rejected(tmp_path):
    def lying_get(url):
        if url.endswith(DID):
            return json.dumps({"id": "did:plc:someoneelse"}).encode(), {}
        raise AssertionError(url)
    with pytest.raises(ValueError, match="DID document is for"):
        capture.capture(URI, str(tmp_path / "x"), get=lying_get)


@pytest.mark.skipif(not os.environ.get("ATPROOF_LIVE"), reason="set ATPROOF_LIVE=1 to hit the network")
def test_capture_live(tmp_path):
    meta = capture.capture(URI, str(tmp_path / "live"))
    assert meta["verdict_at_capture"] in ("present", "absent")


def test_http_get_size_limit(monkeypatch):
    class Resp:
        headers = {}
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def read(self, n): return b"x" * n
    monkeypatch.setattr(capture.urllib.request, "urlopen", lambda req, timeout: Resp())
    with pytest.raises(ValueError, match="exceeds"):
        capture.http_get("https://example.invalid/big", limit=1000)


def test_only_https_is_fetched():
    import pytest

    from atproof import capture

    for url in ("file:///etc/passwd", "http://plc.directory/x", "ftp://host/x"):
        with pytest.raises(ValueError, match="non-https"):
            capture.http_get(url)
