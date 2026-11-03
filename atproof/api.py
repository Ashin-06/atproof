"""Verification service: proof checking behind an API, with a log of every verification.

    POST /v1/verify                 one inclusion or absence proof CAR for a record [verify]
    POST /v1/deleted                a record existed (inclusion proof) and was later removed (absence proof) [verify]
    GET  /v1/verifications[/{id}]   the verification log: who checked which inputs (by SHA-256), the verdict [read]
    GET  /healthz, /readyz, /metrics

Everything is verified offline from the submitted bytes; the service never contacts a PDS or the
PLC directory (capturing proofs stays a command-line step, so callers can't make the server fetch
arbitrary URLs). Submitted CARs are not stored: each verification keeps the SHA-256 of its inputs,
the record URI, the verdict and who asked. Callers send an API key whose role decides the
permissions in brackets; settings come from ATPROOF_* variables (see ops.py and docs/runbook.md).

    python -m atproof serve
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import text

from . import db, ops, verify

settings = ops.load_settings()
ops.setup_logging(settings.log_level)
engine = db.connect(settings.database_url)
_lock = threading.Lock()

app = FastAPI(title="ATProof verification service", version="1.0.0")
ops.install(app, settings, {"database": lambda: engine.connect().close()})

CAR_B64 = Field(..., min_length=4, max_length=ops.MAX_BODY_BYTES, description="the CAR file, base64-encoded")


def _bytes(b64: str, what: str) -> bytes:
    try:
        return base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        raise HTTPException(422, f"{what} is not valid base64") from None


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _identity_sha(identity: Any) -> str:
    return _sha(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode())


def _path(uri: str) -> str:
    try:
        return verify.parse_uri(uri)[1]
    except ValueError:
        raise HTTPException(422, "uri must be at://<did>/<collection>/<rkey>") from None


def _log(ident: dict, kind: str, uri: str, label: str, inputs: Dict[str, str], verdict: str, failures: int) -> str:
    vid = uuid.uuid4().hex
    with _lock, engine.begin() as c:
        c.execute(text("INSERT INTO verifications VALUES (:i, :t, :u, :k, :r, :l, :n, :v, :f)"),
                  {"i": vid, "t": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
                   "u": ident["user"] or "demo", "k": kind, "r": uri, "l": label, "n": json.dumps(inputs),
                   "v": verdict, "f": failures})
    ops.DECISIONS.labels(decision=verdict.replace(" ", "_")).inc()
    return vid


class VerifyRequest(BaseModel):
    car: str = CAR_B64
    identity: Dict[str, Any] | list = Field(..., description="did:plc audit log or DID document")
    uri: str = Field(..., max_length=500, description="at://<did>/<collection>/<rkey>")
    label: str = Field("", max_length=200, description="case reference, for the verification log")


class DeletedRequest(BaseModel):
    inclusion: str = CAR_B64
    absence: str = CAR_B64
    identity: Dict[str, Any] | list
    uri: str = Field(..., max_length=500)
    label: str = Field("", max_length=200)


@app.post("/v1/verify")
def verify_one(req: VerifyRequest, ident: dict = Depends(ops.require("verify"))) -> Dict[str, Any]:
    path, car = _path(req.uri), _bytes(req.car, "car")
    rep = verify.verify_proof(car, req.identity, path)
    inputs = {"car": _sha(car), "identity": _identity_sha(req.identity)}
    vid = _log(ident, "proof", req.uri, req.label, inputs, rep["verdict"], len(rep.get("failures", [])))
    return {"verification_id": vid, "inputs": inputs, **rep, "limits": verify.LIMITS}


@app.post("/v1/deleted")
def verify_deleted(req: DeletedRequest, ident: dict = Depends(ops.require("verify"))) -> Dict[str, Any]:
    path = _path(req.uri)
    inc, ab = _bytes(req.inclusion, "inclusion"), _bytes(req.absence, "absence")
    rep = verify.verify_deleted(inc, ab, req.identity, path)
    inputs = {"inclusion": _sha(inc), "absence": _sha(ab), "identity": _identity_sha(req.identity)}
    vid = _log(ident, "deleted", req.uri, req.label, inputs, rep["verdict"], len(rep["reasons"]))
    return {"verification_id": vid, "inputs": inputs, **rep}


def _row(r) -> Dict[str, Any]:
    d = dict(r)
    if "inputs" in d:
        d["inputs"] = json.loads(d["inputs"])
    return d


@app.get("/v1/verifications", dependencies=[Depends(ops.require("read"))])
def list_verifications(limit: int = Query(50, ge=1, le=1000)) -> Dict[str, Any]:
    with engine.connect() as c:
        rows = c.execute(text("SELECT * FROM verifications ORDER BY created_at DESC LIMIT :n"), {"n": limit}).mappings().all()
    return {"verifications": [_row(r) for r in rows]}


@app.get("/v1/verifications/{verification_id}", dependencies=[Depends(ops.require("read"))])
def get_verification(verification_id: str) -> Dict[str, Any]:
    with engine.connect() as c:
        r = c.execute(text("SELECT * FROM verifications WHERE id = :i"), {"i": verification_id[:64]}).mappings().first()
    if r is None:
        raise HTTPException(404, "verification not found")
    return _row(r)
