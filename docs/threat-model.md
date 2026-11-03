# Threat model

What the verification service protects, from whom, and what is still open. Written for the 1.0.0
code; nobody independent has reviewed it.

## What it protects

| Asset | Where it lives |
|---|---|
| Verdicts (`present`, `absent`, `proven`, …) that may be cited in a case | API responses and the `verifications` table |
| Submitted proofs and identity logs | request bodies only; not stored |
| API keys | callers hold the key; the service holds only SHA-256 hashes |

The worst outcome is a wrong verdict: reporting that a post existed, or was deleted, when the
evidence does not show it.

## Trust boundaries

1. **Examiner → service.** CARs and identity logs may be forged or corrupted on purpose.
2. **Service → network.** None: the service verifies offline. Capturing proofs from a PDS stays a
   command-line step on the examiner's machine.

## Threats and what stops them

| Threat | Mitigation | Residual risk |
|---|---|---|
| A forged or altered proof gets a positive verdict | Every block's hash is checked against its CID; the commit signature is checked (low-S enforced) with the key the identity log says was in force at that revision; the tree walk must reach the record | The signature shows the account's host published it, not which person wrote it (listed in every report) |
| Proofs submitted in the wrong order, or never removed | The deletion check requires the inclusion revision before the absence revision and an absence proof that verifies | — |
| Malformed CBOR exhausts the decoder | Depth and size limits; malformed input ends as verdict `failed`, never an exception | — |
| The server is made to fetch arbitrary URLs (SSRF) | The API never fetches; `capture` only fetches `https://` URLs | — |
| Someone reads the log or runs verifications | API keys with roles; no CORS unless listed | Every `viewer` sees every entry |
| Errors leak data | Validation errors don't echo input; unhandled errors return only a request ID | — |
| A verdict is disputed later | The log keeps the SHA-256 of every input, the URI and the verdict; evidence packages carry their own SHA-256 manifest | The log itself is not signed or hash-chained |
| Upload flooding | 70 MB body cap, per-client rate limit | Rate limit is per process |

## Not covered

- A trusted timestamp over packages (add RFC 3161 if timing matters).
- Key compromise: if the account's signing key leaked, signatures prove nothing.
- TLS (terminate it at the ingress).
