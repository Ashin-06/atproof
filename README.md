# ATProof: Verifiable Evidence of Deleted Bluesky Posts

**Project 4 of 5** · Status: research complete, tool built and tested (29 tests + live check), lab experiments E1-E9 pending
Research cut-off: 10 Oct 2026

## What this is

Every Bluesky post lives in a repository that the account's key signs. When a post is deleted, the protocol erases it without a trace and keeps no history. So the only way to prove later that a deleted post existed is a copy saved **before** deletion, and nobody has built a way to turn that copy into evidence a court, a platform or a journalist's editor can check independently.

ATProof does that. It combines:
1. an **inclusion proof** saved while the post was live (the server's own signed proof, a repo export or a firehose commit);
2. the account's **key history** from its public identity log, so an old signature is checked against the key in force at the time;
3. a later **absence proof** showing the same account's signed repo no longer contains the post.

It verifies everything **offline**: every byte's hash, the commit signature, the tree path, and the order of the two revisions. It also writes plainly what the result does **not** prove.

## Already validated on real data
Using a public post from the official `@bsky.app` account (saved in `tests/fixtures/`):
- all blocks hash-verify and re-encode byte for byte;
- the commit signature verifies (secp256k1) with the key the identity log says was in force;
- the tree walk finds the post, and its ID matches the server's listing exactly;
- the post key's timestamp equals the post's `createdAt` to the millisecond;
- an absence proof for a non-existent post verifies as signed and absent.

## The big caveat
On accounts hosted by Bluesky (most accounts), **the server holds the signing key**. A valid signature shows the account's host published that content under that account, not which human typed it. Every report says so. Details in [research/03](research/03-evidence-method.md).

## Repository layout
```
04-atproto-deleted-post-proof/
├── README.md
├── research/
│   ├── 01-prior-art.md          what exists (Final Words, indigo, alibi talk), the gap
│   ├── 02-protocol.md           DRISL, CIDs, CAR, MST, commits, keys, PLC log, TIDs
│   ├── 03-evidence-method.md    the package, verification steps, what it does NOT show
│   ├── 04-legal-ethics.md       targeted preservation only, data protection
│   ├── 05-experiment-plan.md    done on real data; E1-E9 still to do
│   ├── 06-paper-outline.md
│   └── sources.md               specs, prior work, fixture provenance
├── atproof/
│   ├── cbor.py                  strict DRISL/DAG-CBOR, CIDs, CAR v1, block hash checks
│   ├── mst.py                   tree lookup with proof path: present / absent / unproven
│   ├── keys.py                  secp256k1 + P-256 low-S signatures, multikeys, TIDs, PLC key history
│   ├── verify.py                proof verification, deleted-post check, evidence packages
│   ├── capture.py               preserve ONE record's proof + identity history from the network
│   └── cli.py                   `atproof` command
├── tests/                       29 tests; fixtures = real @bsky.app proofs (10 Oct 2026)
└── pyproject.toml
```

## Tool
```bash
python -m venv .venv && .venv/Scripts/pip install -e .[test]   # Linux/macOS: .venv/bin/pip
pytest -q                     # ATPROOF_LIVE=1 also runs one live capture
```

Workflow for a post you may need to prove later:
```bash
# 1. While the post is live: preserve its signed proof and the account's key history
atproof capture --uri at://did:plc:.../app.bsky.feed.post/<rkey> --out case/live

# 2. After it is deleted: capture again (now a signed absence proof)
atproof capture --uri at://did:plc:.../app.bsky.feed.post/<rkey> --out case/gone

# 3. Build the evidence package and let anyone re-check it offline
atproof package --out case/package --uri at://... --identity case/gone/identity.json \
                --inclusion case/live/proof.car --absence case/gone/proof.car --note "purpose / case ref"
atproof check-package case/package
```
Other commands: `atproof inspect <car>`, `atproof verify <car> --identity <log> --uri <at-uri>`, `atproof deleted --inclusion --absence --identity --uri`.
Use the identity log captured **last** (step 2): the audit log is append-only, so it contains every earlier key.

| Feature | Checked against | Status |
|---|---|---|
| CBOR decode/encode, CIDs, CAR | real proof: 8/8 blocks re-encode byte for byte | ✅ |
| Signature (secp256k1, P-256, low-S, compact) | real @bsky.app commit with key from PLC log; generated keys on both curves | ✅ |
| MST present / absent / unproven, ordering and layer checks | real proofs (depth 6); 300-record reference tree | ✅ |
| Key history and rotation | real PLC log; synthetic rotation before/after the commit | ✅ |
| Deleted-post verdict, packages, re-check, tamper detection | synthetic signed repos; flipped bytes, extra/unsafe manifest entries | ✅ |
| Hostile input (deep nesting, self-linking fake node, oversize responses, corrupt CARs) | crafted inputs | ✅ all end as "failed"/"unproven", never crash or hang |
| Live capture | official @bsky.app post and a non-existent key | ✅ present / absent |

### Known gaps
- **No real deletion run yet** (E1): needs the project's own test account to post, capture, delete, capture again.
- **Firehose commit slices** (E7) and **full repo exports** at scale (E6) are not exercised on real data yet; the verifier accepts any CAR whose first root is the commit.
- **Handles**: `capture` takes a DID, not a handle; resolve the handle first (`com.atproto.identity.resolveHandle` or the `_atproto` DNS record).
- **did:web** accounts have no public key history; keep your own dated copy of the DID document.
- **Timing** is only as trustworthy as the server's claims; add an RFC 3161 timestamp over `MANIFEST.sha256` if timing matters.

## Ethics in one line
For preserving **specific** posts for a legitimate purpose. There is no firehose collector and no bulk mode, by design. Details in [research/04](research/04-legal-ethics.md).
