# ATProof: Verifiable Evidence of Deleted Bluesky Posts

**Project 4 of 5** · Status: research complete, tool in progress
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
```

## Ethics in one line
For preserving **specific** posts for a legitimate purpose. There is no firehose collector and no bulk mode, by design. Details in [research/04](research/04-legal-ethics.md).
