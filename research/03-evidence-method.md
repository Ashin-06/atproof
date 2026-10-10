# 03 · The Evidence Method

## Package contents
| Item | Captured | Proves |
|---|---|---|
| **Inclusion proof** (`getRecord` CAR while the post was live, or a repo export, or the firehose commit that created it) | before deletion | the account's repo, at revision X, contained record R at `collection/rkey` with content C |
| **Identity history** (did:plc audit log; for did:web a saved DID document) | any time (audit log is append-only) | which public key was the account's signing key at revision X's time |
| **Absence proof** (`getRecord` CAR for the same path after deletion) | after deletion | the account's repo, at a later revision Y, does not contain `collection/rkey` |
| **Manifest** | when packaging | SHA-256 of every file, capture times, tool version |

## Verification (all offline)
1. Every block's SHA-256 matches its CID (detects any edit to any byte).
2. The commit decodes, re-encodes to the same CID, and is signed (low-S ECDSA) by the key in force at the commit's time per the identity history.
3. The commit's DID matches the identity history's DID and the record path.
4. The MST walk from the commit's root reaches the path: **present** (record CID matches and decodes) or **absent** (the walk ends on a missing link, with every node on the path present and well-ordered).
5. Revision Y is later than revision X (TID order).

## What a passing package shows
- The account's signing key signed a repository state containing that exact record content, and later signed a state without it.

## What it does not show (state these in every report)
- **Who pressed "post".** For accounts hosted by Bluesky or another provider, the **server holds the signing key**. The signature binds the account's host, not a human.
- **When it was captured.** `rev` and `createdAt` are claims. Add an independent timestamp (RFC 3161 TSA, or a notarised hash) over the package if timing matters.
- **That nothing was edited in between.** A record can be updated at the same path; each proof binds the content at its own revision only.
- **Key compromise.** If the key leaked, signatures prove nothing. Check the identity history for unexpected rotations around the time.
- **did:web history.** Without a saved earlier DID document, an old commit cannot be tied to an old key.

## Why absence needs the full path
A CAR that simply lacks the record proves nothing. An absence proof must contain every node from the signed root down to the point where the key would sit, so the walk ends on an empty link. `atproof` reports `unproven` if any needed node is missing, rather than `absent`.
