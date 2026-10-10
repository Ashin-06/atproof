# 05 · Validation and Experiment Plan

## Done (10 Oct 2026, real data from @bsky.app, saved as fixtures)
- Inclusion proof: 8 blocks hash-verified; all re-encode byte-identically; commit signature valid (secp256k1) with the key from the PLC audit log in force at the commit's `rev` time; MST walk (depth 6) finds the record; record CID equals the server-listed CID; post-key TID equals `createdAt` to the millisecond.
- Absence proof for a non-existent key: signature valid, walk ends `absent`.

## Still to do
| ID | Test | Why |
|---|---|---|
| E1 | Own test account: post → capture inclusion → delete → capture absence → package → verify offline | the full deleted-post workflow end to end |
| E2 | Same with a post **edited** (record updated at the same path) | show the package binds content per revision |
| E3 | P-256 signing key (self-hosted PDS) | second curve on real data |
| E4 | Key rotation: verify an old commit after the account rotates its key | key-history logic on a real rotation |
| E5 | did:web account | no audit log: document the limitation on a real case |
| E6 | Full repo export (`getRepo`) for a mid-size test repo | large CARs, many MST layers |
| E7 | Firehose commit (`#commit` event CAR slice) for create and delete | proofs captured from the event stream |
| E8 | Tampering: flip bytes in record, node, commit; swap the key | every check must fail loudly |
| E9 | Independent cross-check with Go indigo `VerifyCommitSignatureFromCar` on the same CARs | a second implementation agrees |
