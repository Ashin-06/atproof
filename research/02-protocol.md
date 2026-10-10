# 02 · The Parts of the Protocol the Proof Uses

All formats below are implemented in `atproof/` and checked against real data from the official `@bsky.app` account (`tests/fixtures/`, captured 10 Oct 2026).

## Encoding
- **DRISL / DAG-CBOR**: strict CBOR. No floats, no indefinite lengths, string map keys, CID links as tag 42 with a leading `0x00`. Map keys sorted **by length, then bytewise**. Confirmed on real data: the commit's keys appear as `did, rev, sig, data, prev, version`, and re-encoding all 8 blocks of a real proof reproduces them byte for byte.
- **CID**: v1, codec `0x71` (dag-cbor) or `0x55` (raw, blobs), multihash sha2-256 (`0x12 0x20`). String form: `b` + lowercase base32.
- **CAR v1**: varint-length header `{version: 1, roots: [CID]}`, then `varint(len) + CID + block` sections. The first root is the commit.

## Repository
- **Commit (v3)**: `{did, version: 3, data: MST root CID, rev: TID, prev: null, sig: bytes}`. The signature is ECDSA over SHA-256 of the DRISL encoding of the commit **without** `sig`.
- **MST**: nodes `{l, e: [{p, k, v, t}]}`; keys are `collection/rkey`; a key's layer = leading zero bits of sha256(key) // 2 (fanout 4).
- **What the signature covers**: only the commit, which names the MST root. Each node and record is bound by its hash, so every block must be hash-checked and the path walked. A signature check alone proves nothing about a particular record.

## Keys and identity
- Signatures are 64-byte compact `r||s`, **low-S**, on secp256k1 (`k256`, multicodec `0xE7 0x01`) or P-256 (`0x80 0x24`). Public keys are multibase `z` + base58btc. The real `@bsky.app` key is secp256k1.
- **did:plc** identities keep an append-only **audit log** at `https://plc.directory/<did>/log/audit`: every operation with its time, rotation keys and `verificationMethods.atproto` signing key. That gives the key **in force at any past time**, which is what an old commit must be checked against after a key rotation.
- **did:web** identities have only a current document. Old signatures cannot be tied to a past key without an independent saved copy.

## Times
- `rev` and post record keys are **TIDs**: base32-sortable, 53 bits of microseconds since 1970 plus a 10-bit clock id. Real check: post key `3mxhdhodv222n` decodes to `2026-10-09T15:53:59.424Z`, identical to the post's `createdAt`.
- Both times are **claimed by the server and the client**, not by a trusted clock.
