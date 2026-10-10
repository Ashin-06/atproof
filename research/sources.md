# Sources (accessed 10 Oct 2026)

## Specifications
- Repository spec: https://atproto.com/specs/repository
- Cryptography spec: https://atproto.com/specs/cryptography
- Data model (DRISL/DAG-CBOR): https://atproto.com/specs/data-model
- `com.atproto.sync.getRecord`: https://docs.bsky.app/docs/api/com-atproto-sync-get-record
- Repo export blog: https://atproto.com/blog/repo-export
- AT Protocol overview: https://docs.bsky.app/docs/advanced-guides/atproto
- History removal discussion: https://github.com/bluesky-social/atproto/discussions/1410
- PLC directory: https://plc.directory

## Prior and related work
- Final Words (deleted-post feed): https://flowingdata.com/2024/11/19/stream-of-deleted-bluesky-posts/
- my-post-has-an-alibi: https://github.com/Megghaanaa/my-post-has-an-alibi
- Go indigo repo package: https://pkg.go.dev/github.com/bluesky-social/indigo/atproto/repo
- War on CARs (library survey): https://data-service-diaries.pckt.blog/war-on-cars-5xa5v73
- Under Bluesky's hood: https://a-cup-of.coffee/blog/atproto-pds/
- Bluesky and the AT Protocol (paper): https://arxiv.org/pdf/2402.03239

## Test fixtures (public data, official @bsky.app account, captured 10 Oct 2026)
| File | Source |
|---|---|
| `bsky-app-post-3mxhdhodv222n.car` | `https://puffball.us-east.host.bsky.network/xrpc/com.atproto.sync.getRecord?did=did:plc:z72i7hdynmk6r22z27h6tvur&collection=app.bsky.feed.post&rkey=3mxhdhodv222n` |
| `bsky-app-absent-3zzzzzzzzzzzz.car` | same endpoint, `rkey=3zzzzzzzzzzzz` (does not exist) |
| `bsky-app-plc-audit.json` | `https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur/log/audit` |
| `bsky-app-did.json` | `https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur` |
| `bsky-app-post-expected.json` | `com.atproto.repo.listRecords` for the same post (URI, CID, text, createdAt) |
