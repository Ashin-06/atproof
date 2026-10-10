# 01 · Prior Art and the Gap

Searched 10 Oct 2026 (web standard + extended, GitHub, atproto docs and discussions).

| Work | What it does | What it does not do |
|---|---|---|
| [Final Words](https://flowingdata.com/2024/11/19/stream-of-deleted-bluesky-posts/) | listens to the firehose for deletions and shows the deleted text once, anonymised | no proof, no verification, a public feed of deleted posts (a privacy problem, not evidence) |
| [my-post-has-an-alibi](https://github.com/Megghaanaa/my-post-has-an-alibi) | verifies a **live** Bluesky post from scratch (talk material) | nothing for deleted posts, no evidence package |
| Go [indigo `atproto/repo`](https://pkg.go.dev/github.com/bluesky-social/indigo/atproto/repo) | library: load CARs, `VerifyCommitSignatureFromCar` | a library, not an evidence workflow; no identity history, no absence proof |
| Rust atproto-repo / proto-blue, atcute `verifyRecord` | verify records and CIDs | same |
| Python `atproto` SDK | client library | does **not** verify CIDs (per the survey below) |
| [*War on CARs*](https://data-service-diaries.pckt.blog/war-on-cars-5xa5v73) | survey of CAR handling across libraries | points out that the signature covers only the MST root, so per-block checks are essential |
| [`com.atproto.sync.getRecord`](https://docs.bsky.app/docs/api/com-atproto-sync-get-record) | server returns a CAR proving a record's presence **or absence** in the current repo | proves only the current state |

## What the protocol does and does not keep
- Deleting a record leaves **no tombstone** of its content in the repo ([repository spec](https://atproto.com/specs/repository)).
- Commit history is not retained: `prev` is virtually always null and older history was truncated ([discussion #1410](https://github.com/bluesky-social/atproto/discussions/1410)).
- So **a deleted post can only be proven from a copy saved before the deletion**: a `getRecord` proof, a repo export, or a firehose commit that carried it.

## Gap
No tool turns those saved bytes into an evidence package that a third party can check offline:
1. every block's hash matches its content ID,
2. the commit is signed by the key the account's identity log says was in force at that time,
3. the record sits in that commit's tree at the claimed path,
4. a later signed state of the same account **does not** contain it,
5. with the inputs hashed and the limits stated plainly.

## Gap statement
> Bluesky posts are signed, but deletion erases them from the repository without a trace, and no tool produces verifiable evidence that a deleted post existed. We give a method and an offline verifier that combine a preserved inclusion proof, the account's key history and a later absence proof, and we state exactly what such a package does and does not prove.
