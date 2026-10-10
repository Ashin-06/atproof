# 06 · Paper Plan

**Working title:** "Signed but Gone: Verifiable Evidence of Deleted Posts on the AT Protocol"

**Venues:** DFRWS (FSI: Digital Investigation); a short paper at a web/social-media measurement or law-and-technology venue for the custodial-key and privacy discussion.

## Outline
1. Introduction: deleted posts in harassment, litigation and journalism; atproto's signed repositories
2. Background: DRISL, CIDs, CAR, MST, commits, DID PLC audit log, TIDs
3. Related work: social-media evidence preservation, web archiving and authenticity, Merkle-tree transparency logs
4. Method: inclusion + identity history + absence; verification steps; trust assumptions
5. Implementation: `atproof`, strict decoding, canonical re-encoding, path validation
6. Evaluation: real proofs from several PDS types; tampering; key rotation; did:web; cross-check with indigo
7. Discussion: custodial keys; timing claims; privacy and targeted preservation; what platforms could add (signed deletion receipts)
8. Conclusion

## Contributions
1. A precise account of what an atproto signature does and does not prove about a deleted post.
2. An offline evidence-package format and verifier, validated on real network data.
3. Recommendations for platforms and courts.
