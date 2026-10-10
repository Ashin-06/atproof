# 04 · Legal and Ethical Ground Rules

Not legal advice.

## Scope: targeted preservation, not a deleted-post archive
- Deleting a post is often a deliberate choice (regret, safety, privacy). A system that collects everyone's deleted posts (like the Final Words feed) overrides that choice at scale. **`atproof` has no firehose collector and no bulk mode.** It preserves and verifies **specific records** for a **specific purpose**: a harassment victim keeping abusive posts, a journalist or researcher documenting a public statement, a party to litigation, an investigator under legal authority.
- Preserve the minimum: the one record's proof and the identity history, not the whole account.

## Data protection
- Posts are public, but they are personal data. Under GDPR / UK GDPR, keeping a deleted post needs a lawful basis (e.g. legitimate interests, legal claims: Art. 17(3)(e) exempts data needed for legal claims from erasure). India's DPDP Act 2023 and US state laws have their own rules.
- Store packages securely, record why each was made, delete them when the purpose ends.

## Evidence standards
- Keep originals unmodified; work on copies; hash everything (the package manifest does this).
- Report with the "does not show" list from [03](03-evidence-method.md). Overstating what a signature proves (especially the custodial-key point) is the main risk of misuse.
- ISO/IEC 27037 for preservation; consider an RFC 3161 timestamp on the manifest.

## Testing
- Validation used **one public post from the official @bsky.app account** and a non-existent key, nothing else. Deletion experiments use the project's own test account only.
