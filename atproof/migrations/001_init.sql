-- The verification log: one row per check. Submitted CARs are not stored, only the SHA-256 of each
-- input (inputs), so a verdict can be tied to the exhibit files kept in the case's evidence package.
CREATE TABLE verifications (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    kind TEXT NOT NULL,
    uri TEXT NOT NULL,
    label TEXT NOT NULL,
    inputs TEXT NOT NULL,
    verdict TEXT NOT NULL,
    failures INTEGER NOT NULL
);
CREATE INDEX verifications_created ON verifications (created_at);
