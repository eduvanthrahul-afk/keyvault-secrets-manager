-- Passkey (WebAuthn PRF) unlock. Each row is the Account Key wrapped by a key that only the
-- user's authenticator can re-derive. The server cannot unwrap it.
CREATE TABLE passkeys (
    id                   UUID PRIMARY KEY,
    user_id              UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id        VARCHAR(512) NOT NULL,
    name                 VARCHAR(80)  NOT NULL,
    prf_salt             VARCHAR(64)  NOT NULL,
    wrapped_account_key  TEXT         NOT NULL,
    created_at           TIMESTAMPTZ  NOT NULL,
    last_used_at         TIMESTAMPTZ,
    UNIQUE (user_id, credential_id)
);
CREATE INDEX idx_passkeys_user ON passkeys(user_id);
