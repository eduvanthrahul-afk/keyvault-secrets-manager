-- KeyVault v2 schema. The server stores only ciphertext, wrapped keys and verifiers.
-- Nothing in this database is sufficient to decrypt a secret.

CREATE TABLE users (
    id                              UUID PRIMARY KEY,
    email                           VARCHAR(320) NOT NULL UNIQUE,
    display_name                    VARCHAR(80)  NOT NULL,
    auth_hash                       VARCHAR(255) NOT NULL,           -- Argon2id(authKey) — authKey itself is derived client-side
    kdf_algorithm                   VARCHAR(16)  NOT NULL,
    kdf_memory_kib                  INT          NOT NULL,
    kdf_iterations                  INT          NOT NULL,
    kdf_parallelism                 INT          NOT NULL,
    salt                            VARCHAR(64)  NOT NULL,
    protected_account_key           TEXT         NOT NULL,           -- account key wrapped by password KEK
    public_key                      VARCHAR(64)  NOT NULL,           -- X25519
    protected_private_key           TEXT         NOT NULL,           -- wrapped by account key
    recovery_verifier_hash          VARCHAR(64)  NOT NULL,           -- SHA-256(recovery verifier)
    recovery_protected_account_key  TEXT         NOT NULL,           -- account key wrapped by recovery KEK
    totp_secret_enc                 TEXT,                            -- server-side AES-GCM (TOTP must be verified server-side)
    totp_enabled                    BOOLEAN      NOT NULL DEFAULT FALSE,
    totp_last_step                  BIGINT       NOT NULL DEFAULT 0, -- replay protection
    created_at                      TIMESTAMPTZ  NOT NULL,
    updated_at                      TIMESTAMPTZ  NOT NULL
);

CREATE TABLE totp_recovery_codes (
    id          UUID PRIMARY KEY,
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   VARCHAR(64) NOT NULL,
    used_at     TIMESTAMPTZ
);
CREATE INDEX idx_totp_codes_user ON totp_recovery_codes(user_id);

CREATE TABLE sessions (
    id            UUID PRIMARY KEY,
    user_id       UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash    VARCHAR(64)  NOT NULL UNIQUE,                      -- SHA-256 of the opaque cookie value
    created_at    TIMESTAMPTZ  NOT NULL,
    last_seen_at  TIMESTAMPTZ  NOT NULL,
    expires_at    TIMESTAMPTZ  NOT NULL,                             -- absolute lifetime
    ip            VARCHAR(64),
    user_agent    VARCHAR(255),
    revoked_at    TIMESTAMPTZ
);
CREATE INDEX idx_sessions_user ON sessions(user_id);

CREATE TABLE projects (
    id           UUID PRIMARY KEY,
    name         VARCHAR(80)  NOT NULL,
    description  VARCHAR(500) NOT NULL DEFAULT '',
    created_by   UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ  NOT NULL,
    updated_at   TIMESTAMPTZ  NOT NULL
);

CREATE TABLE project_members (
    project_id  UUID        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        VARCHAR(16) NOT NULL CHECK (role IN ('OWNER','ADMIN','DEVELOPER','VIEWER')),
    created_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (project_id, user_id)
);
CREATE INDEX idx_members_user ON project_members(user_id);

CREATE TABLE environments (
    id                UUID PRIMARY KEY,
    project_id        UUID        NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name              VARCHAR(40) NOT NULL,
    slug              VARCHAR(40) NOT NULL,
    position          INT         NOT NULL,
    key_version       INT         NOT NULL DEFAULT 1,
    rotation_needed   BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL,
    UNIQUE (project_id, slug)
);

-- Environment key sealed to a specific member's public key. Possessing a row = cryptographic access.
CREATE TABLE environment_key_grants (
    environment_id  UUID        NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    wrapped_key     TEXT        NOT NULL,
    key_version     INT         NOT NULL,
    granted_by      UUID        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (environment_id, user_id)
);
CREATE INDEX idx_grants_user ON environment_key_grants(user_id);

CREATE TABLE secrets (
    id                  UUID PRIMARY KEY,                            -- client generated (bound into AEAD context)
    environment_id      UUID        NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name_index          VARCHAR(64) NOT NULL,                        -- HMAC blind index → uniqueness without plaintext
    name_ciphertext     TEXT        NOT NULL,
    value_ciphertext    TEXT        NOT NULL,
    comment_ciphertext  TEXT,
    version             INT         NOT NULL,
    key_version         INT         NOT NULL,
    created_by          UUID        NOT NULL,
    updated_by          UUID        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    updated_at          TIMESTAMPTZ NOT NULL,
    UNIQUE (environment_id, name_index)
);

CREATE TABLE secret_versions (
    id                  BIGSERIAL PRIMARY KEY,
    secret_id           UUID        NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    version             INT         NOT NULL,
    name_index          VARCHAR(64) NOT NULL,
    name_ciphertext     TEXT        NOT NULL,
    value_ciphertext    TEXT        NOT NULL,
    comment_ciphertext  TEXT,
    key_version         INT         NOT NULL,
    change_type         VARCHAR(16) NOT NULL,
    changed_by          UUID        NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL,
    UNIQUE (secret_id, version)
);

CREATE TABLE service_tokens (
    id               UUID PRIMARY KEY,
    token_id         VARCHAR(32)  NOT NULL UNIQUE,
    environment_id   UUID         NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    name             VARCHAR(80)  NOT NULL,
    verifier         VARCHAR(64)  NOT NULL,                          -- SHA-256(authSecret); authSecret is 256-bit random
    wrapped_env_key  TEXT         NOT NULL,
    key_version      INT          NOT NULL,
    created_by       UUID         NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL,
    expires_at       TIMESTAMPTZ,
    last_used_at     TIMESTAMPTZ,
    last_used_ip     VARCHAR(64),
    revoked_at       TIMESTAMPTZ
);
CREATE INDEX idx_tokens_env ON service_tokens(environment_id);

CREATE TABLE sends (
    id           VARCHAR(32)  PRIMARY KEY,
    ciphertext   TEXT         NOT NULL,
    max_views    INT          NOT NULL,
    view_count   INT          NOT NULL DEFAULT 0,
    expires_at   TIMESTAMPTZ  NOT NULL,
    created_by   UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ  NOT NULL
);
CREATE INDEX idx_sends_expiry ON sends(expires_at);

-- Tamper-evident audit log: each event hashes the previous event of the same chain.
-- No FK to projects on purpose: the trail must outlive deleted projects.
CREATE TABLE audit_events (
    seq           BIGSERIAL PRIMARY KEY,
    chain_key     VARCHAR(64)  NOT NULL,                             -- "project:<id>" or "user:<id>"
    chain_index   BIGINT       NOT NULL,
    occurred_at   TIMESTAMPTZ  NOT NULL,
    actor_type    VARCHAR(16)  NOT NULL,
    actor_id      UUID,
    actor_label   VARCHAR(320) NOT NULL,
    project_id    UUID,
    action        VARCHAR(64)  NOT NULL,
    target_type   VARCHAR(32),
    target_id     VARCHAR(64),
    ip            VARCHAR(64),
    user_agent    VARCHAR(255),
    details       TEXT         NOT NULL DEFAULT '{}',
    prev_hash     VARCHAR(64)  NOT NULL,
    hash          VARCHAR(64)  NOT NULL,
    UNIQUE (chain_key, chain_index)
);
CREATE INDEX idx_audit_project ON audit_events(project_id, seq DESC);
CREATE INDEX idx_audit_actor ON audit_events(actor_id, seq DESC);

CREATE TABLE audit_chain_heads (
    chain_key    VARCHAR(64) PRIMARY KEY,
    last_index   BIGINT      NOT NULL,
    last_hash    VARCHAR(64) NOT NULL
);
