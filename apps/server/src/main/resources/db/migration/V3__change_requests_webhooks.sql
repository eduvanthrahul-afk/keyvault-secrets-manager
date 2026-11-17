-- Protected environments: developers must propose changes; an admin who is NOT the author approves.
ALTER TABLE environments ADD COLUMN protected BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE change_requests (
    id              UUID PRIMARY KEY,
    environment_id  UUID         NOT NULL REFERENCES environments(id) ON DELETE CASCADE,
    author_id       UUID         REFERENCES users(id) ON DELETE SET NULL,
    title           VARCHAR(140) NOT NULL,
    status          VARCHAR(16)  NOT NULL CHECK (status IN ('OPEN','APPLIED','REJECTED','CANCELLED','CONFLICT')),
    key_version     INT          NOT NULL,
    reviewer_id     UUID         REFERENCES users(id) ON DELETE SET NULL,
    review_comment  VARCHAR(500),
    created_at      TIMESTAMPTZ  NOT NULL,
    closed_at       TIMESTAMPTZ
);
CREATE INDEX idx_cr_env_status ON change_requests(environment_id, status, created_at DESC);

-- Each item carries ciphertext produced by the author's browser; the server never sees plaintext.
CREATE TABLE change_request_items (
    id                  BIGSERIAL PRIMARY KEY,
    change_request_id   UUID        NOT NULL REFERENCES change_requests(id) ON DELETE CASCADE,
    op                  VARCHAR(8)  NOT NULL CHECK (op IN ('CREATE','UPDATE','DELETE')),
    secret_id           UUID        NOT NULL,
    expected_version    INT,
    name_index          VARCHAR(64),
    name_ciphertext     TEXT,
    value_ciphertext    TEXT,
    comment_ciphertext  TEXT
);
CREATE INDEX idx_cr_items ON change_request_items(change_request_id);

-- Outgoing webhooks (transactional outbox). Payloads carry ids and metadata only, never secret material.
CREATE TABLE webhooks (
    id              UUID PRIMARY KEY,
    project_id      UUID         NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    environment_id  UUID         REFERENCES environments(id) ON DELETE CASCADE,
    url             VARCHAR(2048) NOT NULL,
    secret_enc      TEXT         NOT NULL,     -- signing secret, AES-GCM with the server key (server must sign)
    events          VARCHAR(500) NOT NULL,     -- comma-separated event names, or '*'
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by      UUID         REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ  NOT NULL,
    consecutive_failures INT     NOT NULL DEFAULT 0
);
CREATE INDEX idx_webhooks_project ON webhooks(project_id);

CREATE TABLE webhook_deliveries (
    id               UUID PRIMARY KEY,
    webhook_id       UUID         NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event            VARCHAR(64)  NOT NULL,
    payload          TEXT         NOT NULL,
    status           VARCHAR(12)  NOT NULL CHECK (status IN ('PENDING','SUCCEEDED','FAILED')),
    attempts         INT          NOT NULL DEFAULT 0,
    next_attempt_at  TIMESTAMPTZ  NOT NULL,
    response_code    INT,
    last_error       VARCHAR(500),
    created_at       TIMESTAMPTZ  NOT NULL,
    delivered_at     TIMESTAMPTZ
);
CREATE INDEX idx_deliveries_due ON webhook_deliveries(status, next_attempt_at);
CREATE INDEX idx_deliveries_webhook ON webhook_deliveries(webhook_id, created_at DESC);
