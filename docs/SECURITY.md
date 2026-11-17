# Security model

KeyVault is designed so that **a full compromise of the server or database does not reveal any secret**. This document states exactly what that means, how it is achieved, and where the limits are.

## Goals and non-goals

| The server **cannot**… | The server **can**… |
|---|---|
| read secret names, values or notes | see project/environment names, member emails, timestamps, sizes |
| decrypt with anything stored in the DB | deny service (delete data, refuse requests) |
| log in as you with a stolen DB dump | see which user read which environment, and when |
| silently move ciphertext between slots | serve a *malicious web app* (see "Trusting the code") |

## Key hierarchy

```
master password
  └─ Argon2id(salt, m=64 MiB, t=3, p=1)                          [client, Web Worker]
       └─ master key (32 B, never stored, never sent)
            ├─ HKDF-SHA256 "auth" ─► authKey  ──► server stores Argon2id(authKey)  (m=12 MiB, t=3)
            └─ HKDF-SHA256 "kek"  ─► KEK      ──► wraps Account Key (XChaCha20-Poly1305)

recovery key (32 B random, shown once as KV1-XXXXX-…, with checksum)
  ├─ HKDF "recovery-auth" ─► verifier ──► server stores SHA-256(verifier)
  └─ HKDF "recovery-kek"  ─► second wrap of the Account Key

Account Key (32 B random)
  └─ wraps X25519 private key (identity)

Environment Key (32 B random, one per environment, versioned)
  ├─ sealed to each member's X25519 public key  (ephemeral ECDH + HKDF + XChaCha20-Poly1305)
  ├─ wrapped by each access token's wrapKey
  ├─ encrypts secret name / value / note        (AAD = project | env | secret id | field)
  └─ HKDF "blind-index" ─► HMAC-SHA256(name)    (lets the server enforce unique names blindly)
```

### Why each choice

- **Argon2id on the client, again on the server.** A database leak yields `Argon2id(authKey)`; brute-forcing a password from it costs two memory-hard derivations per guess. The authKey alone cannot decrypt anything, because the KEK comes from a separate HKDF branch.
- **Client-enforced KDF minimums.** The server supplies KDF parameters at login. A compromised server could hand out `m=1 KiB` to make the next captured authKey cheap to crack; the client refuses anything below 19 MiB / t=2 (`assertSafeKdf`).
- **XChaCha20-Poly1305.** The 192-bit nonce can be generated randomly at any volume with no collision risk, unlike AES-GCM's 96-bit nonce.
- **AEAD context binding.** Every ciphertext carries `kv|v1|secret|<project>|<env>|<secretId>|<field>` as associated data. A server that moves a production value into development, or swaps a name and a value, causes authentication to fail. The client shows "Integrity check failed".
- **Client-generated ids.** Secret, project and environment ids are UUIDv4s generated on the client so they can be bound into the AAD before the server sees them.
- **Public key self-check.** On unlock, the client recomputes its public key from the decrypted private key and refuses a server-supplied public key that doesn't match.
- **Identity seals and fingerprints.** When adding a member, the server provides their public key. A malicious server could substitute its own. The UI shows a fingerprint and guilloché seal derived from the key and asks the inviter to confirm it out-of-band (the same idea as Signal safety numbers).

## Passkey unlock (WebAuthn PRF)

```
authenticator secret ──PRF(credential, 32-byte salt)──► prfOutput      (only after fingerprint/face/PIN)
prfOutput ──HKDF "passkey-kek"──► KEK ──wraps──► Account Key           (AAD binds the credential id)
server stores: credential id, salt, wrapped Account Key
```

- The PRF output is computed inside the authenticator and never leaves the browser tab, so the server cannot unwrap the Account Key.
- Passkeys **unlock** the vault; they don't replace sign-in. The session (password and optional TOTP) is still required, so a stolen passkey without a session is useless, and vice versa.
- Registering a passkey requires re-entering the master password, because it creates a new way to decrypt the vault. Each passkey can be removed individually and is listed with its last use.
- Authenticators without PRF support are rejected at registration with a clear message instead of silently falling back to something weaker.

## Change requests (four-eyes)

A developer's browser encrypts the proposed values with the environment key and submits them as a request. The reviewer's browser decrypts both the current and the proposed values to show a real diff; values that fail AEAD verification block approval. The server enforces that the approver is an admin and is **not** the author, applies the request under the environment row lock, and refuses to overwrite a secret whose version changed since the request was opened (the request becomes `CONFLICT`). Rotating the environment key invalidates open requests, because they were encrypted under the old key.

## Webhooks

- Payloads carry ids, versions and the actor's email only. They contain no names, values or ciphertext.
- Signature: `X-KeyVault-Signature: t=<unix>,v1=hex(HMAC-SHA256(secret, "<t>.<body>"))`. Receivers should reject timestamps older than five minutes (replay protection). The signing secret is shown once and stored encrypted with the server key, because the server has to sign.
- **SSRF:** only `https://`, no userinfo in the URL, redirects are not followed, and every resolved address must be public: loopback, RFC 1918, link-local (including `169.254.169.254` cloud metadata), CGNAT, multicast and IPv6 unique-local addresses are rejected. The check runs again at delivery time, because DNS can change after a webhook is created. A determined DNS-rebinding attacker could still race the check against the connection; pinning the resolved IP is the next hardening step.
- Endpoints that fail repeatedly are disabled automatically after 20 consecutive failures.

## Client-side analysis

Health checks, environment compare and `${REFERENCE}` resolution all run on decrypted values on the client (`packages/crypto/src/insights.ts`), shared by the web app and `kv doctor` / `kv run`. Running them server-side would require the server to read values, which would break the model.

## Authentication and sessions

- **Opaque server-side sessions** (not JWTs): 256-bit random token in a `__Host-kv_session` cookie (`HttpOnly`, `Secure`, `SameSite=Strict`, path `/`). Only `SHA-256(token)` is stored. 30-minute idle and 12-hour absolute timeout. Sessions are listable and revocable, and all others are revoked on a password change.
- **CSRF**: SameSite=Strict, plus a required `X-KV-Request` header (forces a CORS preflight that is never allowed cross-origin), plus an `Origin` check against the configured app origin.
- **TOTP (RFC 6238)** with ±1 step tolerance, atomic replay protection (`UPDATE … WHERE last_step < ?`), 10 single-use recovery codes stored as SHA-256, and a 5-attempt cap per login challenge. Seeds are encrypted at rest with a server key (AES-256-GCM), because the server must be able to verify codes.
- **Re-authentication** (password re-entry) for enabling or disabling 2FA, rotating the recovery key, changing the password and deleting the account.
- **No user enumeration at login.** Unknown emails get a deterministic fake salt (`HMAC(serverKey, email)`) and an equal-cost Argon2 verification. Registration does reveal that an email is taken; that tradeoff is documented and is the same as most products.
- **Rate limits** (token bucket): per IP and per account on login, MFA, recovery and registration; per token on the machine API.

## Access tokens (machine identities)

```
token = kvs_<tokenId>.<secret>           (tokenId 128-bit, secret 256-bit, both random)
authSecret = HKDF(secret, "st-auth")     → sent as  Authorization: KV-Service-Token <tokenId>.<authSecret>
wrapKey    = HKDF(secret, "st-wrap")     → never leaves the CLI; unwraps the environment key
server stores SHA-256(authSecret) and Enc(wrapKey, envKey)
```

Tokens are read-only, scoped to one environment, can expire, record last-use IP and time, and are revoked automatically when that environment's key is rotated. The CLI strips `KEYVAULT_TOKEN` from the child process environment and refuses plain HTTP to non-local hosts.

## Offboarding and rotation

Removing a member deletes their sealed keys, but they may have kept a copy of an environment key or of the plaintext. So:
1. Every environment they could decrypt is flagged `rotation_needed`, and admins see a banner.
2. **Rotate** runs entirely in the admin's browser: decrypt every secret and every historical version, generate a new key, re-encrypt, and re-seal for the chosen members. The server validates that the payload covers exactly the stored secrets and versions (no orphaned data), checks `expectedKeyVersion` (no concurrent rotation), swaps everything in one transaction, and revokes the environment's tokens.
3. Rotation protects future values. Anything the person could already read should be changed at its source; the UI says this explicitly.

## Audit log

Each event is appended to a per-project (or per-user) chain: `hash_n = SHA-256(hash_{n-1} ‖ length-prefixed fields of event n)`. The chain head row is locked with `SELECT … FOR UPDATE`, so writers serialise. Verification recomputes the chain and detects edits, deletions, reordering and tail truncation. A DB administrator could rewrite the *entire* chain consistently; to detect that, record the head hash shown in the UI periodically (or publish it). That is a standard limit of hash chains without an external anchor.

## Web hardening

- CSP: `default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'`. No inline scripts, no third-party origins, fonts self-hosted. `wasm-unsafe-eval` permits WebAssembly compilation (Argon2) and does **not** allow JS `eval`.
- `Referrer-Policy: no-referrer`, HSTS, `X-Content-Type-Options`, `X-Frame-Options: DENY`, COOP/CORP same-origin, a restrictive `Permissions-Policy`.
- Decrypted keys live only in JS memory: never in localStorage, sessionStorage, IndexedDB or cookies. Reloading the tab locks the vault; 15 minutes of inactivity locks it too.
- Copied secrets are cleared from the clipboard after 30 s when the browser allows it.
- Request bodies are capped at 8 MiB, every ciphertext field has a size and format limit, and errors use RFC 9457 problem responses with no stack traces.

## Known limits (honest list)

- **Trusting the code.** As with every browser-based E2E product, whoever controls the server can serve modified JavaScript. Mitigations are self-hosting, Subresource-Integrity-pinned builds, or using the CLI only. This is the main reason the CLI exists.
- **Metadata** (who is in which project, when secrets change, approximate sizes) is visible to the server.
- **JS memory** cannot be reliably zeroised. Keys are wiped best-effort.
- **Metrics** are exposed only with `Authorization: Bearer $KEYVAULT_METRICS_TOKEN` (constant-time compare; endpoint locked when unset). Labels are low-cardinality and contain no emails, ids or names.
- **Rate limits are per instance** (in-memory). For horizontal scaling, move Bucket4j to its PostgreSQL or Redis backend; the call sites don't change.
- **No email verification** in v2. Registration is open by default; set `KEYVAULT_REGISTRATION_ENABLED=false` for a private instance.

## What changed from v1

v1 sent `authHash` to the server and derived the encryption key *from that same authHash*, so the server held everything needed to decrypt. It also stored the JWT in localStorage, allowed the `"null"` CORS origin, had OTP disabled, and committed a database password to git. v2 is a clean-room redesign with the separation described above.
