// Project / environment key hierarchy:
//
//   Environment Key (random 256-bit, one per environment)
//     ├─ sealed to each member's X25519 public key   → member access is cryptographic,
//     │                                                not just a server-side ACL
//     ├─ wrapped by a service-token key               → CI/CD access without a password
//     ├─ encrypts secret name / value / comment       → AAD binds project+env+secret+field
//     └─ HKDF "blind-index" → HMAC(name)              → server enforces unique names blindly

import { CryptoError, fromB64u, fromUtf8, toB64u, utf8, wipe } from './encoding';
import {
  context,
  decrypt,
  deriveSubkey,
  encrypt,
  generateKey,
  hmacSha256,
  openSealed,
  randomBytes,
  seal,
  sha256,
  type X25519KeyPair,
} from './primitives';

export interface EnvRef {
  projectId: string;
  environmentId: string;
}

export const SECRET_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
export const MAX_SECRET_VALUE_BYTES = 64 * 1024;

export const generateEnvironmentKey = generateKey;

const envKeyAad = (ref: EnvRef) => context('env-key', ref.projectId, ref.environmentId);

/** Share an environment key with a member (or yourself) by sealing it to their public key. */
export function wrapEnvKeyForMember(envKey: Uint8Array, memberPublicKeyB64: string, ref: EnvRef): string {
  return seal(fromB64u(memberPublicKeyB64), envKey, envKeyAad(ref));
}

export function unwrapEnvKey(identity: X25519KeyPair, wrapped: string, ref: EnvRef): Uint8Array {
  const key = openSealed(identity, wrapped, envKeyAad(ref));
  if (key.length !== 32) throw new CryptoError('Unexpected environment key length');
  return key;
}

export interface SecretPlaintext {
  name: string;
  value: string;
  comment?: string;
}

export interface SecretCiphertext {
  nameCiphertext: string;
  valueCiphertext: string;
  commentCiphertext: string | null;
  nameIndex: string;
}

const fieldAad = (ref: EnvRef, secretId: string, field: string) =>
  context('secret', ref.projectId, ref.environmentId, secretId, field);

export function blindIndex(envKey: Uint8Array, name: string): string {
  const k = deriveSubkey(envKey, 'blind-index');
  const out = toB64u(hmacSha256(k, utf8(name)));
  wipe(k);
  return out;
}

export function validateSecret(s: SecretPlaintext): void {
  if (!SECRET_NAME_PATTERN.test(s.name)) {
    throw new CryptoError('Secret names must look like environment variables: letters, digits, underscore');
  }
  if (utf8(s.value).length > MAX_SECRET_VALUE_BYTES) throw new CryptoError('Secret value exceeds 64 KiB');
}

export function encryptSecret(envKey: Uint8Array, ref: EnvRef, secretId: string, s: SecretPlaintext): SecretCiphertext {
  validateSecret(s);
  return {
    nameCiphertext: encrypt(envKey, utf8(s.name), fieldAad(ref, secretId, 'name')),
    valueCiphertext: encrypt(envKey, utf8(s.value), fieldAad(ref, secretId, 'value')),
    commentCiphertext: s.comment ? encrypt(envKey, utf8(s.comment), fieldAad(ref, secretId, 'comment')) : null,
    nameIndex: blindIndex(envKey, s.name),
  };
}

export function decryptSecret(
  envKey: Uint8Array,
  ref: EnvRef,
  secretId: string,
  c: Pick<SecretCiphertext, 'nameCiphertext' | 'valueCiphertext' | 'commentCiphertext'>,
): SecretPlaintext {
  return {
    name: fromUtf8(decrypt(envKey, c.nameCiphertext, fieldAad(ref, secretId, 'name'))),
    value: fromUtf8(decrypt(envKey, c.valueCiphertext, fieldAad(ref, secretId, 'value'))),
    comment: c.commentCiphertext ? fromUtf8(decrypt(envKey, c.commentCiphertext, fieldAad(ref, secretId, 'comment'))) : '',
  };
}

/** RFC 4122 v4 UUID; secret ids are client-generated so they can be bound into the AAD. */
export function newId(): string {
  const b = randomBytes(16);
  b[6] = (b[6]! & 0x0f) | 0x40;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

// ------------------------------------------------------------ service tokens
//
// Token format:  kvs_<tokenId>.<secret>   (tokenId: 16 random bytes, secret: 32 random bytes)
//   authSecret = HKDF(secret, "st-auth")  → sent on each request; server stores SHA-256(authSecret)
//   wrapKey    = HKDF(secret, "st-wrap")  → unwraps the env key; never sent anywhere
// The server can authenticate the token but cannot decrypt anything with what it sees.

const TOKEN_PREFIX = 'kvs_';
const tokenAad = (ref: EnvRef, tokenId: string) => context('service-token', ref.projectId, ref.environmentId, tokenId);

export function createServiceToken(envKey: Uint8Array, ref: EnvRef) {
  const tokenId = toB64u(randomBytes(16));
  const secret = randomBytes(32);
  const authSecret = deriveSubkey(secret, 'st-auth');
  const wrapKey = deriveSubkey(secret, 'st-wrap');
  const result = {
    token: `${TOKEN_PREFIX}${tokenId}.${toB64u(secret)}`,
    tokenId,
    verifier: toB64u(sha256(authSecret)),
    wrappedEnvKey: encrypt(wrapKey, envKey, tokenAad(ref, tokenId)),
  };
  wipe(secret, authSecret, wrapKey);
  return result;
}

export function parseServiceToken(token: string): { tokenId: string; authSecret: string; wrapKey: Uint8Array } {
  const m = /^kvs_([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})$/.exec(token.trim());
  if (!m) throw new CryptoError('Malformed service token');
  const secret = fromB64u(m[2]!);
  const out = {
    tokenId: m[1]!,
    authSecret: toB64u(deriveSubkey(secret, 'st-auth')),
    wrapKey: deriveSubkey(secret, 'st-wrap'),
  };
  wipe(secret);
  return out;
}

export function unwrapServiceTokenEnvKey(wrapKey: Uint8Array, wrappedEnvKey: string, ref: EnvRef, tokenId: string): Uint8Array {
  return decrypt(wrapKey, wrappedEnvKey, tokenAad(ref, tokenId));
}

// ----------------------------------------------------------- one-time sends
// The decryption key lives only in the URL fragment (#...), which browsers never send to servers.

const SEND_AAD = context('send');

export function createSend(plaintext: string): { ciphertext: string; key: string } {
  if (utf8(plaintext).length > MAX_SECRET_VALUE_BYTES) throw new CryptoError('Payload exceeds 64 KiB');
  const key = generateKey();
  const out = { ciphertext: encrypt(key, utf8(plaintext), SEND_AAD), key: toB64u(key) };
  wipe(key);
  return out;
}

export function openSend(ciphertext: string, keyB64: string): string {
  return fromUtf8(decrypt(fromB64u(keyB64), ciphertext, SEND_AAD));
}

/** Parse a .env file into name/value pairs (supports quotes, comments, `export` prefix). */
export function parseDotenv(text: string): SecretPlaintext[] {
  const out: SecretPlaintext[] = [];
  const lines = text.replace(/\r\n?/g, '\n').split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let value = m[2]!;
    const q = value[0];
    if ((q === '"' || q === "'") && !value.endsWith(q)) {
      // multi-line quoted value
      while (i + 1 < lines.length && !value.endsWith(q!)) value += '\n' + lines[++i];
    }
    if (q === '"' && value.endsWith('"') && value.length >= 2) {
      value = value.slice(1, -1).replace(/\\n/g, '\n').replace(/\\"/g, '"');
    } else if (q === "'" && value.endsWith("'") && value.length >= 2) {
      value = value.slice(1, -1);
    } else {
      value = value.replace(/\s+#.*$/, '').trim();
    }
    out.push({ name: m[1]!, value });
  }
  return out;
}

export function toDotenv(secrets: SecretPlaintext[]): string {
  return secrets
    .map((s) => {
      const needsQuotes = /[\s#"'\\]|\n/.test(s.value) || s.value === '';
      const v = needsQuotes ? `"${s.value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n')}"` : s.value;
      return `${s.name}=${v}`;
    })
    .join('\n') + '\n';
}
