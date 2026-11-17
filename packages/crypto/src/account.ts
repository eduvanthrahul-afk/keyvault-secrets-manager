// Account key hierarchy (see docs/SECURITY.md for the diagram):
//
//   master password ──Argon2id(salt, params)──▶ master key (never leaves the device)
//        ├─ HKDF "auth" ─▶ authKey      → sent to server, stored there as Argon2id(authKey)
//        └─ HKDF "kek"  ─▶ password KEK → wraps the random Account Key
//   recovery key (random 256-bit, shown once)
//        ├─ HKDF "recovery-auth" ─▶ recovery verifier
//        └─ HKDF "recovery-kek"  ─▶ second wrap of the Account Key
//   Account Key ──wraps──▶ X25519 private key (identity used to receive shared env keys)

import { argon2id } from 'hash-wasm';
import { CryptoError, fromB64u, fromBase32, fromUtf8, toB64u, toBase32, utf8, wipe } from './encoding';
import {
  context,
  decrypt,
  deriveSubkey,
  encrypt,
  equalBytes,
  generateKey,
  generateKeyPair,
  publicKeyFromPrivate,
  randomBytes,
  sha256,
  type X25519KeyPair,
} from './primitives';

export interface KdfParams {
  algorithm: 'argon2id';
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

/** Bitwarden-equivalent defaults; well above the OWASP 2024 minimum (19 MiB, t=2). */
export const DEFAULT_KDF: KdfParams = { algorithm: 'argon2id', memoryKiB: 65536, iterations: 3, parallelism: 1 };

/**
 * Lower bounds enforced on the CLIENT. A compromised server could otherwise hand out
 * weak KDF parameters at login and make the next captured authKey cheap to brute force.
 */
export const MIN_KDF = { memoryKiB: 19456, iterations: 2, parallelism: 1 } as const;
const MAX_KDF = { memoryKiB: 1048576, iterations: 20, parallelism: 16 } as const;

export function assertSafeKdf(p: KdfParams): void {
  if (p.algorithm !== 'argon2id') throw new CryptoError('Unsupported KDF algorithm');
  const ok =
    p.memoryKiB >= MIN_KDF.memoryKiB && p.memoryKiB <= MAX_KDF.memoryKiB &&
    p.iterations >= MIN_KDF.iterations && p.iterations <= MAX_KDF.iterations &&
    p.parallelism >= MIN_KDF.parallelism && p.parallelism <= MAX_KDF.parallelism;
  if (!ok) throw new CryptoError('Server supplied unsafe KDF parameters; refusing to derive keys');
}

export const MIN_PASSWORD_LENGTH = 12;

export type Argon2Impl = (password: string, salt: Uint8Array, params: KdfParams) => Promise<Uint8Array>;
let argon2Impl: Argon2Impl | null = null;

/** Lets the browser run Argon2id inside a Web Worker so the UI never freezes. */
export function setArgon2Implementation(impl: Argon2Impl | null): void {
  argon2Impl = impl;
}

export async function deriveMasterKey(password: string, salt: Uint8Array, params: KdfParams): Promise<Uint8Array> {
  assertSafeKdf(params);
  if (salt.length < 16) throw new CryptoError('Salt must be at least 16 bytes');
  if (argon2Impl) return argon2Impl(password, salt, params);
  return argon2Local(password, salt, params);
}

export async function argon2Local(password: string, salt: Uint8Array, params: KdfParams): Promise<Uint8Array> {
  const pw = utf8(password.normalize('NFKC'));
  try {
    return (await argon2id({
      password: pw,
      salt,
      parallelism: params.parallelism,
      iterations: params.iterations,
      memorySize: params.memoryKiB,
      hashLength: 32,
      outputType: 'binary',
    })) as Uint8Array;
  } finally {
    wipe(pw);
  }
}

export function splitMasterKey(masterKey: Uint8Array): { authKey: Uint8Array; kek: Uint8Array } {
  return { authKey: deriveSubkey(masterKey, 'auth'), kek: deriveSubkey(masterKey, 'kek') };
}

const AAD_ACCOUNT_KEY_PW = context('account-key', 'password');
const AAD_ACCOUNT_KEY_RECOVERY = context('account-key', 'recovery');
const AAD_PRIVATE_KEY = context('identity', 'x25519-private');

/** Unlocked, in-memory key material for a signed-in user. Never persisted. */
export interface UnlockedAccount {
  accountKey: Uint8Array;
  identity: X25519KeyPair;
}

export interface ProtectedAccount {
  kdf: KdfParams;
  salt: string;
  protectedAccountKey: string;
  publicKey: string;
  protectedPrivateKey: string;
}

export interface RegistrationBundle {
  request: ProtectedAccount & {
    email: string;
    authKey: string;
    recoveryVerifier: string;
    recoveryProtectedAccountKey: string;
  };
  /** Shown once to the user ("Emergency Kit"); never sent to the server. */
  recoveryKey: string;
  unlocked: UnlockedAccount;
}

export async function createAccount(email: string, password: string, kdf: KdfParams = DEFAULT_KDF): Promise<RegistrationBundle> {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new CryptoError(`Master password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  const salt = randomBytes(16);
  const masterKey = await deriveMasterKey(password, salt, kdf);
  const { authKey, kek } = splitMasterKey(masterKey);
  const accountKey = generateKey();
  const identity = generateKeyPair();
  const recovery = createRecoveryWrap(accountKey);

  const bundle: RegistrationBundle = {
    request: {
      email: email.trim().toLowerCase(),
      kdf,
      salt: toB64u(salt),
      authKey: toB64u(authKey),
      protectedAccountKey: encrypt(kek, accountKey, AAD_ACCOUNT_KEY_PW),
      publicKey: toB64u(identity.publicKey),
      protectedPrivateKey: encrypt(accountKey, identity.privateKey, AAD_PRIVATE_KEY),
      recoveryVerifier: recovery.verifier,
      recoveryProtectedAccountKey: recovery.protectedAccountKey,
    },
    recoveryKey: recovery.recoveryKey,
    unlocked: { accountKey, identity },
  };
  wipe(masterKey, authKey, kek);
  return bundle;
}

/** Step 1 of login: derive the credential to send and the KEK to keep locally. */
export async function deriveLoginKeys(password: string, saltB64: string, kdf: KdfParams) {
  const masterKey = await deriveMasterKey(password, fromB64u(saltB64), kdf);
  const { authKey, kek } = splitMasterKey(masterKey);
  wipe(masterKey);
  return { authKey: toB64u(authKey), kek };
}

/** Step 2 of login: unwrap the account key and identity returned by the server. */
export function unlockAccount(kek: Uint8Array, account: Pick<ProtectedAccount, 'protectedAccountKey' | 'publicKey' | 'protectedPrivateKey'>): UnlockedAccount {
  const accountKey = decrypt(kek, account.protectedAccountKey, AAD_ACCOUNT_KEY_PW);
  return { accountKey, identity: openIdentity(accountKey, account) };
}

/** Unlock from an already-recovered account key (e.g. via a passkey). */
export function unlockFromAccountKey(accountKey: Uint8Array, account: Pick<ProtectedAccount, 'publicKey' | 'protectedPrivateKey'>): UnlockedAccount {
  return { accountKey, identity: openIdentity(accountKey, account) };
}

function openIdentity(accountKey: Uint8Array, account: Pick<ProtectedAccount, 'publicKey' | 'protectedPrivateKey'>): X25519KeyPair {
  const privateKey = decrypt(accountKey, account.protectedPrivateKey, AAD_PRIVATE_KEY);
  const publicKey = publicKeyFromPrivate(privateKey);
  // Detect a server that substitutes our own public key (it would then receive shares meant for us).
  if (!equalBytes(publicKey, fromB64u(account.publicKey))) {
    throw new CryptoError('Server returned a public key that does not match your private key');
  }
  return { privateKey, publicKey };
}

/** Re-wraps the existing account key under a new password. Secrets are untouched. */
export async function changePassword(unlocked: UnlockedAccount, newPassword: string, kdf: KdfParams = DEFAULT_KDF) {
  if (newPassword.length < MIN_PASSWORD_LENGTH) {
    throw new CryptoError(`Master password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  const salt = randomBytes(16);
  const masterKey = await deriveMasterKey(newPassword, salt, kdf);
  const { authKey, kek } = splitMasterKey(masterKey);
  const result = {
    kdf,
    salt: toB64u(salt),
    authKey: toB64u(authKey),
    protectedAccountKey: encrypt(kek, unlocked.accountKey, AAD_ACCOUNT_KEY_PW),
  };
  wipe(masterKey, authKey, kek);
  return result;
}

// ---------------------------------------------------------------- recovery

function createRecoveryWrap(accountKey: Uint8Array) {
  const raw = randomBytes(32);
  const checksum = sha256(raw).subarray(0, 2);
  const encoded = toBase32(new Uint8Array([...raw, ...checksum]));
  const recoveryKey = 'KV1-' + (encoded.match(/.{1,5}/g) ?? []).join('-');
  const verifier = toB64u(deriveSubkey(raw, 'recovery-auth'));
  const recoveryKek = deriveSubkey(raw, 'recovery-kek');
  const protectedAccountKey = encrypt(recoveryKek, accountKey, AAD_ACCOUNT_KEY_RECOVERY);
  wipe(raw, recoveryKek);
  return { recoveryKey, verifier, protectedAccountKey };
}

export function parseRecoveryKey(recoveryKey: string): { verifier: string; kek: Uint8Array } {
  const body = recoveryKey.trim().toUpperCase().replace(/^KV1-?/, '');
  const bytes = fromBase32(body);
  if (bytes.length !== 34) throw new CryptoError('Recovery key has the wrong length');
  const raw = bytes.subarray(0, 32);
  if (!equalBytes(sha256(raw).subarray(0, 2), bytes.subarray(32))) {
    throw new CryptoError('Recovery key checksum mismatch; check for typos');
  }
  return { verifier: toB64u(deriveSubkey(raw, 'recovery-auth')), kek: deriveSubkey(raw, 'recovery-kek') };
}

/**
 * Account recovery: unwrap the account key with the recovery key, set a new password and
 * rotate the recovery key (the old one is burned once used).
 */
export async function recoverAccount(
  recoveryKek: Uint8Array,
  account: { recoveryProtectedAccountKey: string; publicKey: string; protectedPrivateKey: string },
  newPassword: string,
) {
  const accountKey = decrypt(recoveryKek, account.recoveryProtectedAccountKey, AAD_ACCOUNT_KEY_RECOVERY);
  const unlocked: UnlockedAccount = { accountKey, identity: openIdentity(accountKey, account) };
  const pw = await changePassword(unlocked, newPassword);
  const recovery = createRecoveryWrap(accountKey);
  return {
    request: { ...pw, recoveryVerifier: recovery.verifier, recoveryProtectedAccountKey: recovery.protectedAccountKey },
    recoveryKey: recovery.recoveryKey,
    unlocked,
  };
}

/** Rotate the emergency recovery key while signed in. */
export function rotateRecoveryKey(unlocked: UnlockedAccount) {
  const r = createRecoveryWrap(unlocked.accountKey);
  return { recoveryKey: r.recoveryKey, request: { recoveryVerifier: r.verifier, recoveryProtectedAccountKey: r.protectedAccountKey } };
}

/** Rough strength estimate for UI feedback (not a security boundary). */
export function estimatePasswordBits(password: string): number {
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 33;
  const unique = new Set(password).size;
  return Math.round(Math.log2(Math.max(pool, 1)) * Math.min(password.length, unique * 1.5));
}

export { fromUtf8 };
