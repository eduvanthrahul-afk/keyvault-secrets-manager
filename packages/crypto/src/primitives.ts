// Low-level primitives. Every ciphertext is bound to a context string through
// AEAD associated data, so the server cannot move a ciphertext from one slot to
// another (for example swap a PROD secret into DEV) without decryption failing.

import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes as nobleRandom } from '@noble/hashes/utils';
import { concat, CryptoError, fromB64u, toB64u, utf8 } from './encoding';

export const KEY_BYTES = 32;
const NONCE_BYTES = 24;
const ENVELOPE_PREFIX = 'kv1.';
const SEALED_PREFIX = 'kv1s.';

export const randomBytes = (n: number): Uint8Array => nobleRandom(n);
export const generateKey = (): Uint8Array => randomBytes(KEY_BYTES);

/** Domain-separated context used as AEAD associated data and as HKDF info. */
export function context(...parts: string[]): Uint8Array {
  for (const p of parts) {
    if (p.includes('|')) throw new CryptoError('Context parts must not contain "|"');
  }
  return utf8(['kv', 'v1', ...parts].join('|'));
}

export function deriveSubkey(ikm: Uint8Array, label: string, length = KEY_BYTES): Uint8Array {
  return hkdf(sha256, ikm, undefined, context('hkdf', label), length);
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

export { sha256 };

function assertKey(key: Uint8Array): void {
  if (!(key instanceof Uint8Array) || key.length !== KEY_BYTES) {
    throw new CryptoError('Key must be 32 bytes');
  }
}

/** XChaCha20-Poly1305 with a random 192-bit nonce (safe to generate randomly at any volume). */
export function encrypt(key: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): string {
  assertKey(key);
  const nonce = randomBytes(NONCE_BYTES);
  const ct = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  return ENVELOPE_PREFIX + toB64u(concat(nonce, ct));
}

export function decrypt(key: Uint8Array, envelope: string, aad: Uint8Array): Uint8Array {
  assertKey(key);
  if (!envelope.startsWith(ENVELOPE_PREFIX)) throw new CryptoError('Unsupported ciphertext version');
  const raw = fromB64u(envelope.slice(ENVELOPE_PREFIX.length));
  if (raw.length < NONCE_BYTES + 16) throw new CryptoError('Ciphertext too short');
  try {
    return xchacha20poly1305(key, raw.subarray(0, NONCE_BYTES), aad).decrypt(raw.subarray(NONCE_BYTES));
  } catch {
    throw new CryptoError('Decryption failed: wrong key, tampered data, or wrong context');
  }
}

export interface X25519KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export function generateKeyPair(): X25519KeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  return { privateKey, publicKey: x25519.getPublicKey(privateKey) };
}

export function publicKeyFromPrivate(privateKey: Uint8Array): Uint8Array {
  return x25519.getPublicKey(privateKey);
}

/**
 * Anonymous sealed box (ECIES-style, similar in spirit to HPKE base mode):
 * ephemeral X25519 -> HKDF(shared, eph_pk || recipient_pk) -> XChaCha20-Poly1305.
 */
export function seal(recipientPublicKey: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): string {
  const eph = generateKeyPair();
  const key = sealKey(x25519.getSharedSecret(eph.privateKey, recipientPublicKey), eph.publicKey, recipientPublicKey);
  const nonce = randomBytes(NONCE_BYTES);
  const ct = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  eph.privateKey.fill(0);
  key.fill(0);
  return SEALED_PREFIX + toB64u(concat(eph.publicKey, nonce, ct));
}

export function openSealed(recipient: X25519KeyPair, sealed: string, aad: Uint8Array): Uint8Array {
  if (!sealed.startsWith(SEALED_PREFIX)) throw new CryptoError('Unsupported sealed-box version');
  const raw = fromB64u(sealed.slice(SEALED_PREFIX.length));
  if (raw.length < 32 + NONCE_BYTES + 16) throw new CryptoError('Sealed box too short');
  const ephPub = raw.subarray(0, 32);
  const nonce = raw.subarray(32, 32 + NONCE_BYTES);
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(recipient.privateKey, ephPub);
  } catch {
    throw new CryptoError('Invalid ephemeral public key');
  }
  const key = sealKey(shared, ephPub, recipient.publicKey);
  try {
    return xchacha20poly1305(key, nonce, aad).decrypt(raw.subarray(32 + NONCE_BYTES));
  } catch {
    throw new CryptoError('Could not open sealed key: not addressed to you, or tampered');
  } finally {
    key.fill(0);
  }
}

function sealKey(shared: Uint8Array, ephPub: Uint8Array, recipientPub: Uint8Array): Uint8Array {
  const key = hkdf(sha256, shared, concat(ephPub, recipientPub), context('sealed-box'), KEY_BYTES);
  shared.fill(0);
  return key;
}

/** Human-comparable fingerprint of a public key, for out-of-band identity verification. */
export function fingerprint(publicKey: Uint8Array): string {
  const digest = sha256(concat(utf8('kv-fingerprint-v1'), publicKey)).subarray(0, 16);
  const groups: string[] = [];
  for (let i = 0; i < digest.length; i += 2) {
    groups.push(((digest[i]! << 8) | digest[i + 1]!).toString().padStart(5, '0'));
  }
  return groups.join(' ');
}

/** Constant-time comparison for byte arrays. */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

export const b64 = { encode: toB64u, decode: fromB64u };
