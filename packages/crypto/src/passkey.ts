// Passkey unlock via the WebAuthn PRF extension.
//
//   authenticator secret (never leaves the device's secure hardware)
//     └─ PRF(credential, salt) ─► 32-byte output (only after user verification: fingerprint/face/PIN)
//          └─ HKDF "passkey-kek" ─► wraps the Account Key   → server stores the wrap + salt
//
// The server never sees the PRF output, so it still cannot unwrap anything. This is a local
// unlock mechanism; signing in to the account still requires the session (password + 2FA).

import { fromB64u, toB64u, wipe } from './encoding';
import { context, decrypt, deriveSubkey, encrypt, randomBytes } from './primitives';

const aad = (credentialId: string) => context('account-key', 'passkey', credentialId);

export function newPrfSalt(): string {
  return toB64u(randomBytes(32));
}

export function wrapAccountKeyWithPasskey(accountKey: Uint8Array, prfOutput: Uint8Array, credentialId: string): string {
  const kek = deriveSubkey(prfOutput, 'passkey-kek');
  try {
    return encrypt(kek, accountKey, aad(credentialId));
  } finally {
    wipe(kek);
  }
}

export function unwrapAccountKeyWithPasskey(wrapped: string, prfOutput: Uint8Array, credentialId: string): Uint8Array {
  const kek = deriveSubkey(prfOutput, 'passkey-kek');
  try {
    return decrypt(kek, wrapped, aad(credentialId));
  } finally {
    wipe(kek);
  }
}

export const prfSaltBytes = (salt: string): Uint8Array => fromB64u(salt);
