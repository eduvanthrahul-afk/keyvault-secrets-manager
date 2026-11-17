// WebAuthn PRF helpers. The PRF output is computed inside the authenticator after user
// verification and never leaves this tab; it is HKDF-ed into a key that wraps the Account Key.

import { b64, randomBytes, utf8 } from '@keyvault/crypto';

type PrfExtensionResults = { prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } } };

const buf = (u: Uint8Array): ArrayBuffer => u.slice().buffer as ArrayBuffer;

export function passkeysSupported(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials?.create;
}

/** Create a passkey and immediately evaluate the PRF with our salt. */
export async function createPasskey(opts: { userId: string; email: string; displayName: string; salt: Uint8Array }) {
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { name: 'KeyVault', id: location.hostname },
      user: { id: buf(utf8(opts.userId)), name: opts.email, displayName: opts.displayName },
      challenge: buf(randomBytes(32)),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      timeout: 60_000,
      extensions: { prf: { eval: { first: buf(opts.salt) } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('Passkey creation was cancelled');
  const ext = cred.getClientExtensionResults() as PrfExtensionResults;
  if (!ext.prf?.enabled && !ext.prf?.results?.first) {
    throw new Error('This authenticator does not support the PRF extension, so it cannot unlock an encrypted vault. Try a platform passkey (Touch ID, Windows Hello) or a recent security key.');
  }
  const credentialId = b64.encode(new Uint8Array(cred.rawId));
  // Some authenticators only return PRF results during get(), not create().
  const prf = ext.prf.results?.first
    ? new Uint8Array(ext.prf.results.first)
    : (await assertPasskey([{ credentialId, prfSalt: b64.encode(opts.salt) }])).prf;
  return { credentialId, prf };
}

/** Ask the user to verify with any of their registered passkeys; returns which one and its PRF output. */
export async function assertPasskey(passkeys: { credentialId: string; prfSalt: string }[]) {
  const evalByCredential: Record<string, { first: ArrayBuffer }> = {};
  for (const p of passkeys) evalByCredential[p.credentialId] = { first: buf(b64.decode(p.prfSalt)) };
  const assertion = (await navigator.credentials.get({
    publicKey: {
      rpId: location.hostname,
      challenge: buf(randomBytes(32)),
      allowCredentials: passkeys.map((p) => ({ type: 'public-key' as const, id: buf(b64.decode(p.credentialId)) })),
      userVerification: 'required',
      timeout: 60_000,
      extensions: { prf: { evalByCredential } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!assertion) throw new Error('Passkey verification was cancelled');
  const first = (assertion.getClientExtensionResults() as PrfExtensionResults).prf?.results?.first;
  if (!first) throw new Error('The authenticator did not return a PRF result');
  return { credentialId: b64.encode(new Uint8Array(assertion.rawId)), prf: new Uint8Array(first) };
}
