import { describe, expect, it } from 'vitest';
import {
  assertSafeKdf,
  b64,
  changePassword,
  context,
  createAccount,
  createSend,
  createServiceToken,
  decrypt,
  decryptSecret,
  deriveLoginKeys,
  encrypt,
  encryptSecret,
  fingerprint,
  fromBase32,
  generateEnvironmentKey,
  generateKey,
  generateKeyPair,
  newId,
  openSealed,
  openSend,
  parseDotenv,
  parseRecoveryKey,
  parseServiceToken,
  recoverAccount,
  seal,
  sha256,
  toBase32,
  toDotenv,
  unlockAccount,
  unwrapEnvKey,
  unwrapServiceTokenEnvKey,
  utf8,
  wrapEnvKeyForMember,
  type KdfParams,
} from '../src';

// Minimum-but-valid params keep the test suite fast; production uses DEFAULT_KDF.
const FAST_KDF: KdfParams = { algorithm: 'argon2id', memoryKiB: 19456, iterations: 2, parallelism: 1 };
const PASSWORD = 'correct horse battery staple';

describe('encoding', () => {
  it('round-trips base64url for all lengths', () => {
    for (let n = 0; n < 70; n++) {
      const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff);
      expect(b64.decode(b64.encode(bytes))).toEqual(bytes);
    }
  });
  it('round-trips base32', () => {
    const bytes = Uint8Array.from({ length: 34 }, (_, i) => i * 7);
    expect(fromBase32(toBase32(bytes))).toEqual(bytes);
  });
  it('rejects malformed base64url', () => {
    expect(() => b64.decode('abc$')).toThrow();
  });
});

describe('AEAD envelope', () => {
  it('decrypts with the same key and context', () => {
    const key = generateKey();
    const ct = encrypt(key, utf8('hello'), context('t'));
    expect(new TextDecoder().decode(decrypt(key, ct, context('t')))).toBe('hello');
  });
  it('fails with a different context (ciphertext substitution)', () => {
    const key = generateKey();
    const ct = encrypt(key, utf8('hello'), context('prod'));
    expect(() => decrypt(key, ct, context('dev'))).toThrow(/Decryption failed/);
  });
  it('fails if a single bit is flipped', () => {
    const key = generateKey();
    const ct = encrypt(key, utf8('hello'), context('t'));
    const raw = b64.decode(ct.slice(4));
    raw[raw.length - 1]! ^= 1;
    expect(() => decrypt(key, 'kv1.' + b64.encode(raw), context('t'))).toThrow();
  });
  it('uses a fresh nonce every time', () => {
    const key = generateKey();
    expect(encrypt(key, utf8('x'), context('t'))).not.toBe(encrypt(key, utf8('x'), context('t')));
  });
});

describe('sealed boxes', () => {
  it('only the recipient can open', () => {
    const alice = generateKeyPair();
    const eve = generateKeyPair();
    const box = seal(alice.publicKey, utf8('k'), context('x'));
    expect(openSealed(alice, box, context('x'))).toEqual(utf8('k'));
    expect(() => openSealed(eve, box, context('x'))).toThrow();
    expect(() => openSealed(alice, box, context('y'))).toThrow();
  });
  it('fingerprints are stable and distinct', () => {
    const a = generateKeyPair();
    expect(fingerprint(a.publicKey)).toBe(fingerprint(a.publicKey));
    expect(fingerprint(a.publicKey)).not.toBe(fingerprint(generateKeyPair().publicKey));
    expect(fingerprint(a.publicKey)).toMatch(/^(\d{5} ){7}\d{5}$/);
  });
});

describe('account lifecycle', () => {
  it('registers, logs in, changes password and recovers', async () => {
    const reg = await createAccount('Alice@Example.com ', PASSWORD, FAST_KDF);
    expect(reg.request.email).toBe('alice@example.com');
    expect(reg.recoveryKey).toMatch(/^KV1-[A-Z2-7-]+$/);
    expect(JSON.stringify(reg.request)).not.toContain(PASSWORD);

    // login
    const login = await deriveLoginKeys(PASSWORD, reg.request.salt, reg.request.kdf);
    expect(login.authKey).toBe(reg.request.authKey);
    const unlocked = unlockAccount(login.kek, reg.request);
    expect(unlocked.accountKey).toEqual(reg.unlocked.accountKey);

    // wrong password
    const bad = await deriveLoginKeys('wrong password!!', reg.request.salt, reg.request.kdf);
    expect(bad.authKey).not.toBe(reg.request.authKey);
    expect(() => unlockAccount(bad.kek, reg.request)).toThrow();

    // change password keeps the same account key
    const changed = await changePassword(unlocked, 'a brand new passphrase', FAST_KDF);
    const login2 = await deriveLoginKeys('a brand new passphrase', changed.salt, changed.kdf);
    expect(unlockAccount(login2.kek, { ...reg.request, ...changed }).accountKey).toEqual(reg.unlocked.accountKey);

    // recovery
    const parsed = parseRecoveryKey(reg.recoveryKey.toLowerCase());
    expect(parsed.verifier).toBe(reg.request.recoveryVerifier);
    const recovered = await recoverAccount(parsed.kek, reg.request, 'recovered passphrase 1');
    expect(recovered.unlocked.accountKey).toEqual(reg.unlocked.accountKey);
    expect(recovered.recoveryKey).not.toBe(reg.recoveryKey);
  });

  it('detects a typo in the recovery key', async () => {
    const reg = await createAccount('a@b.co', PASSWORD, FAST_KDF);
    const chars = reg.recoveryKey.split('');
    const i = chars.findIndex((c, idx) => idx > 5 && /[A-Z]/.test(c));
    chars[i] = chars[i] === 'A' ? 'B' : 'A';
    expect(() => parseRecoveryKey(chars.join(''))).toThrow(/checksum/);
  });

  it('rejects a server-substituted public key', async () => {
    const reg = await createAccount('a@b.co', PASSWORD, FAST_KDF);
    const login = await deriveLoginKeys(PASSWORD, reg.request.salt, reg.request.kdf);
    const evil = b64.encode(generateKeyPair().publicKey);
    expect(() => unlockAccount(login.kek, { ...reg.request, publicKey: evil })).toThrow(/does not match/);
  });

  it('refuses KDF downgrade attacks', () => {
    expect(() => assertSafeKdf({ algorithm: 'argon2id', memoryKiB: 1024, iterations: 1, parallelism: 1 })).toThrow(/unsafe/);
  });

  it('rejects short passwords', async () => {
    await expect(createAccount('a@b.co', 'short', FAST_KDF)).rejects.toThrow(/at least/);
  });
});

describe('environment keys and secrets', () => {
  const ref = { projectId: newId(), environmentId: newId() };

  it('shares env keys to members only', () => {
    const owner = generateKeyPair();
    const member = generateKeyPair();
    const envKey = generateEnvironmentKey();
    const wrapped = wrapEnvKeyForMember(envKey, b64.encode(member.publicKey), ref);
    expect(unwrapEnvKey(member, wrapped, ref)).toEqual(envKey);
    expect(() => unwrapEnvKey(owner, wrapped, ref)).toThrow();
    // a wrapped key cannot be replayed into another environment
    expect(() => unwrapEnvKey(member, wrapped, { ...ref, environmentId: newId() })).toThrow();
  });

  it('encrypts secrets bound to their slot', () => {
    const envKey = generateEnvironmentKey();
    const id = newId();
    const ct = encryptSecret(envKey, ref, id, { name: 'STRIPE_KEY', value: 'sk_live_123', comment: 'billing' });
    expect(decryptSecret(envKey, ref, id, ct)).toEqual({ name: 'STRIPE_KEY', value: 'sk_live_123', comment: 'billing' });
    // server swaps value ciphertext onto another secret id → must fail
    expect(() => decryptSecret(envKey, ref, newId(), ct)).toThrow();
    // server swaps value into name field → must fail
    expect(() => decryptSecret(envKey, ref, id, { ...ct, nameCiphertext: ct.valueCiphertext })).toThrow();
  });

  it('blind index is deterministic per env and hides the name', () => {
    const k1 = generateEnvironmentKey();
    const a = encryptSecret(k1, ref, newId(), { name: 'DB_URL', value: 'x' });
    const b = encryptSecret(k1, ref, newId(), { name: 'DB_URL', value: 'y' });
    const c = encryptSecret(generateEnvironmentKey(), ref, newId(), { name: 'DB_URL', value: 'x' });
    expect(a.nameIndex).toBe(b.nameIndex);
    expect(a.nameIndex).not.toBe(c.nameIndex);
    expect(a.nameIndex).not.toContain('DB_URL');
  });

  it('validates secret names', () => {
    expect(() => encryptSecret(generateEnvironmentKey(), ref, newId(), { name: '1BAD-NAME', value: '' })).toThrow();
  });
});

describe('service tokens', () => {
  it('lets a token holder (and only them) unwrap the env key', () => {
    const ref = { projectId: newId(), environmentId: newId() };
    const envKey = generateEnvironmentKey();
    const st = createServiceToken(envKey, ref);
    expect(st.token).toMatch(/^kvs_/);
    const parsed = parseServiceToken(st.token);
    expect(parsed.tokenId).toBe(st.tokenId);
    // server-side verification is SHA-256(authSecret) == verifier
    expect(b64.encode(sha256(b64.decode(parsed.authSecret)))).toBe(st.verifier);
    expect(unwrapServiceTokenEnvKey(parsed.wrapKey, st.wrappedEnvKey, ref, st.tokenId)).toEqual(envKey);
    // the auth secret the server sees is useless for decryption
    expect(() => unwrapServiceTokenEnvKey(b64.decode(parsed.authSecret), st.wrappedEnvKey, ref, st.tokenId)).toThrow();
  });
  it('rejects malformed tokens', () => {
    expect(() => parseServiceToken('kvs_nope')).toThrow();
  });
});

describe('sends', () => {
  it('round-trips with the fragment key', () => {
    const s = createSend('one-time secret');
    expect(openSend(s.ciphertext, s.key)).toBe('one-time secret');
    expect(() => openSend(s.ciphertext, b64.encode(generateKey()))).toThrow();
  });
});

describe('dotenv', () => {
  it('parses and serialises', () => {
    const text = `# comment\nexport A=1\nB="two words"\nC='single'\nD=plain # trailing\nE="line1\\nline2"\n`;
    const parsed = parseDotenv(text);
    expect(parsed).toEqual([
      { name: 'A', value: '1' },
      { name: 'B', value: 'two words' },
      { name: 'C', value: 'single' },
      { name: 'D', value: 'plain' },
      { name: 'E', value: 'line1\nline2' },
    ]);
    expect(parseDotenv(toDotenv(parsed))).toEqual(parsed);
  });
});
