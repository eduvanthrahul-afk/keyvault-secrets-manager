// End-to-end check against a running server (default http://localhost:8080), using the real
// crypto package and the real CLI binary. Run: npm run e2e
import { execFileSync } from 'node:child_process';
import {
  createAccount, createSend, createServiceToken, decryptSecret, deriveLoginKeys, encryptSecret, generateEnvironmentKey,
  newId, openSend, unlockAccount, unwrapEnvKey, wrapEnvKeyForMember, type UnlockedAccount,
} from '../packages/crypto/src/index';

const BASE = process.env.KEYVAULT_URL ?? 'http://localhost:8080';
let failures = 0;
const ok = (cond: unknown, msg: string) => { console.log(`${cond ? '  ✓' : '  ✗'} ${msg}`); if (!cond) failures++; };

class Client {
  cookie = '';
  async req<T = any>(method: string, path: string, body?: unknown, expect = 200): Promise<T> {
    const res = await fetch(BASE + path, {
      method, headers: { 'Content-Type': 'application/json', 'X-KV-Request': '1', Cookie: this.cookie, Origin: BASE },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const set = res.headers.get('set-cookie');
    if (set) this.cookie = set.split(';')[0]!;
    const text = await res.text();
    if (res.status !== expect) throw new Error(`${method} ${path} → ${res.status} (expected ${expect}): ${text}`);
    return (text ? JSON.parse(text) : undefined) as T;
  }
}

async function signup(name: string) {
  const c = new Client();
  const email = `${name}-${Date.now()}@example.com`;
  const password = `${name} correct horse battery staple`;
  const reg = await createAccount(email, password);
  await c.req('POST', '/api/auth/register', { ...reg.request, displayName: name });
  return { c, email, password, account: reg.unlocked, recoveryKey: reg.recoveryKey, id: '' };
}

async function main() {
  console.log(`E2E against ${BASE}\n`);
  const home = await fetch(BASE + '/');
  ok(home.ok && (await home.text()).includes('<div id="root">'), 'SPA is served from the API server');
  ok(home.headers.get('content-security-policy')?.includes("script-src 'self' 'wasm-unsafe-eval'"), 'strict CSP header present');
  const deep = await fetch(BASE + '/app/p/whatever/secrets');
  ok(deep.ok, 'client-side routes fall back to index.html');

  console.log('\nAccounts');
  const alice = await signup('alice');
  const bob = await signup('bob');
  // fresh login with password-derived keys
  const fresh = new Client();
  const pre = await fresh.req('POST', '/api/auth/prelogin', { email: alice.email });
  const keys = await deriveLoginKeys(alice.password, pre.salt, pre.kdf);
  const login = await fresh.req('POST', '/api/auth/login', { email: alice.email, authKey: keys.authKey });
  const unlocked: UnlockedAccount = unlockAccount(keys.kek, login.session);
  ok(Buffer.from(unlocked.accountKey).equals(Buffer.from(alice.account.accountKey)), 'login on a new device unlocks the same account key');
  const bad = await deriveLoginKeys('wrong wrong wrong', pre.salt, pre.kdf);
  await fresh.req('POST', '/api/auth/login', { email: alice.email, authKey: bad.authKey }, 401);
  ok(true, 'wrong password rejected');
  const ghost = await fresh.req('POST', '/api/auth/prelogin', { email: 'nobody@example.com' });
  ok(ghost.salt.length === 22 && ghost.kdf.algorithm === 'argon2id', 'unknown email gets a plausible fake salt');

  console.log('\nProject and secrets');
  const pid = newId();
  const dev = { id: newId(), key: generateEnvironmentKey() };
  const prod = { id: newId(), key: generateEnvironmentKey() };
  const me = (await alice.c.req('GET', '/api/auth/session')).user;
  alice.id = me.id;
  const pubA = (await alice.c.req('GET', '/api/auth/session')).publicKey;
  await alice.c.req('POST', '/api/projects', {
    id: pid, name: 'payments-api', description: 'e2e', environments: [
      { id: dev.id, name: 'Development', slug: 'development', wrappedKey: wrapEnvKeyForMember(dev.key, pubA, { projectId: pid, environmentId: dev.id }) },
      { id: prod.id, name: 'Production', slug: 'production', wrappedKey: wrapEnvKeyForMember(prod.key, pubA, { projectId: pid, environmentId: prod.id }) },
    ],
  });
  const put = async (env: { id: string; key: Uint8Array }, name: string, value: string) => {
    const id = newId();
    await alice.c.req('POST', `/api/environments/${env.id}/secrets`, { secrets: [{ id, ...encryptSecret(env.key, { projectId: pid, environmentId: env.id }, id, { name, value }), keyVersion: 1 }] });
    return id;
  };
  await put(dev, 'STRIPE_KEY', 'sk_test_dev');
  await put(prod, 'STRIPE_KEY', 'sk_live_prod_123');
  await put(prod, 'DATABASE_URL', 'postgres://prod');
  const listed = await alice.c.req('GET', `/api/environments/${prod.id}/secrets`);
  ok(!JSON.stringify(listed).includes('sk_live_prod_123') && !JSON.stringify(listed).includes('STRIPE_KEY'), 'API responses contain only ciphertext (names too)');

  // unwrap via the stored grant, as the browser does
  const detail = await alice.c.req('GET', `/api/projects/${pid}`);
  const prodView = detail.environments.find((e: any) => e.id === prod.id);
  const k = unwrapEnvKey(unlocked.identity, prodView.wrappedKey, { projectId: pid, environmentId: prod.id });
  const names = listed.secrets.map((s: any) => decryptSecret(k, { projectId: pid, environmentId: prod.id }, s.id, s).name).sort();
  ok(names.join() === 'DATABASE_URL,STRIPE_KEY', 'grant unwraps and decrypts on the client');

  console.log('\nSharing');
  const bobInfo = await alice.c.req('GET', `/api/users/lookup?email=${encodeURIComponent(bob.email)}`);
  bob.id = bobInfo.id;
  await alice.c.req('POST', `/api/projects/${pid}/members`, {
    userId: bob.id, role: 'DEVELOPER',
    grants: [{ environmentId: dev.id, wrappedKey: wrapEnvKeyForMember(dev.key, bobInfo.publicKey, { projectId: pid, environmentId: dev.id }) }],
  });
  const bobDetail = await bob.c.req('GET', `/api/projects/${pid}`);
  const bobDev = bobDetail.environments.find((e: any) => e.id === dev.id);
  const bobKey = unwrapEnvKey(bob.account.identity, bobDev.wrappedKey, { projectId: pid, environmentId: dev.id });
  const bobSecrets = await bob.c.req('GET', `/api/environments/${dev.id}/secrets`);
  ok(decryptSecret(bobKey, { projectId: pid, environmentId: dev.id }, bobSecrets.secrets[0].id, bobSecrets.secrets[0]).value === 'sk_test_dev', 'bob decrypts development with his own private key');
  await bob.c.req('GET', `/api/environments/${prod.id}/secrets`, undefined, 403);
  ok(true, 'bob has no production grant → 403');

  console.log('\nCLI with an access token');
  const st = createServiceToken(prod.key, { projectId: pid, environmentId: prod.id });
  await alice.c.req('POST', `/api/environments/${prod.id}/tokens`, { tokenId: st.tokenId, name: 'ci', verifier: st.verifier, wrappedEnvKey: st.wrappedEnvKey, keyVersion: 1, expiresInDays: 30 });
  const cli = (args: string[]) => execFileSync(process.execPath, ['apps/cli/dist/kv.mjs', ...args], {
    env: { ...process.env, KEYVAULT_TOKEN: st.token, KEYVAULT_URL: BASE }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
  });
  const out = cli(['run', '--', 'node', '-e', 'console.log(process.env.STRIPE_KEY + "|" + (process.env.KEYVAULT_TOKEN ?? "no-token"))']).trim();
  ok(out === 'sk_live_prod_123|no-token', `kv run injects secrets and hides the token (${out})`);
  ok(cli(['get', 'DATABASE_URL']) === 'postgres://prod', 'kv get prints a single value');

  console.log('\nOffboarding and key rotation');
  await alice.c.req('DELETE', `/api/projects/${pid}/members/${bob.id}`, undefined, 204);
  const after = await alice.c.req('GET', `/api/projects/${pid}`);
  ok(after.environments.find((e: any) => e.id === dev.id).rotationNeeded, 'removing bob flags development for rotation');
  // rotate production (also proves token revocation)
  const snap = await alice.c.req('GET', `/api/environments/${prod.id}/rotation`);
  const newKey = generateEnvironmentKey();
  const ref = { projectId: pid, environmentId: prod.id };
  const rotated = snap.secrets.map((s: any) => ({
    id: s.id, ...encryptSecret(newKey, ref, s.id, decryptSecret(prod.key, ref, s.id, s)),
    versions: snap.versions[s.id].map((v: any) => ({ version: v.version, ...encryptSecret(newKey, ref, s.id, decryptSecret(prod.key, ref, s.id, v)) })),
  }));
  const r = await alice.c.req('POST', `/api/environments/${prod.id}/rotation`, {
    expectedKeyVersion: 1, grants: [{ userId: alice.id, wrappedKey: wrapEnvKeyForMember(newKey, pubA, ref) }], secrets: rotated,
  });
  ok(r.newKeyVersion === 2 && r.tokensRevoked === 1, 'rotation re-encrypted everything and revoked the token');
  let cliFailed = false;
  try { cli(['whoami']); } catch { cliFailed = true; }
  ok(cliFailed, 'old token no longer works after rotation');
  const post = await alice.c.req('GET', `/api/environments/${prod.id}/secrets`);
  ok(decryptSecret(newKey, ref, post.secrets[0].id, post.secrets[0]).value.length > 0, 'secrets decrypt with the new key');

  console.log('\nAudit + sends');
  const v = await alice.c.req('GET', `/api/projects/${pid}/audit/verify`);
  ok(v.valid && v.eventsChecked > 8, `project audit chain verifies (${v.eventsChecked} events)`);
  const s = createSend('hello from e2e');
  const created = await alice.c.req('POST', '/api/sends', { ciphertext: s.ciphertext, maxViews: 1, expiresInMinutes: 10 });
  const opened = await new Client().req('POST', `/api/public/sends/${created.id}/open`);
  ok(openSend(opened.ciphertext, s.key) === 'hello from e2e', 'one-time link decrypts with the fragment key');
  await new Client().req('POST', `/api/public/sends/${created.id}/open`, undefined, 404);
  ok(true, 'second open is refused');

  console.log(failures ? `\n${failures} check(s) failed` : '\nAll end-to-end checks passed');
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
