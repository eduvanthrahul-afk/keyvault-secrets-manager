// Creates a realistic fixture for load tests: one account, a project, 60 encrypted secrets and an
// access token. Writes scripts/load/.seed.json for k6.js and bench.ts.
import { writeFileSync } from 'node:fs';
import { createAccount, createServiceToken, encryptSecret, generateEnvironmentKey, newId, parseServiceToken, wrapEnvKeyForMember } from '../../packages/crypto/src/index';

const BASE = process.env.KEYVAULT_URL ?? 'http://localhost:8080';

async function req(method: string, path: string, body: unknown, cookie = '') {
  const res = await fetch(BASE + path, { method, headers: { 'Content-Type': 'application/json', 'X-KV-Request': '1', Cookie: cookie, Origin: BASE }, body: JSON.stringify(body) });
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${await res.text()}`);
  return { json: await res.json().catch(() => null), cookie: res.headers.get('set-cookie')?.split(';')[0] ?? cookie };
}

const reg = await createAccount(`load-${Date.now()}@example.com`, 'load test master password 2026');
const { cookie, json: session } = await req('POST', '/api/auth/register', { ...reg.request, displayName: 'Load Test' });
const projectId = newId();
const environmentId = newId();
const envKey = generateEnvironmentKey();
const ref = { projectId, environmentId };
await req('POST', '/api/projects', {
  id: projectId, name: 'load-test', description: 'k6 fixture',
  environments: [{ id: environmentId, name: 'Production', slug: 'production', wrappedKey: wrapEnvKeyForMember(envKey, session.session.publicKey, ref) }],
}, cookie);
const secrets = Array.from({ length: 60 }, (_, i) => {
  const id = newId();
  return { id, ...encryptSecret(envKey, ref, id, { name: `SECRET_${String(i).padStart(2, '0')}`, value: `value-${i}-${'x'.repeat(40)}` }), keyVersion: 1 };
});
await req('POST', `/api/environments/${environmentId}/secrets`, { secrets }, cookie);
const st = createServiceToken(envKey, ref);
await req('POST', `/api/environments/${environmentId}/tokens`, { tokenId: st.tokenId, name: 'load', verifier: st.verifier, wrappedEnvKey: st.wrappedEnvKey, keyVersion: 1 }, cookie);
const parsed = parseServiceToken(st.token);

writeFileSync(new URL('./.seed.json', import.meta.url), JSON.stringify({
  baseUrl: BASE, environmentId, cookie, token: st.token,
  serviceAuthorization: `KV-Service-Token ${parsed.tokenId}.${parsed.authSecret}`,
}, null, 2));
console.log(`Seeded project with ${secrets.length} secrets → scripts/load/.seed.json`);
