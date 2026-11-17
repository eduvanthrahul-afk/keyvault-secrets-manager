import { createServiceToken, encryptSecret, generateEnvironmentKey, newId } from '@keyvault/crypto';
import { describe, expect, it } from 'vitest';
import { assertSafeUrl, buildEnv, fetchEnvironment, format } from '../src/core';

function fakeServer(tamper = false) {
  const ref = { projectId: newId(), environmentId: newId() };
  const envKey = generateEnvironmentKey();
  const st = createServiceToken(envKey, ref);
  const id1 = newId();
  const s1 = encryptSecret(envKey, ref, id1, { name: 'DATABASE_URL', value: "postgres://u:p'w@db/app" });
  const id2 = newId();
  const s2 = encryptSecret(envKey, ref, id2, { name: 'API_KEY', value: 'abc' });
  let seenAuth = '';
  const impl = (async (_url: URL, init?: RequestInit) => {
    seenAuth = (init?.headers as Record<string, string>).Authorization!;
    return new Response(JSON.stringify({
      ...ref, environmentName: 'Production', keyVersion: 1, tokenId: st.tokenId, wrappedEnvKey: st.wrappedEnvKey,
      secrets: [{ id: id1, ...s1 }, { id: tamper ? id1 : id2, ...s2 }],
    }), { status: 200 });
  }) as unknown as typeof fetch;
  return { token: st.token, impl, auth: () => seenAuth };
}

describe('cli', () => {
  it('fetches and decrypts locally without sending the raw token', async () => {
    const srv = fakeServer();
    const env = await fetchEnvironment('http://localhost:8080', srv.token, srv.impl);
    expect(env.secrets.map((s) => s.name)).toEqual(['DATABASE_URL', 'API_KEY']);
    const secretPart = srv.token.split('.')[1]!;
    expect(srv.auth()).toMatch(/^KV-Service-Token /);
    expect(srv.auth()).not.toContain(secretPart);
  });

  it('detects a server that swaps ciphertexts between secrets', async () => {
    const srv = fakeServer(true);
    await expect(fetchEnvironment('http://localhost:8080', srv.token, srv.impl)).rejects.toThrow(/Decryption failed/);
  });

  it('refuses plain http to remote hosts', () => {
    expect(() => assertSafeUrl('http://example.com')).toThrow(/HTTP/);
    expect(assertSafeUrl('https://example.com').host).toBe('example.com');
    expect(assertSafeUrl('http://localhost:8080').port).toBe('8080');
  });

  it('formats for shells safely and strips the token from child env', () => {
    const secrets = [{ name: 'A', value: "it's" }];
    expect(format(secrets, 'shell')).toBe(`export A='it'\\''s'\n`);
    expect(JSON.parse(format(secrets, 'json'))).toEqual({ A: "it's" });
    const env = buildEnv({ KEYVAULT_TOKEN: 'kvs_x', A: 'old', B: 'keep' }, secrets);
    expect(env).toEqual({ A: "it's", B: 'keep' });
    expect(buildEnv({ A: 'old' }, secrets, false).A).toBe('old');
  });
});

import { escapeCmdArg, resolveWindowsCommand } from '../src/spawn';

describe('windows spawning', () => {
  it('escapes cmd metacharacters so arguments cannot inject commands', () => {
    expect(escapeCmdArg('a & calc')).toBe('^"a ^& calc^"');
    expect(escapeCmdArg('say "hi"')).toBe('^"say \\^"hi\\^"^"');
  });
  it('resolves commands through PATHEXT', () => {
    const files = new Set(['c:\\bin\\npm.cmd']);
    const env = { PATH: 'C:\\bin', PATHEXT: '.EXE;.CMD' };
    // Windows file systems are case-insensitive
    const r = resolveWindowsCommand('npm', env, (p) => files.has(p.toLowerCase()));
    expect(r?.toLowerCase()).toContain('npm.cmd');
  });
});
