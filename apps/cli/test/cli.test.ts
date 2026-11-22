import { createServiceToken, encryptSecret, generateEnvironmentKey, newId } from '@keyvault/crypto';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  assertSafeUrl, buildEnv, doctorJson, dryRunText, fetchEnvironment, format, formatNames, parseFailOn, shouldFail, writeSecretFile,
} from '../src/core';

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

describe('cli commands', () => {
  it('kv list prints secret names only, one per line, never values', async () => {
    const srv = fakeServer();
    const env = await fetchEnvironment('http://localhost:8080', srv.token, srv.impl);
    const text = formatNames(env.secrets);
    expect(text).toBe('DATABASE_URL\nAPI_KEY\n');
    expect(text).not.toContain('postgres://');
    expect(text).not.toContain('abc');
  });

  it('kv export --out writes the file and refuses to overwrite it without --force', () => {
    const dir = mkdtempSync(join(tmpdir(), 'kv-export-'));
    try {
      const file = join(dir, '.env');
      writeSecretFile(file, 'A=1\n');
      expect(readFileSync(file, 'utf8')).toBe('A=1\n');
      expect(() => writeSecretFile(file, 'A=2\n')).toThrow(/--force/);
      expect(readFileSync(file, 'utf8')).toBe('A=1\n');
      writeSecretFile(file, 'A=2\n', true);
      expect(readFileSync(file, 'utf8')).toBe('A=2\n');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // Windows ignores POSIX permission bits, so this only runs on POSIX hosts.
  it.skipIf(process.platform === 'win32')('kv export --out creates the file with mode 0600', () => {
    const dir = mkdtempSync(join(tmpdir(), 'kv-export-'));
    try {
      const file = join(dir, '.env');
      writeSecretFile(file, 'A=1\n');
      expect(statSync(file).mode & 0o777).toBe(0o600);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('kv doctor --json prints JSON with score, environment and findings keys', () => {
    const findings = [{ severity: 'warning', secret: 'API_KEY', message: 'weak value', fix: 'rotate it' }];
    const parsed = JSON.parse(doctorJson('Production', 80, findings));
    expect(Object.keys(parsed).sort()).toEqual(['environment', 'findings', 'score']);
    expect(parsed.environment).toBe('Production');
    expect(parsed.score).toBe(80);
    expect(parsed.findings).toEqual(findings);
  });

  it('kv doctor --fail-on warning fails on a warning finding, the default does not', () => {
    const warn = [{ severity: 'warning' }];
    // main.ts maps shouldFail(...) to exit code 2; these helpers drive that branch.
    expect(shouldFail(warn, parseFailOn('warning'))).toBe(true);
    expect(shouldFail(warn, parseFailOn(undefined))).toBe(false);
  });

  it('kv doctor rejects an unknown --fail-on value', () => {
    expect(() => parseFailOn('bogus')).toThrow(/Invalid --fail-on/);
  });

  it('kv run --dry-run prints secret names and the command, never values', async () => {
    const srv = fakeServer();
    const env = await fetchEnvironment('http://localhost:8080', srv.token, srv.impl);
    // dryRunText is the pure helper behind the --dry-run branch; main.ts returns before run()/launch() is called.
    const text = dryRunText(['node', 'app.js'], env.secrets, {});
    expect(text).toContain('would inject 2 secret(s): DATABASE_URL, API_KEY');
    expect(text).toContain('command: node app.js');
    expect(text).not.toContain('postgres://');
    expect(text).not.toContain('abc');
  });
});

