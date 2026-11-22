// Fetch + decrypt logic, separated from the CLI entry point so it can be unit tested.
import { writeFileSync } from 'node:fs';
import {
  analyzeHealth,
  decryptSecret,
  parseServiceToken,
  resolveReferences,
  toDotenv,
  unwrapServiceTokenEnvKey,
  wipe,
  type SecretPlaintext,
} from '@keyvault/crypto';

export interface FetchedEnvironment {
  projectId: string;
  environmentId: string;
  environmentName: string;
  environmentSlug: string;
  secrets: SecretPlaintext[];
}

interface ServiceResponse {
  projectId: string;
  environmentId: string;
  environmentName: string;
  environmentSlug?: string;
  keyVersion: number;
  tokenId: string;
  wrappedEnvKey: string;
  secrets: { id: string; nameCiphertext: string; valueCiphertext: string; commentCiphertext: string | null }[];
}

export class CliError extends Error {}

export function assertSafeUrl(url: string): URL {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    throw new CliError(`Invalid KEYVAULT_URL: ${url}`);
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) {
    throw new CliError('Refusing to send a token over plain HTTP to a non-local server. Use https://.');
  }
  return u;
}

export async function fetchEnvironment(baseUrl: string, token: string, fetchImpl: typeof fetch = fetch): Promise<FetchedEnvironment> {
  const url = assertSafeUrl(baseUrl);
  let parsed;
  try {
    parsed = parseServiceToken(token);
  } catch {
    throw new CliError('KEYVAULT_TOKEN is not a valid KeyVault access token (expected kvs_…)');
  }
  const res = await fetchImpl(new URL('/api/v1/service/secrets', url), {
    headers: { Authorization: `KV-Service-Token ${parsed.tokenId}.${parsed.authSecret}`, 'User-Agent': 'keyvault-cli/2.0', Accept: 'application/json' },
  });
  if (!res.ok) {
    let detail = `HTTP ${res.status}`;
    try {
      detail = ((await res.json()) as { detail?: string }).detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new CliError(`KeyVault rejected the request: ${detail}`);
  }
  const body = (await res.json()) as ServiceResponse;
  if (body.tokenId !== parsed.tokenId) throw new CliError('Server response is for a different token');
  const ref = { projectId: body.projectId, environmentId: body.environmentId };
  const envKey = unwrapServiceTokenEnvKey(parsed.wrapKey, body.wrappedEnvKey, ref, parsed.tokenId);
  try {
    const secrets = body.secrets.map((s) => decryptSecret(envKey, ref, s.id, s));
    return { projectId: body.projectId, environmentId: body.environmentId, environmentName: body.environmentName,
      environmentSlug: body.environmentSlug ?? body.environmentName.toLowerCase(), secrets };
  } finally {
    wipe(envKey, parsed.wrapKey);
  }
}

export function format(secrets: SecretPlaintext[], fmt: string): string {
  switch (fmt) {
    case 'dotenv':
      return toDotenv(secrets);
    case 'json':
      return JSON.stringify(Object.fromEntries(secrets.map((s) => [s.name, s.value])), null, 2) + '\n';
    case 'shell':
      return secrets.map((s) => `export ${s.name}='${s.value.replace(/'/g, `'\\''`)}'`).join('\n') + '\n';
    default:
      throw new CliError(`Unknown format "${fmt}". Use dotenv, json or shell.`);
  }
}

/** Secrets override the parent environment unless --no-override is given. */
export function buildEnv(parent: NodeJS.ProcessEnv, secrets: SecretPlaintext[], override = true): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...parent };
  delete env.KEYVAULT_TOKEN; // never leak the token into the child process
  for (const s of secrets) {
    if (override || env[s.name] === undefined) env[s.name] = s.value;
  }
  return env;
}

/** Resolve ${NAME} references exactly like the web app does. Fails loudly on broken references. */
export function resolveAll(secrets: SecretPlaintext[]): SecretPlaintext[] {
  const resolved = resolveReferences(secrets);
  return secrets.map((s) => {
    const r = resolved.get(s.name)!;
    if (r.error) throw new CliError(`${s.name}: ${r.error}`);
    return { name: s.name, value: r.value };
  });
}

/** Secret names only, one per line. Values are never included. */
export function formatNames(secrets: SecretPlaintext[]): string {
  return secrets.length ? secrets.map((s) => s.name).join('\n') + '\n' : '';
}

/**
 * Write an export to a file. Refuses to overwrite an existing file unless force is set.
 * New files are created with mode 0600 (owner-only; Windows ignores POSIX modes).
 */
export function writeSecretFile(path: string, content: string, force = false): void {
  try {
    writeFileSync(path, content, { flag: force ? 'w' : 'wx', mode: 0o600 });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'EEXIST') {
      throw new CliError(`${path} already exists. Use --force to overwrite it.`);
    }
    throw e;
  }
}

/** Describe what `kv run` would inject and run, without starting the process. Names only, never values. */
export function dryRunText(command: string[], secrets: SecretPlaintext[], parent: NodeJS.ProcessEnv, override = true): string {
  const names = secrets.filter((s) => override || parent[s.name] === undefined).map((s) => s.name);
  return `would inject ${names.length} secret(s): ${names.join(', ') || '(none)'}\ncommand: ${command.join(' ')}\n(dry run: process not started)\n`;
}

/** JSON report for `kv doctor --json`. */
export function doctorJson<F extends { severity: string }>(environment: string, score: number, findings: F[]): string {
  return JSON.stringify({ score, environment, findings }, null, 2) + '\n';
}

export type FailOn = 'critical' | 'warning';

/** Parse --fail-on. Defaults to critical-only, matching the previous behaviour. */
export function parseFailOn(value: string | undefined): FailOn {
  if (value === undefined) return 'critical';
  if (value === 'critical' || value === 'warning') return value;
  throw new CliError(`Invalid --fail-on "${value}". Use critical or warning.`);
}

function severityRank(sev: string): number {
  return sev === 'critical' ? 2 : sev === 'warning' ? 1 : 0;
}

/** True when any finding is at or above the failOn severity. */
export function shouldFail(findings: ReadonlyArray<{ severity: string }>, failOn: FailOn): boolean {
  return findings.some((f) => severityRank(f.severity) >= severityRank(failOn));
}

export type HealthReport = ReturnType<typeof analyzeHealth>;

