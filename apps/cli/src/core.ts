// Fetch + decrypt logic, separated from the CLI entry point so it can be unit tested.
import {
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
