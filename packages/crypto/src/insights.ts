// Client-side intelligence over DECRYPTED secrets. All of this must run on the client:
// the server cannot see values, so it cannot resolve references, compare environments or
// detect a live key in the wrong place. Shared by the web app and the CLI.

// ----------------------------------------------------------- references
//
// A value may reference another secret in the same environment:  ${DB_HOST}:${DB_PORT}
// Write $${ to produce a literal "${". References resolve recursively, with cycle detection.

const REF = /\$\$\{|\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g;
const MAX_DEPTH = 16;

export interface Resolved {
  value: string;
  references: string[];
  error?: string;
}

export function findReferences(value: string): string[] {
  const out = new Set<string>();
  for (const m of value.matchAll(REF)) if (m[1]) out.add(m[1]);
  return [...out];
}

export function resolveReferences(secrets: { name: string; value: string }[]): Map<string, Resolved> {
  const raw = new Map(secrets.map((s) => [s.name, s.value]));
  const done = new Map<string, Resolved>();

  const resolve = (name: string, stack: string[]): Resolved => {
    const cached = done.get(name);
    if (cached) return cached;
    const value = raw.get(name)!;
    const refs = findReferences(value);
    let error: string | undefined;
    if (stack.length > MAX_DEPTH) {
      return { value, references: refs, error: 'References are nested too deeply' };
    }
    const out = value.replace(REF, (whole, ref?: string) => {
      if (!ref) return '${'; // escaped
      if (stack.includes(ref) || ref === name) {
        error ??= `Circular reference: ${[...stack, name, ref].join(' → ')}`;
        return whole;
      }
      if (!raw.has(ref)) {
        error ??= `\${${ref}} does not exist in this environment`;
        return whole;
      }
      const inner = resolve(ref, [...stack, name]);
      if (inner.error) error ??= inner.error;
      return inner.value;
    });
    const result: Resolved = { value: out, references: refs, ...(error ? { error } : {}) };
    done.set(name, result);
    return result;
  };

  for (const s of secrets) resolve(s.name, []);
  return done;
}

// --------------------------------------------------------------- health

export type Severity = 'critical' | 'warning' | 'info';

export interface Finding {
  rule: string;
  severity: Severity;
  environment: string;
  secret: string;
  message: string;
  fix: string;
}

export interface HealthEnvironment {
  slug: string;
  name: string;
  secrets: { name: string; value: string; updatedAt?: string }[];
}

const LIVE_PATTERNS: { re: RegExp; label: string }[] = [
  { re: /\bsk_live_[0-9A-Za-z]{8,}/, label: 'Stripe live secret key' },
  { re: /\brk_live_[0-9A-Za-z]{8,}/, label: 'Stripe live restricted key' },
  { re: /\bxox[bp]-[0-9A-Za-z-]{10,}/, label: 'Slack token' },
  { re: /\bgh[pousr]_[0-9A-Za-z]{30,}/, label: 'GitHub token' },
  { re: /\bAKIA[0-9A-Z]{16}\b/, label: 'AWS access key' },
  { re: /\bSG\.[0-9A-Za-z_-]{16,}\.[0-9A-Za-z_-]{16,}/, label: 'SendGrid key' },
];
const TEST_PATTERNS = [/\b[sprk]k_test_[0-9A-Za-z]{4,}/, /\bsandbox\b/i, /\.test\.|staging\./i];
const WEAK = new Set(['password', 'changeme', 'change-me', 'admin', 'secret', '123456', '12345678', 'qwerty', 'letmein', 'default', 'test', 'root', 'pass']);
const PLACEHOLDER = /^(todo|tbd|xxx+|fixme|(replace|change)[-_ ]?me|<.*>|\.\.\.|your[-_].*|example)$/i;
const SENSITIVE_NAME = /(PASSWORD|PASSWD|SECRET|TOKEN|PRIVATE|API_?KEY|_KEY$|^KEY$|CREDENTIAL|SALT)/i;
const LOCALHOST = /\b(localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal)\b/i;
const DAY = 86_400_000;

const isProd = (slug: string) => /^(prod|production|live)$/i.test(slug);

export function analyzeHealth(envs: HealthEnvironment[], now = Date.now()): { score: number; findings: Finding[] } {
  const findings: Finding[] = [];
  const add = (f: Finding) => findings.push(f);

  for (const env of envs) {
    const resolved = resolveReferences(env.secrets);
    for (const s of env.secrets) {
      const v = s.value;
      const at = { environment: env.name, secret: s.name };
      const r = resolved.get(s.name);
      if (r?.error) add({ ...at, rule: 'broken-reference', severity: 'critical', message: r.error, fix: 'Create the referenced secret or fix the name.' });

      if (!isProd(env.slug)) {
        for (const p of LIVE_PATTERNS) {
          if (p.re.test(v) && /live|AKIA|gh|xox|SG\./.test(v)) {
            add({ ...at, rule: 'live-key-outside-production', severity: 'critical', message: `${p.label} found in ${env.name}.`, fix: 'Use a test/sandbox credential here; live keys belong only in production.' });
            break;
          }
        }
      } else {
        if (TEST_PATTERNS[0]!.test(v)) add({ ...at, rule: 'test-key-in-production', severity: 'critical', message: 'Looks like a test key running in production.', fix: 'Replace it with the live credential.' });
        if (LOCALHOST.test(v)) add({ ...at, rule: 'localhost-in-production', severity: 'warning', message: 'Points at localhost in production.', fix: 'Use the production host name.' });
      }

      if (v === '') {
        add({ ...at, rule: 'empty', severity: 'info', message: 'Value is empty.', fix: 'Delete it, or set a value so apps don\'t silently fall back.' });
      } else if (PLACEHOLDER.test(v.trim())) {
        add({ ...at, rule: 'placeholder', severity: 'warning', message: `Value "${v.trim()}" looks like a placeholder.`, fix: 'Set the real value.' });
      } else if (SENSITIVE_NAME.test(s.name) && findReferences(v).length === 0 && (WEAK.has(v.toLowerCase()) || (v.length < 12 && !/^\d+$/.test(v)))) {
        add({ ...at, rule: 'weak-value', severity: isProd(env.slug) ? 'critical' : 'warning', message: `${s.name} looks sensitive but its value is short or common.`, fix: 'Generate a long random value (32+ characters).' });
      }

      if (s.updatedAt) {
        const age = (now - new Date(s.updatedAt).getTime()) / DAY;
        if (age > 365) add({ ...at, rule: 'stale', severity: 'warning', message: `Not changed in ${Math.floor(age)} days.`, fix: 'Rotate it at the provider, then update it here.' });
        else if (age > 180 && SENSITIVE_NAME.test(s.name)) add({ ...at, rule: 'stale', severity: 'info', message: `Not changed in ${Math.floor(age)} days.`, fix: 'Consider rotating it.' });
      }
    }
  }

  // Cross-environment: the same credential in production and elsewhere defeats isolation.
  const prod = envs.filter((e) => isProd(e.slug));
  for (const p of prod) {
    const prodValues = new Map(p.secrets.filter((s) => s.value.length >= 8).map((s) => [s.name, s.value]));
    for (const other of envs.filter((e) => e !== p)) {
      for (const s of other.secrets) {
        if (prodValues.get(s.name) === s.value && findReferences(s.value).length === 0 && SENSITIVE_NAME.test(s.name)) {
          add({ environment: other.name, secret: s.name, rule: 'shared-with-production', severity: 'critical', message: `Same value as in ${p.name}.`, fix: `Give ${other.name} its own credential so a leak there can't reach production.` });
        }
      }
    }
  }

  const weight = { critical: 15, warning: 5, info: 1 } as const;
  const order = { critical: 0, warning: 1, info: 2 } as const;
  findings.sort((a, b) => order[a.severity] - order[b.severity] || a.environment.localeCompare(b.environment) || a.secret.localeCompare(b.secret));
  const score = Math.max(0, 100 - findings.reduce((n, f) => n + weight[f.severity], 0));
  return { score, findings };
}

// ----------------------------------------------------------------- diff

export type DiffCell = { present: false } | { present: true; value: string };
export interface DiffRow {
  name: string;
  cells: DiffCell[];
  status: 'same' | 'differs' | 'missing';
}

/** Compare environments by secret name. "same" = identical everywhere it exists AND present everywhere. */
export function diffEnvironments(envs: HealthEnvironment[]): DiffRow[] {
  const names = [...new Set(envs.flatMap((e) => e.secrets.map((s) => s.name)))].sort();
  return names.map((name) => {
    const cells: DiffCell[] = envs.map((e) => {
      const s = e.secrets.find((x) => x.name === name);
      return s ? { present: true, value: s.value } : { present: false };
    });
    const present = cells.filter((c): c is { present: true; value: string } => c.present);
    const status = present.length < envs.length ? 'missing' : new Set(present.map((c) => c.value)).size === 1 ? 'same' : 'differs';
    return { name, cells, status };
  });
}
