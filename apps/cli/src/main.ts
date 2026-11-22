import { launch } from './spawn';
import { parseArgs } from 'node:util';
import { analyzeHealth } from '@keyvault/crypto';
import { buildEnv, CliError, dryRunText, doctorJson, fetchEnvironment, format, formatNames, parseFailOn, resolveAll, shouldFail, writeSecretFile } from './core';

const HELP = `kv: KeyVault CLI

Secrets are fetched as ciphertext and decrypted locally with your access token.

Usage:
  kv run [--no-override] [--dry-run] -- <command> [args...]   Run a command with secrets as env vars
                                                  (--dry-run prints the injected names and command, and does not start it)
  kv list                                         Print secret names only (never values)
  kv export [--format dotenv|json|shell] [--out <file> [--force]]
                                                  Print secrets (default: dotenv), or write them to a file
                                                  (created with mode 0600; --force overwrites an existing file)
  kv get <NAME>                                   Print one secret's value
  kv whoami                                       Show which project/environment the token reads
  kv doctor [--json] [--fail-on critical|warning] Check secrets for leaks, weak values, broken references
                                                  (--json prints a JSON report; exit code 2 on critical findings,
                                                  or on warnings too with --fail-on warning)

Values may reference other secrets (\${HOST}:\${PORT}); they are resolved locally before use.

Configuration (flags override environment variables):
  --token, KEYVAULT_TOKEN   Access token (kvs_…), created under Project → Access tokens
  --url,   KEYVAULT_URL     Server URL (default http://localhost:8080)
`;

async function main(argv: string[]): Promise<number> {
  const dash = argv.indexOf('--');
  const own = dash >= 0 ? argv.slice(0, dash) : argv;
  const child = dash >= 0 ? argv.slice(dash + 1) : [];
  const { values: opts, positionals } = parseArgs({
    args: own,
    allowPositionals: true,
    options: {
      token: { type: 'string' },
      url: { type: 'string' },
      format: { type: 'string', short: 'f', default: 'dotenv' },
      'no-override': { type: 'boolean', default: false },
      'dry-run': { type: 'boolean', default: false },
      out: { type: 'string' },
      force: { type: 'boolean', default: false },
      json: { type: 'boolean', default: false },
      'fail-on': { type: 'string' },
      help: { type: 'boolean', short: 'h' },
      version: { type: 'boolean', short: 'v' },
    },
  });
  const [cmd, ...rest] = positionals;
  if (opts.version) return out('2.1.0\n');
  if (opts.help || !cmd) return out(HELP);

  const token = opts.token ?? process.env.KEYVAULT_TOKEN;
  const url = opts.url ?? process.env.KEYVAULT_URL ?? 'http://localhost:8080';
  if (!token) throw new CliError('No token. Set KEYVAULT_TOKEN or pass --token.');
  const env = await fetchEnvironment(url, token);
  const values = () => resolveAll(env.secrets);

  switch (cmd) {
    case 'run': {
      const command = child.length ? child : rest;
      if (!command.length) throw new CliError('Usage: kv run -- <command> [args...]');
      const override = !opts['no-override'];
      if (opts['dry-run']) return out(dryRunText(command, values(), process.env, override));
      return run(command, buildEnv(process.env, values(), override));
    }
    case 'list':
      return out(formatNames(env.secrets));
    case 'export': {
      const text = format(values(), opts.format!);
      if (!opts.out) return out(text);
      writeSecretFile(opts.out, text, opts.force);
      return 0;
    }
    case 'get': {
      const name = rest[0];
      if (!name) throw new CliError('Usage: kv get <NAME>');
      const s = values().find((x) => x.name === name);
      if (!s) throw new CliError(`${name} is not set in ${env.environmentName}`);
      return out(s.value + (process.stdout.isTTY ? '\n' : ''));
    }
    case 'whoami':
      return out(`project:     ${env.projectId}\nenvironment: ${env.environmentName} (${env.environmentId})\nsecrets:     ${env.secrets.length}\n`);
    case 'doctor': {
      const failOn = parseFailOn(opts['fail-on']);
      const { score, findings } = analyzeHealth([{ slug: env.environmentSlug, name: env.environmentName, secrets: env.secrets }]);
      if (opts.json) {
        out(doctorJson(env.environmentName, score, findings));
      } else {
        const icon = { critical: 'x', warning: '!', info: '-' } as const;
        let text = `${env.environmentName}: health ${score}/100, ${findings.length} finding(s)
`;
        for (const f of findings) text += `  [${icon[f.severity]}] ${f.secret}: ${f.message}
      ${f.fix}
`;
        out(text);
      }
      return shouldFail(findings, failOn) ? 2 : 0;
    }
    default:
      throw new CliError(`Unknown command "${cmd}". Run kv --help.`);
  }
}

function out(s: string): number {
  process.stdout.write(s);
  return 0;
}

function run(command: string[], env: NodeJS.ProcessEnv): Promise<number> {
  return new Promise((resolve) => {
    const proc = launch(command, env);
    const forward = (sig: NodeJS.Signals) => proc.kill(sig);
    process.on('SIGINT', forward);
    process.on('SIGTERM', forward);
    proc.on('error', (e) => {
      process.stderr.write(`kv: could not start ${command[0]}: ${e.message}\n`);
      resolve(127);
    });
    proc.on('exit', (code, signal) => resolve(code ?? (signal ? 128 : 1)));
  });
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e) => {
    process.stderr.write(`kv: ${e instanceof CliError ? e.message : (e as Error).stack ?? e}\n`);
    process.exit(1);
  },
);
