// Cross-platform child process launch WITHOUT handing a concatenated string to a shell.
// POSIX: plain execvp. Windows: resolve the command on PATH/PATHEXT; .exe/.com run directly,
// .cmd/.bat shims (npm, npx, yarn…) go through cmd.exe with every argument escaped.
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';

export function resolveWindowsCommand(cmd: string, env: NodeJS.ProcessEnv, exists: (p: string) => boolean = existsSync): string | null {
  const exts = (env.PATHEXT ?? '.COM;.EXE;.BAT;.CMD').split(';').filter(Boolean);
  const hasExt = path.win32.extname(cmd) !== '';
  const explicit = cmd.includes('\\') || cmd.includes('/');
  const dirs = explicit ? [''] : ['', ...(env.PATH ?? env.Path ?? '').split(';').filter(Boolean)];
  for (const dir of dirs) {
    const base = dir ? path.win32.join(dir, cmd) : cmd;
    if (hasExt && exists(base)) return base;
    for (const ext of exts) if (exists(base + ext)) return base + ext;
  }
  return null;
}

/** Escape one argument for cmd.exe (same approach as cross-spawn). */
export function escapeCmdArg(arg: string): string {
  let a = arg.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\*)$/, '$1$1');
  a = `"${a}"`;
  return a.replace(/[()%!^"<>&|]/g, '^$&');
}

export function launch(command: string[], env: NodeJS.ProcessEnv): ChildProcess {
  const [cmd, ...args] = command as [string, ...string[]];
  if (process.platform !== 'win32') return spawn(cmd, args, { env, stdio: 'inherit' });
  const resolved = resolveWindowsCommand(cmd, env) ?? cmd;
  if (/\.(cmd|bat)$/i.test(resolved)) {
    const line = [escapeCmdArg(resolved), ...args.map(escapeCmdArg)].join(' ');
    return spawn(env.ComSpec ?? 'cmd.exe', ['/d', '/s', '/c', `"${line}"`], { env, stdio: 'inherit', windowsVerbatimArguments: true });
  }
  return spawn(resolved, args, { env, stdio: 'inherit' });
}
