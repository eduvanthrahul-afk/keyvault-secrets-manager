import { estimatePasswordBits } from '@keyvault/crypto';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  type ButtonHTMLAttributes,
  type InputHTMLAttributes,
  type ReactNode,
} from 'react';

// ---------------------------------------------------------------- icons
// Small hand-drawn set; 1.6px strokes match the engraved look.
const paths: Record<string, ReactNode> = {
  eye: <><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z" /><circle cx="12" cy="12" r="3" /></>,
  eyeOff: <><path d="M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4.1M6.6 6.6A17 17 0 0 0 2 12s3.6 7 10 7a9.7 9.7 0 0 0 5.4-1.6" /><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" /></>,
  copy: <><rect x="8" y="8" width="13" height="13" rx="2" /><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3" /></>,
  check: <path d="M4 12.5 9.5 18 20 6" />,
  plus: <path d="M12 5v14M5 12h14" />,
  edit: <><path d="M4 20h4L19 9a2.8 2.8 0 0 0-4-4L4 16v4Z" /><path d="M13.5 6.5l4 4" /></>,
  trash: <><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3" /></>,
  history: <><path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 3v5h5M12 7v5l3 3" /></>,
  lock: <><rect x="4" y="11" width="16" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></>,
  unlock: <><rect x="4" y="11" width="16" height="10" rx="2" /><path d="M8 11V7a4 4 0 0 1 7.5-2" /></>,
  key: <><circle cx="8" cy="15" r="4" /><path d="m11 12 9-9M17 6l3 3M15 8l2 2" /></>,
  search: <><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></>,
  upload: <path d="M12 16V4M7 9l5-5 5 5M4 16v4h16v-4" />,
  download: <path d="M12 4v12M7 11l5 5 5-5M4 16v4h16v-4" />,
  users: <><circle cx="9" cy="8" r="3.5" /><path d="M2.5 20a6.5 6.5 0 0 1 13 0" /><path d="M16 4.5a3.5 3.5 0 0 1 0 7M18.5 14a6.5 6.5 0 0 1 3 6" /></>,
  layers: <><path d="m12 3 9 5-9 5-9-5 9-5Z" /><path d="m3 13 9 5 9-5" /></>,
  terminal: <><rect x="3" y="4" width="18" height="16" rx="2" /><path d="m7 9 3 3-3 3M13 15h4" /></>,
  activity: <path d="M3 12h4l3-8 4 16 3-8h4" />,
  settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1Z" /></>,
  send: <path d="M21 3 10 14M21 3l-7 18-4-7-7-4 18-7Z" />,
  user: <><circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0 1 16 0" /></>,
  menu: <path d="M4 6h16M4 12h16M4 18h16" />,
  x: <path d="M6 6l12 12M18 6 6 18" />,
  rotate: <><path d="M21 12a9 9 0 1 1-2.6-6.4L21 8" /><path d="M21 3v5h-5" /></>,
  shield: <path d="M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6l-8-3Z" />,
  alert: <><path d="M12 3 2 20h20L12 3Z" /><path d="M12 10v4M12 17h.01" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>,
  moon: <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z" />,
  monitor: <><rect x="2" y="4" width="20" height="13" rx="2" /><path d="M8 21h8M12 17v4" /></>,
  chevron: <path d="m9 6 6 6-6 6" />,
  github: <path d="M9 19c-4.3 1.4-4.3-2.5-6-3m12 5v-3.5c0-1 .1-1.4-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 0 0-1.3-3.2 4.2 4.2 0 0 0-.1-3.2s-1.1-.3-3.5 1.3a12.3 12.3 0 0 0-6.2 0C6.5 2.8 5.4 3.1 5.4 3.1a4.2 4.2 0 0 0-.1 3.2A4.6 4.6 0 0 0 4 9.5c0 4.6 2.7 5.7 5.5 6-.6.6-.6 1.2-.5 2V21" />,
  fingerprint: <><path d="M12 11v3a8 8 0 0 1-1 4M8.5 16.5a12 12 0 0 0 .5-4.5 3 3 0 0 1 6 0c0 1.3-.1 2.6-.3 3.8M17.3 18.8A21 21 0 0 0 18 12a6 6 0 0 0-11.5-2.4M5 15.4A13 13 0 0 0 6 12" /></>,
  diff: <><path d="M12 3v14M5 10h14M5 21h14" /></>,
  heart: <path d="M3 12h4l2-5 4 10 2-5h6" />,
  logout: <path d="M15 4h4a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1h-4M10 16l-4-4 4-4M6 12h10" />,
};

export function Icon({ name, size = 16, className }: { name: keyof typeof paths; size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className={className}>
      {paths[name]}
    </svg>
  );
}

// -------------------------------------------------------------- buttons

type BtnProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: 'primary' | 'brass' | 'danger' | 'ghost' | 'default';
  size?: 'sm' | 'lg' | 'icon';
  busy?: boolean;
  block?: boolean;
};

export function Button({ variant = 'default', size, busy, block, className, children, disabled, ...rest }: BtnProps) {
  const cls = ['btn', variant !== 'default' && variant, size, block && 'block', className].filter(Boolean).join(' ');
  return (
    <button className={cls} disabled={disabled || busy} aria-busy={busy || undefined} {...rest}>
      {busy && <span className="spinner" aria-hidden="true" />}
      {children}
    </button>
  );
}

// --------------------------------------------------------------- fields

type FieldProps = InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: ReactNode; error?: string | null; code?: boolean };

export function Field({ label, hint, error, code, className, ...rest }: FieldProps) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input id={id} className={`input ${code ? 'code' : ''} ${className ?? ''}`} aria-invalid={error ? true : undefined}
        aria-describedby={hint || error ? `${id}-d` : undefined} {...rest} />
      {error ? <span id={`${id}-d`} className="error">{error}</span> : hint ? <span id={`${id}-d`} className="hint">{hint}</span> : null}
    </div>
  );
}

export function PasswordMeter({ password }: { password: string }) {
  const bits = estimatePasswordBits(password);
  const level = password.length < 12 ? 1 : bits < 60 ? 1 : bits < 80 ? 2 : 3;
  const label = password.length === 0 ? 'Use 12+ characters. A few unrelated words works well.'
    : password.length < 12 ? `${12 - password.length} more characters needed`
    : level === 1 ? 'Weak: add length or variety' : level === 2 ? 'Fair: longer is better' : 'Strong';
  return (
    <div className="stack" style={{ '--gap': '6px' } as React.CSSProperties}>
      <div className="meter" data-level={level} aria-hidden="true">
        <span style={{ width: `${Math.min(100, (bits / 100) * 100)}%` }} />
      </div>
      <span className="xs faint" aria-live="polite">{label}</span>
    </div>
  );
}

// --------------------------------------------------------------- modal

export function Modal({ open, onClose, title, children, footer, wide, description }: {
  open: boolean; onClose: () => void; title: string; children: ReactNode; footer?: ReactNode; wide?: boolean; description?: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog ref={ref} aria-labelledby={titleId} className={`modal ${wide ? 'wide' : ''}`} onClose={onClose} onCancel={(e) => { e.preventDefault(); onClose(); }}
      onClick={(e) => { if (e.target === ref.current) onClose(); }}>
      {open && (
        <>
          <div className="modal-head">
            <div>
              <h3 id={titleId}>{title}</h3>
              {description && <p className="small muted" style={{ marginTop: 6 }}>{description}</p>}
            </div>
            <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close"><Icon name="x" /></Button>
          </div>
          <div className="modal-body">{children}</div>
          {footer && <div className="modal-foot">{footer}</div>}
        </>
      )}
    </dialog>
  );
}

// --------------------------------------------------------------- toasts

export interface ToastAction { label: string; onClick: () => void; durationMs?: number }
interface Toast { id: number; text: string; kind: 'info' | 'error'; action?: ToastAction }
type PushToast = (text: string, kind?: Toast['kind'], action?: ToastAction) => void;
const ToastCtx = createContext<PushToast>(() => {});

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), []);
  const push = useCallback<PushToast>((text, kind = 'info', action) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t.slice(-3), { id, text, kind, action }]);
    window.setTimeout(() => dismiss(id), action?.durationMs ?? (kind === 'error' ? 6000 : 3200));
  }, [dismiss]);
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`}>
            <span className="grow">{t.text}</span>
            {t.action && <button type="button" className="toast-action" onClick={() => { t.action!.onClick(); dismiss(t.id); }}>{t.action.label}</button>}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

/** Placeholder rows while data loads; keeps layout stable instead of a spinner flash. */
export function SkeletonRows({ rows = 5, cols = 3 }: { rows?: number; cols?: number }) {
  return (
    <div className="skeleton-rows" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <div className="skeleton-row" key={i}>
          {Array.from({ length: cols }, (_, j) => <span key={j} className="skeleton" style={{ width: `${[28, 46, 14][j % 3]! + ((i * 7) % 12)}%` }} />)}
        </div>
      ))}
    </div>
  );
}

/** True when keyboard focus is somewhere the user is typing (shortcuts must not fire there). */
export function isTyping(): boolean {
  const el = document.activeElement as HTMLElement | null;
  return !!el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT' || el.isContentEditable);
}

export function anyDialogOpen(): boolean {
  return !!document.querySelector('dialog[open]');
}

export const useToast = () => useContext(ToastCtx);

// ----------------------------------------------------------- clipboard

/** Copies, then clears the clipboard after 30s if it still holds the secret. */
export async function copySecret(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
  window.setTimeout(async () => {
    try {
      if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText('');
    } catch {
      /* readText needs permission; best effort only */
    }
  }, 30_000);
}

export function CopyButton({ value, label = 'Copy', iconOnly, secret }: { value: string | (() => string); label?: string; iconOnly?: boolean; secret?: boolean }) {
  const [done, setDone] = useState(false);
  const toast = useToast();
  return (
    <Button size={iconOnly ? 'icon' : 'sm'} variant={iconOnly ? 'ghost' : 'default'} aria-label={iconOnly ? label : undefined} title={label}
      onClick={async () => {
        try {
          const v = typeof value === 'function' ? value() : value;
          if (secret) await copySecret(v); else await navigator.clipboard.writeText(v);
          setDone(true);
          window.setTimeout(() => setDone(false), 1400);
        } catch (e) {
          toast((e as Error).message || 'Copy failed', 'error');
        }
      }}>
      <Icon name={done ? 'check' : 'copy'} />
      {!iconOnly && (done ? 'Copied' : label)}
    </Button>
  );
}

// --------------------------------------------------------------- misc

export function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : 'Something went wrong';
}

const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const diff = (new Date(iso).getTime() - Date.now()) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return 'just now';
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute');
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour');
  if (abs < 86400 * 30) return rtf.format(Math.round(diff / 86400), 'day');
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

export function downloadText(filename: string, text: string): void {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function Spinner({ label = 'Loading' }: { label?: string }) {
  return <div className="center-fill muted row"><span className="spinner" /> <span>{label}…</span></div>;
}
