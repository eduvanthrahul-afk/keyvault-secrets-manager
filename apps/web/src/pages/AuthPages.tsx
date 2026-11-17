import { parseRecoveryKey, recoverAccount, MIN_PASSWORD_LENGTH } from '@keyvault/crypto';
import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { Identicon } from '../components/Identicon';
import { Logo } from '../components/Logo';
import { Button, CopyButton, Field, Icon, PasswordMeter, downloadText, errorMessage } from '../components/ui';
import { passkeysSupported } from '../lib/passkey';
import { api } from '../lib/api';
import { useVault } from '../lib/vault';

function AuthLayout({ children, quote }: { children: ReactNode; quote?: ReactNode }) {
  return (
    <div className="auth">
      <header className="auth-top">
        <Link to="/" className="brand" style={{ padding: 0 }}><Logo /> KeyVault</Link>
      </header>
      <main className="auth-card boxed">{children}</main>
      <p className="auth-foot">
        {quote ?? <>Your master password never leaves this device. Keys are derived locally with Argon2id; we can't read your secrets or reset your password.</>}
      </p>
    </div>
  );
}

export function Login() {
  const vault = useVault();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const next = (location.state as { from?: string } | null)?.from ?? '/app';

  if (vault.status === 'unlocked') return <Navigate to={next} replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mfaToken) {
        await vault.completeMfa(mfaToken, code);
      } else {
        const r = await vault.login(email, password);
        if (r) {
          setMfaToken(r.mfaToken);
          setBusy(false);
          return;
        }
      }
      navigate(next, { replace: true });
    } catch (err) {
      setError(errorMessage(err));
      if (mfaToken && /expired|start again/i.test(errorMessage(err))) setMfaToken(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout>
      <div>
        <h1>{mfaToken ? 'Two-step verification' : 'Sign in'}</h1>
        <p className="sub">{mfaToken ? 'Enter the 6-digit code from your authenticator app, or one of your recovery codes.' : 'Unlocking happens on this device. It takes a second while your key is derived.'}</p>
      </div>
      <form className="stack" style={{ '--gap': '14px' } as React.CSSProperties} onSubmit={submit} noValidate>
        {mfaToken ? (
          <Field label="Verification code" value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code"
            inputMode="text" autoFocus code required maxLength={16} />
        ) : (
          <>
            <Field label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required autoFocus />
            <Field label="Master password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" required />
          </>
        )}
        {error && <div className="notice danger" role="alert">{error}</div>}
        <Button variant="primary" size="lg" type="submit" busy={busy} block>{mfaToken ? 'Verify and sign in' : busy ? 'Deriving keys' : 'Sign in'}</Button>
      </form>
      <div className="row spread small">
        <Link to="/register">Create an account</Link>
        <Link to="/recover">Forgot your password?</Link>
      </div>
    </AuthLayout>
  );
}

export function Register() {
  const vault = useVault();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [regOpen, setRegOpen] = useState(true);

  useEffect(() => {
    api.config().then((c) => setRegOpen(c.registrationEnabled)).catch(() => {});
  }, []);

  if (recoveryKey) {
    return <EmergencyKit email={email} recoveryKey={recoveryKey} onDone={() => navigate('/app', { replace: true })} />;
  }
  if (vault.status === 'unlocked') return <Navigate to="/app" replace />;

  const mismatch = confirm.length > 0 && confirm !== password;
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (password.length < MIN_PASSWORD_LENGTH) return setError(`Use at least ${MIN_PASSWORD_LENGTH} characters.`);
    if (password !== confirm) return setError('The two passwords do not match.');
    setBusy(true);
    setError(null);
    try {
      setRecoveryKey(await vault.register(email, name || email.split('@')[0]!, password));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout>
      <div>
        <h1>Create your vault</h1>
        <p className="sub">Your keys are generated in this browser. Choose a master password you'll remember: nobody, including us, can reset it.</p>
      </div>
      {!regOpen && <div className="notice warn">Registration is closed on this server.</div>}
      <form className="stack" style={{ '--gap': '14px' } as React.CSSProperties} onSubmit={submit} noValidate>
        <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" maxLength={80} placeholder="Ada Lovelace" />
        <Field label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required />
        <div className="stack" style={{ '--gap': '8px' } as React.CSSProperties}>
          <Field label="Master password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required />
          <PasswordMeter password={password} />
        </div>
        <Field label="Confirm master password" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password"
          error={mismatch ? 'Passwords do not match' : null} required />
        {error && <div className="notice danger" role="alert">{error}</div>}
        <Button variant="primary" size="lg" type="submit" busy={busy} disabled={!regOpen} block>{busy ? 'Generating your keys' : 'Create account'}</Button>
      </form>
      <p className="small muted">Already have an account? <Link to="/login">Sign in</Link></p>
    </AuthLayout>
  );
}

function EmergencyKit({ email, recoveryKey, onDone }: { email: string; recoveryKey: string; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const kit = `KeyVault Emergency Kit\n======================\n\nAccount: ${email}\nCreated: ${new Date().toISOString()}\n\nRecovery key:\n${recoveryKey}\n\nThis key can reset your master password and decrypt your account.\nStore it offline (print it, or keep it in a separate password manager).\nAnyone who has this key and knows your email can reset your password, so guard it like the password itself.\n`;
  return (
    <AuthLayout quote={<>This is the only time you'll see this key. KeyVault cannot recover your account without it.</>}>
      <div>
        <h1>Save your Emergency Kit</h1>
        <p className="sub">If you forget your master password, this recovery key is the only way back into your vault.</p>
      </div>
      <div className="reveal-box recovery-key" aria-label="Recovery key">{recoveryKey}</div>
      <div className="row wrap">
        <Button onClick={() => { downloadText('keyvault-emergency-kit.txt', kit); setSaved(true); }}>Download kit</Button>
        <CopyButton value={recoveryKey} label="Copy key" secret />
        <Button onClick={() => window.print()}>Print</Button>
      </div>
      <label className="check">
        <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
        <span>I've stored my recovery key somewhere safe and offline.</span>
      </label>
      <Button variant="brass" size="lg" disabled={!saved} onClick={onDone} block>Open my vault</Button>
    </AuthLayout>
  );
}

export function Recover() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [key, setKey] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [newKey, setNewKey] = useState<string | null>(null);

  if (newKey) {
    return <EmergencyKit email={email} recoveryKey={newKey} onDone={() => navigate('/login', { replace: true })} />;
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (password.length < MIN_PASSWORD_LENGTH) return setError(`Use at least ${MIN_PASSWORD_LENGTH} characters.`);
    setBusy(true);
    setError(null);
    try {
      const parsed = parseRecoveryKey(key);
      const start = await api.auth.recoverStart(email, parsed.verifier);
      const result = await recoverAccount(parsed.kek, start, password);
      await api.auth.recoverComplete({ recoveryToken: start.recoveryToken, ...result.request });
      setNewKey(result.recoveryKey);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthLayout quote={<>Recovery happens on your device too: your recovery key unwraps your account key locally, and the server only checks a one-way verifier.</>}>
      <div>
        <h1>Recover your account</h1>
        <p className="sub">Use the recovery key from your Emergency Kit to set a new master password. You'll get a new recovery key afterwards and all other sessions will be signed out.</p>
      </div>
      <form className="stack" style={{ '--gap': '14px' } as React.CSSProperties} onSubmit={submit} noValidate>
        <Field label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required />
        <Field label="Recovery key" value={key} onChange={(e) => setKey(e.target.value)} placeholder="KV1-XXXXX-XXXXX-…" code required autoComplete="off" spellCheck={false} />
        <div className="stack" style={{ '--gap': '8px' } as React.CSSProperties}>
          <Field label="New master password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required />
          <PasswordMeter password={password} />
        </div>
        {error && <div className="notice danger" role="alert">{error}</div>}
        <Button variant="primary" size="lg" type="submit" busy={busy} block>Reset master password</Button>
      </form>
      <p className="small muted"><Link to="/login">Back to sign in</Link></p>
    </AuthLayout>
  );
}

export function LockScreen() {
  const vault = useVault();
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pkBusy, setPkBusy] = useState(false);
  const [hasPasskey, setHasPasskey] = useState(false);
  useEffect(() => {
    if (!passkeysSupported()) return;
    api.account.passkeys().then((p) => setHasPasskey(p.length > 0)).catch(() => {});
  }, []);
  return (
    <div className="lockscreen">
      <form className="auth-card boxed" onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setError(null);
        try {
          await vault.unlock(password);
        } catch (err) {
          setError(errorMessage(err));
        } finally {
          setBusy(false);
        }
      }}>
        <div className="seal-wrap"><Identicon publicKey={vault.bundle?.publicKey} size={56} title="Your identicon" /></div>
        <div style={{ textAlign: 'center' }}>
          <h1>Vault locked</h1>
          <p className="sub">Signed in as <b>{vault.bundle?.user.email}</b>. Enter your master password to decrypt your keys on this device.</p>
        </div>
        <Field label="Master password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" autoFocus required />
        {error && <div className="notice danger" role="alert">{error}</div>}
        <Button variant="brass" size="lg" type="submit" busy={busy} block>Unlock</Button>
        {hasPasskey && (
          <Button size="lg" type="button" busy={pkBusy} block onClick={async () => {
            setPkBusy(true);
            setError(null);
            try { await vault.unlockWithPasskey(); } catch (err) { setError(errorMessage(err)); } finally { setPkBusy(false); }
          }}><Icon name="key" /> Unlock with passkey</Button>
        )}
        <Button variant="ghost" type="button" onClick={() => vault.logout()}>Sign out instead</Button>
      </form>
    </div>
  );
}
