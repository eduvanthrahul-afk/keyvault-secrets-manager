import { b64, changePassword, fingerprint, MIN_PASSWORD_LENGTH, newPrfSalt, rotateRecoveryKey, wipe, wrapAccountKeyWithPasskey } from '@keyvault/crypto';
import { createPasskey, passkeysSupported } from '../lib/passkey';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import QRCode from 'qrcode';
import { useState } from 'react';
import { Identicon } from '../components/Identicon';
import { Button, CopyButton, Field, Icon, Modal, PasswordMeter, Spinner, downloadText, errorMessage, timeAgo, useToast } from '../components/ui';
import { api } from '../lib/api';
import { useVault } from '../lib/vault';
import { EventList, VerifyBadge } from './ProjectExtras';

/** Asks for the master password and returns the derived auth key (server re-verifies it). */
function ConfirmPassword({ open, title, description, action, danger, onClose, onConfirm, extra }: {
  open: boolean; title: string; description: string; action: string; danger?: boolean; onClose: () => void;
  onConfirm: (authKey: string, extra: string) => Promise<void>; extra?: string;
}) {
  const vault = useVault();
  const [pw, setPw] = useState('');
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const close = () => { setPw(''); setCode(''); setError(null); onClose(); };
  return (
    <Modal open={open} onClose={close} title={title} description={description}
      footer={<><Button onClick={close}>Cancel</Button><Button variant={danger ? 'danger' : 'primary'} className={danger ? 'solid' : ''} busy={busy} disabled={!pw}
        onClick={async () => {
          setBusy(true); setError(null);
          try { await onConfirm(await vault.authKeyFor(pw), code); setPw(''); setCode(''); } catch (e) { setError(errorMessage(e)); } finally { setBusy(false); }
        }}>{action}</Button></>}>
      <Field label="Master password" type="password" value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="current-password" autoFocus />
      {extra && <Field label={extra} value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" code />}
      {error && <div className="notice danger" role="alert">{error}</div>}
    </Modal>
  );
}

export function Account() {
  const vault = useVault();
  const toast = useToast();
  const qc = useQueryClient();
  const me = useQuery({ queryKey: ['me'], queryFn: api.account.me });
  const sessions = useQuery({ queryKey: ['sessions'], queryFn: api.account.sessions });
  const activity = useQuery({ queryKey: ['activity'], queryFn: () => api.account.activity() });
  const [name, setName] = useState(vault.bundle!.user.displayName);
  const [dialog, setDialog] = useState<null | 'totp-setup' | 'totp-disable' | 'recovery' | 'delete' | 'passkey'>(null);
  const passkeys = useQuery({ queryKey: ['passkeys'], queryFn: api.account.passkeys });
  const [pkName, setPkName] = useState(defaultPasskeyName());
  const removePk = useMutation({
    mutationFn: api.account.removePasskey,
    onSuccess: () => { toast('Passkey removed'); qc.invalidateQueries({ queryKey: ['passkeys'] }); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const [totp, setTotp] = useState<{ secret: string; qr: string } | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [newRecovery, setNewRecovery] = useState<string | null>(null);
  const [cur, setCur] = useState('');
  const [next, setNext] = useState('');
  const [next2, setNext2] = useState('');
  const pk = vault.bundle!.publicKey;
  const totpOn = me.data?.profile.totpEnabled ?? vault.bundle!.user.totpEnabled;

  const refreshAll = () => { qc.invalidateQueries({ queryKey: ['me'] }); qc.invalidateQueries({ queryKey: ['sessions'] }); qc.invalidateQueries({ queryKey: ['activity'] }); };

  const saveName = useMutation({
    mutationFn: () => api.account.updateProfile(name.trim()),
    onSuccess: () => { toast('Name updated'); void vault.refresh(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const enableTotp = useMutation({
    mutationFn: () => api.account.totpEnable(totpCode.trim()),
    onSuccess: (r) => { setTotp(null); setTotpCode(''); setCodes(r.recoveryCodes); refreshAll(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const pwChange = useMutation({
    mutationFn: async () => {
      if (next.length < MIN_PASSWORD_LENGTH) throw new Error(`Use at least ${MIN_PASSWORD_LENGTH} characters.`);
      if (next !== next2) throw new Error('The new passwords do not match.');
      const currentAuthKey = await vault.authKeyFor(cur);
      const r = await changePassword(vault.account!, next);
      await api.account.changePassword({ currentAuthKey, ...r });
    },
    onSuccess: async () => { toast('Master password changed. Other sessions were signed out.'); setCur(''); setNext(''); setNext2(''); await vault.refresh(); refreshAll(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.account.revokeSession(id),
    onSuccess: () => { toast('Session signed out'); refreshAll(); },
  });
  const revokeOthers = useMutation({
    mutationFn: api.account.revokeOthers,
    onSuccess: (r) => { toast(`Signed out ${r.revoked} other session${r.revoked === 1 ? '' : 's'}`); refreshAll(); },
  });

  return (
    <div className="page">
      <div className="page-head"><div><h1>Account &amp; security</h1><p className="sub">Everything here is about proving it's you, on this device and to your teammates.</p></div></div>

      <div>
        <section className="section">
          <div className="intro"><h3>Your identity</h3><p>Your identicon and fingerprint are derived from your public key. When someone adds you to a project, read them this fingerprint so they know the key really is yours.</p></div>
          <div className="row wrap" style={{ '--gap': '20px' } as React.CSSProperties}>
            <Identicon publicKey={pk} size={72} title="Your identicon" />
            <div className="stack" style={{ '--gap': '6px' } as React.CSSProperties}>
              <span className="fingerprint" style={{ fontSize: 'var(--t-sm)' }}>{fingerprint(b64.decode(pk))}</span>
              <span className="xs faint">X25519 public key · {pk.slice(0, 12)}…</span>
            </div>
          </div>
        </section>

        <section className="section">
          <div className="intro"><h3>Profile</h3><p>Your email is your sign-in name and can't be changed.</p></div>
          <div className="stack">
            <Field label="Email" value={vault.bundle!.user.email} disabled />
            <Field label="Display name" value={name} onChange={(e) => setName(e.target.value)} maxLength={80} />
            <div><Button busy={saveName.isPending} disabled={!name.trim() || name === vault.bundle!.user.displayName} onClick={() => saveName.mutate()}>Save name</Button></div>
          </div>
        </section>

        <section className="section">
          <div className="intro"><h3>Two-step verification</h3><p>Ask for a code from an authenticator app after your password. Protects your session if your password leaks; your encryption is already protected by the password itself.</p></div>
          <div className="stack">
            {totpOn ? (
              <>
                <div className="notice ok row"><Icon name="check" /> On. {me.data && <span className="muted">{me.data.recoveryCodesRemaining} recovery codes left.</span>}</div>
                <div><Button variant="danger" onClick={() => setDialog('totp-disable')}>Turn off</Button></div>
              </>
            ) : totp ? (
              <div className="row wrap" style={{ alignItems: 'flex-start', '--gap': '20px' } as React.CSSProperties}>
                <img src={totp.qr} alt="QR code for your authenticator app" className="qr" />
                <div className="stack grow" style={{ minWidth: 220 }}>
                  <p className="small">Scan with Google Authenticator, 1Password, Aegis or similar. Can't scan? Enter this key:</p>
                  <code className="codeblock">{totp.secret.match(/.{1,4}/g)?.join(' ')}</code>
                  <Field label="6-digit code" value={totpCode} onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))} inputMode="numeric" autoComplete="one-time-code" code />
                  <div className="row"><Button variant="primary" busy={enableTotp.isPending} disabled={totpCode.length !== 6} onClick={() => enableTotp.mutate()}>Turn on</Button><Button variant="ghost" onClick={() => setTotp(null)}>Cancel</Button></div>
                </div>
              </div>
            ) : (
              <div><Button variant="primary" onClick={() => setDialog('totp-setup')}><Icon name="shield" /> Set up authenticator app</Button></div>
            )}
          </div>
        </section>

        <section className="section">
          <div className="intro"><h3>Passkey unlock</h3><p>Unlock with Touch ID, Windows Hello or a security key instead of typing your master password. The passkey derives an encryption key inside your device (WebAuthn PRF); the server never sees it.</p></div>
          <div className="stack">
            {!passkeysSupported() && <div className="notice warn">This browser doesn't support passkeys.</div>}
            {passkeys.data && passkeys.data.length > 0 && (
              <div className="panel">
                {passkeys.data.map((p) => (
                  <div key={p.id} className="member" style={{ gridTemplateColumns: 'auto 1fr auto' }}>
                    <Icon name="key" size={20} />
                    <div style={{ minWidth: 0 }}>
                      <div className="small"><b>{p.name}</b></div>
                      <div className="xs faint">Added {timeAgo(p.createdAt)} · last used {timeAgo(p.lastUsedAt)}</div>
                    </div>
                    <Button size="sm" variant="danger" busy={removePk.isPending && removePk.variables === p.id} onClick={() => removePk.mutate(p.id)}>Remove</Button>
                  </div>
                ))}
              </div>
            )}
            {passkeysSupported() && (
              <div className="row wrap" style={{ alignItems: 'flex-end' }}>
                <div style={{ flex: '1 1 220px', maxWidth: 320 }}><Field label="Passkey name" value={pkName} onChange={(e) => setPkName(e.target.value)} maxLength={80} /></div>
                <Button variant="primary" disabled={!pkName.trim()} onClick={() => setDialog('passkey')}><Icon name="plus" /> Add passkey</Button>
              </div>
            )}
          </div>
        </section>

        <section className="section">
          <div className="intro"><h3>Master password</h3><p>Changing it re-wraps your account key on this device. Your secrets aren't re-encrypted and your teammates aren't affected.</p></div>
          <form className="stack" onSubmit={(e) => { e.preventDefault(); pwChange.mutate(); }}>
            <Field label="Current master password" type="password" value={cur} onChange={(e) => setCur(e.target.value)} autoComplete="current-password" />
            <div className="stack" style={{ '--gap': '8px' } as React.CSSProperties}>
              <Field label="New master password" type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" />
              <PasswordMeter password={next} />
            </div>
            <Field label="Confirm new master password" type="password" value={next2} onChange={(e) => setNext2(e.target.value)} autoComplete="new-password"
              error={next2 && next2 !== next ? 'Passwords do not match' : null} />
            <div><Button variant="primary" type="submit" busy={pwChange.isPending} disabled={!cur || !next}>Change master password</Button></div>
          </form>
        </section>

        <section className="section">
          <div className="intro"><h3>Recovery key</h3><p>Lost your Emergency Kit, or worried someone saw it? Replace it. The old key stops working immediately.</p></div>
          <div><Button onClick={() => setDialog('recovery')}><Icon name="key" /> Create a new recovery key</Button></div>
        </section>

        <section className="section">
          <div className="intro"><h3>Signed-in sessions</h3><p>Sessions end after 30 minutes idle or 12 hours total.</p></div>
          <div className="stack">
            <div className="panel">
              {sessions.isLoading ? <Spinner /> : sessions.data?.map((s) => (
                <div key={s.id} className="member" style={{ gridTemplateColumns: '1fr auto' }}>
                  <div style={{ minWidth: 0 }}>
                    <div className="small"><b>{describeAgent(s.userAgent)}</b> {s.current && <span className="badge ok">this device</span>}</div>
                    <div className="xs faint">{s.ip ?? 'unknown IP'} · active {timeAgo(s.lastSeenAt)} · signed in {timeAgo(s.createdAt)}</div>
                  </div>
                  {!s.current && <Button size="sm" onClick={() => revoke.mutate(s.id)}>Sign out</Button>}
                </div>
              ))}
            </div>
            <div><Button size="sm" busy={revokeOthers.isPending} onClick={() => revokeOthers.mutate()}>Sign out all other sessions</Button></div>
          </div>
        </section>

        <section className="section">
          <div className="intro"><h3>Account activity</h3><p>Sign-ins, failed attempts and security changes, in a hash chain you can verify.</p><div style={{ marginTop: 12 }}><VerifyBadge verify={api.account.verifyActivity} /></div></div>
          <div className="panel">{activity.data ? <EventList events={activity.data.slice(0, 25)} /> : <Spinner />}</div>
        </section>

        <section className="section danger-zone">
          <div className="intro"><h3>Delete account</h3><p>Projects only you belong to are deleted with it. Hand over projects you share before deleting.</p></div>
          <div><Button variant="danger" onClick={() => setDialog('delete')}><Icon name="trash" /> Delete my account</Button></div>
        </section>
      </div>

      <ConfirmPassword open={dialog === 'totp-setup'} title="Confirm it's you" description="Enter your master password to start setting up two-step verification." action="Continue"
        onClose={() => setDialog(null)} onConfirm={async (authKey) => {
          const s = await api.account.totpSetup(authKey);
          setTotp({ secret: s.secret, qr: await QRCode.toDataURL(s.otpauthUri, { margin: 0, width: 176 }) });
          setDialog(null);
        }} />
      <ConfirmPassword open={dialog === 'totp-disable'} title="Turn off two-step verification" description="Your account will be protected by your master password alone." action="Turn off" danger
        extra="Authenticator or recovery code" onClose={() => setDialog(null)} onConfirm={async (authKey, code) => {
          await api.account.totpDisable(authKey, code); toast('Two-step verification is off'); setDialog(null); refreshAll();
        }} />
      <ConfirmPassword open={dialog === 'passkey'} title="Confirm it's you" description="Adding a passkey creates a new way to decrypt your vault, so enter your master password first. Your device will then ask for your fingerprint, face or PIN." action="Continue"
        onClose={() => setDialog(null)} onConfirm={async (authKey) => {
          const salt = newPrfSalt();
          const { credentialId, prf } = await createPasskey({ userId: vault.bundle!.user.id, email: vault.bundle!.user.email, displayName: vault.bundle!.user.displayName, salt: b64.decode(salt) });
          try {
            const wrappedAccountKey = wrapAccountKeyWithPasskey(vault.account!.accountKey, prf, credentialId);
            await api.account.addPasskey({ currentAuthKey: authKey, credentialId, name: pkName.trim(), prfSalt: salt, wrappedAccountKey });
          } finally { wipe(prf); }
          toast('Passkey added. You can now unlock with it.'); setDialog(null); qc.invalidateQueries({ queryKey: ['passkeys'] }); refreshAll();
        }} />
      <ConfirmPassword open={dialog === 'recovery'} title="Replace recovery key" description="Your current recovery key will stop working." action="Create new key"
        onClose={() => setDialog(null)} onConfirm={async (authKey) => {
          const r = rotateRecoveryKey(vault.account!);
          await api.account.rotateRecovery({ currentAuthKey: authKey, ...r.request });
          setNewRecovery(r.recoveryKey); setDialog(null);
        }} />
      <ConfirmPassword open={dialog === 'delete'} title="Delete your account?" description="This permanently deletes your keys. Anything only you could decrypt is gone for good." action="Delete account" danger
        onClose={() => setDialog(null)} onConfirm={async (authKey) => { await api.account.delete(authKey); await vault.logout(); }} />

      <Modal open={!!codes} onClose={() => setCodes(null)} title="Save your recovery codes" description="Each code works once if you lose your authenticator. This is the only time they're shown."
        footer={<><Button onClick={() => downloadText('keyvault-2fa-recovery-codes.txt', codes!.join('\n') + '\n')}>Download</Button><Button variant="primary" onClick={() => setCodes(null)}>Done</Button></>}>
        <div className="codeblock" style={{ columns: 2 }}>{codes?.join('\n')}</div>
      </Modal>
      <Modal open={!!newRecovery} onClose={() => setNewRecovery(null)} title="Your new recovery key" description="Store it offline. The previous key no longer works."
        footer={<><Button onClick={() => downloadText('keyvault-emergency-kit.txt', `KeyVault recovery key for ${vault.bundle!.user.email}\n\n${newRecovery}\n`)}>Download</Button><Button variant="primary" onClick={() => setNewRecovery(null)}>I've stored it</Button></>}>
        <div className="reveal-box recovery-key">{newRecovery}</div>
        <CopyButton value={newRecovery ?? ''} label="Copy key" secret />
      </Modal>
    </div>
  );
}

function defaultPasskeyName(): string {
  const ua = navigator.userAgent;
  if (/Mac OS/.test(ua) && !/iPhone|iPad/.test(ua)) return 'Mac (Touch ID)';
  if (/Windows/.test(ua)) return 'Windows Hello';
  if (/iPhone|iPad/.test(ua)) return 'iPhone (Face ID)';
  if (/Android/.test(ua)) return 'Android';
  return 'Security key';
}

function describeAgent(ua: string | null): string {
  if (!ua) return 'Unknown client';
  if (/keyvault-cli/i.test(ua)) return 'KeyVault CLI';
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Linux/.test(ua) ? 'Linux' : '';
  return os ? `${browser} on ${os}` : browser;
}
