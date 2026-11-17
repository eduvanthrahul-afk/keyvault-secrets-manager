// The in-memory vault. Decrypted keys live ONLY in this React context (JS memory): never in
// localStorage, sessionStorage, IndexedDB or cookies. Reloading the tab or idling locks the vault.

import {
  createAccount,
  deriveLoginKeys,
  unlockAccount,
  unlockFromAccountKey,
  unwrapAccountKeyWithPasskey,
  unwrapEnvKey,
  wipe,
  type UnlockedAccount,
} from '@keyvault/crypto';
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { api, ApiError, type EnvironmentView, type SessionBundle } from './api';
import { assertPasskey } from './passkey';

type Status = 'loading' | 'signed-out' | 'locked' | 'unlocked';

interface VaultApi {
  status: Status;
  bundle: SessionBundle | null;
  account: UnlockedAccount | null;
  login(email: string, password: string): Promise<{ mfaToken: string } | null>;
  completeMfa(mfaToken: string, code: string): Promise<void>;
  register(email: string, displayName: string, password: string): Promise<string>;
  unlock(password: string): Promise<void>;
  /** Unlock with a registered passkey (WebAuthn PRF). */
  unlockWithPasskey(): Promise<void>;
  lock(): void;
  logout(): Promise<void>;
  /** Re-derives the auth key for "confirm your password" flows. */
  authKeyFor(password: string): Promise<string>;
  envKey(projectId: string, env: EnvironmentView): Uint8Array;
  refresh(): Promise<void>;
}

const VaultContext = createContext<VaultApi | null>(null);
const IDLE_LOCK_MS = 15 * 60 * 1000;

export function VaultProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<Status>('loading');
  const [bundle, setBundle] = useState<SessionBundle | null>(null);
  const [account, setAccount] = useState<UnlockedAccount | null>(null);
  const envKeys = useRef(new Map<string, Uint8Array>());
  const pendingKek = useRef<Uint8Array | null>(null);

  const clearKeys = useCallback(() => {
    setAccount((a) => {
      if (a) wipe(a.accountKey, a.identity.privateKey);
      return null;
    });
    envKeys.current.forEach((k) => wipe(k));
    envKeys.current.clear();
  }, []);

  const refresh = useCallback(async () => {
    try {
      const b = await api.auth.session();
      setBundle(b);
      setStatus((s) => (s === 'unlocked' ? 'unlocked' : 'locked'));
    } catch {
      setBundle(null);
      clearKeys();
      setStatus('signed-out');
    }
  }, [clearKeys]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Session expired / revoked elsewhere → drop everything.
  useEffect(() => {
    const onUnauthorized = () => {
      clearKeys();
      setBundle(null);
      setStatus('signed-out');
    };
    window.addEventListener('kv:unauthorized', onUnauthorized);
    return () => window.removeEventListener('kv:unauthorized', onUnauthorized);
  }, [clearKeys]);

  // Auto-lock after inactivity.
  useEffect(() => {
    if (status !== 'unlocked') return;
    let timer = window.setTimeout(() => lockNow(), IDLE_LOCK_MS);
    const bump = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => lockNow(), IDLE_LOCK_MS);
    };
    const events = ['pointerdown', 'keydown', 'scroll'] as const;
    events.forEach((e) => window.addEventListener(e, bump, { passive: true }));
    function lockNow() {
      clearKeys();
      setStatus('locked');
    }
    return () => {
      window.clearTimeout(timer);
      events.forEach((e) => window.removeEventListener(e, bump));
    };
  }, [status, clearKeys]);

  const finishLogin = useCallback((session: SessionBundle, kek: Uint8Array) => {
    try {
      const unlocked = unlockAccount(kek, session);
      setBundle(session);
      setAccount(unlocked);
      setStatus('unlocked');
    } finally {
      wipe(kek);
    }
  }, []);

  const value = useMemo<VaultApi>(() => ({
    status,
    bundle,
    account,

    async login(email, password) {
      const pre = await api.auth.prelogin(email);
      const { authKey, kek } = await deriveLoginKeys(password, pre.salt, pre.kdf);
      const res = await api.auth.login(email, authKey);
      if (res.mfaRequired && res.mfaToken) {
        pendingKek.current = kek;
        return { mfaToken: res.mfaToken };
      }
      finishLogin(res.session!, kek);
      return null;
    },

    async completeMfa(mfaToken, code) {
      const res = await api.auth.mfa(mfaToken, code);
      const kek = pendingKek.current;
      pendingKek.current = null;
      if (!kek) throw new Error('Sign-in expired. Start again.');
      finishLogin(res.session!, kek);
    },

    async register(email, displayName, password) {
      const reg = await createAccount(email, password);
      const res = await api.auth.register({ ...reg.request, displayName });
      setBundle(res.session!);
      setAccount(reg.unlocked);
      setStatus('unlocked');
      return reg.recoveryKey;
    },

    async unlock(password) {
      if (!bundle) throw new Error('No session');
      const { kek } = await deriveLoginKeys(password, bundle.salt, bundle.kdf);
      try {
        setAccount(unlockAccount(kek, bundle));
        setStatus('unlocked');
      } catch {
        throw new Error('That master password is not correct.');
      } finally {
        wipe(kek);
      }
    },

    async unlockWithPasskey() {
      if (!bundle) throw new Error('No session');
      const passkeys = await api.account.passkeys();
      if (passkeys.length === 0) throw new Error('No passkeys registered for this account');
      const { credentialId, prf } = await assertPasskey(passkeys);
      const pk = passkeys.find((p) => p.credentialId === credentialId);
      if (!pk) throw new Error('Unknown passkey');
      try {
        const accountKey = unwrapAccountKeyWithPasskey(pk.wrappedAccountKey, prf, pk.credentialId);
        setAccount(unlockFromAccountKey(accountKey, bundle));
        setStatus('unlocked');
        void api.account.passkeyUsed(pk.id).catch(() => {});
      } catch {
        throw new Error('This passkey could not unlock the vault. Remove it and register it again.');
      } finally {
        wipe(prf);
      }
    },

    lock() {
      clearKeys();
      setStatus('locked');
    },

    async logout() {
      try {
        await api.auth.logout();
      } catch (e) {
        if (!(e instanceof ApiError)) throw e;
      }
      clearKeys();
      setBundle(null);
      setStatus('signed-out');
    },

    async authKeyFor(password) {
      if (!bundle) throw new Error('No session');
      const { authKey, kek } = await deriveLoginKeys(password, bundle.salt, bundle.kdf);
      wipe(kek);
      return authKey;
    },

    envKey(projectId, env) {
      if (!account) throw new Error('Vault is locked');
      if (!env.wrappedKey) throw new Error(`You have not been granted access to ${env.name}`);
      const cacheKey = `${env.id}:${env.grantKeyVersion}`;
      let key = envKeys.current.get(cacheKey);
      if (!key) {
        key = unwrapEnvKey(account.identity, env.wrappedKey, { projectId, environmentId: env.id });
        envKeys.current.set(cacheKey, key);
      }
      return key;
    },

    refresh,
  }), [status, bundle, account, finishLogin, clearKeys, refresh]);

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}

export function useVault(): VaultApi {
  const v = useContext(VaultContext);
  if (!v) throw new Error('useVault outside VaultProvider');
  return v;
}
