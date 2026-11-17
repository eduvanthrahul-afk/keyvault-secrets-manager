// Thin typed client for the KeyVault API. Every request is same-origin, carries the
// session cookie automatically, and sends the X-KV-Request header the server's CSRF guard requires.

import type { KdfParams } from '@keyvault/crypto';

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-KV-Request': '1', Accept: 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  const data = text ? JSON.parse(text) : undefined;
  if (!res.ok) {
    if (res.status === 401 && path !== '/api/auth/session') window.dispatchEvent(new Event('kv:unauthorized'));
    throw new ApiError(res.status, data?.code ?? 'error', data?.detail ?? `Request failed (${res.status})`);
  }
  return data as T;
}

const get = <T>(p: string) => request<T>('GET', p);
const post = <T>(p: string, b?: unknown) => request<T>('POST', p, b ?? {});
const put = <T>(p: string, b: unknown) => request<T>('PUT', p, b);
const patch = <T>(p: string, b: unknown) => request<T>('PATCH', p, b);
const del = <T>(p: string, b?: unknown) => request<T>('DELETE', p, b);

// ------------------------------------------------------------------ types

export type Role = 'OWNER' | 'ADMIN' | 'DEVELOPER' | 'VIEWER';
export const ROLE_RANK: Record<Role, number> = { VIEWER: 0, DEVELOPER: 1, ADMIN: 2, OWNER: 3 };
export const atLeast = (r: Role | undefined, min: Role) => !!r && ROLE_RANK[r] >= ROLE_RANK[min];

export interface Profile { id: string; email: string; displayName: string; totpEnabled: boolean; createdAt: string }

export interface SessionBundle {
  user: Profile;
  kdf: KdfParams;
  salt: string;
  protectedAccountKey: string;
  publicKey: string;
  protectedPrivateKey: string;
}

export interface LoginResponse { mfaRequired: boolean; mfaToken: string | null; session: SessionBundle | null }

export interface ProjectSummary {
  id: string; name: string; description: string; role: Role; environmentCount: number; memberCount: number;
  secretCount: number; rotationNeeded: boolean; createdAt: string; updatedAt: string;
}

export interface EnvironmentView {
  id: string; name: string; slug: string; position: number; keyVersion: number; rotationNeeded: boolean;
  secretCount: number; tokenCount: number; wrappedKey: string | null; grantKeyVersion: number | null;
  protected: boolean; openChangeRequests: number;
}

export interface MemberView {
  userId: string; email: string; displayName: string; publicKey: string; role: Role; environmentIds: string[]; joinedAt: string;
}

export interface ProjectDetail {
  id: string; name: string; description: string; role: Role; createdAt: string;
  environments: EnvironmentView[]; members: MemberView[];
}

export interface SecretView {
  id: string; nameCiphertext: string; valueCiphertext: string; commentCiphertext: string | null; version: number;
  keyVersion: number; createdAt: string; updatedAt: string; updatedBy: string | null;
}

export interface EnvironmentSecrets { projectId: string; environmentId: string; environmentName: string; keyVersion: number; secrets: SecretView[] }

export interface VersionView {
  version: number; nameCiphertext: string; valueCiphertext: string; commentCiphertext: string | null; keyVersion: number;
  changeType: 'CREATE' | 'UPDATE' | 'ROLLBACK'; changedBy: string | null; createdAt: string;
}

export interface SecretInput {
  id: string; nameIndex: string; nameCiphertext: string; valueCiphertext: string; commentCiphertext: string | null; keyVersion: number;
}

export interface TokenView {
  id: string; tokenId: string; name: string; createdBy: string | null; createdAt: string; expiresAt: string | null;
  lastUsedAt: string | null; lastUsedIp: string | null; keyVersion: number;
}

export interface AuditEvent {
  seq: number; chainIndex: number; occurredAt: string; actorType: string; actorId: string | null; actorLabel: string;
  projectId: string | null; action: string; targetType: string | null; targetId: string | null; ip: string | null;
  userAgent: string | null; details: Record<string, unknown>; hash: string;
}

export interface VerifyResult { valid: boolean; eventsChecked: number; firstBrokenIndex: number | null; headHash: string }

export interface SessionInfo { id: string; createdAt: string; lastSeenAt: string; expiresAt: string; ip: string | null; userAgent: string | null; current: boolean }

export interface SendView { id: string; maxViews: number; viewCount: number; expiresAt: string; createdAt: string }

export type ChangeOp = 'CREATE' | 'UPDATE' | 'DELETE';
export interface ChangeItemInput {
  op: ChangeOp; secretId: string; expectedVersion?: number | null;
  nameIndex?: string; nameCiphertext?: string; valueCiphertext?: string; commentCiphertext?: string | null;
}
export interface ChangeRequestView {
  id: string; environmentId: string; title: string; status: 'OPEN' | 'APPLIED' | 'REJECTED' | 'CANCELLED' | 'CONFLICT';
  authorId: string | null; author: string | null; reviewer: string | null; reviewComment: string | null; keyVersion: number;
  createdAt: string; closedAt: string | null; itemCount: number;
  items: { op: ChangeOp; secretId: string; expectedVersion: number | null; nameCiphertext: string | null; valueCiphertext: string | null; commentCiphertext: string | null }[];
}
export interface WebhookView {
  id: string; environmentId: string | null; url: string; events: string[]; enabled: boolean; createdAt: string;
  consecutiveFailures: number; lastStatus: string | null; lastDeliveryAt: string | null;
}
export interface DeliveryView {
  id: string; event: string; status: 'PENDING' | 'SUCCEEDED' | 'FAILED'; attempts: number; responseCode: number | null;
  lastError: string | null; createdAt: string; deliveredAt: string | null; nextAttemptAt: string;
}

export interface PasskeyView { id: string; credentialId: string; name: string; prfSalt: string; wrappedAccountKey: string; createdAt: string; lastUsedAt: string | null }

export interface UserLookup { id: string; email: string; displayName: string; publicKey: string }

export interface RotationSnapshot {
  keyVersion: number; projectId: string; secrets: SecretView[]; versions: Record<string, VersionView[]>;
}

// -------------------------------------------------------------- endpoints

export const api = {
  config: () => get<{ registrationEnabled: boolean; version: string }>('/api/config'),
  auth: {
    prelogin: (email: string) => post<{ kdf: KdfParams; salt: string }>('/api/auth/prelogin', { email }),
    register: (body: unknown) => post<LoginResponse>('/api/auth/register', body),
    login: (email: string, authKey: string) => post<LoginResponse>('/api/auth/login', { email, authKey }),
    mfa: (mfaToken: string, code: string) => post<LoginResponse>('/api/auth/login/mfa', { mfaToken, code }),
    session: () => get<SessionBundle>('/api/auth/session'),
    logout: () => post<void>('/api/auth/logout'),
    recoverStart: (email: string, recoveryVerifier: string) =>
      post<{ recoveryToken: string; recoveryProtectedAccountKey: string; publicKey: string; protectedPrivateKey: string }>(
        '/api/auth/recover/start', { email, recoveryVerifier }),
    recoverComplete: (body: unknown) => post<void>('/api/auth/recover/complete', body),
  },
  account: {
    me: () => get<{ profile: Profile; recoveryCodesRemaining: number; activeSessions: number }>('/api/account'),
    updateProfile: (displayName: string) => patch<Profile>('/api/account/profile', { displayName }),
    changePassword: (body: unknown) => post<void>('/api/account/password', body),
    rotateRecovery: (body: unknown) => post<void>('/api/account/recovery-key', body),
    sessions: () => get<SessionInfo[]>('/api/account/sessions'),
    revokeSession: (id: string) => del<void>(`/api/account/sessions/${id}`),
    revokeOthers: () => post<{ revoked: number }>('/api/account/sessions/revoke-others'),
    totpSetup: (currentAuthKey: string) => post<{ secret: string; otpauthUri: string }>('/api/account/totp/setup', { currentAuthKey }),
    totpEnable: (code: string) => post<{ recoveryCodes: string[] }>('/api/account/totp/enable', { code }),
    totpDisable: (currentAuthKey: string, code: string) => post<void>('/api/account/totp/disable', { currentAuthKey, code }),
    activity: (before?: number) => get<AuditEvent[]>(`/api/account/activity${before ? `?before=${before}` : ''}`),
    verifyActivity: () => get<VerifyResult>('/api/account/activity/verify'),
    delete: (currentAuthKey: string) => post<void>('/api/account/delete', { currentAuthKey }),
    passkeys: () => get<PasskeyView[]>('/api/account/passkeys'),
    addPasskey: (body: unknown) => post<PasskeyView[]>('/api/account/passkeys', body),
    passkeyUsed: (id: string) => post<void>(`/api/account/passkeys/${id}/used`),
    removePasskey: (id: string) => del<void>(`/api/account/passkeys/${id}`),
  },
  projects: {
    list: () => get<ProjectSummary[]>('/api/projects'),
    create: (body: unknown) => post<ProjectDetail>('/api/projects', body),
    get: (id: string) => get<ProjectDetail>(`/api/projects/${id}`),
    update: (id: string, name: string, description: string) => patch<ProjectDetail>(`/api/projects/${id}`, { name, description }),
    remove: (id: string, confirmName: string) => del<void>(`/api/projects/${id}`, { confirmName }),
    createEnvironment: (id: string, body: unknown) => post<ProjectDetail>(`/api/projects/${id}/environments`, body),
    renameEnvironment: (id: string, envId: string, name: string) => patch<ProjectDetail>(`/api/projects/${id}/environments/${envId}`, { name }),
    setProtection: (id: string, envId: string, enabled: boolean) =>
      put<ProjectDetail>(`/api/projects/${id}/environments/${envId}/protection`, { enabled }),
    deleteEnvironment: (id: string, envId: string) => del<ProjectDetail>(`/api/projects/${id}/environments/${envId}`),
    addMember: (id: string, body: unknown) => post<ProjectDetail>(`/api/projects/${id}/members`, body),
    changeRole: (id: string, userId: string, role: Role) => patch<ProjectDetail>(`/api/projects/${id}/members/${userId}`, { role }),
    removeMember: (id: string, userId: string) => del<void>(`/api/projects/${id}/members/${userId}`),
    setGrant: (id: string, envId: string, userId: string, wrappedKey: string, keyVersion: number) =>
      put<ProjectDetail>(`/api/projects/${id}/environments/${envId}/grants/${userId}`, { wrappedKey, keyVersion }),
    revokeGrant: (id: string, envId: string, userId: string) => del<ProjectDetail>(`/api/projects/${id}/environments/${envId}/grants/${userId}`),
    audit: (id: string, before?: number) => get<AuditEvent[]>(`/api/projects/${id}/audit${before ? `?before=${before}` : ''}`),
    verifyAudit: (id: string) => get<VerifyResult>(`/api/projects/${id}/audit/verify`),
  },
  changeRequests: {
    list: (envId: string, status = 'OPEN') => get<ChangeRequestView[]>(`/api/environments/${envId}/change-requests?status=${status}`),
    get: (envId: string, id: string) => get<ChangeRequestView>(`/api/environments/${envId}/change-requests/${id}`),
    create: (envId: string, title: string, keyVersion: number, items: ChangeItemInput[]) =>
      post<ChangeRequestView>(`/api/environments/${envId}/change-requests`, { title, keyVersion, items }),
    approve: (envId: string, id: string, comment?: string) => post<ChangeRequestView>(`/api/environments/${envId}/change-requests/${id}/approve`, { comment }),
    reject: (envId: string, id: string, comment?: string) => post<ChangeRequestView>(`/api/environments/${envId}/change-requests/${id}/reject`, { comment }),
  },
  webhooks: {
    list: (projectId: string) => get<{ webhooks: WebhookView[]; events: string[] }>(`/api/projects/${projectId}/webhooks`),
    create: (projectId: string, url: string, events: string[], environmentId: string | null) =>
      post<{ webhook: WebhookView; signingSecret: string }>(`/api/projects/${projectId}/webhooks`, { url, events, environmentId }),
    toggle: (projectId: string, id: string, enabled: boolean) => patch<WebhookView[]>(`/api/projects/${projectId}/webhooks/${id}`, { enabled }),
    remove: (projectId: string, id: string) => del<void>(`/api/projects/${projectId}/webhooks/${id}`),
    ping: (projectId: string, id: string) => post<DeliveryView>(`/api/projects/${projectId}/webhooks/${id}/ping`),
    deliveries: (projectId: string, id: string) => get<DeliveryView[]>(`/api/projects/${projectId}/webhooks/${id}/deliveries`),
    redeliver: (projectId: string, deliveryId: string) => post<void>(`/api/projects/${projectId}/webhooks/deliveries/${deliveryId}/redeliver`),
  },
  users: {
    lookup: (email: string) => get<UserLookup>(`/api/users/lookup?email=${encodeURIComponent(email)}`),
  },
  secrets: {
    list: (envId: string) => get<EnvironmentSecrets>(`/api/environments/${envId}/secrets`),
    create: (envId: string, secrets: SecretInput[]) => post<SecretView[]>(`/api/environments/${envId}/secrets`, { secrets }),
    update: (envId: string, id: string, body: Omit<SecretInput, 'id'> & { expectedVersion: number }) =>
      put<SecretView>(`/api/environments/${envId}/secrets/${id}`, body),
    remove: (envId: string, id: string) => del<void>(`/api/environments/${envId}/secrets/${id}`),
    versions: (envId: string, id: string) => get<VersionView[]>(`/api/environments/${envId}/secrets/${id}/versions`),
    rollback: (envId: string, id: string, toVersion: number, expectedVersion: number) =>
      post<SecretView>(`/api/environments/${envId}/secrets/${id}/rollback`, { toVersion, expectedVersion }),
    rotationSnapshot: (envId: string) => get<RotationSnapshot>(`/api/environments/${envId}/rotation`),
    rotate: (envId: string, body: unknown) =>
      post<{ newKeyVersion: number; secretsReencrypted: number; membersWithAccess: number; tokensRevoked: number }>(
        `/api/environments/${envId}/rotation`, body),
  },
  tokens: {
    list: (envId: string) => get<TokenView[]>(`/api/environments/${envId}/tokens`),
    create: (envId: string, body: unknown) => post<TokenView>(`/api/environments/${envId}/tokens`, body),
    revoke: (envId: string, id: string) => del<void>(`/api/environments/${envId}/tokens/${id}`),
  },
  sends: {
    list: () => get<SendView[]>('/api/sends'),
    create: (ciphertext: string, maxViews: number, expiresInMinutes: number) =>
      post<SendView>('/api/sends', { ciphertext, maxViews, expiresInMinutes }),
    remove: (id: string) => del<void>(`/api/sends/${id}`),
    open: (id: string) => post<{ ciphertext: string; remainingViews: number; expiresAt: string }>(`/api/public/sends/${id}/open`),
  },
};
