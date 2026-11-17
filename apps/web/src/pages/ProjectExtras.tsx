import { createServiceToken } from '@keyvault/crypto';
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button, CopyButton, Field, Icon, Modal, Spinner, errorMessage, formatDate, timeAgo, useToast } from '../components/ui';
import { api, atLeast, type AuditEvent, type VerifyResult } from '../lib/api';
import { useVault } from '../lib/vault';
import { useProject } from './Project';

// ================================================================ tokens

export function Tokens() {
  const { project, refetch } = useProject();
  const vault = useVault();
  const toast = useToast();
  const usable = project.environments.filter((e) => e.wrappedKey);
  const [envId, setEnvId] = useState(usable[0]?.id ?? '');
  const env = usable.find((e) => e.id === envId);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState('');
  const [days, setDays] = useState('90');
  const [issued, setIssued] = useState<string | null>(null);
  const qc = useQueryClient();
  const tokens = useQuery({ queryKey: ['tokens', envId], enabled: !!envId, queryFn: () => api.tokens.list(envId) });

  const create = useMutation({
    mutationFn: async () => {
      const st = createServiceToken(vault.envKey(project.id, env!), { projectId: project.id, environmentId: env!.id });
      await api.tokens.create(env!.id, {
        tokenId: st.tokenId, name: name.trim(), verifier: st.verifier, wrappedEnvKey: st.wrappedEnvKey,
        keyVersion: env!.keyVersion, expiresInDays: days === 'never' ? null : Number(days),
      });
      return st.token;
    },
    onSuccess: (t) => { setIssued(t); setCreating(false); setName(''); qc.invalidateQueries({ queryKey: ['tokens', envId] }); refetch(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => api.tokens.revoke(envId, id),
    onSuccess: () => { toast('Token revoked'); qc.invalidateQueries({ queryKey: ['tokens', envId] }); refetch(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });

  if (usable.length === 0) return <div className="panel empty"><p>You need access to at least one environment to issue tokens.</p></div>;
  const origin = window.location.origin;

  return (
    <div className="stack" style={{ '--gap': '16px' } as React.CSSProperties}>
      <div className="row spread wrap">
        <div className="row wrap">
          <label className="small muted" htmlFor="tok-env">Environment</label>
          <select id="tok-env" className="select" style={{ width: 'auto', minHeight: 34 }} value={envId} onChange={(e) => setEnvId(e.target.value)}>
            {usable.map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}
          </select>
        </div>
        <Button variant="primary" onClick={() => setCreating(true)}><Icon name="plus" /> New access token</Button>
      </div>
      <p className="muted small" style={{ maxWidth: '70ch' }}>
        Access tokens are read-only and scoped to one environment. The token carries its own decryption key: the server stores a hash
        for authentication and a copy of the environment key it can't open. Use them in CI, containers and the <code>kv</code> CLI.
      </p>

      <div className="panel">
        {tokens.isLoading ? <Spinner /> : tokens.data && tokens.data.length > 0 ? (
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Name</th><th>Created</th><th>Expires</th><th>Last used</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>{tokens.data.map((t) => (
              <tr key={t.id}>
                <td><b>{t.name}</b><div className="xs faint code">kvs_{t.tokenId.slice(0, 8)}…</div></td>
                <td className="small muted">{timeAgo(t.createdAt)}<div className="xs faint">{t.createdBy}</div></td>
                <td className="small">{t.expiresAt ? timeAgo(t.expiresAt) : <span className="badge brass">never</span>}</td>
                <td className="small muted">{timeAgo(t.lastUsedAt)}{t.lastUsedIp && <div className="xs faint">{t.lastUsedIp}</div>}</td>
                <td className="actions"><Button size="sm" variant="danger" busy={revoke.isPending && revoke.variables === t.id} onClick={() => revoke.mutate(t.id)}>Revoke</Button></td>
              </tr>
            ))}</tbody>
          </table></div>
        ) : <div className="empty"><h3>No tokens for {env?.name}</h3><p>Create one to let CI or a server fetch these secrets without a password.</p></div>}
      </div>

      <div className="panel">
        <div className="panel-head"><h3>Use it from the command line</h3></div>
        <div className="panel-body stack">
          <div className="codeblock">{`npm install -g ./apps/cli   # from this repository
export KEYVAULT_TOKEN=kvs_…   # store it as a CI secret
export KEYVAULT_URL=${origin}

kv run -- npm start           # injects secrets as env vars, nothing written to disk
kv export --format dotenv     # print .env (careful where you redirect it)
kv get DATABASE_URL`}</div>
        </div>
      </div>

      <Modal open={creating} onClose={() => setCreating(false)} title={`New token for ${env?.name}`}
        footer={<><Button onClick={() => setCreating(false)}>Cancel</Button><Button variant="primary" busy={create.isPending} disabled={!name.trim()} onClick={() => create.mutate()}>Create token</Button></>}>
        <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} placeholder="github-actions-deploy" maxLength={80} autoFocus />
        <div className="field">
          <label htmlFor="tok-exp">Expires</label>
          <select id="tok-exp" className="select" value={days} onChange={(e) => setDays(e.target.value)}>
            <option value="7">In 7 days</option><option value="30">In 30 days</option><option value="90">In 90 days</option>
            <option value="365">In 1 year</option><option value="never">Never (not recommended)</option>
          </select>
        </div>
      </Modal>
      <Modal open={!!issued} onClose={() => setIssued(null)} title="Copy your token now" description="This is the only time it's shown. KeyVault keeps only a hash, so it can't show it again."
        footer={<Button variant="primary" onClick={() => setIssued(null)}>I've stored it</Button>}>
        <div className="reveal-box">{issued}</div>
        <CopyButton value={issued ?? ''} label="Copy token" secret />
      </Modal>
    </div>
  );
}

// ============================================================== activity

const ACTION_TEXT: Record<string, string> = {
  'project.created': 'created the project', 'project.updated': 'updated project details', 'project.deleted': 'deleted the project',
  'environment.created': 'created an environment', 'environment.renamed': 'renamed an environment', 'environment.deleted': 'deleted an environment',
  'environment.key_rotated': 'rotated an environment key', 'member.added': 'added a member', 'member.removed': 'removed a member',
  'member.left': 'left the project', 'member.role_changed': 'changed a role', 'grant.set': 'granted environment access',
  'grant.revoked': 'revoked environment access', 'secret.created': 'created secrets', 'secret.updated': 'updated a secret',
  'secret.deleted': 'deleted a secret', 'secret.rolled_back': 'restored a previous version', 'secrets.read': 'read secrets',
  'token.created': 'created an access token', 'token.revoked': 'revoked an access token',
  'account.created': 'created the account', 'auth.login': 'signed in', 'auth.login_failed': 'failed to sign in (wrong password)',
  'auth.mfa_failed': 'entered a wrong 2FA code', 'auth.logout': 'signed out', 'auth.session_revoked': 'revoked a session',
  'auth.sessions_revoked': 'signed out other sessions', 'account.password_changed': 'changed the master password',
  'account.recovered': 'recovered the account', 'account.recovery_key_rotated': 'replaced the recovery key',
  'account.totp_enabled': 'turned on two-step verification', 'account.totp_disabled': 'turned off two-step verification',
  'auth.reauth_failed': 'failed a password confirmation', 'auth.recovery_failed': 'tried a wrong recovery key',
  'account.passkey_added': 'added a passkey', 'account.passkey_removed': 'removed a passkey', 'auth.passkey_unlock': 'unlocked with a passkey',
  'send.created': 'created a one-time link', 'send.opened': 'opened a one-time link',
};

export function EventList({ events }: { events: AuditEvent[] }) {
  const { project } = useProjectSafe();
  const envName = (id: unknown) => project?.environments.find((e) => e.id === id)?.name;
  return (
    <div className="timeline">
      {events.map((e) => {
        const env = envName(e.targetType === 'environment' ? e.targetId : e.details.environment);
        const danger = /failed|deleted|revoked|removed/.test(e.action);
        return (
          <div className="event" key={e.seq}>
            <div className="when" title={formatDate(e.occurredAt)}>{timeAgo(e.occurredAt)}</div>
            <div>
              <div className="what"><b>{e.actorLabel}</b> <span className={danger ? '' : 'muted'} style={danger ? { color: 'var(--danger)' } : undefined}>{ACTION_TEXT[e.action] ?? e.action}</span>{env && <> in <b>{env}</b></>}</div>
              <div className="meta">
                {Object.entries(e.details).filter(([k]) => !['environment', 'ids'].includes(k)).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : String(v)}`).join('  ')}
                {e.ip && <>  ip: {e.ip}</>}
              </div>
              <div className="hash" title="Chain hash of this event">#{e.chainIndex} {e.hash.slice(0, 16)}…</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function useProjectSafe() {
  try { return useProject() ?? { project: undefined }; } catch { return { project: undefined }; }
}

export function VerifyBadge({ verify }: { verify: () => Promise<VerifyResult> }) {
  const [res, setRes] = useState<VerifyResult | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="row wrap">
      {res && (res.valid
        ? <span className="badge ok"><Icon name="check" size={12} /> {res.eventsChecked} events verified</span>
        : <span className="badge danger"><Icon name="alert" size={12} /> Chain broken at event #{res.firstBrokenIndex}</span>)}
      {res && <span className="xs faint code" title="Write this down to detect future rewrites">head {res.headHash.slice(0, 12)}…</span>}
      <Button size="sm" busy={busy} onClick={async () => { setBusy(true); try { setRes(await verify()); } finally { setBusy(false); } }}>
        <Icon name="shield" /> Verify integrity
      </Button>
    </div>
  );
}

export function Activity() {
  const { project } = useProject();
  const q = useInfiniteQuery({
    queryKey: ['audit', project.id],
    queryFn: ({ pageParam }) => api.projects.audit(project.id, pageParam),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => (last.length === 50 ? last[last.length - 1]!.seq : undefined),
  });
  const events = q.data?.pages.flat() ?? [];
  return (
    <div className="panel">
      <div className="panel-head">
        <p className="small muted" style={{ maxWidth: '56ch' }}>Each entry includes the hash of the previous one. Editing or deleting any past entry breaks the chain from that point on.</p>
        <VerifyBadge verify={() => api.projects.verifyAudit(project.id)} />
      </div>
      {q.isLoading ? <Spinner /> : <EventList events={events} />}
      {q.hasNextPage && <div className="panel-body"><Button busy={q.isFetchingNextPage} onClick={() => q.fetchNextPage()}>Load older events</Button></div>}
    </div>
  );
}

// ============================================================== settings

export function ProjectSettings() {
  const { project, refetch } = useProject();
  const toast = useToast();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [name, setName] = useState(project.name);
  const [description, setDescription] = useState(project.description);
  const [confirm, setConfirm] = useState('');
  const [deleting, setDeleting] = useState(false);
  const save = useMutation({
    mutationFn: () => api.projects.update(project.id, name.trim(), description.trim()),
    onSuccess: () => { toast('Saved'); refetch(); qc.invalidateQueries({ queryKey: ['projects'] }); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const remove = useMutation({
    mutationFn: () => api.projects.remove(project.id, confirm),
    onSuccess: () => { toast(`Deleted ${project.name}`); qc.invalidateQueries({ queryKey: ['projects'] }); navigate('/app'); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  return (
    <div>
      <section className="section">
        <div className="intro"><h3>Details</h3><p>Names and descriptions are not encrypted. Don't put secrets here.</p></div>
        <div className="stack">
          <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} maxLength={80} />
          <Field label="Description" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} />
          <div><Button variant="primary" busy={save.isPending} disabled={!name.trim()} onClick={() => save.mutate()}>Save changes</Button></div>
        </div>
      </section>
      {atLeast(project.role, 'OWNER') && (
        <section className="section danger-zone">
          <div className="intro"><h3>Delete project</h3><p>Removes every environment, secret, version and token. The activity log is kept.</p></div>
          <div><Button variant="danger" onClick={() => setDeleting(true)}><Icon name="trash" /> Delete project</Button></div>
        </section>
      )}
      <Modal open={deleting} onClose={() => setDeleting(false)} title={`Delete ${project.name}?`} description="This cannot be undone."
        footer={<><Button onClick={() => setDeleting(false)}>Cancel</Button><Button variant="danger" className="solid" disabled={confirm !== project.name} busy={remove.isPending} onClick={() => remove.mutate()}>Delete forever</Button></>}>
        <Field label={`Type ${project.name} to confirm`} value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
      </Modal>
    </div>
  );
}
