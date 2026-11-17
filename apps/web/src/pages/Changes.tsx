import { decryptSecret, type SecretPlaintext } from '@keyvault/crypto';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Button, Field, Icon, Modal, Spinner, errorMessage, formatDate, timeAgo, useToast } from '../components/ui';
import { api, atLeast, type ChangeRequestView, type EnvironmentView } from '../lib/api';
import { useVault } from '../lib/vault';
import { useProject } from './Project';

const STATUS_BADGE: Record<ChangeRequestView['status'], string> = {
  OPEN: 'accent', APPLIED: 'ok', REJECTED: 'danger', CANCELLED: '', CONFLICT: 'brass',
};

/** Review queue for protected environments. Every diff is decrypted in the reviewer's browser. */
export function Changes() {
  const { project } = useProject();
  const [params, setParams] = useSearchParams();
  const envs = project.environments.filter((e) => e.wrappedKey);
  const env = envs.find((e) => e.slug === params.get('env')) ?? envs.find((e) => e.openChangeRequests > 0) ?? envs.find((e) => e.protected) ?? envs[0];
  const [view, setView] = useState<'OPEN' | 'ALL'>('OPEN');

  if (!env) return <div className="panel empty"><p>You need access to an environment to review changes.</p></div>;
  return (
    <div className="stack" style={{ '--gap': '16px' } as React.CSSProperties}>
      <div className="row spread wrap">
        <div className="env-switch" role="tablist" aria-label="Environment">
          {envs.map((e) => (
            <a key={e.id} href={`?env=${e.slug}`} role="tab" aria-selected={e.id === env.id} data-env={e.slug} className={e.id === env.id ? 'active' : ''}
              onClick={(ev) => { ev.preventDefault(); setParams({ env: e.slug }); }}>
              {e.name}{e.openChangeRequests > 0 && <span className="badge accent" style={{ height: 18 }}>{e.openChangeRequests}</span>}
            </a>
          ))}
        </div>
        <div className="env-switch">
          <a href="#" className={view === 'OPEN' ? 'active' : ''} onClick={(e) => { e.preventDefault(); setView('OPEN'); }}>Open</a>
          <a href="#" className={view === 'ALL' ? 'active' : ''} onClick={(e) => { e.preventDefault(); setView('ALL'); }}>History</a>
        </div>
      </div>
      {!env.protected && (
        <div className="notice"><Icon name="shield" /><span>{env.name} isn't protected, so changes apply immediately. Admins can require reviews under Environments.</span></div>
      )}
      <ChangeList env={env} status={view} />
    </div>
  );
}

function ChangeList({ env, status }: { env: EnvironmentView; status: 'OPEN' | 'ALL' }) {
  const q = useQuery({ queryKey: ['changes', env.id, status], queryFn: () => api.changeRequests.list(env.id, status) });
  const [open, setOpen] = useState<string | null>(null);
  if (q.isLoading) return <Spinner />;
  if (!q.data?.length) {
    return (
      <div className="panel empty">
        <Icon name="check" size={28} />
        <h3>{status === 'OPEN' ? 'Nothing waiting for review' : 'No change requests yet'}</h3>
        <p>When a developer edits a protected environment, their change shows up here for an admin to approve.</p>
      </div>
    );
  }
  return (
    <div className="panel">
      {q.data.map((cr) => (
        <div key={cr.id} className="member" style={{ gridTemplateColumns: 'minmax(0,1fr) auto' }}>
          <div style={{ minWidth: 0 }}>
            <div className="row" style={{ gap: 8 }}>
              <b>{cr.title}</b>
              <span className={`badge ${STATUS_BADGE[cr.status]}`}>{cr.status.charAt(0) + cr.status.slice(1).toLowerCase()}</span>
            </div>
            <div className="xs faint" style={{ marginTop: 2 }}>
              {cr.author ?? 'deleted user'} · {cr.itemCount} change{cr.itemCount === 1 ? '' : 's'} · opened {timeAgo(cr.createdAt)}
              {cr.reviewer && <> · {cr.status === 'APPLIED' ? 'approved' : 'closed'} by {cr.reviewer}</>}
            </div>
            {cr.reviewComment && <div className="small muted" style={{ marginTop: 4 }}>“{cr.reviewComment}”</div>}
          </div>
          <Button size="sm" onClick={() => setOpen(cr.id)}>{cr.status === 'OPEN' ? 'Review' : 'View'}</Button>
        </div>
      ))}
      {open && <ReviewDialog env={env} id={open} onClose={() => setOpen(null)} />}
    </div>
  );
}

function ReviewDialog({ env, id, onClose }: { env: EnvironmentView; id: string; onClose: () => void }) {
  const { project, refetch } = useProject();
  const vault = useVault();
  const toast = useToast();
  const qc = useQueryClient();
  const [comment, setComment] = useState('');
  const cr = useQuery({ queryKey: ['change', id], queryFn: () => api.changeRequests.get(env.id, id) });
  const current = useQuery({ queryKey: ['secrets', env.id], queryFn: () => api.secrets.list(env.id) });
  const me = vault.bundle!.user.id;

  const rows = useMemo(() => {
    if (!cr.data || !current.data) return [];
    const key = vault.envKey(project.id, env);
    const ref = { projectId: project.id, environmentId: env.id };
    const dec = (secretId: string, c: { nameCiphertext: string | null; valueCiphertext: string | null; commentCiphertext: string | null }): SecretPlaintext | null => {
      if (!c.nameCiphertext || !c.valueCiphertext) return null;
      try { return decryptSecret(key, ref, secretId, c as { nameCiphertext: string; valueCiphertext: string; commentCiphertext: string | null }); } catch { return null; }
    };
    return cr.data.items.map((it) => {
      const cur = current.data!.secrets.find((s) => s.id === it.secretId);
      const before = cur ? dec(it.secretId, cur) : null;
      const after = it.op === 'DELETE' ? null : dec(it.secretId, it);
      const stale = it.op !== 'CREATE' && cur && cur.version !== it.expectedVersion;
      return { it, before, after, stale, tampered: it.op !== 'DELETE' && !after };
    });
  }, [cr.data, current.data, env, project.id, vault]);

  const done = (verb: string) => () => {
    toast(verb);
    qc.invalidateQueries({ queryKey: ['changes', env.id] });
    qc.invalidateQueries({ queryKey: ['secrets', env.id] });
    refetch();
    onClose();
  };
  const approve = useMutation({
    mutationFn: () => api.changeRequests.approve(env.id, id, comment || undefined),
    onSuccess: (r) => (r.status === 'APPLIED' ? done('Approved and applied')() : (toast(r.reviewComment ?? 'Conflict', 'error'), done('Marked as conflict')())),
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const reject = useMutation({
    mutationFn: () => api.changeRequests.reject(env.id, id, comment || undefined),
    onSuccess: done(cr.data?.authorId === me ? 'Request cancelled' : 'Request rejected'),
    onError: (e) => toast(errorMessage(e), 'error'),
  });

  const data = cr.data;
  const isAuthor = data?.authorId === me;
  const canReview = atLeast(project.role, 'ADMIN') && !isAuthor && data?.status === 'OPEN';
  const anyTampered = rows.some((r) => r.tampered);

  return (
    <Modal open onClose={onClose} wide title={data?.title ?? 'Change request'}
      description={data ? `${data.author ?? 'deleted user'} · opened ${formatDate(data.createdAt)} · ${env.name}` : undefined}
      footer={data?.status === 'OPEN' ? (
        <>
          {(canReview || isAuthor) && <Button variant="danger" busy={reject.isPending} onClick={() => reject.mutate()}>{isAuthor ? 'Cancel request' : 'Reject'}</Button>}
          {canReview && <Button variant="primary" busy={approve.isPending} disabled={anyTampered} onClick={() => approve.mutate()}>Approve and apply</Button>}
          {!canReview && !isAuthor && <span className="small muted">Only admins can review.</span>}
          {isAuthor && atLeast(project.role, 'ADMIN') && <span className="small muted">Another admin has to approve your own request.</span>}
        </>
      ) : <Button onClick={onClose}>Close</Button>}>
      {(cr.isLoading || current.isLoading) ? <Spinner label="Decrypting" /> : (
        <>
          {anyTampered && <div className="notice danger"><Icon name="alert" /><span>Some proposed values failed integrity checks and can't be shown. Don't approve this request.</span></div>}
          <div className="panel table-wrap">
            <table className="table">
              <thead><tr><th>Change</th><th>Name</th><th>Current</th><th>Proposed</th></tr></thead>
              <tbody>
                {rows.map(({ it, before, after, stale, tampered }) => (
                  <tr key={it.secretId}>
                    <td><span className={`badge ${it.op === 'DELETE' ? 'danger' : it.op === 'CREATE' ? 'ok' : 'accent'}`}>{it.op.toLowerCase()}</span>{stale && <div className="xs" style={{ color: 'var(--warning)', marginTop: 4 }}>changed since</div>}</td>
                    <td><span className="secret-name">{after?.name ?? before?.name ?? '(unknown)'}</span>{before && after && before.name !== after.name && <div className="xs faint">was {before.name}</div>}</td>
                    <td>{before ? <span className="secret-value revealed" style={{ maxWidth: 260 }}>{before.value || '(empty)'}</span> : <span className="faint">-</span>}</td>
                    <td>{it.op === 'DELETE' ? <span className="faint">removed</span> : tampered ? <span className="badge danger">integrity check failed</span> : <span className="secret-value revealed" style={{ maxWidth: 260 }}>{after!.value || '(empty)'}</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {data?.status === 'OPEN' && (canReview || isAuthor) && <Field label="Comment (optional)" value={comment} onChange={(e) => setComment(e.target.value)} maxLength={500} />}
          {data?.reviewComment && <div className="notice"><span><b>{data.reviewer ?? 'Reviewer'}:</b> {data.reviewComment}</span></div>}
        </>
      )}
    </Modal>
  );
}
