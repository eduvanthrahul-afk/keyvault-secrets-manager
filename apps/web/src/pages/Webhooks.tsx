import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Button, CopyButton, Field, Icon, Modal, Spinner, errorMessage, timeAgo, useToast } from '../components/ui';
import { api, type WebhookView } from '../lib/api';
import { useProject } from './Project';

const VERIFY_SNIPPET = `import crypto from 'node:crypto';

// Express: app.post('/keyvault', express.raw({ type: 'application/json' }), handler)
function verify(rawBody, header, secret) {
  const { t, v1 } = Object.fromEntries(header.split(',').map((p) => p.split('=')));
  if (Math.abs(Date.now() / 1000 - Number(t)) > 300) return false; // replay window
  const expected = crypto.createHmac('sha256', secret).update(\`\${t}.\${rawBody}\`).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(v1), Buffer.from(expected));
}`;

export function Webhooks() {
  const { project } = useProject();
  const toast = useToast();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ['webhooks', project.id], queryFn: () => api.webhooks.list(project.id) });
  const [creating, setCreating] = useState(false);
  const [url, setUrl] = useState('');
  const [envId, setEnvId] = useState('');
  const [events, setEvents] = useState<Set<string>>(new Set(['secret.created', 'secret.updated', 'secret.deleted', 'environment.key_rotated']));
  const [secret, setSecret] = useState<string | null>(null);
  const [inspect, setInspect] = useState<WebhookView | null>(null);
  const invalidate = () => qc.invalidateQueries({ queryKey: ['webhooks', project.id] });

  const create = useMutation({
    mutationFn: () => api.webhooks.create(project.id, url.trim(), [...events], envId || null),
    onSuccess: (r) => { setSecret(r.signingSecret); setCreating(false); setUrl(''); invalidate(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const ping = useMutation({
    mutationFn: (id: string) => api.webhooks.ping(project.id, id),
    onSuccess: (d) => { toast(d.status === 'SUCCEEDED' ? `Ping delivered (HTTP ${d.responseCode})` : `Ping failed: ${d.lastError}`, d.status === 'SUCCEEDED' ? 'info' : 'error'); invalidate(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const toggle = useMutation({ mutationFn: (w: WebhookView) => api.webhooks.toggle(project.id, w.id, !w.enabled), onSuccess: invalidate });
  const remove = useMutation({ mutationFn: (id: string) => api.webhooks.remove(project.id, id), onSuccess: () => { toast('Webhook deleted'); invalidate(); } });

  const envName = (id: string | null) => (id ? project.environments.find((e) => e.id === id)?.name ?? 'deleted' : 'All environments');

  return (
    <div className="stack" style={{ '--gap': '16px' } as React.CSSProperties}>
      <div className="row spread wrap">
        <p className="muted small" style={{ maxWidth: '70ch' }}>
          Notify your deploy pipeline when secrets change so services restart with fresh values. Payloads contain ids and metadata only:
          KeyVault can't send secret values because it can't read them. Every request is signed with HMAC-SHA256.
        </p>
        <Button variant="primary" onClick={() => setCreating(true)}><Icon name="plus" /> Add webhook</Button>
      </div>

      <div className="panel">
        {q.isLoading ? <Spinner /> : q.data?.webhooks.length ? (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Endpoint</th><th>Scope</th><th>Last delivery</th><th><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {q.data.webhooks.map((w) => (
                  <tr key={w.id}>
                    <td style={{ maxWidth: 360 }}>
                      <div className="code small" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{w.url}</div>
                      <div className="xs faint">{w.events.join(', ')}</div>
                    </td>
                    <td className="small">{envName(w.environmentId)}</td>
                    <td className="small">
                      {!w.enabled ? <span className="badge">Disabled</span>
                        : w.lastStatus === 'SUCCEEDED' ? <span className="badge ok">Delivered</span>
                        : w.lastStatus === 'FAILED' || w.consecutiveFailures > 0 ? <span className="badge danger">Failing ({w.consecutiveFailures})</span>
                        : w.lastStatus === 'PENDING' ? <span className="badge brass">Retrying</span> : <span className="faint">never</span>}
                      {w.lastDeliveryAt && <div className="xs faint" style={{ marginTop: 2 }}>{timeAgo(w.lastDeliveryAt)}</div>}
                    </td>
                    <td className="actions">
                      <Button size="sm" busy={ping.isPending && ping.variables === w.id} onClick={() => ping.mutate(w.id)}>Send test</Button>
                      <Button size="sm" variant="ghost" onClick={() => setInspect(w)}>Deliveries</Button>
                      <Button size="sm" variant="ghost" onClick={() => toggle.mutate(w)}>{w.enabled ? 'Disable' : 'Enable'}</Button>
                      <Button size="icon" variant="ghost" aria-label="Delete webhook" onClick={() => remove.mutate(w.id)}><Icon name="trash" /></Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty">
            <h3>No webhooks yet</h3>
            <p>Point one at your CI (GitHub Actions repository_dispatch, a Vercel deploy hook, or your own endpoint) to redeploy whenever a secret changes.</p>
          </div>
        )}
      </div>

      <div className="panel">
        <div className="panel-head"><h3>Verify signatures</h3><CopyButton value={VERIFY_SNIPPET} label="Copy" /></div>
        <div className="panel-body"><pre className="codeblock" style={{ margin: 0 }}>{VERIFY_SNIPPET}</pre></div>
      </div>

      <Modal open={creating} onClose={() => setCreating(false)} title="Add webhook" description="Must be a public https:// endpoint. Private and internal addresses are rejected."
        footer={<><Button onClick={() => setCreating(false)}>Cancel</Button><Button variant="primary" busy={create.isPending} disabled={!url.trim() || events.size === 0} onClick={() => create.mutate()}>Add webhook</Button></>}>
        <Field label="Endpoint URL" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://api.example.com/hooks/keyvault" autoFocus code />
        <div className="field">
          <label htmlFor="wh-env">Environment</label>
          <select id="wh-env" className="select" value={envId} onChange={(e) => setEnvId(e.target.value)}>
            <option value="">All environments</option>
            {project.environments.map((e) => <option key={e.id} value={e.id}>{e.name}</option>)}
          </select>
        </div>
        <div className="field">
          <span className="label">Events</span>
          <div className="env-chips">
            {(q.data?.events ?? []).map((ev) => (
              <button key={ev} type="button" className={`chip ${events.has(ev) ? 'on' : ''}`} aria-pressed={events.has(ev)}
                onClick={() => setEvents((s) => { const n = new Set(s); if (n.has(ev)) n.delete(ev); else n.add(ev); return n; })}>{ev}</button>
            ))}
          </div>
        </div>
      </Modal>

      <Modal open={!!secret} onClose={() => setSecret(null)} title="Save the signing secret" description="Use it to verify the X-KeyVault-Signature header. It is shown only once."
        footer={<Button variant="primary" onClick={() => setSecret(null)}>I've stored it</Button>}>
        <div className="reveal-box">{secret}</div>
        <CopyButton value={secret ?? ''} label="Copy secret" secret />
      </Modal>

      {inspect && <Deliveries webhook={inspect} onClose={() => setInspect(null)} />}
    </div>
  );
}

function Deliveries({ webhook, onClose }: { webhook: WebhookView; onClose: () => void }) {
  const { project } = useProject();
  const toast = useToast();
  const q = useQuery({ queryKey: ['deliveries', webhook.id], queryFn: () => api.webhooks.deliveries(project.id, webhook.id), refetchInterval: 3000 });
  const redeliver = useMutation({
    mutationFn: (id: string) => api.webhooks.redeliver(project.id, id),
    onSuccess: () => { toast('Queued for redelivery'); void q.refetch(); },
  });
  return (
    <Modal open onClose={onClose} wide title="Recent deliveries" description={webhook.url}>
      {q.isLoading ? <Spinner /> : q.data?.length ? (
        <div className="panel table-wrap">
          <table className="table">
            <thead><tr><th>Event</th><th>Status</th><th>Attempts</th><th>When</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>{q.data.map((d) => (
              <tr key={d.id}>
                <td className="code small">{d.event}</td>
                <td>
                  <span className={`badge ${d.status === 'SUCCEEDED' ? 'ok' : d.status === 'FAILED' ? 'danger' : 'brass'}`}>{d.status.toLowerCase()}{d.responseCode ? ` · ${d.responseCode}` : ''}</span>
                  {d.lastError && d.status !== 'SUCCEEDED' && <div className="xs faint" style={{ marginTop: 2, maxWidth: 260 }}>{d.lastError}</div>}
                  {d.status === 'PENDING' && d.attempts > 0 && <div className="xs faint">next try {timeAgo(d.nextAttemptAt)}</div>}
                </td>
                <td className="small">{d.attempts}</td>
                <td className="small muted">{timeAgo(d.createdAt)}</td>
                <td className="actions">{d.status !== 'SUCCEEDED' && <Button size="sm" onClick={() => redeliver.mutate(d.id)}>Retry now</Button>}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      ) : <p className="muted small">No deliveries yet. Use "Send test".</p>}
    </Modal>
  );
}
