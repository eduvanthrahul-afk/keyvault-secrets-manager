import { analyzeHealth, decryptSecret, diffEnvironments, encryptSecret, newId, type DiffCell, type Finding, type HealthEnvironment, type Severity } from '@keyvault/crypto';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { mustPropose } from './Secrets';
import { useToast } from '../components/ui';
import { useQueries } from '@tanstack/react-query';
import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Button, Icon, Spinner } from '../components/ui';
import { api, atLeast } from '../lib/api';
import { useVault } from '../lib/vault';
import { useProject } from './Project';

/** Fetch and decrypt every environment the user holds a key for. Runs entirely client-side. */
function useDecryptedEnvironments() {
  const { project } = useProject();
  const vault = useVault();
  const envs = project.environments.filter((e) => e.wrappedKey);
  const queries = useQueries({ queries: envs.map((e) => ({ queryKey: ['secrets', e.id], queryFn: () => api.secrets.list(e.id) })) });
  const loading = queries.some((q) => q.isLoading);
  const data = useMemo<HealthEnvironment[]>(() => {
    if (loading) return [];
    return envs.map((env, i) => {
      const res = queries[i]!.data;
      const key = vault.envKey(project.id, env);
      const ref = { projectId: project.id, environmentId: env.id };
      const secrets = (res?.secrets ?? []).flatMap((s) => {
        try {
          const p = decryptSecret(key, ref, s.id, s);
          return [{ name: p.name, value: p.value, updatedAt: s.updatedAt }];
        } catch {
          return [];
        }
      });
      return { slug: env.slug, name: env.name, secrets };
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loading, ...queries.map((q) => q.dataUpdatedAt)]);
  const locked = project.environments.filter((e) => !e.wrappedKey);
  return { loading, data, locked };
}

// ================================================================ compare

export function Compare() {
  const { project } = useProject();
  const { loading, data, locked } = useDecryptedEnvironments();
  const [showValues, setShowValues] = useState(false);
  const [onlyProblems, setOnlyProblems] = useState(false);
  const rows = useMemo(() => diffEnvironments(data), [data]);

  if (loading) return <Spinner label="Decrypting environments" />;
  if (data.length < 2) {
    return <div className="panel empty"><h3>Nothing to compare yet</h3><p>You need access to at least two environments. {locked.length > 0 && `Ask an admin for ${locked.map((e) => e.name).join(', ')}.`}</p></div>;
  }
  const shown = rows.filter((r) => !onlyProblems || r.status === 'missing');
  const missing = rows.filter((r) => r.status === 'missing').length;
  const same = rows.filter((r) => r.status === 'same').length;

  return (
    <div className="stack" style={{ '--gap': '16px' } as React.CSSProperties}>
      <div className="row spread wrap">
        <p className="muted small" style={{ maxWidth: '68ch' }}>
          Side-by-side view of every secret name across environments, decrypted on this device. Missing names are the usual reason a
          deploy works in staging and breaks in production.
        </p>
        <div className="row wrap">
          <label className="check"><input type="checkbox" checked={onlyProblems} onChange={(e) => setOnlyProblems(e.target.checked)} /><span>Only missing</span></label>
          <Button size="sm" onClick={() => setShowValues((v) => !v)}><Icon name={showValues ? 'eyeOff' : 'eye'} /> {showValues ? 'Hide values' : 'Show values'}</Button>
        </div>
      </div>
      <div className="row wrap">
        <span className="badge">{rows.length} names</span>
        <span className={`badge ${missing ? 'danger' : 'ok'}`}>{missing} missing somewhere</span>
        <span className="badge">{same} identical everywhere</span>
        {locked.length > 0 && <span className="badge">{locked.map((e) => e.name).join(', ')} not shown (no key)</span>}
      </div>
      <div className="panel table-wrap">
        <table className="table diff-table">
          <thead><tr><th>Name</th>{data.map((e) => <th key={e.slug}>{e.name}</th>)}<th>Status</th></tr></thead>
          <tbody>
            {shown.map((r) => (
              <tr key={r.name}>
                <td><span className="secret-name">{r.name}</span></td>
                {r.cells.map((c, i) => (
                  <td key={i} className="cell">
                    {!c.present ? <AddFromOther name={r.name} target={data[i]!.slug} rows={r.cells} envs={data} />
                      : showValues ? <span className="secret-value revealed" style={{ maxWidth: 240 }}>{c.value || '(empty)'}</span>
                      : <span className="faint">set · {c.value.length} chars</span>}
                  </td>
                ))}
                <td>
                  {r.status === 'missing' && <span className="badge danger">Missing</span>}
                  {r.status === 'differs' && <span className="badge ok">Differs</span>}
                  {r.status === 'same' && <span className="badge brass" title="Same value in every environment">Identical</span>}
                </td>
              </tr>
            ))}
            {shown.length === 0 && <tr><td colSpan={data.length + 2} className="muted small">Every name exists in every environment.</td></tr>}
          </tbody>
        </table>
      </div>
      <p className="xs faint">Opening this page records a read of each environment in the <Link to={`/app/p/${project.id}/activity`}>activity log</Link>.</p>
    </div>
  );
}

// ================================================================= health

const SEV_LED: Record<Severity, string> = { critical: 'alert', warning: 'warn', info: '' };
const SEV_LABEL: Record<Severity, string> = { critical: 'Critical', warning: 'Warning', info: 'Info' };

export function Health() {
  const { project } = useProject();
  const { loading, data, locked } = useDecryptedEnvironments();
  const [sev, setSev] = useState<Severity | 'all'>('all');
  const { score, findings } = useMemo(() => analyzeHealth(data), [data]);

  if (loading) return <Spinner label="Decrypting and analysing" />;
  const counts = { critical: 0, warning: 0, info: 0 } as Record<Severity, number>;
  findings.forEach((f) => counts[f.severity]++);
  const shown = findings.filter((f) => sev === 'all' || f.severity === sev);
  const color = score >= 85 ? 'var(--led-green)' : score >= 60 ? 'var(--signal)' : 'var(--led-red)';
  const circ = 2 * Math.PI * 30;

  return (
    <div className="stack" style={{ '--gap': '16px' } as React.CSSProperties}>
      <div className="panel panel-body health-score">
        <svg className="gauge" viewBox="0 0 76 76" role="img" aria-label={`Health score ${score} out of 100`}>
          <circle cx="38" cy="38" r="30" className="gauge-track" />
          <circle cx="38" cy="38" r="30" className="gauge-fill" stroke={color} strokeDasharray={`${(score / 100) * circ} ${circ}`} />
          <text x="38" y="45" textAnchor="middle" className="gauge-text">{score}</text>
        </svg>
        <div className="stack" style={{ '--gap': '6px' } as React.CSSProperties}>
          <h3 style={{ fontSize: 'var(--t-lg)' }}>{score >= 85 ? 'In good shape' : score >= 60 ? 'Needs attention' : 'At risk'}</h3>
          <p className="small muted" style={{ maxWidth: '62ch' }}>
            Checks run on decrypted values in your browser: live keys outside production, test keys in production, credentials shared
            with production, weak or placeholder values, broken references and stale secrets. The server can't run these, because
            it can't read your secrets.
          </p>
          {locked.length > 0 && <p className="xs faint">Not checked (no key): {locked.map((e) => e.name).join(', ')}.</p>}
        </div>
      </div>

      <div className="row wrap">
        {(['all', 'critical', 'warning', 'info'] as const).map((s) => (
          <button key={s} type="button" className={`chip ${sev === s ? 'on' : ''}`} aria-pressed={sev === s} onClick={() => setSev(s)}>
            {s === 'all' ? `All ${findings.length}` : `${SEV_LABEL[s]} ${counts[s]}`}
          </button>
        ))}
      </div>

      <div className="panel">
        {shown.length === 0 ? (
          <div className="empty"><Icon name="check" size={28} /><h3>No issues found</h3><p>Nothing in {data.map((e) => e.name).join(', ')} tripped a check.</p></div>
        ) : shown.map((f: Finding, i) => (
          <div className="finding" key={i}>
            <span className={`led ${SEV_LED[f.severity]}`} title={SEV_LABEL[f.severity]} />
            <div style={{ minWidth: 0 }}>
              <div className="small"><span className="secret-name">{f.secret}</span> <span className="faint">in {f.environment}</span></div>
              <div className="small" style={{ marginTop: 2 }}>{f.message}</div>
              <div className="xs faint" style={{ marginTop: 2 }}>{f.fix}</div>
            </div>
            <Link className="btn sm" to={`/app/p/${project.id}/secrets?env=${data.find((e) => e.name === f.environment)?.slug ?? ''}`}>Open</Link>
          </div>
        ))}
      </div>
    </div>
  );
}

/** Copy a value that exists elsewhere into the environment where it's missing (decrypt → re-encrypt locally). */
function AddFromOther({ name, target, rows, envs }: { name: string; target: string; rows: DiffCell[]; envs: HealthEnvironment[] }) {
  const { project, refetch } = useProject();
  const vault = useVault();
  const toast = useToast();
  const qc = useQueryClient();
  const srcIndex = rows.findIndex((c) => c.present);
  const source = envs[srcIndex];
  const targetEnv = project.environments.find((e) => e.slug === target)!;
  const add = useMutation({
    mutationFn: async () => {
      const cell = rows[srcIndex] as { present: true; value: string };
      const ref = { projectId: project.id, environmentId: targetEnv.id };
      const id = newId();
      const ct = encryptSecret(vault.envKey(project.id, targetEnv), ref, id, { name, value: cell.value });
      if (mustPropose(project.role, targetEnv)) {
        await api.changeRequests.create(targetEnv.id, `Add ${name} (copied from ${source!.name})`, targetEnv.keyVersion, [{ op: 'CREATE', secretId: id, ...ct }]);
        return 'proposed';
      }
      await api.secrets.create(targetEnv.id, [{ id, ...ct, keyVersion: targetEnv.keyVersion }]);
      return 'added';
    },
    onSuccess: (how) => {
      toast(how === 'proposed' ? `Proposed ${name} for ${targetEnv.name}` : `Copied ${name} to ${targetEnv.name}`);
      qc.invalidateQueries({ queryKey: ['secrets', targetEnv.id] });
      refetch();
    },
    onError: (e) => toast((e as Error).message, 'error'),
  });
  if (!source || !atLeast(project.role, 'DEVELOPER')) return <span className="cell-missing">missing</span>;
  return (
    <span className="row" style={{ gap: 6 }}>
      <span className="cell-missing">missing</span>
      <Button size="sm" variant="ghost" busy={add.isPending} onClick={() => add.mutate()} title={`Copy the value from ${source.name}`}>Add from {source.name}</Button>
    </span>
  );
}
