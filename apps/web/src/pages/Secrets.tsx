import {
  decryptSecret,
  encryptSecret,
  newId,
  parseDotenv,
  randomBytes,
  resolveReferences,
  SECRET_NAME_PATTERN,
  toDotenv,
  type EnvRef,
  type SecretPlaintext,
} from '@keyvault/crypto';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useEffect, useMemo, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { Button, CopyButton, Field, Icon, Modal, SkeletonRows, Spinner, anyDialogOpen, copySecret, downloadText, errorMessage, formatDate, isTyping, timeAgo, useToast } from '../components/ui';
import { api, atLeast, type ChangeItemInput, type EnvironmentView, type Role, type SecretView } from '../lib/api';
import { useVault } from '../lib/vault';
import { useProject } from './Project';

interface Row {
  view: SecretView;
  plain: SecretPlaintext | null; // null → failed authentication (tampered or wrong key)
}

export function Secrets() {
  const { project } = useProject();
  const [params, setParams] = useSearchParams();
  const envs = project.environments;
  const selected = envs.find((e) => e.slug === params.get('env')) ?? envs.find((e) => e.wrappedKey) ?? envs[0];

  if (!selected) return <div className="panel empty"><p>This project has no environments yet.</p></div>;

  return (
    <div className="stack" style={{ '--gap': '16px' } as React.CSSProperties}>
      <div className="env-switch" role="tablist" aria-label="Environment">
        {envs.map((e) => (
          <a key={e.id} href={`?env=${e.slug}`} role="tab" aria-selected={e.id === selected.id} data-env={e.slug}
            className={e.id === selected.id ? 'active' : ''}
            onClick={(ev) => { ev.preventDefault(); setParams({ env: e.slug }); }}>
            {!e.wrappedKey && <Icon name="lock" size={12} className="lock" />}
            {e.name}
            <span className="faint xs">{e.secretCount}</span>
          </a>
        ))}
      </div>
      {selected.wrappedKey ? <EnvironmentSecrets key={selected.id} env={selected} /> : (
        <div className="panel empty">
          <Icon name="lock" size={28} />
          <h3>You don't hold the key for {selected.name}</h3>
          <p>Access to an environment is cryptographic: an admin has to seal its key to your identity. Ask a project admin to grant you {selected.name}.</p>
        </div>
      )}
    </div>
  );
}

function EnvironmentSecrets({ env }: { env: EnvironmentView }) {
  const { project, refetch } = useProject();
  const vault = useVault();
  const qc = useQueryClient();
  const toast = useToast();
  const ref: EnvRef = { projectId: project.id, environmentId: env.id };
  const canWrite = atLeast(project.role, 'DEVELOPER');
  const propose = mustPropose(project.role, env);
  const [filter, setFilter] = useState('');
  const [revealed, setRevealed] = useState<Set<string>>(new Set());
  const [revealAll, setRevealAll] = useState(false);
  const [editing, setEditing] = useState<Row | 'new' | null>(null);
  const [history, setHistory] = useState<Row | null>(null);
  const [importing, setImporting] = useState(false);
  const [importText, setImportText] = useState('');
  const [deleting, setDeleting] = useState<Row[] | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [lastClicked, setLastClicked] = useState<number | null>(null);
  const [sort, setSort] = useState<{ key: 'name' | 'updated'; dir: 1 | -1 }>({ key: 'name', dir: 1 });
  const [inline, setInline] = useState<{ id: string; draft: string } | null>(null);
  const [pending, setPending] = useState<Set<string>>(new Set());
  const filterRef = useRef<HTMLInputElement>(null);
  const deleteTimers = useRef(new Map<string, { timer: number; rows: Row[] }>());

  const q = useQuery({ queryKey: ['secrets', env.id], queryFn: () => api.secrets.list(env.id) });

  const rows: Row[] = useMemo(() => {
    if (!q.data) return [];
    const key = vault.envKey(project.id, env);
    return q.data.secrets.map((s) => {
      try {
        return { view: s, plain: decryptSecret(key, ref, s.id, s) };
      } catch {
        return { view: s, plain: null };
      }
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q.data, env.id, env.grantKeyVersion]);

  const resolved = useMemo(() => resolveReferences(rows.filter((r) => r.plain).map((r) => r.plain!)), [rows]);
  const valueOf = (r: Row) => resolved.get(r.plain!.name)?.value ?? r.plain!.value;
  const visible = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return rows
      .filter((r) => !pending.has(r.view.id))
      .filter((r) => !f || r.plain?.name.toLowerCase().includes(f) || r.plain?.comment?.toLowerCase().includes(f))
      .sort((a, b) => sort.key === 'name'
        ? sort.dir * (a.plain?.name ?? '').localeCompare(b.plain?.name ?? '')
        : sort.dir * (new Date(a.view.updatedAt).getTime() - new Date(b.view.updatedAt).getTime()));
  }, [rows, filter, sort, pending]);
  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['secrets', env.id] });
    refetch();
  };
  const selectedRows = visible.filter((r) => selected.has(r.view.id));

  // ---- reveal with automatic re-masking after 30 s
  const reveal = (id: string) => {
    setRevealed((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
    window.setTimeout(() => setRevealed((s) => { const n = new Set(s); n.delete(id); return n; }), 30_000);
  };
  useEffect(() => {
    if (!revealAll) return;
    const t = window.setTimeout(() => setRevealAll(false), 30_000);
    return () => window.clearTimeout(t);
  }, [revealAll]);

  // ---- delete with undo: rows disappear immediately, the API call happens after 6 s
  const commitDelete = async (rs: Row[]) => {
    try {
      await Promise.all(rs.map((r) => api.secrets.remove(env.id, r.view.id)));
    } catch (e) {
      toast(errorMessage(e), 'error');
    } finally {
      setPending((p) => { const n = new Set(p); rs.forEach((r) => n.delete(r.view.id)); return n; });
      invalidate();
    }
  };
  const scheduleDelete = async (rs: Row[]) => {
    setDeleting(null);
    setSelected(new Set());
    const label = rs.length === 1 ? rs[0]!.plain?.name ?? 'secret' : `${rs.length} secrets`;
    if (propose) {
      try {
        await api.changeRequests.create(env.id, `Delete ${label}`, env.keyVersion,
          rs.map((r) => ({ op: 'DELETE' as const, secretId: r.view.id, expectedVersion: r.view.version })));
        toast(`Proposed deleting ${label}`);
        invalidate();
      } catch (e) { toast(errorMessage(e), 'error'); }
      return;
    }
    const key = rs.map((r) => r.view.id).join(',');
    setPending((p) => new Set([...p, ...rs.map((r) => r.view.id)]));
    const timer = window.setTimeout(() => { deleteTimers.current.delete(key); void commitDelete(rs); }, 6000);
    deleteTimers.current.set(key, { timer, rows: rs });
    toast(`Deleted ${label}`, 'info', {
      label: 'Undo', durationMs: 6000,
      onClick: () => {
        const entry = deleteTimers.current.get(key);
        if (!entry) return;
        window.clearTimeout(entry.timer);
        deleteTimers.current.delete(key);
        setPending((p) => { const n = new Set(p); rs.forEach((r) => n.delete(r.view.id)); return n; });
      },
    });
  };
  // Leaving the page commits any delete that is still waiting for its undo window.
  useEffect(() => () => {
    deleteTimers.current.forEach(({ timer, rows: rs }) => { window.clearTimeout(timer); void Promise.all(rs.map((r) => api.secrets.remove(env.id, r.view.id))); });
    deleteTimers.current.clear();
  }, [env.id]);

  // ---- inline value editing
  const saveInline = useMutation({
    mutationFn: async ({ r, value }: { r: Row; value: string }) => {
      const ct = encryptSecret(vault.envKey(project.id, env), ref, r.view.id, { name: r.plain!.name, value, comment: r.plain!.comment });
      if (propose) {
        await api.changeRequests.create(env.id, `Update ${r.plain!.name}`, env.keyVersion, [{ op: 'UPDATE', secretId: r.view.id, expectedVersion: r.view.version, ...ct }]);
        return 'proposed';
      }
      await api.secrets.update(env.id, r.view.id, { ...ct, keyVersion: env.keyVersion, expectedVersion: r.view.version });
      return 'saved';
    },
    onSuccess: (how, { r }) => { setInline(null); toast(how === 'proposed' ? `Proposed new value for ${r.plain!.name}` : `Saved ${r.plain!.name}`); invalidate(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });

  // ---- bulk copy to another environment (decrypt here, re-encrypt for the target)
  const copyTargets = project.environments.filter((e) => e.id !== env.id && e.wrappedKey);
  const copyTo = useMutation({
    mutationFn: async (targetId: string) => {
      const target = project.environments.find((e) => e.id === targetId)!;
      const tKey = vault.envKey(project.id, target);
      const tRef = { projectId: project.id, environmentId: target.id };
      const existing = await api.secrets.list(target.id);
      const names = new Set(existing.secrets.flatMap((s) => { try { return [decryptSecret(tKey, tRef, s.id, s).name]; } catch { return []; } }));
      const items = selectedRows.filter((r) => r.plain && !names.has(r.plain.name)).map((r) => {
        const id = newId();
        return { id, ...encryptSecret(tKey, tRef, id, r.plain!) };
      });
      const skipped = selectedRows.length - items.length;
      if (items.length) {
        if (mustPropose(project.role, target)) {
          await api.changeRequests.create(target.id, `Copy ${items.length} secrets from ${env.name}`, target.keyVersion,
            items.map(({ id, ...ct }) => ({ op: 'CREATE' as const, secretId: id, ...ct })));
        } else {
          await api.secrets.create(target.id, items.map((i) => ({ ...i, keyVersion: target.keyVersion })));
        }
      }
      return { target, copied: items.length, skipped, proposed: mustPropose(project.role, target) };
    },
    onSuccess: ({ target, copied, skipped, proposed }) => {
      toast(`${proposed ? 'Proposed copying' : 'Copied'} ${copied} to ${target.name}${skipped ? ` (${skipped} already existed)` : ''}`);
      setSelected(new Set());
      qc.invalidateQueries({ queryKey: ['secrets', target.id] });
      refetch();
    },
    onError: (e) => toast(errorMessage(e), 'error'),
  });

  // ---- selection with shift-click ranges
  const toggleRow = (index: number, id: string, shift: boolean) => {
    setSelected((s) => {
      const n = new Set(s);
      if (shift && lastClicked !== null) {
        const [a, b] = [Math.min(lastClicked, index), Math.max(lastClicked, index)];
        const on = !s.has(id);
        visible.slice(a, b + 1).forEach((r) => (on ? n.add(r.view.id) : n.delete(r.view.id)));
      } else if (n.has(id)) n.delete(id); else n.add(id);
      return n;
    });
    setLastClicked(index);
  };
  const allSelected = visible.length > 0 && visible.every((r) => selected.has(r.view.id));

  // ---- keyboard shortcuts and paste-to-import
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || anyDialogOpen()) return;
      if (e.key === 'Escape' && !isTyping()) { setSelected(new Set()); return; }
      if (isTyping()) return;
      if (e.key === '/') { e.preventDefault(); filterRef.current?.focus(); }
      else if (e.key === 'n' && canWrite) { e.preventDefault(); setEditing('new'); }
      else if (e.key === 'i' && canWrite) { e.preventDefault(); setImportText(''); setImporting(true); }
      else if (e.key === 'r') { e.preventDefault(); setRevealAll((v) => !v); }
    };
    const onPaste = (e: ClipboardEvent) => {
      if (!canWrite || isTyping() || anyDialogOpen()) return;
      const text = e.clipboardData?.getData('text') ?? '';
      if (parseDotenv(text).length === 0) return;
      e.preventDefault();
      setImportText(text);
      setImporting(true);
    };
    window.addEventListener('keydown', onKey);
    window.addEventListener('paste', onPaste);
    return () => { window.removeEventListener('keydown', onKey); window.removeEventListener('paste', onPaste); };
  }, [canWrite]);

  // Exports contain RESOLVED values: that's what an app would receive.
  const asDotenv = (subset?: Row[]) => toDotenv((subset ?? rows).filter((r) => r.plain).map((r) => ({ name: r.plain!.name, value: valueOf(r) })));
  const tampered = rows.filter((r) => !r.plain).length;
  const sortBy = (key: 'name' | 'updated') => setSort((s) => (s.key === key ? { key, dir: (s.dir * -1) as 1 | -1 } : { key, dir: key === 'name' ? 1 : -1 }));
  const arrow = (key: 'name' | 'updated') => (sort.key === key ? <span className="arrow">{sort.dir === 1 ? '▲' : '▼'}</span> : null);

  if (q.error) return <div className="notice danger">{errorMessage(q.error)}</div>;

  return (
    <div className="panel">
      <div className="panel-head">
        <label className="filter">
          <span className="sr-only">Filter secrets</span>
          <Icon name="search" />
          <input ref={filterRef} className="input" placeholder="Filter by name or note" value={filter} onChange={(e) => setFilter(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Escape') { setFilter(''); (e.target as HTMLInputElement).blur(); } }} />
          {!filter && <span className="kbd" style={{ position: 'absolute', right: 8, top: '50%', translate: '0 -50%' }}>/</span>}
        </label>
        <div className="row wrap">
          <Button size="sm" variant="ghost" onClick={() => setRevealAll((v) => !v)} title="Reveal all values for 30 seconds (r)">
            <Icon name={revealAll ? 'eyeOff' : 'eye'} /> {revealAll ? 'Hide all' : 'Reveal all'}
          </Button>
          <CopyButton value={() => asDotenv()} label="Copy .env" secret />
          <Button size="sm" onClick={() => downloadText(`${project.name}.${env.slug}.env`, asDotenv())}><Icon name="download" /> Export</Button>
          {canWrite && <Button size="sm" onClick={() => { setImportText(''); setImporting(true); }} title="Import a .env file (i), or paste one anywhere"><Icon name="upload" /> Import</Button>}
          {canWrite && <Button size="sm" variant="primary" onClick={() => setEditing('new')} title="Add secret (n)"><Icon name="plus" /> {propose ? 'Propose secret' : 'Add secret'}</Button>}
        </div>
      </div>

      {env.protected && (
        <div className="notice" style={{ margin: 16, marginBottom: 0 }}>
          <Icon name="shield" />
          <span className="grow">
            {env.name} is protected. {atLeast(project.role, 'ADMIN') ? 'You can edit directly as an admin; developers propose changes for review.' : 'Your edits become change requests that an admin approves.'}
            {env.openChangeRequests > 0 && <> <Link to={`/app/p/${project.id}/changes?env=${env.slug}`}>{env.openChangeRequests} open request{env.openChangeRequests > 1 ? 's' : ''}</Link>.</>}
          </span>
        </div>
      )}
      {tampered > 0 && (
        <div className="notice danger" style={{ margin: 16 }} role="alert">
          {tampered} secret{tampered > 1 ? 's' : ''} failed integrity checks and could not be decrypted. The ciphertext was modified or
          moved from another slot. Check the activity log.
        </div>
      )}

      {selectedRows.length > 0 && (
        <div className="bulk-bar" role="toolbar" aria-label="Bulk actions">
          <span className="count">{selectedRows.length} selected</span>
          <CopyButton value={() => asDotenv(selectedRows)} label="Copy as .env" secret />
          {canWrite && copyTargets.length > 0 && (
            <select className="select" aria-label="Copy selected to environment" value="" disabled={copyTo.isPending}
              onChange={(e) => e.target.value && copyTo.mutate(e.target.value)}>
              <option value="">Copy to…</option>
              {copyTargets.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
            </select>
          )}
          {canWrite && <Button size="sm" variant="danger" onClick={() => setDeleting(selectedRows)}><Icon name="trash" /> Delete</Button>}
          <Button size="sm" variant="ghost" onClick={() => setSelected(new Set())}>Clear <span className="kbd">Esc</span></Button>
        </div>
      )}

      {q.isLoading ? <SkeletonRows rows={6} cols={3} /> : rows.length === 0 ? (
        <div className="empty">
          <h3>No secrets in {env.name} yet</h3>
          <p>Add them one by one, import a .env file, or just paste one anywhere on this page. Values are encrypted before they leave this tab.</p>
          {canWrite && <div className="row"><Button onClick={() => { setImportText(''); setImporting(true); }}><Icon name="upload" /> Import .env</Button><Button variant="primary" onClick={() => setEditing('new')}><Icon name="plus" /> Add secret</Button></div>}
        </div>
      ) : (
        <div className="table-wrap">
          <table className="table stack-sm">
            <thead>
              <tr>
                <th className="sel"><input type="checkbox" aria-label="Select all" checked={allSelected} onChange={() => setSelected(allSelected ? new Set() : new Set(visible.map((r) => r.view.id)))} /></th>
                <th><button type="button" className="th-sort" onClick={() => sortBy('name')}>Name {arrow('name')}</button></th>
                <th>Value</th>
                <th className="nowrap"><button type="button" className="th-sort" onClick={() => sortBy('updated')}>Updated {arrow('updated')}</button></th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {visible.map((r, index) => {
                const shown = revealAll || revealed.has(r.view.id);
                const editingThis = inline?.id === r.view.id;
                return (
                  <tr key={r.view.id} className={selected.has(r.view.id) ? 'selected' : ''}>
                    <td className="sel">
                      <input type="checkbox" aria-label={`Select ${r.plain?.name ?? 'secret'}`} checked={selected.has(r.view.id)}
                        onClick={(e) => toggleRow(index, r.view.id, (e as React.MouseEvent).shiftKey)} onChange={() => {}} />
                    </td>
                    <td style={{ minWidth: 180 }}>
                      {r.plain ? <span className="secret-name">{r.plain.name}</span> : <span className="badge danger">Integrity check failed</span>}
                      {r.plain && (resolved.get(r.plain.name)?.references.length ?? 0) > 0 && (
                        <span className="ref-badge" title={`Template: ${r.plain.value}`}>{resolved.get(r.plain.name)!.references.map((x) => '${' + x + '}').join(' ')}</span>
                      )}
                      {r.plain && resolved.get(r.plain.name)?.error && <div className="secret-comment" style={{ color: 'var(--danger)' }}>{resolved.get(r.plain.name)!.error}</div>}
                      {r.plain?.comment && <div className="secret-comment">{r.plain.comment}</div>}
                    </td>
                    <td style={{ maxWidth: 460 }} className={`value-cell ${canWrite && r.plain ? 'editable' : ''}`}
                      onClick={() => { if (canWrite && r.plain && !editingThis) setInline({ id: r.view.id, draft: r.plain.value }); }}
                      title={canWrite && r.plain && !editingThis ? 'Click to edit' : undefined}>
                      {r.plain && (editingThis ? (
                        <div className="inline-edit" onClick={(e) => e.stopPropagation()}>
                          <textarea autoFocus aria-label={`New value for ${r.plain.name}`} value={inline.draft} spellCheck={false}
                            onChange={(e) => setInline({ id: r.view.id, draft: e.target.value })}
                            onKeyDown={(e) => {
                              if (e.key === 'Escape') { e.preventDefault(); setInline(null); }
                              if (e.key === 'Enter' && !e.shiftKey) {
                                e.preventDefault();
                                if (inline.draft === r.plain!.value) setInline(null); else saveInline.mutate({ r, value: inline.draft });
                              }
                            }} />
                          <span className="hint">{saveInline.isPending ? 'Saving…' : <>↵ {propose ? 'propose' : 'save'} · Esc</>}</span>
                        </div>
                      ) : shown
                        ? <span className="secret-value revealed">{valueOf(r) || <i className="faint">empty</i>}</span>
                        : <span className="secret-value mask" aria-label="Hidden value">••••••••••••</span>)}
                    </td>
                    <td className="nowrap small muted" title={`${formatDate(r.view.updatedAt)} by ${r.view.updatedBy ?? 'unknown'}`}>
                      {timeAgo(r.view.updatedAt)} <span className="faint">· v{r.view.version}</span>
                    </td>
                    <td className="actions">
                      {r.plain && <>
                        <Button size="icon" variant="ghost" aria-label={shown ? `Hide ${r.plain.name}` : `Reveal ${r.plain.name}`} title={shown ? 'Hide' : 'Reveal for 30s'}
                          onClick={() => reveal(r.view.id)} disabled={revealAll}>
                          <Icon name={shown ? 'eyeOff' : 'eye'} />
                        </Button>
                        <CopyButton iconOnly value={valueOf(r)} label={`Copy ${r.plain.name}`} secret />
                        <Button size="icon" variant="ghost" aria-label={`History of ${r.plain.name}`} title="History" onClick={() => setHistory(r)}><Icon name="history" /></Button>
                        {canWrite && <Button size="icon" variant="ghost" aria-label={`Edit ${r.plain.name}`} title="Edit name, value and note" onClick={() => setEditing(r)}><Icon name="edit" /></Button>}
                      </>}
                      {canWrite && <Button size="icon" variant="ghost" aria-label={`Delete ${r.plain?.name ?? 'secret'}`} title="Delete" onClick={() => setDeleting([r])}><Icon name="trash" /></Button>}
                    </td>
                  </tr>
                );
              })}
              {visible.length === 0 && <tr><td colSpan={5} className="muted small">No secrets match "{filter}".</td></tr>}
            </tbody>
          </table>
        </div>
      )}
      {rows.length > 0 && (
        <div className="panel-body xs faint row spread wrap" style={{ borderTop: '1px solid var(--border)', paddingTop: 10, paddingBottom: 10 }}>
          <span>{visible.length} of {rows.length - pending.size} secrets{filter && ' match'}</span>
          <span>Click a value to edit · shift-click to select a range · paste a .env anywhere to import · <span className="kbd">?</span> for shortcuts</span>
        </div>
      )}

      <SecretEditor env={env} row={editing} existing={rows} onClose={() => setEditing(null)} onSaved={invalidate} />
      <SecretHistory env={env} row={history} onClose={() => setHistory(null)} onRestored={invalidate} canWrite={canWrite && !propose} />
      <ImportDialog env={env} open={importing} initialText={importText} existing={rows} onClose={() => setImporting(false)} onDone={invalidate} />
      <Modal open={!!deleting} onClose={() => setDeleting(null)}
        title={deleting?.length === 1 ? `Delete ${deleting[0]!.plain?.name ?? 'secret'}?` : `Delete ${deleting?.length} secrets?`}
        description={propose
          ? `${env.name} is protected, so this opens a change request for an admin to approve.`
          : `This removes ${deleting?.length === 1 ? 'it' : 'them'} and the version history from ${env.name}. You'll have 6 seconds to undo.`}
        footer={<><Button onClick={() => setDeleting(null)}>Cancel</Button><Button variant="danger" className="solid" onClick={() => deleting && void scheduleDelete(deleting)}>{propose ? 'Propose deletion' : 'Delete'}</Button></>}>
        {deleting && deleting.length > 1 && <div className="codeblock">{deleting.map((r) => r.plain?.name ?? r.view.id).join('\n')}</div>}
      </Modal>
    </div>
  );
}

function SecretEditor({ env, row, existing, onClose, onSaved }: {
  env: EnvironmentView; row: Row | 'new' | null; existing: Row[]; onClose: () => void; onSaved: () => void;
}) {
  const { project } = useProject();
  const vault = useVault();
  const toast = useToast();
  const isNew = row === 'new';
  const current = row && row !== 'new' ? row : null;
  const [name, setName] = useState('');
  const [value, setValue] = useState('');
  const [comment, setComment] = useState('');
  const [initFor, setInitFor] = useState<string | null>(null);

  const key = row === 'new' ? 'new' : row?.view.id ?? null;
  if (key !== initFor) {
    setInitFor(key);
    setName(current?.plain?.name ?? '');
    setValue(current?.plain?.value ?? '');
    setComment(current?.plain?.comment ?? '');
  }

  const preview = useMemo(() => {
    if (!/\$\{/.test(value) || !name) return null;
    const others = existing.filter((r) => r.plain && r.view.id !== current?.view.id && r.plain.name !== name).map((r) => r.plain!);
    return resolveReferences([...others, { name, value }]).get(name) ?? null;
  }, [value, name, existing, current]);
  const nameError = name && !SECRET_NAME_PATTERN.test(name) ? 'Letters, digits and underscores; must not start with a digit.'
    : existing.some((r) => r.plain?.name === name && r.view.id !== current?.view.id) ? `${name} already exists in ${env.name}.` : null;

  const propose = mustPropose(project.role, env);
  const dirty = !!row && (name !== (current?.plain?.name ?? '') || value !== (current?.plain?.value ?? '') || comment !== (current?.plain?.comment ?? ''));
  const close = () => { if (!dirty || window.confirm('Discard your unsaved changes?')) onClose(); };
  const generate = () => {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
    const bytes = randomBytes(40);
    setValue(Array.from(bytes, (b) => alphabet[b % alphabet.length]).join(''));
  };
  const save = useMutation({
    mutationFn: async () => {
      const ref = { projectId: project.id, environmentId: env.id };
      const envKey = vault.envKey(project.id, env);
      const plain = { name, value, comment };
      const id = isNew ? newId() : current!.view.id;
      const ct = encryptSecret(envKey, ref, id, plain);
      if (propose) {
        return api.changeRequests.create(env.id, isNew ? `Add ${name}` : `Update ${name}`, env.keyVersion, [
          { op: isNew ? 'CREATE' : 'UPDATE', secretId: id, expectedVersion: isNew ? null : current!.view.version, ...ct },
        ]);
      }
      if (isNew) return api.secrets.create(env.id, [{ id, ...ct, keyVersion: env.keyVersion }]);
      return api.secrets.update(env.id, id, { ...ct, keyVersion: env.keyVersion, expectedVersion: current!.view.version });
    },
    onSuccess: () => { toast(propose ? `Proposed: ${name}. An admin will review it.` : isNew ? `Added ${name}` : `Saved ${name}`); onSaved(); onClose(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });

  return (
    <Modal open={!!row} onClose={close} title={isNew ? `Add secret to ${env.name}` : `Edit ${current?.plain?.name}`}
      description={isNew ? 'The name, value and note are all encrypted. The server only sees an HMAC of the name, so it can reject duplicates.' : `Saving creates version ${(current?.view.version ?? 0) + 1}. Earlier versions stay in history.`}
      footer={<><Button onClick={close}>Cancel</Button><Button variant="primary" busy={save.isPending} disabled={!name || !!nameError} onClick={() => save.mutate()}>{propose ? 'Propose change' : isNew ? 'Add secret' : 'Save changes'}</Button></>}>
      {propose && <div className="notice warn"><Icon name="shield" /> <span>{env.name} is protected. Your change becomes a request that another admin approves.</span></div>}
      <Field label="Name" value={name} code onChange={(e) => setName(e.target.value.toUpperCase().replace(/[^A-Z0-9_]/g, '_'))}
        placeholder="DATABASE_URL" error={nameError} autoFocus={isNew} spellCheck={false} autoComplete="off" />
      <div className="field">
        <div className="row spread">
          <label htmlFor="secret-value" className="label">Value</label>
          <Button size="sm" variant="ghost" onClick={generate} title="40 random characters from a 56-symbol alphabet (~232 bits)"><Icon name="key" /> Generate</Button>
        </div>
        <textarea id="secret-value" className="textarea code" value={value} onChange={(e) => setValue(e.target.value)} spellCheck={false} autoComplete="off"
          onKeyDown={(e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey) && name && !nameError) save.mutate(); }} />
        <span className="hint">{value.length} characters · <span className="kbd">Ctrl</span> <span className="kbd">↵</span> to save</span>
      </div>
      {preview && <div className="field"><span className="label">Resolves to</span><div className={preview.error ? 'notice danger' : 'secret-value revealed'}>{preview.error ?? (preview.value || '(empty)')}</div></div>}
      <p className="xs faint">Reference other secrets in {env.name} with <code>{'${NAME}'}</code>; write <code>{'$${'}</code> for a literal. References resolve on your device and in the CLI.</p>
      <Field label="Note" value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Where it comes from, who owns it" maxLength={500} />
    </Modal>
  );
}

function SecretHistory({ env, row, onClose, onRestored, canWrite }: { env: EnvironmentView; row: Row | null; onClose: () => void; onRestored: () => void; canWrite: boolean }) {
  const { project } = useProject();
  const vault = useVault();
  const toast = useToast();
  const q = useQuery({ queryKey: ['versions', row?.view.id], enabled: !!row, queryFn: () => api.secrets.versions(env.id, row!.view.id) });
  const restore = useMutation({
    mutationFn: (v: number) => api.secrets.rollback(env.id, row!.view.id, v, row!.view.version),
    onSuccess: (_, v) => { toast(`Restored version ${v}`); onRestored(); onClose(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const key = row ? vault.envKey(project.id, env) : null;
  return (
    <Modal open={!!row} onClose={onClose} wide title={`History of ${row?.plain?.name ?? ''}`} description="Decrypted on this device. Restoring a version creates a new version with the old value.">
      {q.isLoading ? <Spinner /> : (
        <div className="timeline panel">
          {q.data?.map((v) => {
            let plain: SecretPlaintext | null = null;
            try { plain = decryptSecret(key!, { projectId: project.id, environmentId: env.id }, row!.view.id, v); } catch { /* tampered */ }
            const isCurrent = v.version === row?.view.version;
            return (
              <div className="event" key={v.version}>
                <div className="when">v{v.version} · {timeAgo(v.createdAt)}<br />{v.changedBy ?? 'unknown'}</div>
                <div className="row spread" style={{ alignItems: 'flex-start' }}>
                  <div className="grow">
                    <div className="row" style={{ '--gap': '6px' } as React.CSSProperties}>
                      <span className="badge">{v.changeType.toLowerCase()}</span>
                      {isCurrent && <span className="badge ok">current</span>}
                      {plain && plain.name !== row?.plain?.name && <span className="xs faint">named {plain.name}</span>}
                    </div>
                    <div className="secret-value revealed" style={{ marginTop: 6 }}>{plain ? plain.value || <i className="faint">empty</i> : <span className="badge danger">Integrity check failed</span>}</div>
                  </div>
                  <div className="row">
                    {plain && <Button size="icon" variant="ghost" aria-label="Copy value" onClick={() => copySecret(plain!.value).then(() => toast('Copied'))}><Icon name="copy" /></Button>}
                    {canWrite && !isCurrent && plain && <Button size="sm" busy={restore.isPending && restore.variables === v.version} onClick={() => restore.mutate(v.version)}>Restore</Button>}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Modal>
  );
}

function ImportDialog({ env, open, initialText, existing, onClose, onDone }: { env: EnvironmentView; open: boolean; initialText?: string; existing: Row[]; onClose: () => void; onDone: () => void }) {
  const { project } = useProject();
  const vault = useVault();
  const toast = useToast();
  const [text, setText] = useState('');
  const [overwrite, setOverwrite] = useState(false);
  useEffect(() => { if (open) setText(initialText ?? ''); }, [open, initialText]);
  const parsed = useMemo(() => parseDotenv(text), [text]);
  const byName = new Map(existing.filter((r) => r.plain).map((r) => [r.plain!.name, r]));
  const fresh = parsed.filter((p) => !byName.has(p.name));
  const clashes = parsed.filter((p) => byName.has(p.name));

  const run = useMutation({
    mutationFn: async () => {
      const ref = { projectId: project.id, environmentId: env.id };
      const key = vault.envKey(project.id, env);
      // last occurrence wins, like dotenv
      const unique = [...new Map(fresh.map((p) => [p.name, p])).values()];
      if (mustPropose(project.role, env)) {
        const items: ChangeItemInput[] = unique.map((p) => { const id = newId(); return { op: 'CREATE' as const, secretId: id, ...encryptSecret(key, ref, id, p) }; });
        if (overwrite) {
          for (const p of clashes) {
            const r = byName.get(p.name)!;
            if (r.plain!.value !== p.value) items.push({ op: 'UPDATE', secretId: r.view.id, expectedVersion: r.view.version, ...encryptSecret(key, ref, r.view.id, { ...p, comment: r.plain!.comment }) });
          }
        }
        if (items.length) await api.changeRequests.create(env.id, `Import ${items.length} secrets from .env`, env.keyVersion, items);
        return { added: 0, updated: 0, proposed: items.length };
      }
      if (unique.length) {
        await api.secrets.create(env.id, unique.map((p) => {
          const id = newId();
          return { id, ...encryptSecret(key, ref, id, p), keyVersion: env.keyVersion };
        }));
      }
      let updated = 0;
      if (overwrite) {
        for (const p of clashes) {
          const r = byName.get(p.name)!;
          if (r.plain!.value === p.value) continue;
          await api.secrets.update(env.id, r.view.id, { ...encryptSecret(key, ref, r.view.id, { ...p, comment: r.plain!.comment }), keyVersion: env.keyVersion, expectedVersion: r.view.version });
          updated++;
        }
      }
      return { added: unique.length, updated, proposed: 0 };
    },
    onSuccess: (r) => { toast(r.proposed ? `Proposed ${r.proposed} changes for review` : `Imported ${r.added} new, updated ${r.updated}`); setText(''); onDone(); onClose(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });

  return (
    <Modal open={open} onClose={onClose} wide title={`Import into ${env.name}`} description="Paste a .env file or choose one. It's parsed and encrypted here; plaintext is never uploaded."
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" busy={run.isPending} disabled={parsed.length === 0} onClick={() => run.mutate()}>Import {fresh.length + (overwrite ? clashes.length : 0)} secrets</Button></>}>
      <input type="file" accept=".env,text/plain" className="small" onChange={async (e) => { const f = e.target.files?.[0]; if (f) setText(await f.text()); }} />
      <textarea className="textarea code" style={{ minHeight: 180 }} value={text} onChange={(e) => setText(e.target.value)} placeholder={'DATABASE_URL=postgres://…\nSTRIPE_KEY="sk_live_…"'} spellCheck={false} aria-label=".env contents" />
      {parsed.length > 0 && (
        <p className="small muted">{fresh.length} new{clashes.length > 0 && <>, {clashes.length} already exist ({clashes.slice(0, 4).map((c) => c.name).join(', ')}{clashes.length > 4 ? '…' : ''})</>}.</p>
      )}
      {clashes.length > 0 && (
        <label className="check"><input type="checkbox" checked={overwrite} onChange={(e) => setOverwrite(e.target.checked)} /><span>Overwrite existing values (a new version is kept for each)</span></label>
      )}
      <p className="xs faint">Tip: the CLI can do this too. See <Link to={`/app/p/${project.id}/tokens`}>Access tokens</Link>.</p>
    </Modal>
  );
}

/** In a protected environment, anyone below admin proposes changes instead of writing directly. */
export function mustPropose(role: Role, env: EnvironmentView): boolean {
  return env.protected && !atLeast(role, 'ADMIN');
}
