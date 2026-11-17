import {
  b64,
  decryptSecret,
  encryptSecret,
  fingerprint,
  generateEnvironmentKey,
  newId,
  wipe,
  wrapEnvKeyForMember,
} from '@keyvault/crypto';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Identicon } from '../components/Identicon';
import { Button, Field, Icon, Modal, errorMessage, useToast } from '../components/ui';
import { api, atLeast, ROLE_RANK, type EnvironmentView, type MemberView, type Role, type UserLookup } from '../lib/api';
import { useVault } from '../lib/vault';
import { useProject } from './Project';

const ROLES: { role: Role; blurb: string }[] = [
  { role: 'VIEWER', blurb: 'Read secrets in granted environments' },
  { role: 'DEVELOPER', blurb: 'Read and change secrets, create access tokens' },
  { role: 'ADMIN', blurb: 'Manage members, environments and key rotation' },
  { role: 'OWNER', blurb: 'Everything, including deleting the project' },
];

const fp = (pk: string) => { try { return fingerprint(b64.decode(pk)); } catch { return 'invalid key'; } };

// ================================================================ members

export function Members() {
  const { project, refetch } = useProject();
  const vault = useVault();
  const toast = useToast();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<MemberView | null>(null);
  const me = vault.bundle!.user.id;
  const isAdmin = atLeast(project.role, 'ADMIN');

  const grant = useMutation({
    mutationFn: async ({ m, env, on }: { m: MemberView; env: EnvironmentView; on: boolean }) => {
      if (!on) return api.projects.revokeGrant(project.id, env.id, m.userId);
      const key = vault.envKey(project.id, env);
      return api.projects.setGrant(project.id, env.id, m.userId,
        wrapEnvKeyForMember(key, m.publicKey, { projectId: project.id, environmentId: env.id }), env.keyVersion);
    },
    onSuccess: (_, v) => { toast(v.on ? `Granted ${v.env.name} to ${v.m.displayName}` : `Revoked ${v.env.name}. Rotate its key to finish.`); refetch(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const role = useMutation({
    mutationFn: ({ m, r }: { m: MemberView; r: Role }) => api.projects.changeRole(project.id, m.userId, r),
    onSuccess: () => { toast('Role updated'); refetch(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const remove = useMutation({
    mutationFn: (m: MemberView) => api.projects.removeMember(project.id, m.userId),
    onSuccess: (_, m) => {
      setRemoving(null);
      qc.invalidateQueries({ queryKey: ['projects'] });
      if (m.userId === me) { toast(`You left ${project.name}`); navigate('/app'); } else { toast(`Removed ${m.displayName}`); refetch(); }
    },
    onError: (e) => toast(errorMessage(e), 'error'),
  });

  const canManage = (m: MemberView) => isAdmin && (project.role === 'OWNER' || ROLE_RANK[m.role] < ROLE_RANK[project.role]);

  return (
    <div className="stack" style={{ '--gap': '16px' } as React.CSSProperties}>
      <div className="row spread wrap">
        <p className="muted small" style={{ maxWidth: '64ch' }}>
          Roles decide what the server lets each person do. Environment chips decide what they can decrypt: a filled chip means
          that environment's key is sealed to their identity.
        </p>
        {isAdmin && <Button variant="primary" onClick={() => setAdding(true)}><Icon name="plus" /> Add member</Button>}
      </div>
      <div className="panel">
        {project.members.map((m) => (
          <div className="member" key={m.userId}>
            <Identicon publicKey={m.publicKey} size={36} title={`Identicon of ${m.email}`} />
            <div style={{ minWidth: 0 }} className="stack" >
              <div>
                <div className="row" style={{ '--gap': '8px' } as React.CSSProperties}>
                  <b>{m.displayName}</b>{m.userId === me && <span className="badge">you</span>}
                </div>
                <div className="small muted">{m.email}</div>
                <div className="fingerprint" title="Public key fingerprint">{fp(m.publicKey)}</div>
              </div>
              <div className="env-chips" role="group" aria-label={`Environment access for ${m.email}`}>
                {project.environments.map((env) => {
                  const on = m.environmentIds.includes(env.id);
                  const can = canManage(m) && !!env.wrappedKey && m.userId !== me;
                  return (
                    <button key={env.id} type="button" className={`chip ${on ? 'on' : ''}`} disabled={!can || grant.isPending} aria-pressed={on}
                      title={can ? (on ? `Revoke ${env.name}` : `Grant ${env.name}`) : on ? 'Has access' : 'No access'}
                      onClick={() => grant.mutate({ m, env, on: !on })}>
                      {on ? <Icon name="key" size={12} /> : <Icon name="lock" size={12} />} {env.name}
                    </button>
                  );
                })}
              </div>
            </div>
            <div className="row">
              {canManage(m) && m.userId !== me ? (
                <select className="select" style={{ minHeight: 32, width: 'auto' }} value={m.role} aria-label={`Role for ${m.email}`}
                  onChange={(e) => role.mutate({ m, r: e.target.value as Role })}>
                  {ROLES.filter((r) => project.role === 'OWNER' || ROLE_RANK[r.role] <= ROLE_RANK[project.role]).map((r) => <option key={r.role} value={r.role}>{r.role.toLowerCase()}</option>)}
                </select>
              ) : <span className="badge">{m.role.toLowerCase()}</span>}
              {(canManage(m) || m.userId === me) && (
                <Button size="sm" variant="danger" onClick={() => setRemoving(m)}>{m.userId === me ? 'Leave' : 'Remove'}</Button>
              )}
            </div>
          </div>
        ))}
      </div>
      <AddMember open={adding} onClose={() => setAdding(false)} />
      <Modal open={!!removing} onClose={() => setRemoving(null)} title={removing?.userId === me ? `Leave ${project.name}?` : `Remove ${removing?.displayName}?`}
        description={removing?.userId === me ? 'You lose access immediately. Someone will need to add you back.' : 'Their sealed keys are deleted. Environments they could read are flagged for key rotation, because they may have kept a copy.'}
        footer={<><Button onClick={() => setRemoving(null)}>Cancel</Button><Button variant="danger" className="solid" busy={remove.isPending} onClick={() => removing && remove.mutate(removing)}>{removing?.userId === me ? 'Leave project' : 'Remove member'}</Button></>}>
        <span />
      </Modal>
    </div>
  );
}

function AddMember({ open, onClose }: { open: boolean; onClose: () => void }) {
  const { project, refetch } = useProject();
  const vault = useVault();
  const toast = useToast();
  const [email, setEmail] = useState('');
  const [found, setFound] = useState<UserLookup | null>(null);
  const [verified, setVerified] = useState(false);
  const [role, setRole] = useState<Role>('DEVELOPER');
  const [envs, setEnvs] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const grantable = project.environments.filter((e) => e.wrappedKey);

  const reset = () => { setEmail(''); setFound(null); setVerified(false); setEnvs(new Set()); setError(null); setRole('DEVELOPER'); };
  const close = () => { reset(); onClose(); };

  const lookup = useMutation({
    mutationFn: () => api.users.lookup(email),
    onSuccess: (u) => { setFound(u); setError(null); setEnvs(new Set(grantable.filter((e) => e.slug !== 'production').map((e) => e.id))); },
    onError: (e) => setError(errorMessage(e)),
  });
  const add = useMutation({
    mutationFn: () => api.projects.addMember(project.id, {
      userId: found!.id, role,
      grants: grantable.filter((e) => envs.has(e.id)).map((env) => ({
        environmentId: env.id,
        wrappedKey: wrapEnvKeyForMember(vault.envKey(project.id, env), found!.publicKey, { projectId: project.id, environmentId: env.id }),
      })),
    }),
    onSuccess: () => { toast(`Added ${found!.displayName}`); refetch(); close(); },
    onError: (e) => setError(errorMessage(e)),
  });

  return (
    <Modal open={open} onClose={close} wide title="Add a member"
      description="They need a KeyVault account first. Environment keys are sealed to their public key in your browser."
      footer={found ? <><Button onClick={() => setFound(null)}>Back</Button><Button variant="primary" busy={add.isPending} disabled={!verified} onClick={() => add.mutate()}>Add {found.displayName}</Button></> : <><Button onClick={close}>Cancel</Button><Button variant="primary" busy={lookup.isPending} disabled={!email} onClick={() => lookup.mutate()}>Find account</Button></>}>
      {!found ? (
        <form onSubmit={(e) => { e.preventDefault(); lookup.mutate(); }}>
          <Field label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoFocus placeholder="teammate@company.com" />
        </form>
      ) : (
        <>
          <div className="row" style={{ '--gap': '16px', alignItems: 'flex-start' } as React.CSSProperties}>
            <Identicon publicKey={found.publicKey} size={64} title={`Identicon of ${found.email}`} />
            <div className="stack" style={{ '--gap': '6px' } as React.CSSProperties}>
              <b>{found.displayName}</b>
              <span className="small muted">{found.email}</span>
              <span className="fingerprint">{fp(found.publicKey)}</span>
              <p className="xs faint" style={{ maxWidth: '48ch' }}>Ask {found.displayName} to open Account &amp; security and read you their fingerprint, or compare identicons on a call. A match proves the server didn't swap in its own key.</p>
            </div>
          </div>
          <label className="check"><input type="checkbox" checked={verified} onChange={(e) => setVerified(e.target.checked)} /><span>I've confirmed this fingerprint with {found.displayName} through another channel.</span></label>
          <div className="field">
            <label htmlFor="role">Role</label>
            <select id="role" className="select" value={role} onChange={(e) => setRole(e.target.value as Role)}>
              {ROLES.filter((r) => project.role === 'OWNER' || ROLE_RANK[r.role] <= ROLE_RANK[project.role]).map((r) => <option key={r.role} value={r.role}>{r.role.toLowerCase()}: {r.blurb}</option>)}
            </select>
          </div>
          <div className="field">
            <span className="label">Environments they can decrypt</span>
            <div className="env-chips">
              {grantable.map((e) => (
                <button key={e.id} type="button" className={`chip ${envs.has(e.id) ? 'on' : ''}`} aria-pressed={envs.has(e.id)}
                  onClick={() => setEnvs((s) => { const n = new Set(s); if (n.has(e.id)) n.delete(e.id); else n.add(e.id); return n; })}>
                  <Icon name={envs.has(e.id) ? 'key' : 'lock'} size={12} /> {e.name}
                </button>
              ))}
            </div>
          </div>
        </>
      )}
      {error && <div className="notice danger" role="alert">{error}</div>}
    </Modal>
  );
}

// ============================================================ environments

export function Environments() {
  const { project, refetch } = useProject();
  const vault = useVault();
  const toast = useToast();
  const qc = useQueryClient();
  const isAdmin = atLeast(project.role, 'ADMIN');
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState('');
  const [rotating, setRotating] = useState<EnvironmentView | null>(null);
  const [deleting, setDeleting] = useState<EnvironmentView | null>(null);
  const [renaming, setRenaming] = useState<EnvironmentView | null>(null);
  const [newName, setNewName] = useState('');

  const add = useMutation({
    mutationFn: async () => {
      const id = newId();
      const key = generateEnvironmentKey();
      const wrappedKey = wrapEnvKeyForMember(key, vault.bundle!.publicKey, { projectId: project.id, environmentId: id });
      wipe(key);
      const slug = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 40) || 'env';
      return api.projects.createEnvironment(project.id, { id, name: name.trim(), slug, grants: [{ userId: vault.bundle!.user.id, wrappedKey }] });
    },
    onSuccess: () => { toast(`Created ${name}`); setName(''); setAdding(false); refetch(); qc.invalidateQueries({ queryKey: ['projects'] }); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const remove = useMutation({
    mutationFn: (env: EnvironmentView) => api.projects.deleteEnvironment(project.id, env.id),
    onSuccess: () => { toast('Environment deleted'); setDeleting(null); refetch(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const protect = useMutation({
    mutationFn: ({ env, enabled }: { env: EnvironmentView; enabled: boolean }) => api.projects.setProtection(project.id, env.id, enabled),
    onSuccess: (_, v) => { toast(v.enabled ? `${v.env.name} now requires review` : `${v.env.name} accepts direct changes`); refetch(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const rename = useMutation({
    mutationFn: () => api.projects.renameEnvironment(project.id, renaming!.id, newName.trim()),
    onSuccess: () => { toast('Renamed'); setRenaming(null); refetch(); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });

  return (
    <div className="stack" style={{ '--gap': '16px' } as React.CSSProperties}>
      <div className="row spread wrap">
        <p className="muted small" style={{ maxWidth: '64ch' }}>Every environment has its own 256-bit key. Rotating it re-encrypts every secret and its history in your browser, then re-seals the new key for the people who should keep access.</p>
        {isAdmin && <Button variant="primary" onClick={() => setAdding(true)}><Icon name="plus" /> New environment</Button>}
      </div>
      <div className="panel table-wrap">
        <table className="table">
          <thead><tr><th>Environment</th><th>Secrets</th><th>Tokens</th><th>Key</th><th>Changes</th><th><span className="sr-only">Actions</span></th></tr></thead>
          <tbody>
            {project.environments.map((e) => (
              <tr key={e.id}>
                <td><b>{e.name}</b> <span className="faint xs code">{e.slug}</span></td>
                <td>{e.secretCount}</td>
                <td>{e.tokenCount}</td>
                <td>
                  <div className="row" style={{ '--gap': '6px' } as React.CSSProperties}>
                    <span className="badge">v{e.keyVersion}</span>
                    {e.rotationNeeded ? <span className="badge brass">Rotation recommended</span> : e.wrappedKey ? <span className="badge ok">You hold it</span> : <span className="badge">No access</span>}
                  </div>
                </td>
                <td>
                  {isAdmin ? (
                    <label className="check" title="Require an admin's approval for changes by developers">
                      <input type="checkbox" checked={e.protected} disabled={protect.isPending} onChange={(ev) => protect.mutate({ env: e, enabled: ev.target.checked })} />
                      <span>{e.protected ? 'Require review' : 'Direct'}</span>
                    </label>
                  ) : e.protected ? <span className="badge accent">Review required</span> : <span className="faint small">Direct</span>}
                </td>
                <td className="actions">
                  {isAdmin && e.wrappedKey && <Button size="sm" variant={e.rotationNeeded ? 'brass' : 'default'} onClick={() => setRotating(e)}><Icon name="rotate" /> Rotate key</Button>}
                  {isAdmin && <Button size="icon" variant="ghost" aria-label={`Rename ${e.name}`} onClick={() => { setRenaming(e); setNewName(e.name); }}><Icon name="edit" /></Button>}
                  {isAdmin && project.environments.length > 1 && <Button size="icon" variant="ghost" aria-label={`Delete ${e.name}`} onClick={() => setDeleting(e)}><Icon name="trash" /></Button>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Modal open={adding} onClose={() => setAdding(false)} title="New environment" description="A new key is generated and sealed to you. Grant teammates access from Members."
        footer={<><Button onClick={() => setAdding(false)}>Cancel</Button><Button variant="primary" busy={add.isPending} disabled={!name.trim()} onClick={() => add.mutate()}>Create environment</Button></>}>
        <Field label="Name" value={name} onChange={(e) => setName(e.target.value)} maxLength={40} placeholder="Preview" autoFocus />
      </Modal>
      <Modal open={!!renaming} onClose={() => setRenaming(null)} title={`Rename ${renaming?.name}`}
        footer={<><Button onClick={() => setRenaming(null)}>Cancel</Button><Button variant="primary" busy={rename.isPending} disabled={!newName.trim()} onClick={() => rename.mutate()}>Rename</Button></>}>
        <Field label="Name" value={newName} onChange={(e) => setNewName(e.target.value)} maxLength={40} autoFocus />
      </Modal>
      <Modal open={!!deleting} onClose={() => setDeleting(null)} title={`Delete ${deleting?.name}?`}
        description={`All ${deleting?.secretCount ?? 0} secrets, their history and ${deleting?.tokenCount ?? 0} access tokens are deleted. This cannot be undone.`}
        footer={<><Button onClick={() => setDeleting(null)}>Cancel</Button><Button variant="danger" className="solid" busy={remove.isPending} onClick={() => deleting && remove.mutate(deleting)}>Delete environment</Button></>}>
        <span />
      </Modal>
      {rotating && <RotateKey env={rotating} onClose={() => setRotating(null)} />}
    </div>
  );
}

function RotateKey({ env, onClose }: { env: EnvironmentView; onClose: () => void }) {
  const { project, refetch } = useProject();
  const vault = useVault();
  const toast = useToast();
  const qc = useQueryClient();
  const holders = project.members.filter((m) => m.environmentIds.includes(env.id));
  const [keep, setKeep] = useState<Set<string>>(new Set(holders.map((m) => m.userId)));
  const me = vault.bundle!.user.id;

  const rotate = useMutation({
    mutationFn: async () => {
      const ref = { projectId: project.id, environmentId: env.id };
      const oldKey = vault.envKey(project.id, env);
      const snap = await api.secrets.rotationSnapshot(env.id);
      const newKey = generateEnvironmentKey();
      try {
        const secrets = snap.secrets.map((s) => {
          const plain = decryptSecret(oldKey, ref, s.id, s);
          const cur = encryptSecret(newKey, ref, s.id, plain);
          return {
            id: s.id, ...cur,
            versions: (snap.versions[s.id] ?? []).map((v) => {
              const p = decryptSecret(oldKey, ref, s.id, v);
              return { version: v.version, ...encryptSecret(newKey, ref, s.id, p) };
            }),
          };
        });
        const grants = project.members.filter((m) => keep.has(m.userId)).map((m) => ({
          userId: m.userId, wrappedKey: wrapEnvKeyForMember(newKey, m.publicKey, ref),
        }));
        return await api.secrets.rotate(env.id, { expectedKeyVersion: snap.keyVersion, grants, secrets });
      } finally {
        wipe(newKey);
      }
    },
    onSuccess: (r) => {
      toast(`Rotated to key v${r.newKeyVersion}: ${r.secretsReencrypted} secrets re-encrypted, ${r.tokensRevoked} tokens revoked`);
      qc.invalidateQueries({ queryKey: ['secrets', env.id] });
      qc.invalidateQueries({ queryKey: ['projects'] });
      refetch();
      onClose();
    },
    onError: (e) => toast(errorMessage(e), 'error'),
  });

  return (
    <Modal open onClose={onClose} wide title={`Rotate the ${env.name} key`}
      description="Your browser decrypts every secret and every past version, encrypts them under a fresh key, and seals that key to the people you keep below."
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="brass" busy={rotate.isPending} onClick={() => rotate.mutate()}><Icon name="rotate" /> Rotate key</Button></>}>
      <div className="notice warn small">
        All {env.tokenCount} access tokens for {env.name} stop working, because they hold the old key. Issue new ones afterwards.
        Rotation protects future changes; if someone may have copied secret values, change those values at their source too.
      </div>
      <div className="field">
        <span className="label">Who keeps access</span>
        <div className="stack" style={{ '--gap': '8px' } as React.CSSProperties}>
          {project.members.map((m) => (
            <label key={m.userId} className="check">
              <input type="checkbox" checked={keep.has(m.userId)} disabled={m.userId === me}
                onChange={(e) => setKeep((s) => { const n = new Set(s); if (e.target.checked) n.add(m.userId); else n.delete(m.userId); return n; })} />
              <span>{m.displayName} <span className="faint">({m.email}, {m.role.toLowerCase()})</span></span>
            </label>
          ))}
        </div>
      </div>
    </Modal>
  );
}

