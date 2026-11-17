import { generateEnvironmentKey, newId, wipe, wrapEnvKeyForMember } from '@keyvault/crypto';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Identicon } from '../components/Identicon';
import { Button, Field, Icon, Modal, SkeletonRows, errorMessage, timeAgo, useToast } from '../components/ui';
import { api } from '../lib/api';
import { useVault } from '../lib/vault';

const DEFAULT_ENVS = [
  { name: 'Development', slug: 'development' },
  { name: 'Staging', slug: 'staging' },
  { name: 'Production', slug: 'production' },
];

export function Projects() {
  const projects = useQuery({ queryKey: ['projects'], queryFn: api.projects.list });
  const [creating, setCreating] = useState(false);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <h1>Projects</h1>
          <p className="sub">Each project holds its own environments, members and access tokens.</p>
        </div>
        <Button variant="primary" onClick={() => setCreating(true)}><Icon name="plus" /> New project</Button>
      </div>

      {projects.isLoading ? <div className="panel"><SkeletonRows rows={3} /></div> : projects.data && projects.data.length > 0 ? (
        <div className="project-list">
          {projects.data.map((p) => (
            <Link key={p.id} to={`/app/p/${p.id}`} className="project-row">
              <div className="head">
                <Identicon seed={p.id} size={28} />
                <div style={{ minWidth: 0 }} className="grow">
                  <div className="name">{p.name}</div>
                  <div className="desc">{p.description || 'No description'}</div>
                </div>
                {p.rotationNeeded && <span className="badge brass" title="A member was removed; rotate keys">Rotate keys</span>}
              </div>
              <div className="stats">
                <span><b>{p.secretCount}</b>secrets</span>
                <span><b>{p.environmentCount}</b>environments</span>
                <span><b>{p.memberCount}</b>{p.memberCount === 1 ? 'member' : 'members'}</span>
              </div>
              <div className="foot">
                <span className="badge">{p.role.charAt(0) + p.role.slice(1).toLowerCase()}</span>
                <span>Updated {timeAgo(p.updatedAt)}</span>
              </div>
            </Link>
          ))}
        </div>
      ) : (
        <div className="panel empty">
          <h3>Start with your first project</h3>
          <p>A project is usually one app or service. You'll get development, staging and production environments, each with its own encryption key.</p>
          <Button variant="primary" onClick={() => setCreating(true)}><Icon name="plus" /> New project</Button>
        </div>
      )}
      <CreateProject open={creating} onClose={() => setCreating(false)} />
    </div>
  );
}

function CreateProject({ open, onClose }: { open: boolean; onClose: () => void }) {
  const vault = useVault();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const toast = useToast();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [envs, setEnvs] = useState(DEFAULT_ENVS.map((e) => ({ ...e, on: true })));

  const create = useMutation({
    mutationFn: async () => {
      const account = vault.account!;
      const projectId = newId();
      const myPublicKey = vault.bundle!.publicKey;
      const environments = envs.filter((e) => e.on).map((e) => {
        const id = newId();
        const key = generateEnvironmentKey();
        const wrappedKey = wrapEnvKeyForMember(key, myPublicKey, { projectId, environmentId: id });
        wipe(key);
        return { id, name: e.name, slug: e.slug, wrappedKey };
      });
      void account;
      return api.projects.create({ id: projectId, name: name.trim(), description: description.trim(), environments });
    },
    onSuccess: (p) => {
      qc.invalidateQueries({ queryKey: ['projects'] });
      toast(`Created ${p.name}`);
      onClose();
      setName('');
      setDescription('');
      navigate(`/app/p/${p.id}`);
    },
    onError: (e) => toast(errorMessage(e), 'error'),
  });

  return (
    <Modal open={open} onClose={onClose} title="New project"
      description="Environment keys are generated in your browser and sealed to your identity before anything is sent."
      footer={<>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="primary" busy={create.isPending} disabled={!name.trim() || !envs.some((e) => e.on)} onClick={() => create.mutate()}>Create project</Button>
      </>}>
      <Field label="Project name" value={name} onChange={(e) => setName(e.target.value)} maxLength={80} placeholder="payments-api" autoFocus />
      <Field label="Description" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} placeholder="Optional" />
      <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0, '--gap': '8px' } as React.CSSProperties}>
        <legend className="label" style={{ marginBottom: 8 }}>Environments</legend>
        {envs.map((e, i) => (
          <label key={e.slug} className="check">
            <input type="checkbox" checked={e.on} onChange={(ev) => setEnvs(envs.map((x, j) => (j === i ? { ...x, on: ev.target.checked } : x)))} />
            <span>{e.name}</span>
          </label>
        ))}
      </fieldset>
    </Modal>
  );
}
