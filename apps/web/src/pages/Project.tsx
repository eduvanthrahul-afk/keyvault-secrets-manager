import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Navigate, NavLink, Outlet, useOutletContext, useParams } from 'react-router-dom';
import { Identicon } from '../components/Identicon';
import { Button, Icon, Spinner } from '../components/ui';
import { api, atLeast, type ProjectDetail } from '../lib/api';

export interface ProjectCtx {
  project: ProjectDetail;
  refetch: () => void;
}

export const useProject = () => useOutletContext<ProjectCtx>();

export function ProjectLayout() {
  const { projectId } = useParams();
  const q = useQuery({ queryKey: ['project', projectId], queryFn: () => api.projects.get(projectId!), retry: false });

  if (q.isLoading) return <Spinner />;
  if (q.error || !q.data) {
    return (
      <div className="page"><div className="panel empty">
        <h3>Project not found</h3>
        <p>It may have been deleted, or you're no longer a member.</p>
      </div></div>
    );
  }
  const p = q.data;
  const rotation = p.environments.filter((e) => e.rotationNeeded);
  const openCrs = p.environments.reduce((n, e) => n + e.openChangeRequests, 0);
  const tab = (to: string, icon: Parameters<typeof Icon>[0]['name'], label: string, end = false) => (
    <NavLink to={to} end={end} className={({ isActive }) => `tab ${isActive ? 'active' : ''}`}><Icon name={icon} /> {label}</NavLink>
  );

  return (
    <div className="page">
      <div className="page-head">
        <div className="row" style={{ gap: 14, alignItems: 'center' }}>
          <Identicon seed={p.id} size={40} />
          <div>
          <div className="row" style={{ gap: 10 }}><h1>{p.name}</h1><span className="badge">{p.role.charAt(0) + p.role.slice(1).toLowerCase()}</span></div>
          <p className="sub">{p.description || `${p.environments.length} environments · ${p.members.length} ${p.members.length === 1 ? 'member' : 'members'}`}</p>
          </div>
        </div>
      </div>
      {rotation.length > 0 && atLeast(p.role, 'ADMIN') && (
        <div className="notice warn row" role="status">
          <Icon name="alert" />
          <span className="grow">Someone lost access to {rotation.map((e) => e.name).join(', ')}. They may have copied the old key, so rotate it and change any secrets they could read.</span>
          <NavLink className="btn sm" to="environments">Review</NavLink>
        </div>
      )}
      {atLeast(p.role, 'ADMIN') && <Onboarding project={p} />}
      <nav className="tabs" aria-label="Project sections">
        {tab('secrets', 'key', 'Secrets')}
        <NavLink to="changes" className={({ isActive }) => `tab ${isActive ? 'active' : ''}`}><Icon name="history" /> Changes{openCrs > 0 && <span className="badge accent" style={{ height: 18 }}>{openCrs}</span>}</NavLink>
        {tab('health', 'shield', 'Health')}
        {tab('compare', 'layers', 'Compare')}
        {tab('members', 'users', 'Members')}
        {tab('environments', 'layers', 'Environments')}
        {atLeast(p.role, 'DEVELOPER') && tab('tokens', 'terminal', 'Access tokens')}
        {atLeast(p.role, 'DEVELOPER') && tab('activity', 'activity', 'Activity')}
        {atLeast(p.role, 'ADMIN') && tab('webhooks', 'send', 'Webhooks')}
        {atLeast(p.role, 'ADMIN') && tab('settings', 'settings', 'Settings')}
      </nav>
      <Outlet context={{ project: p, refetch: () => void q.refetch() } satisfies ProjectCtx} />
    </div>
  );
}

export function ProjectIndex() {
  return <Navigate to="secrets" replace />;
}

const DISMISS_KEY = (id: string) => `kv-onboarding-dismissed:${id}`;

/** Getting-started checklist for admins of a new project; derived from real project state, dismissible. */
function Onboarding({ project }: { project: ProjectDetail }) {
  const [dismissed, setDismissed] = useState(() => {
    try { return localStorage.getItem(DISMISS_KEY(project.id)) === '1'; } catch { return false; }
  });
  const steps = [
    { done: project.environments.some((e) => e.secretCount > 0), label: 'Add your first secret', hint: 'Or paste a .env file', to: 'secrets' },
    { done: project.members.length > 1, label: 'Invite a teammate', hint: 'Verify their identicon', to: 'members' },
    { done: project.environments.some((e) => e.tokenCount > 0), label: 'Connect CI', hint: 'Create an access token', to: 'tokens' },
    { done: project.environments.some((e) => e.protected), label: 'Protect production', hint: 'Require reviews', to: 'environments' },
  ];
  const done = steps.filter((s) => s.done).length;
  if (dismissed || done === steps.length) return null;
  return (
    <section className="panel onboarding" aria-label="Getting started">
      <div className="row spread">
        <div>
          <h3>Set up {project.name}</h3>
          <p className="small muted" style={{ marginTop: 2 }}>{done} of {steps.length} done</p>
        </div>
        <Button size="sm" variant="ghost" onClick={() => { setDismissed(true); try { localStorage.setItem(DISMISS_KEY(project.id), '1'); } catch { /* ignore */ } }}>Dismiss</Button>
      </div>
      <div className="progress"><span style={{ width: `${(done / steps.length) * 100}%` }} /></div>
      <div className="steps-row">
        {steps.map((s) => (
          <Link key={s.label} to={s.to} className={`step ${s.done ? 'done' : ''}`}>
            <span className="tick">{s.done && <Icon name="check" size={12} />}</span>
            <span><b style={{ fontWeight: 500 }}>{s.label}</b><br /><span className="xs faint">{s.hint}</span></span>
          </Link>
        ))}
      </div>
    </section>
  );
}
