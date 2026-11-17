import { createSend, openSend } from '@keyvault/crypto';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Logo } from '../components/Logo';
import { Button, CopyButton, Icon, Spinner, errorMessage, timeAgo, useToast } from '../components/ui';
import { api } from '../lib/api';

const EXPIRY = [
  { label: '1 hour', minutes: 60 },
  { label: '1 day', minutes: 1440 },
  { label: '7 days', minutes: 10080 },
];

export function SendCreate() {
  const toast = useToast();
  const qc = useQueryClient();
  const [text, setText] = useState('');
  const [views, setViews] = useState(1);
  const [minutes, setMinutes] = useState(1440);
  const [link, setLink] = useState<string | null>(null);
  const list = useQuery({ queryKey: ['sends'], queryFn: api.sends.list });

  const create = useMutation({
    mutationFn: async () => {
      const s = createSend(text);
      const res = await api.sends.create(s.ciphertext, views, minutes);
      return `${window.location.origin}/s/${res.id}#${s.key}`;
    },
    onSuccess: (l) => { setLink(l); setText(''); qc.invalidateQueries({ queryKey: ['sends'] }); },
    onError: (e) => toast(errorMessage(e), 'error'),
  });
  const remove = useMutation({
    mutationFn: api.sends.remove,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['sends'] }),
  });

  return (
    <div className="page">
      <div className="page-head"><div><h1>One-time share</h1><p className="sub">Send a password or key to someone without a KeyVault account. The link carries the decryption key after the #, which browsers never send to a server.</p></div></div>
      <div className="panel">
        <div className="panel-body stack" style={{ '--gap': '14px' } as React.CSSProperties}>
          {link ? (
            <>
              <div className="notice ok">Link created. Send it over a different channel than you'd usually use for the context around it.</div>
              <div className="reveal-box">{link}</div>
              <div className="row"><CopyButton value={link} label="Copy link" /><Button variant="ghost" onClick={() => setLink(null)}>Share something else</Button></div>
            </>
          ) : (
            <>
              <div className="field">
                <label htmlFor="send-text">What do you want to share?</label>
                <textarea id="send-text" className="textarea code" value={text} onChange={(e) => setText(e.target.value)} placeholder="The staging database password is…" spellCheck={false} />
              </div>
              <div className="row wrap" style={{ '--gap': '20px' } as React.CSSProperties}>
                <div className="field"><label htmlFor="send-views">Can be opened</label>
                  <select id="send-views" className="select" value={views} onChange={(e) => setViews(Number(e.target.value))}>
                    {[1, 2, 3, 5, 10].map((n) => <option key={n} value={n}>{n === 1 ? 'Once' : `${n} times`}</option>)}
                  </select></div>
                <div className="field"><label htmlFor="send-exp">Expires after</label>
                  <select id="send-exp" className="select" value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
                    {EXPIRY.map((x) => <option key={x.minutes} value={x.minutes}>{x.label}</option>)}
                  </select></div>
              </div>
              <div><Button variant="primary" busy={create.isPending} disabled={!text} onClick={() => create.mutate()}><Icon name="send" /> Create link</Button></div>
            </>
          )}
        </div>
      </div>
      {list.data && list.data.length > 0 && (
        <div className="panel table-wrap">
          <table className="table">
            <thead><tr><th>Link</th><th>Opened</th><th>Expires</th><th><span className="sr-only">Actions</span></th></tr></thead>
            <tbody>{list.data.map((s) => {
              const gone = s.viewCount >= s.maxViews || new Date(s.expiresAt) < new Date();
              return (
                <tr key={s.id}>
                  <td className="code xs">/s/{s.id.slice(0, 10)}…</td>
                  <td>{s.viewCount} of {s.maxViews} {gone && <span className="badge">burned</span>}</td>
                  <td className="small muted">{timeAgo(s.expiresAt)}</td>
                  <td className="actions"><Button size="sm" variant="ghost" onClick={() => remove.mutate(s.id)}>Delete</Button></td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function SendOpen() {
  const { id } = useParams();
  const [state, setState] = useState<'ready' | 'busy' | 'open' | 'error'>('ready');
  const [text, setText] = useState('');
  const [info, setInfo] = useState('');
  const key = window.location.hash.slice(1);

  async function reveal() {
    setState('busy');
    try {
      const r = await api.sends.open(id!);
      setText(openSend(r.ciphertext, key));
      setInfo(r.remainingViews === 0 ? 'This link has now been destroyed.' : `This link can be opened ${r.remainingViews} more time${r.remainingViews === 1 ? '' : 's'}.`);
      history.replaceState(null, '', window.location.pathname); // drop the key from the address bar
      setState('open');
    } catch (e) {
      setInfo(errorMessage(e));
      setState('error');
    }
  }

  return (
    <div className="lockscreen">
      <div className="auth-card boxed">
        <div className="seal-wrap"><Logo size={40} /></div>
        <div style={{ textAlign: 'center' }}>
          <h1>{state === 'open' ? 'Here it is' : state === 'error' ? 'Link unavailable' : 'Someone shared a secret with you'}</h1>
          <p className="sub">{state === 'ready' ? 'It\'s decrypted in your browser. Opening it may destroy the link, so copy it somewhere safe.' : info}</p>
        </div>
        {!key && state === 'ready' && <div className="notice danger">This link is missing its key (the part after #). Ask the sender for the full link.</div>}
        {state === 'ready' && <Button variant="brass" size="lg" disabled={!key} onClick={reveal} block>Reveal secret</Button>}
        {state === 'busy' && <Spinner label="Decrypting" />}
        {state === 'open' && <><div className="reveal-box" style={{ whiteSpace: 'pre-wrap' }}>{text}</div><CopyButton value={text} label="Copy" secret /></>}
        <p className="small muted" style={{ textAlign: 'center' }}>Shared with <Link to="/">KeyVault</Link>, a zero-knowledge secrets manager.</p>
      </div>
    </div>
  );
}
