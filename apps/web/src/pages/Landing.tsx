import { Link } from 'react-router-dom';
import { Logo } from '../components/Logo';
import { Icon } from '../components/ui';
import { useVault } from '../lib/vault';

const REPO = 'https://github.com/eduvanthrahul-afk/keyvault-secrets-manager';

const FEATURES: { icon: Parameters<typeof Icon>[0]['name']; title: string; body: string }[] = [
  { icon: 'lock', title: 'End-to-end encrypted', body: 'Names, values and notes are encrypted in the browser or CLI with XChaCha20-Poly1305 before they reach the API.' },
  { icon: 'layers', title: 'Per-environment keys', body: 'Development, staging and production each have their own key, sealed individually to every member who should read them.' },
  { icon: 'rotate', title: 'Zero-knowledge rotation', body: 'Offboard someone and re-encrypt every secret and its full history client-side, in one atomic swap.' },
  { icon: 'terminal', title: 'CI/CD access tokens', body: 'Read-only, environment-scoped, expiring tokens. kv run injects secrets into a process without writing a .env file.' },
  { icon: 'heart', title: 'Secret health checks', body: 'Catch live keys in development, test keys in production and credentials shared across environments.' },
  { icon: 'diff', title: 'Environment compare', body: 'See which variables are missing in production before the deploy fails, not after.' },
  { icon: 'fingerprint', title: 'Passkey unlock', body: 'Unlock with Touch ID or Windows Hello. WebAuthn PRF derives the key inside your device.' },
  { icon: 'history', title: 'Versions and rollback', body: 'Every change is versioned. Restore any previous value; concurrent edits are rejected instead of lost.' },
  { icon: 'activity', title: 'Tamper-evident audit log', body: 'Every read and change is hash-chained. Verify the whole history in one click.' },
];

const PRIMITIVES = [
  ['Password stretching', 'Argon2id', '64 MiB, t=3, in a Web Worker; client refuses weak server-supplied parameters'],
  ['Key derivation', 'HKDF-SHA256', 'separate branches for login and encryption'],
  ['Encryption', 'XChaCha20-Poly1305', 'random 192-bit nonces, AAD binds every value to its project, environment and field'],
  ['Sharing', 'X25519 sealed boxes', 'environment keys sealed to each member; identicons and fingerprints for verification'],
  ['Unlock', 'WebAuthn PRF', 'passkey-derived key wraps the account key'],
  ['Sessions', 'Opaque, server-side', '__Host- cookie, SameSite=Strict, 30 min idle, revocable'],
];

export function Landing() {
  const { status } = useVault();
  const signedIn = status === 'locked' || status === 'unlocked';
  return (
    <div className="landing">
      <header className="site-nav">
        <div className="inner">
          <Link to="/" className="brand" style={{ padding: 0 }}><Logo /> KeyVault</Link>
          <nav className="links" aria-label="Sections">
            <a href="#features">Features</a>
            <a href="#security">Security</a>
            <a href="#cli">CLI</a>
            <a href={REPO} rel="noreferrer">GitHub</a>
          </nav>
          <div className="right">
            {signedIn ? <Link className="btn primary" to="/app">Open dashboard</Link> : (
              <>
                <Link className="btn ghost" to="/login">Sign in</Link>
                <Link className="btn primary" to="/register">Get started</Link>
              </>
            )}
          </div>
        </div>
      </header>

      <main>
        <section className="container hero">
          <span className="pill"><span className="dot" style={{ color: 'var(--success)' }} /> Open source · Self-hostable · Zero-knowledge</span>
          <h1>Secrets management your server can't read.</h1>
          <p className="lede">
            KeyVault stores your team's API keys and environment variables encrypted on the client. Share them per environment,
            inject them into CI, and audit every read, without trusting the database.
          </p>
          <div className="cta">
            <Link className="btn primary lg" to={signedIn ? '/app' : '/register'}>{signedIn ? 'Open dashboard' : 'Create a free vault'}</Link>
            <a className="btn lg" href={REPO} rel="noreferrer"><Icon name="github" /> View source</a>
          </div>

          <div className="mock" aria-hidden="true">
            <div className="mock-window">
              <div className="mock-bar"><i /><i /><i /><span className="url">keyvault.dev/app/p/payments-api/secrets</span></div>
              <div className="mock-body">
                <div className="mock-side">
                  <div className="item"><Icon name="layers" size={14} /> All projects</div>
                  <div className="item on"><Icon name="key" size={14} /> payments-api</div>
                  <div className="item"><Icon name="key" size={14} /> web-dashboard</div>
                  <div className="item"><Icon name="key" size={14} /> ingest-worker</div>
                </div>
                <div className="mock-main">
                  <div className="row spread" style={{ marginBottom: 14 }}>
                    <span className="title">payments-api</span>
                    <span className="btn sm primary">Add secret</span>
                  </div>
                  <div className="env-switch" style={{ marginBottom: 14 }}>
                    <a data-env="development">Development</a><a data-env="staging">Staging</a><a data-env="production" className="active">Production</a>
                  </div>
                  <div className="panel">
                    <table className="table">
                      <thead><tr><th>Name</th><th>Value</th><th>Updated</th></tr></thead>
                      <tbody>
                        <tr><td className="secret-name">DATABASE_URL</td><td><span className="secret-value revealed" style={{ display: 'inline-block' }}>postgres://app@db.internal:5432/billing</span></td><td className="faint">2h ago</td></tr>
                        <tr><td className="secret-name">STRIPE_SECRET_KEY</td><td className="mask">••••••••••••</td><td className="faint">3d ago</td></tr>
                        <tr><td className="secret-name">SENTRY_DSN</td><td className="mask">••••••••••••</td><td className="faint">1w ago</td></tr>
                        <tr><td className="secret-name">REDIS_URL</td><td className="mask">••••••••••••</td><td className="faint">1w ago</td></tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
            <div className="terminal">
              <div><span className="p">$</span> kv run -- npm start</div>
              <div className="dim">✓ fetched 4 secrets for payments-api / production</div>
              <div className="dim">✓ decrypted locally, nothing written to disk</div>
              <div><span className="ok">▲</span> server listening on :3000</div>
            </div>
          </div>
        </section>

        <section className="container section-block" id="features">
          <div className="eyebrow-free">
            <h2>Everything a team needs to stop pasting secrets into Slack.</h2>
            <p>Built for the way developers actually work: environments, CI pipelines, people joining and leaving.</p>
          </div>
          <div className="features">
            {FEATURES.map((f) => (
              <div className="feature" key={f.title}>
                <span className="ico"><Icon name={f.icon} /></span>
                <h3>{f.title}</h3>
                <p>{f.body}</p>
              </div>
            ))}
          </div>
        </section>

        <section className="container section-block" id="security">
          <div className="eyebrow-free">
            <h2>What you see, and what the server stores.</h2>
            <p>A full database dump yields ciphertext, wrapped keys and one-way verifiers. Nothing in it decrypts a secret.</p>
          </div>
          <div className="split">
            <div className="panel">
              <div className="panel-head"><h3>In your browser</h3><span className="badge ok">decrypted</span></div>
              <pre><span className="k">STRIPE_SECRET_KEY</span>=sk_live_51HxYz9Qm…{'\n'}<span className="k">DATABASE_URL</span>=postgres://app@db.internal/billing{'\n'}<span className="c"># changed by ada@acme.dev, 2h ago (v4)</span></pre>
            </div>
            <div className="panel">
              <div className="panel-head"><h3>In PostgreSQL</h3><span className="badge">ciphertext</span></div>
              <pre><span className="k">name_ciphertext</span>  kv1.mT9xQ2v8lJ0cRk…{'\n'}<span className="k">value_ciphertext</span> kv1.Hc4pRZt1yQwe0b…{'\n'}<span className="k">name_index</span>       7Kq1vN0ZP8e3sA…{'\n'}<span className="k">wrapped_key</span>      kv1s.Yd02MvqAp1…</pre>
            </div>
          </div>
          <div className="panel table-wrap" style={{ marginTop: 16 }}>
            <table className="table">
              <thead><tr><th>Layer</th><th>Primitive</th><th>Details</th></tr></thead>
              <tbody>{PRIMITIVES.map(([a, b, c]) => <tr key={a}><td>{a}</td><td><code>{b}</code></td><td className="muted">{c}</td></tr>)}</tbody>
            </table>
          </div>
        </section>

        <section className="container section-block" id="cli">
          <div className="eyebrow-free">
            <h2>From dashboard to deploy in three steps.</h2>
            <p>The CLI uses the same crypto package as the web app. The server only ever sees ciphertext.</p>
          </div>
          <ol className="steps">
            <li><span className="n">01</span><h3>Create an access token</h3><p>Scoped to one environment, read-only, with an expiry. The token carries its own decryption key.</p></li>
            <li><span className="n">02</span><h3>Store it as a CI secret</h3><p>Set <code>KEYVAULT_TOKEN</code> in GitHub Actions, GitLab or your container runtime.</p></li>
            <li><span className="n">03</span><h3>Run your app</h3><p><code>kv run -- npm start</code> decrypts in memory and injects the variables into the process.</p></li>
          </ol>
          <div className="terminal" style={{ marginTop: 24 }}>
            <div className="p"># .github/workflows/deploy.yml</div>
            <div>- run: npx kv run -- npm run migrate</div>
            <div>  env:</div>
            <div>    KEYVAULT_TOKEN: ${'{{'} secrets.KEYVAULT_TOKEN {'}}'}</div>
            <div>    KEYVAULT_URL: https://keyvault.example.com</div>
          </div>

          <div className="cta-band">
            <div>
              <h2>Stop trusting your database with plaintext.</h2>
              <p>Free and open source. Self-host it or use it here.</p>
            </div>
            <div className="row">
              <Link className="btn primary lg" to={signedIn ? '/app' : '/register'}>{signedIn ? 'Open dashboard' : 'Get started'}</Link>
              <a className="btn lg" href={REPO} rel="noreferrer">Read the security model</a>
            </div>
          </div>
        </section>
      </main>

      <footer className="footer">
        <div className="inner">
          <span>KeyVault · MIT licensed</span>
          <span className="row" style={{ gap: 16 }}>
            <Link to="/login">Sign in</Link>
            <Link to="/recover">Recover an account</Link>
            <a href={REPO} rel="noreferrer">GitHub</a>
          </span>
        </div>
      </footer>
    </div>
  );
}
