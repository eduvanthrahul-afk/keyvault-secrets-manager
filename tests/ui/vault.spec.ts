import { expect, test, type Page } from '@playwright/test';

const PASSWORD = 'analytical engine notes 1843';

/** Collect console errors and CSP violations; every test asserts there are none. */
function watchConsole(page: Page) {
  const problems: string[] = [];
  page.on('pageerror', (e) => problems.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    const t = m.text();
    if (m.type() === 'error' && !/status of 401/.test(t)) problems.push(t);
    if (/Content Security Policy/i.test(t)) problems.push(t);
  });
  return problems;
}

async function register(page: Page) {
  const email = `ui-${Date.now()}-${Math.random().toString(36).slice(2, 7)}@example.com`;
  await page.goto('/register');
  await page.getByLabel('Name').fill('Ada Lovelace');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Master password', { exact: true }).fill(PASSWORD);
  await page.getByLabel('Confirm master password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Create account' }).click();
  await expect(page.getByText('Save your Emergency Kit')).toBeVisible({ timeout: 30_000 });
  await expect(page.locator('.recovery-key')).toContainText(/^KV1-/);
  await page.getByLabel("I've stored my recovery key").check();
  await page.getByRole('button', { name: 'Open my vault' }).click();
  await expect(page.getByRole('heading', { name: 'Projects' })).toBeVisible();
  return email;
}

async function createProject(page: Page, name = 'payments-api') {
  await page.getByRole('button', { name: 'New project' }).first().click();
  await page.getByLabel('Project name').fill(name);
  await page.getByRole('button', { name: 'Create project' }).click();
  await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
}

async function importEnv(page: Page, text: string, count: number) {
  await page.getByRole('button', { name: 'Import .env' }).first().click();
  await page.getByLabel('.env contents').fill(text);
  await page.getByRole('button', { name: `Import ${count} secrets` }).click();
}

async function unlock(page: Page) {
  await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible();
  await page.getByLabel('Master password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Unlock', exact: true }).click();
}

test('landing page renders without CSP violations', async ({ page }) => {
  const problems = watchConsole(page);
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText("can't read");
  await expect(page.getByText('kv run -- npm start').first()).toBeVisible();
  expect(problems).toEqual([]);
});

test('secrets lifecycle: import, references, edit, history, lock/unlock', async ({ page }) => {
  const problems = watchConsole(page);
  await register(page);
  await createProject(page);
  await importEnv(page, 'DB_HOST=db.internal\nDB_PORT=5432\nDATABASE_URL=postgres://app@${DB_HOST}:${DB_PORT}/billing\nSTRIPE_SECRET_KEY=sk_test_51HxYz\n', 4);
  await expect(page.getByText('STRIPE_SECRET_KEY')).toBeVisible();

  // references resolve client-side
  await page.getByRole('button', { name: 'Reveal DATABASE_URL' }).click();
  await expect(page.getByText('postgres://app@db.internal:5432/billing')).toBeVisible();

  // edit creates a version
  await page.getByRole('button', { name: 'Edit STRIPE_SECRET_KEY' }).click();
  await page.locator('#secret-value').fill('sk_test_rotated_9999');
  await page.getByRole('button', { name: 'Save changes' }).click();
  await page.getByRole('button', { name: 'History of STRIPE_SECRET_KEY' }).click();
  await expect(page.getByText('sk_test_51HxYz')).toBeVisible();
  await page.keyboard.press('Escape');

  // reload wipes keys from memory → lock screen
  await page.reload();
  await unlock(page);
  await expect(page.getByText('STRIPE_SECRET_KEY')).toBeVisible();
  expect(problems).toEqual([]);
});

test('health check and environment compare catch real mistakes', async ({ page }) => {
  await register(page);
  await createProject(page, 'billing');
  await importEnv(page, 'STRIPE_SECRET_KEY=sk_live_51HxYzABCDEFGH\nDB_PASSWORD=same-password-everywhere\n', 2);
  await page.getByRole('tab', { name: /Production/ }).click();
  await importEnv(page, 'DB_PASSWORD=same-password-everywhere\nREDIS_URL=redis://localhost:6379\n', 2);
  await expect(page.getByText('REDIS_URL')).toBeVisible();

  await page.getByRole('link', { name: 'Health' }).click();
  await expect(page.getByText('Stripe live secret key found in Development.')).toBeVisible();
  await expect(page.getByText('Same value as in Production.')).toBeVisible();
  await expect(page.getByText('Points at localhost in production.')).toBeVisible();

  await page.getByRole('link', { name: 'Compare' }).click();
  await expect(page.getByText(/missing somewhere/)).toBeVisible();
  await expect(page.locator('tr', { hasText: 'REDIS_URL' }).getByText('Missing', { exact: true })).toBeVisible();
});

test('passkey unlock with a virtual authenticator (WebAuthn PRF)', async ({ page, context, browserName }) => {
  test.skip(browserName !== 'chromium', 'Virtual authenticators need the Chrome DevTools protocol');
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true },
  });

  await register(page);
  await page.getByRole('link', { name: /Account/ }).click();
  await page.getByRole('button', { name: 'Add passkey' }).click();
  await page.getByRole('dialog').getByLabel('Master password', { exact: true }).fill(PASSWORD);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByText('Passkey added')).toBeVisible();

  await page.reload();
  await expect(page.getByRole('heading', { name: 'Vault locked' })).toBeVisible();
  await page.getByRole('button', { name: 'Unlock with passkey' }).click();
  await expect(page.getByRole('heading', { name: 'Account & security' })).toBeVisible();
  await expect(page.getByText(/last used just now/)).toBeVisible();
});

test('phone layout has no horizontal scroll', async ({ page }) => {
  await register(page);
  await createProject(page, 'mobile');
  await importEnv(page, 'A_VERY_LONG_SECRET_NAME_FOR_LAYOUT_TESTING=value-with-no-spaces-at-all-0123456789abcdef\n', 1);
  await page.setViewportSize({ width: 375, height: 812 });
  for (const path of ['', '/health', '/compare', '/members', '/environments']) {
    await page.getByRole('button', { name: 'Open navigation' }).isVisible();
    const url = page.url().replace(/\/app\/p\/([^/]+).*/, `/app/p/$1/secrets`).replace('/secrets', path || '/secrets');
    await page.evaluate((u) => history.pushState(null, '', u), url);
    await page.evaluate(() => dispatchEvent(new PopStateEvent('popstate')));
    await page.waitForTimeout(400);
    const { overflow, offenders } = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth - innerWidth,
      offenders: [...document.querySelectorAll('body *')].filter((e) => {
        if (e.getBoundingClientRect().right <= innerWidth + 1) return false;
        for (let a = e.parentElement; a && a !== document.body; a = a.parentElement) {
          if (getComputedStyle(a).overflowX !== 'visible') return false; // inside a scroller/clipper: fine
        }
        return true;
      }).concat([...document.querySelectorAll('#root > *, #root > * > *, #root > * > * > *')].filter((e) => e.scrollWidth > innerWidth + 1 || e.getBoundingClientRect().right > innerWidth + 1))
        .slice(0, 6).map((e) => `${e.tagName.toLowerCase()}.${String((e as HTMLElement).className)}[sw=${e.scrollWidth},r=${Math.round(e.getBoundingClientRect().right)}]`),
    }));
    expect(overflow, `overflow on ${path || '/secrets'}: ${offenders.join(', ')}`).toBeLessThanOrEqual(0);
  }
});
