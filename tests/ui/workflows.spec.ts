import { createServer } from 'node:http';
import { expect, test, type Browser, type Page } from '@playwright/test';

const PASSWORD = 'analytical engine notes 1843';

async function newUser(browser: Browser, name: string) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const email = `${name.toLowerCase()}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}@example.com`;
  await page.goto('/register');
  await page.getByLabel('Name').fill(name);
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Master password', { exact: true }).fill(PASSWORD);
  await page.getByLabel('Confirm master password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel("I've stored my recovery key").check({ timeout: 30_000 });
  await page.getByRole('button', { name: 'Open my vault' }).click();
  await expect(page.getByRole('heading', { name: 'Projects' })).toBeVisible();
  return { page, email };
}

async function createProject(page: Page, name: string) {
  await page.getByRole('button', { name: 'New project' }).first().click();
  await page.getByLabel('Project name').fill(name);
  await page.getByRole('button', { name: 'Create project' }).click();
  await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
}

test('developer proposes a production change, a different admin reviews and applies it', async ({ browser }) => {
  const owner = await newUser(browser, 'Owner');
  const dev = await newUser(browser, 'Dev');
  await createProject(owner.page, 'checkout');

  // owner adds the developer with access to Production (protected by default)
  await owner.page.getByRole('link', { name: 'Members' }).click();
  await owner.page.getByRole('button', { name: 'Add member' }).click();
  await owner.page.getByLabel('Email').fill(dev.email);
  await owner.page.getByRole('button', { name: 'Find account' }).click();
  await owner.page.getByLabel(/I've confirmed this fingerprint/).check();
  await owner.page.getByRole('dialog').getByRole('button', { name: /Production/ }).click();
  await owner.page.getByRole('button', { name: /^Add Dev/ }).click();
  await expect(owner.page.locator('.member', { hasText: dev.email })).toBeVisible();

  // developer edits production → becomes a change request
  await dev.page.reload();
  await dev.page.getByLabel('Master password').fill(PASSWORD);
  await dev.page.getByRole('button', { name: 'Unlock', exact: true }).click();
  await dev.page.getByRole('link', { name: 'checkout' }).first().click();
  await dev.page.getByRole('tab', { name: /Production/ }).click();
  await expect(dev.page.getByText(/Production is protected/)).toBeVisible();
  await dev.page.getByRole('button', { name: 'Add secret' }).first().click();
  await dev.page.getByLabel('Name').fill('STRIPE_SECRET_KEY');
  await dev.page.locator('#secret-value').fill('sk_live_from_review');
  await dev.page.getByRole('button', { name: 'Propose change' }).click();
  await expect(dev.page.getByText(/An admin will review it/)).toBeVisible();

  // owner reviews: sees the decrypted proposed value, approves
  await owner.page.getByRole('link', { name: /Changes/ }).click();
  await owner.page.getByRole('button', { name: 'Review' }).click();
  await expect(owner.page.getByRole('dialog').getByText('sk_live_from_review')).toBeVisible();
  await owner.page.getByRole('button', { name: 'Approve and apply' }).click();
  await expect(owner.page.getByText('Approved and applied')).toBeVisible();

  // the developer now sees it as a real secret
  await dev.page.reload();
  await dev.page.getByLabel('Master password').fill(PASSWORD);
  await dev.page.getByRole('button', { name: 'Unlock', exact: true }).click();
  await dev.page.getByRole('tab', { name: /Production/ }).click();
  await expect(dev.page.getByText('STRIPE_SECRET_KEY')).toBeVisible();
});

test('webhook test delivery reaches a local endpoint with a signature', async ({ browser }) => {
  const received: { sig?: string; event?: string }[] = [];
  const server = createServer((req, res) => {
    received.push({ sig: req.headers['x-keyvault-signature'] as string, event: req.headers['x-keyvault-event'] as string });
    req.resume();
    res.writeHead(204).end();
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  try {
    const { page } = await newUser(browser, 'Ops');
    await createProject(page, 'deploys');
    await page.getByRole('link', { name: 'Webhooks' }).click();
    await page.getByRole('button', { name: 'Add webhook' }).click();
    await page.getByLabel('Endpoint URL').fill(`http://127.0.0.1:${port}/hook`);
    await page.getByRole('dialog').getByRole('button', { name: 'Add webhook' }).click();
    await expect(page.locator('.reveal-box')).toContainText('whsec_');
    await page.getByRole('button', { name: "I've stored it" }).click();
    await page.getByRole('button', { name: 'Send test' }).click();
    await expect(page.getByText(/Ping delivered/)).toBeVisible();
    expect(received[0]?.event).toBe('ping');
    expect(received[0]?.sig).toMatch(/^t=\d+,v1=[0-9a-f]{64}$/);
  } finally {
    server.close();
  }
});
