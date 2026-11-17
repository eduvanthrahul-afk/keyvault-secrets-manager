import { expect, test, type Page } from '@playwright/test';

const PASSWORD = 'analytical engine notes 1843';

async function setup(page: Page) {
  await page.goto('/register');
  await page.getByLabel('Name').fill('Grace Hopper');
  await page.getByLabel('Email').fill(`ux-${Date.now()}-${Math.random().toString(36).slice(2, 6)}@example.com`);
  await page.getByLabel('Master password', { exact: true }).fill(PASSWORD);
  await page.getByLabel('Confirm master password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByLabel("I've stored my recovery key").check({ timeout: 30_000 });
  await page.getByRole('button', { name: 'Open my vault' }).click();
  await page.getByRole('button', { name: 'New project' }).first().click();
  await page.getByLabel('Project name').fill('ux-lab');
  await page.getByRole('button', { name: 'Create project' }).click();
  await expect(page.getByRole('heading', { name: 'ux-lab', exact: true })).toBeVisible();
}

test('paste a .env anywhere, edit inline, undo a delete, bulk copy to another environment', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await setup(page);

  // paste-to-import: dispatch a paste event on the page with dotenv text
  await page.evaluate(() => {
    const data = new DataTransfer();
    data.setData('text/plain', 'API_URL=https://api.example.com\nAPI_TOKEN=tok_123\nFEATURE_FLAG=on\n');
    window.dispatchEvent(new ClipboardEvent('paste', { clipboardData: data }));
  });
  await expect(page.getByRole('dialog').getByText('3 new')).toBeVisible();
  await page.getByRole('button', { name: 'Import 3 secrets' }).click();
  await expect(page.getByText('API_TOKEN')).toBeVisible();

  // inline edit: click the masked value, type, Enter
  await page.locator('tr', { hasText: 'FEATURE_FLAG' }).locator('.value-cell').click();
  const box = page.getByLabel('New value for FEATURE_FLAG');
  await box.fill('off');
  await box.press('Enter');
  await expect(page.getByText('Saved FEATURE_FLAG')).toBeVisible();
  await page.getByRole('button', { name: 'Reveal FEATURE_FLAG' }).click();
  await expect(page.locator('tr', { hasText: 'FEATURE_FLAG' }).getByText('off', { exact: true })).toBeVisible();

  // delete with undo: row disappears, Undo brings it back, nothing is deleted server-side
  await page.getByRole('button', { name: 'Delete API_URL' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.locator('tr', { hasText: 'API_URL' })).toHaveCount(0);
  await page.getByRole('button', { name: 'Undo' }).click();
  await expect(page.locator('tr', { hasText: 'API_URL' })).toHaveCount(1);
  await page.waitForTimeout(6500);
  await page.reload();
  await page.getByLabel('Master password').fill(PASSWORD);
  await page.getByRole('button', { name: 'Unlock', exact: true }).click();
  await expect(page.getByText('API_URL')).toBeVisible();

  // bulk: select two rows with shift-click range, copy them to Staging
  await page.getByLabel('Select API_TOKEN').click();
  await page.getByLabel('Select FEATURE_FLAG').click({ modifiers: ['Shift'] });
  await expect(page.getByText('3 selected')).toBeVisible(); // API_TOKEN, API_URL, FEATURE_FLAG (sorted by name)
  await page.getByLabel('Copy selected to environment').selectOption({ label: 'Staging' });
  await expect(page.getByText('Copied 3 to Staging')).toBeVisible();
  await page.getByRole('tab', { name: /Staging/ }).click();
  await expect(page.getByText('FEATURE_FLAG')).toBeVisible();
});

test('keyboard shortcuts: / filters, n opens the editor with a generator, ? shows help', async ({ page }) => {
  await setup(page);
  await page.keyboard.press('n');
  await expect(page.getByRole('dialog', { name: /Add secret/ })).toBeVisible();
  await page.getByLabel('Name').fill('SESSION_SECRET');
  await page.getByRole('button', { name: 'Generate' }).click();
  await expect(page.locator('#secret-value')).toHaveValue(/^[A-Za-z0-9]{40}$/);
  await page.locator('#secret-value').press('Control+Enter');
  await expect(page.getByText('Added SESSION_SECRET')).toBeVisible();

  await page.keyboard.press('/');
  await expect(page.getByPlaceholder('Filter by name or note')).toBeFocused();
  await page.keyboard.type('nothing-matches');
  await expect(page.getByText('No secrets match')).toBeVisible();
  await page.keyboard.press('Escape');

  await page.keyboard.press('?');
  await expect(page.getByRole('dialog', { name: 'Keyboard shortcuts' })).toBeVisible();
});
