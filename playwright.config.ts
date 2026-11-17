import { defineConfig, devices } from '@playwright/test';

// Browser tests against a running server (npm run dev:server). In CI the workflow starts it.
// Locally you can reuse an installed browser: PW_CHANNEL=msedge or PW_CHANNEL=chrome.
export default defineConfig({
  testDir: 'tests/ui',
  timeout: 90_000,
  expect: { timeout: 15_000 },
  fullyParallel: false,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: process.env.KEYVAULT_URL ?? 'http://localhost:8080',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], channel: process.env.PW_CHANNEL, viewport: { width: 1360, height: 860 } } },
  ],
});
