import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  use: {
    baseURL: "http://127.0.0.1:3000",
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: "pnpm start",
    url: "http://127.0.0.1:3000",
    reuseExistingServer: false,
    env: {
      TAWNY_E2E_AUTH_BYPASS: "1",
      TAWNY_API_URL: "http://127.0.0.1:5099",
      TAWNY_WEB_HMAC_SECRET: "test-hmac-secret",
      BETTER_AUTH_SECRET: "test-better-auth-secret",
      BETTER_AUTH_URL: "http://127.0.0.1:3000",
      DATABASE_URL: "sqlserver://sa:DevPassw0rd!@127.0.0.1:1433/Tawny",
    },
  },
});
