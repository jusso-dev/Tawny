import { chromium } from "@playwright/test";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const webDir = resolve(scriptDir, "..");
const repoRoot = resolve(webDir, "..");
const dockerEnv = await readDockerEnv();

const baseUrl = (
  process.env.TAWNY_SCREENSHOT_BASE_URL ??
  process.env.PLAYWRIGHT_BASE_URL ??
  `http://localhost:${dockerEnv.TAWNY_WEB_PORT ?? process.env.TAWNY_WEB_PORT ?? "3000"}`
).replace(/\/+$/, "");
const email = process.env.TAWNY_SCREENSHOT_EMAIL ?? "admin@example.com";
const password = process.env.TAWNY_SCREENSHOT_PASSWORD ?? "ChangeMe123!";
const outDir = resolve(
  repoRoot,
  process.env.TAWNY_SCREENSHOT_OUT_DIR ?? "docs/screenshots",
);
const width = Number.parseInt(process.env.TAWNY_SCREENSHOT_WIDTH ?? "1440", 10);
const height = Number.parseInt(process.env.TAWNY_SCREENSHOT_HEIGHT ?? "1000", 10);
const theme = process.env.TAWNY_SCREENSHOT_THEME ?? "dark";

await mkdir(outDir, { recursive: true });

const browser = await chromium.launch();
const context = await browser.newContext({
  viewport: { width, height },
  deviceScaleFactor: 1,
  colorScheme: theme === "light" ? "light" : "dark",
});
const page = await context.newPage();

try {
  await page.addInitScript((nextTheme) => {
    localStorage.setItem("tawny-theme", nextTheme);
  }, theme);
  await page.addStyleTag({ content: "nextjs-portal { display: none !important; }" });

  await login(page);
  await captureDashboard(page);
  await captureDetections(page);
  await captureDetectionFormats(page);
  await captureIntegrations(page);
  await captureAlerts(page);
  const agentHref = await captureAgents(page);
  if (agentHref) {
    await captureAgentDetail(page, agentHref);
  } else {
    console.warn("No agent row found. Start the synthetic agent to capture detail screenshots.");
  }
  await captureEnrollment(page);
  console.log(`README screenshots written to ${outDir}`);
} finally {
  await browser.close();
}

async function login(page) {
  await page.goto(`${baseUrl}/login`, { waitUntil: "networkidle" });
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL(/\/agents$/, { timeout: 15000 });
  await page.waitForLoadState("networkidle");
}

async function captureDashboard(page) {
  await page.goto(`${baseUrl}/`, { waitUntil: "networkidle" });
  await waitForChrome(page);
  await screenshot(page, "dashboard.png");

  await page.keyboard.press(process.platform === "darwin" ? "Meta+K" : "Control+K");
  await page.locator("[cmdk-root]").first().waitFor({ state: "visible" });
  await screenshot(page, "command-palette.png");
  await page.keyboard.press("Escape");
}

async function captureAgents(page) {
  await page.goto(`${baseUrl}/agents`, { waitUntil: "networkidle" });
  await waitForChrome(page);
  await screenshot(page, "agents.png");
  return await page.locator('tbody a[href^="/agents/"]').first().getAttribute("href").catch(() => null);
}

async function captureDetections(page) {
  await page.goto(`${baseUrl}/detections`, { waitUntil: "networkidle" });
  await waitForChrome(page);
  await page.getByText("Imported rules").waitFor({ state: "visible", timeout: 10000 });
  await screenshot(page, "detections.png");
}

async function captureDetectionFormats(page) {
  await page.goto(`${baseUrl}/detections`, { waitUntil: "networkidle" });
  await waitForChrome(page);
  await page.getByText("Accepted Sigma subset").waitFor({ state: "visible", timeout: 10000 });
  await screenshot(page, "detections-rule-formats.png");
  await page.getByRole("button", { name: "Raw IoCs" }).click();
  await page.getByText("sha256 1 | sha1 0 | ip 1 | domain 1").waitFor({ state: "visible", timeout: 10000 });
  await screenshot(page, "detections-ioc-raw-format.png");
}

async function captureIntegrations(page) {
  await page.goto(`${baseUrl}/integrations`, { waitUntil: "networkidle" });
  await waitForChrome(page);
  await page.getByText("Microsoft Sentinel").waitFor({ state: "visible", timeout: 10000 });
  await screenshot(page, "integrations-sentinel.png");
}

async function captureAlerts(page) {
  await page.goto(`${baseUrl}/alerts`, { waitUntil: "networkidle" });
  await waitForChrome(page);
  await page.getByText("Detection matches").waitFor({ state: "visible", timeout: 10000 });
  await screenshot(page, "alerts.png");
}

async function captureAgentDetail(page, href) {
  await page.goto(`${baseUrl}${href}`, { waitUntil: "networkidle" });
  await waitForChrome(page);
  await waitForEventType(page, "process snapshot");
  await screenshot(page, "agent-detail-processes.png");

  const tabs = [
    ["Network", "agent-detail-network.png", "network snapshot"],
    ["FIM", "agent-detail-fim.png", "file integrity"],
    ["Sessions", "agent-detail-sessions.png", "user session"],
    ["Raw events", "agent-detail-raw-events.png", "system info"],
  ];

  for (const [tab, fileName, expectedType] of tabs) {
    await selectEventTab(page, tab);
    await waitForEventType(page, expectedType).catch(() => {
      console.warn(`No ${expectedType} event visible while capturing ${fileName}; capturing current tab state.`);
    });
    await screenshot(page, fileName);
  }
}

async function captureEnrollment(page) {
  await page.goto(`${baseUrl}/enrollment`, { waitUntil: "networkidle" });
  await waitForChrome(page);
  await screenshot(page, "enrollment.png");
}

async function screenshot(page, name) {
  await page.screenshot({
    path: resolve(outDir, name),
    fullPage: false,
    animations: "disabled",
  });
  console.log(`captured ${name}`);
}

async function waitForChrome(page) {
  await page.locator("header").first().waitFor({ state: "visible" });
  await page.locator("img").first().waitFor({ state: "visible" }).catch(() => {});
  await page
    .waitForFunction(() => Array.from(document.images).every((image) => image.complete), null, {
      timeout: 5000,
    })
    .catch(() => {});
}

async function selectEventTab(page, tab) {
  const button = page.getByRole("button", { name: tab, exact: true });
  await button.click();
  await page.waitForFunction(
    (label) => {
      const buttons = Array.from(document.querySelectorAll("button"));
      return buttons.some(
        (candidate) => candidate.textContent?.trim() === label && candidate.getAttribute("data-active") === "true",
      );
    },
    tab,
    { timeout: 10000 },
  );
}

async function waitForEventType(page, expectedType) {
  await page.locator("tbody tr").first().waitFor({ state: "visible", timeout: 10000 });
  await page
    .getByRole("cell", { name: expectedType, exact: true })
    .first()
    .waitFor({ state: "visible", timeout: 10000 });
}

async function readDockerEnv() {
  try {
    const text = await readFile(resolve(repoRoot, "docker/.env"), "utf8");
    return Object.fromEntries(
      text
        .split(/\r?\n/)
        .filter((line) => line && !line.startsWith("#") && line.includes("="))
        .map((line) => {
          const index = line.indexOf("=");
          return [line.slice(0, index), line.slice(index + 1)];
        }),
    );
  } catch {
    return {};
  }
}
