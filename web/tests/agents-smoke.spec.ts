import { createServer, type Server } from "node:http";
import { test, expect } from "@playwright/test";

let api: Server;

test.beforeAll(async () => {
  api = createServer((req, res) => {
    if (req.url === "/api/agents") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("[]");
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "not found" }));
  });

  await new Promise<void>((resolve) => api.listen(5099, "127.0.0.1", resolve));
});

test.afterAll(async () => {
  await new Promise<void>((resolve, reject) => {
    api.close((err) => (err ? reject(err) : resolve()));
  });
});

test("agents list smoke path renders after test login bypass", async ({ page }) => {
  await page.goto("/agents");

  await expect(page.getByRole("heading", { name: "Agents" })).toBeVisible();
  await expect(page.getByText("No agents yet.")).toBeVisible();
});
