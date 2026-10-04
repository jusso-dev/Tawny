// Playwright is not a dependency of this repo. This script is the UI gate:
// index.html's hashed assets exist, every dashboard route is in the SPA
// source, and that script runs with a window global while module and require
// are absent.
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const uiDir = path.join(root, "server", "ui");
const htmlPath = path.join(uiDir, "index.html");
const html = fs.readFileSync(htmlPath, "utf8");

const refs = [...html.matchAll(/(?:href|src)="(\/assets\/[^"]+)"/g)].map((m) => m[1]);
if (refs.length < 2) {
  throw new Error("index.html is missing hashed css and js assets");
}
for (const ref of refs) {
  const file = path.join(uiDir, ref.slice(1));
  if (!fs.existsSync(file)) throw new Error(`missing UI asset ${ref}`);
}

const jsRef = refs.find((ref) => ref.endsWith(".js"));
if (!jsRef) throw new Error("index.html has no script asset");
const jsPath = path.join(uiDir, jsRef.slice(1));
const source = fs.readFileSync(jsPath, "utf8");

const routes = [
  "/login",
  "/agents",
  "/alerts",
  "/hunt",
  "/detections",
  "/threat-intel",
  "/suppressions",
  "/audit",
  "/api-tokens",
  "/enrollment",
  "/users",
  "/admin/jobs",
];
for (const route of routes) {
  if (!source.includes(`"${route}"`) && !source.includes(`'${route}'`)) {
    throw new Error(`SPA source missing route ${route}`);
  }
}
if (!source.includes("/agents/")) throw new Error("SPA source missing agent detail route");
if (!source.includes("EventSource")) throw new Error("SPA source missing EventSource");

function element() {
  return {
    className: "",
    textContent: "",
    value: "",
    checked: false,
    style: {},
    children: [],
    appendChild(child) {
      this.children.push(child);
      return child;
    },
    replaceWith() {},
    addEventListener() {},
    setAttribute() {},
    append() {},
  };
}

const document = {
  getElementById() {
    return element();
  },
  createElement() {
    return element();
  },
  createTextNode(text) {
    return { textContent: text };
  },
};

const sandbox = {
  document,
  location: { pathname: "/", assign() {}, hash: "" },
  fetch() {
    return Promise.resolve({
      status: 200,
      text() {
        return Promise.resolve('{"role":"admin","csrf_token":"x"}');
      },
    });
  },
  EventSource: function EventSource() {
    this.close = function close() {};
  },
  console,
  setTimeout,
  clearTimeout,
};
sandbox.window = sandbox;
vm.createContext(sandbox);
if (Object.hasOwn(sandbox, "module") || Object.hasOwn(sandbox, "require")) {
  throw new Error("browser context already has module or require");
}
vm.runInContext(source, sandbox, { filename: jsPath });
if (sandbox.module !== undefined || sandbox.require !== undefined) {
  throw new Error("SPA script saw module or require");
}
if (sandbox.window !== sandbox) throw new Error("SPA script replaced window");
await new Promise((resolve) => setTimeout(resolve, 20));
console.log(`ui fallback ok assets=${refs.length} routes=${routes.length}`);
