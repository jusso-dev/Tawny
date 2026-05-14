import { createHmac } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

const apiUrl = env("TAWNY_API_URL", "http://api:5080").replace(/\/+$/, "");
const hmacSecret = env("TAWNY_WEB_HMAC_SECRET", "");
const statePath = env("SYNTHETIC_AGENT_STATE_PATH", "/state/agent.json");
const hostname = env("SYNTHETIC_AGENT_HOSTNAME", "tawny-docker-agent");
const agentVersion = env("SYNTHETIC_AGENT_VERSION", "synthetic-docker-0.1.0");
const os = env("SYNTHETIC_AGENT_OS", "macos");
const osVersion = env("SYNTHETIC_AGENT_OS_VERSION", "synthetic-container");
const arch = env("SYNTHETIC_AGENT_ARCH", "arm64");
const eventIntervalMs = envInt("SYNTHETIC_AGENT_EVENT_INTERVAL_SECONDS", 300) * 1000;
const heartbeatIntervalMs = envInt("SYNTHETIC_AGENT_HEARTBEAT_INTERVAL_SECONDS", 300) * 1000;
const maxBatches = envNonNegativeInt("SYNTHETIC_AGENT_MAX_BATCHES", 0);
const webUserId = env("SYNTHETIC_AGENT_WEB_USER_ID", "00000000-0000-0000-0000-000000000000");
const webUserRole = env("SYNTHETIC_AGENT_WEB_USER_ROLE", "Admin");

let state = await readState();
let startedAt = Date.now();
let sequence = 0;
let lastHeartbeatAt = 0;
let lastEventAt = 0;

log(`starting synthetic agent for ${apiUrl}`);
log(maxBatches > 0
  ? `sending up to ${maxBatches} telemetry batches every ${eventIntervalMs / 1000}s`
  : `sending telemetry batches every ${eventIntervalMs / 1000}s`);
log(`heartbeating every ${heartbeatIntervalMs / 1000}s`);

for (;;) {
  try {
    if (!state?.agentId || !state?.jwt) {
      state = await enroll();
      await writeState(state);
    }

    if (maxBatches === 0 && state.completed) {
      state.completed = false;
      state.batchesSent = 0;
      await writeState(state);
      log("continuous telemetry enabled; resuming from previous completed state");
    }

    let now = Date.now();
    if (now - lastHeartbeatAt >= heartbeatIntervalMs) {
      const ok = await heartbeat(state);
      lastHeartbeatAt = Date.now();
      if (!ok) {
        state = null;
        continue;
      }
    }

    if (state.completed) {
      log("max telemetry batches already sent; heartbeating only");
      await sleep(nextDelay());
      continue;
    }

    now = Date.now();
    if (now - lastEventAt >= eventIntervalMs) {
      await sendEvents(state);
      lastEventAt = Date.now();
      if (maxBatches > 0 && (state.batchesSent ?? 0) >= maxBatches) {
        state.completed = true;
        await writeState(state);
        log(`sent ${state.batchesSent} telemetry batches; heartbeating only`);
      }
    }
  } catch (err) {
    console.error(`[synthetic-agent] ${err.stack ?? err.message ?? err}`);
  }

  await sleep(nextDelay());
}

async function enroll() {
  const enrollmentToken = env("SYNTHETIC_AGENT_ENROLLMENT_TOKEN", "") || await createEnrollmentToken();
  const body = {
    enrollment_token: enrollmentToken,
    hostname,
    os,
    os_version: osVersion,
    arch,
    agent_version: agentVersion,
  };
  const res = await apiFetch("/api/agents/enroll", {
    method: "POST",
    body,
  });

  const json = await parseJson(res);
  const next = {
    agentId: json.agent_id,
    jwt: json.jwt,
    jwtExpiresAt: json.jwt_expires_at,
    batchesSent: 0,
    completed: false,
  };
  log(`enrolled ${next.agentId} (${hostname})`);
  return next;
}

async function createEnrollmentToken() {
  if (!hmacSecret) {
    throw new Error("TAWNY_WEB_HMAC_SECRET is required to create a synthetic enrollment token.");
  }

  const res = await apiFetch("/api/enrollment-tokens", {
    method: "POST",
    body: { lifetime_hours: 24 },
    headers: webUserHeaders("POST", "/api/enrollment-tokens"),
  });
  const json = await parseJson(res);
  log(`created enrollment token ${json.id}`);
  return json.token;
}

async function heartbeat(current) {
  const res = await apiFetch("/api/agents/heartbeat", {
    method: "POST",
    bearer: current.jwt,
    body: {
      agent_version: agentVersion,
      uptime_seconds: Math.floor((Date.now() - startedAt) / 1000),
      buffer_depth: 0,
    },
    throwOnError: false,
  });

  if (res.status === 401 || res.status === 404) {
    log(`heartbeat returned ${res.status}; re-enrolling`);
    return false;
  }

  if (!res.ok) {
    throw new Error(`heartbeat failed: ${res.status} ${await res.text()}`);
  }

  log(`heartbeat ok for ${current.agentId}`);
  return true;
}

async function sendEvents(current) {
  const occurred_at = Math.floor(Date.now() / 1000);
  const events = [
    {
      type: "system_info",
      occurred_at,
      payload: {
        platform: os,
        hostname,
        os_version: osVersion,
        architecture: arch,
        source: "docker-synthetic-agent",
        sequence,
      },
    },
    {
      type: "process_snapshot",
      occurred_at,
      payload: {
        processes: [
          { pid: 1, name: "node", path: "/usr/local/bin/node", user: "node" },
          { pid: 42, name: `quoted-"process-${sequence}`, path: "C:\\Synthetic\\Agent.exe", user: "synthetic" },
        ],
      },
    },
    {
      type: "network_snapshot",
      occurred_at,
      payload: {
        connections: [
          {
            protocol: "tcp",
            local_address: hostname,
            local_port: 50000 + (sequence % 1000),
            remote_address: "api",
            remote_port: 5080,
            state: "established",
            owning_process: "node",
          },
        ],
      },
    },
    {
      type: "file_integrity",
      occurred_at,
      payload: {
        path: `/synthetic/config-${sequence % 3}.toml`,
        old_sha256: sequence === 0 ? null : "0".repeat(64),
        new_sha256: String(sequence % 10).repeat(64),
        size_bytes: 128 + sequence,
      },
    },
    {
      type: "user_session",
      occurred_at,
      payload: {
        username: "synthetic-user",
        session_id: `docker-${sequence}`,
        state: "active",
      },
    },
  ];

  const res = await apiFetch("/api/agents/events", {
    method: "POST",
    bearer: current.jwt,
    body: { events },
    throwOnError: false,
  });

  if (res.status === 401 || res.status === 404) {
    log(`event ingest returned ${res.status}; re-enrolling`);
    state = null;
    return;
  }

  if (res.status !== 202) {
    throw new Error(`event ingest failed: ${res.status} ${await res.text()}`);
  }

  sequence += 1;
  current.batchesSent = (current.batchesSent ?? 0) + 1;
  await writeState(current);
  log(`sent ${events.length} events for ${current.agentId}`);
}

function webUserHeaders(method, path) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const canonical = [method.toUpperCase(), path, timestamp, webUserId, webUserRole].join("\n");
  const signature = createHmac("sha256", hmacSecret).update(canonical).digest("hex");
  return {
    "X-User-Id": webUserId,
    "X-User-Role": webUserRole,
    "X-Timestamp": timestamp,
    "X-Signature": signature,
  };
}

async function apiFetch(path, options = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers ?? {}),
  };
  if (options.bearer) {
    headers.Authorization = `Bearer ${options.bearer}`;
  }

  const res = await fetch(`${apiUrl}${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });

  if (options.throwOnError !== false && !res.ok) {
    throw new Error(`${options.method ?? "GET"} ${path} failed: ${res.status} ${await res.text()}`);
  }
  return res;
}

async function parseJson(res) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`expected JSON from ${res.url}, got ${res.status}: ${text}`);
  }
}

async function readState() {
  try {
    return JSON.parse(await readFile(statePath, "utf8"));
  } catch {
    return null;
  }
}

async function writeState(next) {
  await mkdir(dirname(statePath), { recursive: true });
  await writeFile(statePath, `${JSON.stringify(next, null, 2)}\n`, "utf8");
}

function env(key, fallback) {
  return process.env[key] || fallback;
}

function envInt(key, fallback) {
  const value = Number.parseInt(process.env[key] ?? "", 10);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function envNonNegativeInt(key, fallback) {
  const value = Number.parseInt(process.env[key] ?? "", 10);
  return Number.isFinite(value) && value >= 0 ? value : fallback;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function nextDelay() {
  return Math.max(1000, Math.min(heartbeatIntervalMs, eventIntervalMs, 30_000));
}

function log(message) {
  console.log(`[synthetic-agent] ${new Date().toISOString()} ${message}`);
}
