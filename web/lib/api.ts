import "server-only";
import { createHmac, createHash, randomBytes } from "node:crypto";

const API_URL = process.env.TAWNY_API_URL ?? "http://localhost:5080";
const HMAC_SECRET = process.env.TAWNY_WEB_HMAC_SECRET ?? "";
const TENANT_ID = process.env.TAWNY_TENANT_ID ?? "00000000-0000-0000-0000-000000000001";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
  }
}

async function errorMessage(res: Response, fallback: string) {
  const text = await res.text().catch(() => "");
  if (!text) return fallback;

  try {
    const body = JSON.parse(text) as { error?: unknown; title?: unknown; detail?: unknown };
    const message = body.error ?? body.detail ?? body.title;
    return typeof message === "string" && message.trim().length > 0 ? message : fallback;
  } catch {
    return text.trim().length > 0 ? text : fallback;
  }
}

function pathOnly(path: string): string {
  const q = path.indexOf("?");
  return q < 0 ? path : path.slice(0, q);
}

function canonicalQuery(path: string): string {
  const q = path.indexOf("?");
  if (q < 0 || q === path.length - 1) return "";
  const raw = path.slice(q + 1);
  const params = new URLSearchParams(raw);
  const pairs: Array<[string, string]> = [];
  for (const [key, value] of params.entries()) {
    pairs.push([key, value]);
  }
  pairs.sort((a, b) => {
    const keyCmp = a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0;
    if (keyCmp !== 0) return keyCmp;
    return a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0;
  });
  return pairs
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join("&");
}

function bodyDigest(body: string): string {
  return createHash("sha256").update(body, "utf8").digest("hex");
}

function sign(
  method: string,
  path: string,
  userId: string,
  role: string,
  body: string,
  contentType: string,
) {
  const ts = Math.floor(Date.now() / 1000).toString();
  const nonce = randomBytes(16).toString("hex");
  const signedPath = pathOnly(path);
  const query = canonicalQuery(path);
  const digest = bodyDigest(body);
  // `userId` must be the persisted Better Auth user id.
  const canonical = [
    "v2",
    method.toUpperCase(),
    signedPath,
    query,
    digest,
    contentType,
    userId,
    role,
    TENANT_ID,
    ts,
    nonce,
  ].join("\n");
  const sig = createHmac("sha256", HMAC_SECRET).update(canonical).digest("hex");
  return {
    "X-User-Id": userId,
    "X-User-Role": role,
    "X-Tenant-Id": TENANT_ID,
    "X-Timestamp": ts,
    "X-Nonce": nonce,
    "X-Signature": sig,
  };
}

export async function apiGet<T>(path: string, userId: string, role: string): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    headers: sign("GET", path, userId, role, "", ""),
    cache: "no-store",
  });
  if (!res.ok) {
    throw new ApiError(await errorMessage(res, `API ${path} returned ${res.status}`), res.status);
  }
  return res.json() as Promise<T>;
}

export async function apiPost<T>(
  path: string,
  body: unknown,
  userId: string,
  role: string,
): Promise<T> {
  const raw = JSON.stringify(body);
  const res = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: {
      ...sign("POST", path, userId, role, raw, "application/json"),
      "Content-Type": "application/json",
    },
    body: raw,
    cache: "no-store",
  });
  if (!res.ok) {
    throw new ApiError(await errorMessage(res, `API ${path} returned ${res.status}`), res.status);
  }
  return res.json() as Promise<T>;
}

export async function apiPut<T>(
  path: string,
  body: unknown,
  userId: string,
  role: string,
): Promise<T> {
  const raw = JSON.stringify(body);
  const res = await fetch(`${API_URL}${path}`, {
    method: "PUT",
    headers: {
      ...sign("PUT", path, userId, role, raw, "application/json"),
      "Content-Type": "application/json",
    },
    body: raw,
    cache: "no-store",
  });
  if (!res.ok) {
    throw new ApiError(await errorMessage(res, `API ${path} returned ${res.status}`), res.status);
  }
  return res.json() as Promise<T>;
}

export async function apiDelete(path: string, userId: string, role: string): Promise<void> {
  const res = await fetch(`${API_URL}${path}`, {
    method: "DELETE",
    headers: sign("DELETE", path, userId, role, "", ""),
    cache: "no-store",
  });
  if (!res.ok && res.status !== 204) {
    throw new ApiError(await errorMessage(res, `API ${path} returned ${res.status}`), res.status);
  }
}
