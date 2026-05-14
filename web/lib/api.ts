import "server-only";
import { createHmac } from "node:crypto";

const API_URL = process.env.TAWNY_API_URL ?? "http://localhost:5080";
const HMAC_SECRET = process.env.TAWNY_WEB_HMAC_SECRET ?? "";

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

function sign(method: string, path: string, userId: string, role: string) {
  const ts = Math.floor(Date.now() / 1000).toString();
  const signedPath = path.split("?")[0] || path;
  // `userId` must be the persisted Better Auth user id. The API maps it to
  // ClaimTypes.NameIdentifier through the HMAC handler for audit attribution.
  const canonical = [method.toUpperCase(), signedPath, ts, userId, role].join("\n");
  const sig = createHmac("sha256", HMAC_SECRET).update(canonical).digest("hex");
  return {
    "X-User-Id": userId,
    "X-User-Role": role,
    "X-Timestamp": ts,
    "X-Signature": sig,
  };
}

export async function apiGet<T>(path: string, userId: string, role: string): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, {
    headers: sign("GET", path, userId, role),
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
  const res = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: { ...sign("POST", path, userId, role), "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  });
  if (!res.ok) {
    throw new ApiError(await errorMessage(res, `API ${path} returned ${res.status}`), res.status);
  }
  return res.json() as Promise<T>;
}
