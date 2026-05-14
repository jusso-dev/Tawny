import "server-only";
import { createHmac } from "node:crypto";

const API_URL = process.env.TAWNY_API_URL ?? "http://localhost:5080";
const HMAC_SECRET = process.env.TAWNY_WEB_HMAC_SECRET ?? "";

function sign(method: string, path: string, userId: string, role: string) {
  const ts = Math.floor(Date.now() / 1000).toString();
  const signedPath = path.split("?")[0] || path;
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
  if (!res.ok) throw new Error(`API ${path} returned ${res.status}`);
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
  if (!res.ok) throw new Error(`API ${path} returned ${res.status}`);
  return res.json() as Promise<T>;
}
