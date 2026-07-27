import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiGet, apiPost } from "@/lib/api";

const schema = z.object({
  name: z.string().trim().min(1).max(160),
  provider: z.enum(["aws", "azure"]),
  external_account_id: z.string().trim().min(1).max(128),
  credential_mode: z.enum(["aws_assume_role", "azure_managed_identity", "azure_client_secret"]),
  configuration: z.record(z.string(), z.unknown()),
  credential: z.record(z.string(), z.unknown()).nullable().optional(),
  is_enabled: z.boolean(),
});

export async function GET() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (authRole(session.user) !== "Admin") return NextResponse.json({ error: "Admin access required." }, { status: 403 });
  try {
    return NextResponse.json(await apiGet("/api/cloud-connections", session.user.id, authRole(session.user)));
  } catch (error) {
    return failure(error, "Failed to load cloud connections.");
  }
}

export async function POST(request: NextRequest) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (authRole(session.user) !== "Admin") return NextResponse.json({ error: "Admin access required." }, { status: 403 });
  const parsed = schema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid connection." }, { status: 400 });
  try {
    return NextResponse.json(await apiPost("/api/cloud-connections", parsed.data, session.user.id, authRole(session.user)));
  } catch (error) {
    return failure(error, "Failed to save cloud connection.");
  }
}

function failure(error: unknown, fallback: string) {
  if (error instanceof ApiError && error.status >= 400 && error.status < 600) {
    return NextResponse.json({ error: error.message }, { status: error.status });
  }
  return NextResponse.json({ error: fallback }, { status: 502 });
}
