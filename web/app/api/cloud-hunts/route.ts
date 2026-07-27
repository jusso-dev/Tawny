import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiGet, apiPost } from "@/lib/api";

const schema = z.object({
  cloud_connection_id: z.string().uuid(),
  name: z.string().trim().min(1).max(160),
  description: z.string().max(4000).nullable().optional(),
  source: z.enum([
    "aws_cloud_trail",
    "aws_guard_duty",
    "azure_activity_log",
    "azure_entra_audit_log",
    "azure_entra_sign_in_log",
  ]),
  query: z.record(z.string(), z.unknown()),
  is_enabled: z.boolean(),
  interval_minutes: z.number().int().min(1).max(1440),
  lookback_minutes: z.number().int().min(1).max(43200),
  severity: z.enum(["low", "medium", "high", "critical"]),
  mitre_techniques: z.array(z.string()).optional(),
});

export async function GET() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  try {
    return NextResponse.json(await apiGet("/api/cloud-hunts", session.user.id, authRole(session.user)));
  } catch (error) {
    return failure(error, "Failed to load cloud hunts.");
  }
}

export async function POST(request: NextRequest) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (authRole(session.user) !== "Admin") return NextResponse.json({ error: "Admin access required." }, { status: 403 });
  const parsed = schema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid cloud hunt." }, { status: 400 });
  try {
    return NextResponse.json(await apiPost("/api/cloud-hunts", parsed.data, session.user.id, authRole(session.user)));
  } catch (error) {
    return failure(error, "Failed to save cloud hunt.");
  }
}

function failure(error: unknown, fallback: string) {
  if (error instanceof ApiError && error.status >= 400 && error.status < 600) {
    return NextResponse.json({ error: error.message }, { status: error.status });
  }
  return NextResponse.json({ error: fallback }, { status: 502 });
}
