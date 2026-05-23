import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiPost } from "@/lib/api";

const schema = z.object({
  name: z.string().trim().min(1).max(160),
  reason: z.string().nullable().optional(),
  scope: z.enum(["all_rules", "specific_rule"]),
  alert_rule_id: z.string().uuid().nullable().optional(),
  agent_id: z.string().uuid().nullable().optional(),
  payload_path: z.string().nullable().optional(),
  operator: z.enum(["exists", "equals", "contains", "greater_than", "less_than"]),
  match_value: z.string().nullable().optional(),
  is_enabled: z.boolean(),
  expires_at: z.string().datetime().nullable().optional(),
});

export async function POST(req: NextRequest) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json().catch(() => null);
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid request." }, { status: 400 });
  }

  try {
    const data = await apiPost("/api/suppression-rules", parsed.data, session.user.id, authRole(session.user));
    return NextResponse.json(data);
  } catch (err) {
    if (err instanceof ApiError && err.status >= 400 && err.status < 500) {
      return NextResponse.json({ error: err.message }, { status: err.status });
    }
    return NextResponse.json({ error: "Failed to create suppression rule." }, { status: 502 });
  }
}
