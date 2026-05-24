import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiPost } from "@/lib/api";

const schema = z.object({
  name: z.string().trim().min(1).max(160),
  kind: z.enum(["urlhaus_csv", "urlhaus_json", "otx_pulse", "misp_events", "taxii21", "generic_csv"]),
  url: z.string().url(),
  auth_header_name: z.string().nullable().optional(),
  auth_header_value: z.string().nullable().optional(),
  default_severity: z.enum(["low", "medium", "high", "critical"]).optional(),
  interval_minutes: z.number().int().min(5).max(10080).optional(),
  is_enabled: z.boolean().optional(),
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
    const data = await apiPost("/api/threat-intel-feeds", parsed.data, session.user.id, authRole(session.user));
    return NextResponse.json(data);
  } catch (err) {
    if (err instanceof ApiError && err.status >= 400 && err.status < 500) {
      return NextResponse.json({ error: err.message }, { status: err.status });
    }
    return NextResponse.json({ error: "Failed to create feed." }, { status: 502 });
  }
}
