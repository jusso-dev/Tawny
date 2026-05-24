import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiDelete, apiPut } from "@/lib/api";

const schema = z.object({
  name: z.string().trim().min(1).max(160),
  description: z.string().nullable().optional(),
  query: z.string().trim().min(1),
  is_scheduled: z.boolean(),
  schedule_cron: z.string().nullable().optional(),
  alert_on_match: z.boolean(),
  alert_severity: z.enum(["low", "medium", "high", "critical"]),
  mitre_techniques: z.array(z.string()).optional(),
  is_shared: z.boolean().optional(),
});

export async function PUT(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await ctx.params;
  const body = await req.json().catch(() => null);
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid request." }, { status: 400 });
  }

  try {
    const data = await apiPut(`/api/hunts/${id}`, parsed.data, session.user.id, authRole(session.user));
    return NextResponse.json(data);
  } catch (err) {
    if (err instanceof ApiError && err.status >= 400 && err.status < 500) {
      return NextResponse.json({ error: err.message }, { status: err.status });
    }
    return NextResponse.json({ error: "Failed to update hunt." }, { status: 502 });
  }
}

export async function DELETE(_: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id } = await ctx.params;
  try {
    await apiDelete(`/api/hunts/${id}`, session.user.id, authRole(session.user));
    return new NextResponse(null, { status: 204 });
  } catch (err) {
    if (err instanceof ApiError && err.status >= 400 && err.status < 500) {
      return NextResponse.json({ error: err.message }, { status: err.status });
    }
    return NextResponse.json({ error: "Failed to delete hunt." }, { status: 502 });
  }
}
