import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiGet, apiPut } from "@/lib/api";

const schema = z.object({
  base_url: z.string().trim().url(),
  events_url: z.string().trim().url(),
  api_key_header: z.string().trim().regex(/^[A-Za-z0-9-]{1,64}$/),
  api_key: z.string().max(4096).nullable().optional(),
  records_path: z.string().trim().max(256),
  verify_tls: z.boolean(),
  is_enabled: z.boolean(),
  interval_minutes: z.number().int().min(1).max(1440),
});

export async function GET() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (authRole(session.user) !== "Admin") {
    return NextResponse.json({ error: "Admin access required." }, { status: 403 });
  }

  try {
    const data = await apiGet(
      "/api/integrations/unifi",
      session.user.id,
      authRole(session.user),
    );
    return NextResponse.json(data);
  } catch (error) {
    return apiFailure(error, "Failed to load UniFi integration.");
  }
}

export async function PUT(request: NextRequest) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (authRole(session.user) !== "Admin") {
    return NextResponse.json({ error: "Admin access required." }, { status: 403 });
  }

  const parsed = schema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    const field = issue?.path[0];
    const label = field === "base_url"
      ? "Controller URL"
      : field === "events_url"
        ? "Records URL"
        : field === "api_key_header"
          ? "API key header"
          : field === "records_path"
            ? "Records path"
            : field === "interval_minutes"
              ? "Check interval"
              : "UniFi configuration";
    return NextResponse.json(
      { error: `${label}: ${issue?.message ?? "invalid value."}` },
      { status: 400 },
    );
  }

  try {
    const data = await apiPut(
      "/api/integrations/unifi",
      parsed.data,
      session.user.id,
      authRole(session.user),
    );
    return NextResponse.json(data);
  } catch (error) {
    return apiFailure(error, "Failed to save UniFi integration.");
  }
}

function apiFailure(error: unknown, fallback: string) {
  if (error instanceof ApiError && error.status >= 400 && error.status < 500) {
    return NextResponse.json({ error: error.message }, { status: error.status });
  }
  return NextResponse.json({ error: fallback }, { status: 502 });
}
