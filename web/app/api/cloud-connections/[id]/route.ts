import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiDelete, apiPut } from "@/lib/api";

const schema = z.object({
  name: z.string().trim().min(1).max(160),
  provider: z.enum(["aws", "azure"]),
  external_account_id: z.string().trim().min(1).max(128),
  credential_mode: z.enum(["aws_assume_role", "azure_managed_identity", "azure_client_secret"]),
  configuration: z.record(z.string(), z.unknown()),
  credential: z.record(z.string(), z.unknown()).nullable().optional(),
  is_enabled: z.boolean(),
});

export async function PUT(request: NextRequest, context: { params: Promise<{ id: string }> }) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (authRole(session.user) !== "Admin") return NextResponse.json({ error: "Admin access required." }, { status: 403 });
  const parsed = schema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid connection." }, { status: 400 });
  const { id } = await context.params;
  try {
    return NextResponse.json(await apiPut(
      "/api/cloud-connections/" + id,
      parsed.data,
      session.user.id,
      authRole(session.user),
    ));
  } catch (error) {
    return failure(error);
  }
}

export async function DELETE(_: NextRequest, context: { params: Promise<{ id: string }> }) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (authRole(session.user) !== "Admin") return NextResponse.json({ error: "Admin access required." }, { status: 403 });
  const { id } = await context.params;
  try {
    await apiDelete("/api/cloud-connections/" + id, session.user.id, authRole(session.user));
    return new NextResponse(null, { status: 204 });
  } catch (error) {
    return failure(error);
  }
}

function failure(error: unknown) {
  if (error instanceof ApiError && error.status >= 400 && error.status < 600) {
    return NextResponse.json({ error: error.message }, { status: error.status });
  }
  return NextResponse.json({ error: "Cloud connection request failed." }, { status: 502 });
}
