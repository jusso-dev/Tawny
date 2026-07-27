import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiPost } from "@/lib/api";

const schema = z.object({
  source: z.enum([
    "aws_cloud_trail",
    "aws_guard_duty",
    "azure_activity_log",
    "azure_entra_audit_log",
    "azure_entra_sign_in_log",
  ]),
});

export async function POST(request: NextRequest, context: { params: Promise<{ id: string }> }) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (authRole(session.user) !== "Admin") return NextResponse.json({ error: "Admin access required." }, { status: 403 });
  const parsed = schema.safeParse(await request.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "Invalid cloud source." }, { status: 400 });
  const { id } = await context.params;
  try {
    return NextResponse.json(await apiPost(
      "/api/cloud-connections/" + id + "/test",
      parsed.data,
      session.user.id,
      authRole(session.user),
    ));
  } catch (error) {
    if (error instanceof ApiError && error.status >= 400 && error.status < 600) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Cloud connection test failed." }, { status: 502 });
  }
}
