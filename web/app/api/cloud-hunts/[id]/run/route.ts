import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiPost } from "@/lib/api";

export async function POST(_: NextRequest, context: { params: Promise<{ id: string }> }) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (authRole(session.user) !== "Admin") return NextResponse.json({ error: "Admin access required." }, { status: 403 });
  const { id } = await context.params;
  try {
    return NextResponse.json(await apiPost("/api/cloud-hunts/" + id + "/run", {}, session.user.id, authRole(session.user)));
  } catch (error) {
    if (error instanceof ApiError && error.status >= 400 && error.status < 600) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Cloud hunt failed." }, { status: 502 });
  }
}
