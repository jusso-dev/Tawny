import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiDelete } from "@/lib/api";

export async function DELETE(_: NextRequest, ctx: { params: Promise<{ id: string; alertId: string }> }) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { id, alertId } = await ctx.params;
  try {
    await apiDelete(`/api/cases/${id}/alerts/${alertId}`, session.user.id, authRole(session.user));
    return new NextResponse(null, { status: 204 });
  } catch (err) {
    if (err instanceof ApiError && err.status >= 400 && err.status < 500) {
      return NextResponse.json({ error: err.message }, { status: err.status });
    }
    return NextResponse.json({ error: "Failed to remove alert." }, { status: 502 });
  }
}
