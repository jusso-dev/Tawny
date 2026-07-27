import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiGet } from "@/lib/api";

export async function GET(request: NextRequest) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const limit = Math.min(500, Math.max(1, Number.parseInt(request.nextUrl.searchParams.get("limit") ?? "20", 10) || 20));
  const path = "/api/cloud-findings?limit=" + limit;
  try {
    return NextResponse.json(await apiGet(path, session.user.id, authRole(session.user)));
  } catch (error) {
    if (error instanceof ApiError && error.status >= 400 && error.status < 600) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json({ error: "Failed to load cloud findings." }, { status: 502 });
  }
}
