import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiPost } from "@/lib/api";

export async function POST() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  if (authRole(session.user) !== "Admin") {
    return NextResponse.json({ error: "Admin access required." }, { status: 403 });
  }

  try {
    const data = await apiPost(
      "/api/integrations/unifi/test",
      {},
      session.user.id,
      authRole(session.user),
    );
    return NextResponse.json(data);
  } catch (error) {
    if (error instanceof ApiError && error.status >= 400 && error.status < 500) {
      return NextResponse.json({ error: error.message }, { status: error.status });
    }
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "UniFi connection test failed." },
      { status: 502 },
    );
  }
}
