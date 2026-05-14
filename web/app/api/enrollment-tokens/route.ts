import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { apiPost } from "@/lib/api";

type CreateEnrollmentTokenResponse = {
  id: string;
  token: string;
  expires_at: string;
};

export async function POST(req: NextRequest) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = (await req.json().catch(() => null)) as { lifetime_hours?: unknown } | null;
  const lifetimeHours = Number(body?.lifetime_hours ?? 24);
  if (!Number.isInteger(lifetimeHours) || lifetimeHours < 1 || lifetimeHours > 168) {
    return NextResponse.json({ error: "Lifetime must be between 1 and 168 hours." }, { status: 400 });
  }

  try {
    const token = await apiPost<CreateEnrollmentTokenResponse>(
      "/api/enrollment-tokens",
      { lifetime_hours: lifetimeHours },
      session.user.id,
      authRole(session.user),
    );
    return NextResponse.json(token);
  } catch {
    return NextResponse.json({ error: "Failed to create token." }, { status: 502 });
  }
}
