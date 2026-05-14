import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { apiGet } from "@/lib/api";

type Params = {
  params: Promise<{ id: string }>;
};

export async function GET(req: NextRequest, { params }: Params) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;
  const query = req.nextUrl.searchParams.toString();
  const path = `/api/agents/${id}/events${query ? `?${query}` : ""}`;

  try {
    const events = await apiGet(path, session.user.id, "Admin");
    return NextResponse.json(events);
  } catch {
    return NextResponse.json({ error: "Failed to load events" }, { status: 502 });
  }
}
