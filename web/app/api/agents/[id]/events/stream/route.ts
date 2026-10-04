import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiStream } from "@/lib/api";

export const dynamic = "force-dynamic";

type Params = {
  params: Promise<{ id: string }>;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// Proxies the API's Server-Sent Events stream. The browser cannot call the API
// directly because requests must carry the web server's HMAC signature.
export async function GET(req: NextRequest, { params }: Params) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;
  if (!UUID.test(id)) {
    return NextResponse.json({ error: "Invalid agent id" }, { status: 400 });
  }

  try {
    const upstream = await apiStream(
      `/api/agents/${id}/events/stream`,
      session.user.id,
      authRole(session.user),
      req.signal,
    );
    return new Response(upstream.body, {
      headers: {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache, no-transform",
        "X-Accel-Buffering": "no",
      },
    });
  } catch (err) {
    const status = err instanceof ApiError && err.status === 404 ? 404 : 502;
    return NextResponse.json({ error: "Failed to open event stream" }, { status });
  }
}
