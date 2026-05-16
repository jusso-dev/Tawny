import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiPost } from "@/lib/api";

type ImportIocResponse = {
  rules: Array<{
    id: string;
    name: string;
    format: "ioc" | "sigma" | "tawny_predicate";
  }>;
  skipped_indicators: string[];
};

const importIocRequestSchema = z.object({
  definition: z.string().trim().min(1, "Threat intel content is required."),
  source_format: z.enum(["auto", "stix", "openioc", "raw"]).optional(),
  severity: z.enum(["low", "medium", "high", "critical"]).optional(),
  is_enabled: z.boolean().optional(),
});

export async function POST(req: NextRequest) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null);
  const parsed = importIocRequestSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid request." }, { status: 400 });
  }

  try {
    const result = await apiPost<ImportIocResponse>(
      "/api/alert-rules/iocs",
      {
        definition: parsed.data.definition,
        source_format: parsed.data.source_format ?? "auto",
        severity: parsed.data.severity ?? "high",
        is_enabled: parsed.data.is_enabled !== false,
      },
      session.user.id,
      authRole(session.user),
    );
    return NextResponse.json(result);
  } catch (err) {
    if (err instanceof ApiError && err.status >= 400 && err.status < 500) {
      return NextResponse.json({ error: err.message }, { status: 400 });
    }

    return NextResponse.json({ error: "Failed to import IoCs." }, { status: 502 });
  }
}
