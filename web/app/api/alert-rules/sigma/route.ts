import { headers } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { auth } from "@/lib/auth";
import { authRole } from "@/lib/auth-role";
import { ApiError, apiPost } from "@/lib/api";

type AlertRuleResponse = {
  id: string;
  name: string;
  format: "sigma" | "tawny_predicate";
};

const importSigmaRequestSchema = z.object({
  rule_yaml: z.string().trim().min(1, "Rule YAML is required."),
  is_enabled: z.boolean().optional(),
});

export async function POST(req: NextRequest) {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json().catch(() => null);
  const parsed = importSigmaRequestSchema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.issues[0]?.message ?? "Invalid request." }, { status: 400 });
  }

  try {
    const rule = await apiPost<AlertRuleResponse>(
      "/api/alert-rules/sigma",
      {
        rule_yaml: parsed.data.rule_yaml,
        is_enabled: parsed.data.is_enabled !== false,
      },
      session.user.id,
      authRole(session.user),
    );
    return NextResponse.json(rule);
  } catch (err) {
    if (err instanceof ApiError && err.status >= 400 && err.status < 500) {
      return NextResponse.json({ error: err.message }, { status: 400 });
    }

    return NextResponse.json({ error: "Failed to import Sigma rule." }, { status: 502 });
  }
}
