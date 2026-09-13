import { NextResponse, type NextRequest } from "next/server";
import { z } from "zod";

import { konversifySsoLogin } from "@calcom/features/auth/lib/konversify-sso/login";
import logger from "@calcom/lib/logger";
import prisma from "@calcom/prisma";

export const dynamic = "force-dynamic";

const bodySchema = z.object({ token: z.string().min(1) });

// TEMP DIAGNOSTIC (remove after the env-visibility question is settled):
// reports what the running server process actually resolves for the flag.
export async function GET() {
  return NextResponse.json({
    flag: process.env.KONVERSIFY_SSO_ENABLED,
    flagTrue: process.env.KONVERSIFY_SSO_ENABLED === "true",
    jwks: Boolean(process.env.KONVERSIFY_JWKS_URL),
    nodeEnv: process.env.NODE_ENV,
  });
}

export async function POST(req: NextRequest) {
  const parsed = bodySchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid request" }, { status: 400 });
  }

  const result = await konversifySsoLogin(parsed.data.token, prisma);
  if (!result.ok) {
    logger.warn("konversify sso rejected", { reason: result.reason });
    return NextResponse.json({ error: "Konversify SSO failed" }, { status: result.status });
  }

  const response = NextResponse.json({ login: true });
  response.cookies.set(result.session.cookieName, result.session.sessionToken, {
    ...result.session.cookieOptions,
    maxAge: result.session.cookieMaxAge,
  });
  return response;
}
