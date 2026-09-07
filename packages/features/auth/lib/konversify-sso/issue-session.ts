import process from "node:process";

import { WEBAPP_URL } from "@calcom/lib/constants";
import { defaultCookies } from "@calcom/lib/default-cookies";
import type { User } from "@calcom/prisma/client";
import type { CookieOption } from "next-auth";

import { getOptions } from "../next-auth-options";
import type { KonversifySsoSession } from "./types";

// next-auth's default session.maxAge (30 days)
const SESSION_MAX_AGE = 30 * 24 * 60 * 60;

export class KonversifySessionError extends Error {
  constructor(public status: 503, public reason: string) {
    super(`konversify sso session: ${reason}`);
  }
}

// Issues the standard NextAuth JWT session exactly the way the login flow
// does: the same jwt.encode wrapper from next-auth-options (which honors a
// user's sessionTimeout metadata) and the same session-token cookie
// (name + options) NextAuth itself sets. A minimal token {sub, email} is
// enough — the jwt callback rebuilds the full session (profile, upId, org)
// from the database on the next /api/auth/session request.
export async function issueKonversifySession(
  user: Pick<User, "id" | "name" | "email" | "avatarUrl">
): Promise<KonversifySsoSession> {
  const secret = process.env.NEXTAUTH_SECRET;
  if (!secret) {
    throw new KonversifySessionError(503, "not_configured");
  }

  const sessionToken = await getOptions({
    getDubId: () => undefined,
    getTrackingData: () => ({}),
  }).jwt.encode({
    token: {
      sub: String(user.id),
      name: user.name ?? undefined,
      email: user.email,
      ...(user.avatarUrl ? { picture: user.avatarUrl } : {}),
    },
    secret,
    maxAge: SESSION_MAX_AGE,
  });

  if (typeof sessionToken !== "string") {
    throw new KonversifySessionError(503, "encode_failed");
  }

  const sessionCookie = defaultCookies(
    WEBAPP_URL?.startsWith("https://")
  ).sessionToken;

  return {
    sessionToken,
    cookieName: sessionCookie.name,
    cookieOptions: { ...sessionCookie.options } as CookieOption["options"],
    cookieMaxAge: SESSION_MAX_AGE,
  };
}
