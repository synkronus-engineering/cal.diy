import type { CookieOption } from "next-auth";

export interface KonversifySsoClaims {
  sub: string;
  email: string;
  workspaceId: string;
  role: string;
}

export interface KonversifySsoSession {
  /** value for the next-auth session-token cookie */
  sessionToken: string;
  cookieName: string;
  cookieOptions: CookieOption["options"];
  cookieMaxAge: number;
}
