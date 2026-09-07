import process from "node:process";
import { createRemoteJWKSet, jwtVerify } from "jose";

import type { KonversifySsoClaims } from "./types";

export class KonversifySsoError extends Error {
  constructor(
    public status: 401 | 503,
    public reason: string
  ) {
    super(`konversify sso rejected: ${reason}`);
  }
}

export function isKonversifySsoEnabled() {
  return process.env.KONVERSIFY_SSO_ENABLED === "true";
}

const jwksByURL = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getJWKS(url: string) {
  let jwks = jwksByURL.get(url);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(url));
    jwksByURL.set(url, jwks);
  }
  return jwks;
}

const errorCode = (err: unknown): string | undefined => {
  const code = (err as { code?: unknown })?.code;
  return typeof code === "string" ? code : undefined;
};

// token-safe classification: only jose error codes / transport error codes are
// used — jose messages embed received claim values and must never be logged
const rejectReason = (err: unknown): string => {
  const code = errorCode(err);

  // jose network failures and a malformed JWKS response are deployment
  // faults, not bad tokens
  if (code === "ERR_JWKS_TIMEOUT" || code === "ERR_JWKS_INVALID") {
    return "jwks_unreachable";
  }
  // fetch transport errors (undici sets ECONNREFUSED / ENOTFOUND / UND_ERR_*)
  if (
    err instanceof TypeError ||
    (code && !code.startsWith("ERR_J")) ||
    err instanceof URIError
  ) {
    return "jwks_unreachable";
  }
  if (code === "ERR_JWKS_NO_MATCHING_KEY") {
    return "no_matching_key";
  }
  if (code === "ERR_JWT_EXPIRED") {
    return "expired";
  }
  return "invalid_token";
};

export async function verifyKonversifyToken(token: string): Promise<KonversifySsoClaims> {
  const jwksUrl = process.env.KONVERSIFY_JWKS_URL;
  const issuer = process.env.KONVERSIFY_SSO_ISSUER;
  const audience = process.env.KONVERSIFY_SSO_AUDIENCE;
  // jose skips claim checks for undefined options — a half-configured
  // deployment must reject tokens, not accept them unchecked
  if (!jwksUrl || !issuer || !audience) {
    throw new KonversifySsoError(503, "not_configured");
  }

  try {
    const { payload } = await jwtVerify(token, getJWKS(jwksUrl), {
      issuer,
      audience,
      algorithms: ["ES256"],
    });

    const claims = payload as unknown as KonversifySsoClaims;
    if (
      typeof claims.email !== "string" ||
      !claims.email ||
      typeof claims.workspaceId !== "string" ||
      !claims.workspaceId
    ) {
      throw new KonversifySsoError(401, "invalid_token");
    }

    return claims;
  } catch (err) {
    if (err instanceof KonversifySsoError) {
      throw err;
    }
    const reason = rejectReason(err);
    throw new KonversifySsoError(reason === "jwks_unreachable" ? 503 : 401, reason);
  }
}
