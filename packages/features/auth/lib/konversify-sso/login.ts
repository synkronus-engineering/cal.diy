import type { PrismaClient } from "@calcom/prisma/client";

import {
  ensureKonversifyMembership,
  ensureKonversifyTeam,
  ensureKonversifyUser,
} from "./provision";
import { issueKonversifySession, KonversifySessionError } from "./issue-session";
import type { KonversifySsoSession } from "./types";
import { isKonversifySsoEnabled, KonversifySsoError, verifyKonversifyToken } from "./verify-token";

type Db = Pick<PrismaClient, "user" | "team" | "membership">;

export type KonversifySsoResult =
  | { ok: true; session: KonversifySsoSession }
  | { ok: false; status: 401 | 404 | 503; reason: string };

export async function konversifySsoLogin(token: string, db: Db): Promise<KonversifySsoResult> {
  if (!isKonversifySsoEnabled()) {
    return { ok: false, status: 404, reason: "disabled" };
  }

  try {
    const claims = await verifyKonversifyToken(token);
    const user = await ensureKonversifyUser(claims, db);
    const team = await ensureKonversifyTeam(claims.workspaceId, db);
    await ensureKonversifyMembership(user, team, claims.role, db);
    const session = await issueKonversifySession(user);
    return { ok: true, session };
  } catch (err) {
    if (err instanceof KonversifySsoError || err instanceof KonversifySessionError) {
      // the reason is a token-safe classification; jose messages embed
      // received claim values and must never surface
      return { ok: false, status: err.status, reason: err.reason };
    }
    throw err;
  }
}
