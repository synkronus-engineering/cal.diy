import { randomString } from "@calcom/lib/random";
import slugify from "@calcom/lib/slugify";
import type { User } from "@calcom/prisma/client";
import { CreationSource, MembershipRole } from "@calcom/prisma/enums";
import type { PrismaClient } from "@calcom/prisma/client";
import type { KonversifySsoClaims } from "./types";
import { KonversifySsoError } from "./verify-token";

type Db = Pick<PrismaClient, "user" | "team" | "membership">;

// ChatbotX workspaces map 1:1 to cal.diy teams (booking teams, not
// organizations). The deterministic key is the team slug:
// "konversify-ws-<workspaceId>". Only this module creates teams with that
// slug pattern.
export const konversifyTeamSlug = (workspaceId: string) =>
  slugify(`konversify-ws-${workspaceId}`);

// The shell mints the token with the member's role in the target workspace
// ("owner" | "agent"): only actual workspace owners get the team OWNER grade,
// everyone else lands on ADMIN (the manage-team grade; MEMBER could not edit
// team event types).
const membershipRole = (shellRole: string) =>
  shellRole.toLowerCase() === "owner" ? MembershipRole.OWNER : MembershipRole.ADMIN;

export async function ensureKonversifyTeam(workspaceId: string, db: Db) {
  const slug = konversifyTeamSlug(workspaceId);
  const existing = await db.team.findFirst({
    where: { slug, parentId: null },
    orderBy: { id: "asc" },
  });
  if (existing) {
    return existing;
  }

  const created = await db.team.create({
    data: {
      name: `Konversify ${workspaceId}`,
      slug,
    },
  });

  // two concurrent first logins for the same workspace can both pass the
  // findFirst above (slug, NULL parentId) is not enforced as unique by the
  // database): the oldest team is the canonical one, so drop the loser.
  // Nothing can reference it yet — memberships are created after this.
  const canonical = await db.team.findFirst({
    where: { slug, parentId: null },
    orderBy: { id: "asc" },
  });
  if (!canonical) {
    throw new KonversifySsoError(503, "team_recheck_failed");
  }
  if (canonical.id !== created.id) {
    await db.team.delete({ where: { id: created.id } });
    return canonical;
  }

  return created;
}

export async function ensureKonversifyUser(claims: KonversifySsoClaims, db: Db) {
  const existing = await db.user.findFirst({
    where: { email: { equals: claims.email, mode: "insensitive" } },
    orderBy: { id: "asc" },
  });
  if (existing) {
    return existing;
  }

  // mirrors the OAuth user creation in next-auth-options: slugified username
  // with a random suffix, pre-verified email. No UserPassword row is created,
  // so dashboard password login is impossible for SSO users — they sign in
  // through Konversify only.
  return db.user.create({
    data: {
      username: `${slugify(claims.email.split("@")[0])}-${randomString(6).toLowerCase()}`,
      email: claims.email,
      name: claims.email.split("@")[0],
      emailVerified: new Date(Date.now()),
      verified: true,
      creationSource: CreationSource.WEBAPP,
    },
  });
}

export async function ensureKonversifyMembership(
  user: { id: number },
  team: { id: number },
  shellRole: string,
  db: Db
) {
  return db.membership.upsert({
    where: {
      userId_teamId: {
        userId: user.id,
        teamId: team.id,
      },
    },
    update: {
      role: membershipRole(shellRole),
      accepted: true,
    },
    create: {
      userId: user.id,
      teamId: team.id,
      role: membershipRole(shellRole),
      accepted: true,
    },
  });
}
