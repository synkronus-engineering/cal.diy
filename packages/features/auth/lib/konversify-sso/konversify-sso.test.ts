// @vitest-environment node

import http from "node:http";
import nodeCrypto from "node:crypto";
import { AddressInfo } from "node:net";
import { exportJWK, SignJWT } from "jose";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { konversifySsoLogin } from "./login";
import { konversifyTeamSlug } from "./provision";

// vi.mock factories are hoisted above imports — the mock fn must come from
// vi.hoisted or it would not be initialized when the factory runs
const { encodeMock } = vi.hoisted(() => ({
  encodeMock: vi.fn(async ({ token }: { token: unknown }) => `ENCODED:${JSON.stringify(token)}`),
}));

vi.mock("../next-auth-options", () => ({
  getOptions: () => ({
    jwt: {
      encode: encodeMock,
    },
  }),
}));

vi.mock("@calcom/lib/constants", () => ({
  WEBAPP_URL: "https://booking.konversify.app",
}));

vi.mock("@calcom/lib/default-cookies", () => ({
  defaultCookies: (useSecureCookies: boolean) => ({
    sessionToken: {
      name: `${useSecureCookies ? "__Secure-" : ""}next-auth.session-token`,
      options: {
        path: "/",
        httpOnly: true,
        secure: useSecureCookies,
        sameSite: useSecureCookies ? "none" : "lax",
      },
    },
  }),
}));

process.env.KONVERSIFY_SSO_ENABLED = "true";
process.env.KONVERSIFY_SSO_ISSUER = "https://my.konversify.app";
process.env.KONVERSIFY_SSO_AUDIENCE = "konversify-tools";
process.env.NEXTAUTH_SECRET = "test-nextauth-secret";

const ISSUER = process.env.KONVERSIFY_SSO_ISSUER!;
const AUDIENCE = process.env.KONVERSIFY_SSO_AUDIENCE!;
const KID = "test-key-1";

let jwksServer: http.Server;
let signingKey: nodeCrypto.KeyObject;

// mock JWKS endpoint of the Konversify shell, backed by a locally generated
// ES256 keypair
beforeAll(async () => {
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  signingKey = privateKey;
  const jwk = {
    ...(await exportJWK(publicKey)),
    kid: KID,
    alg: "ES256",
    use: "sig",
  };

  jwksServer = http.createServer((req, res) => {
    if (req.url?.includes("/jwks.json")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ keys: [jwk] }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => jwksServer.listen(0, "127.0.0.1", resolve));
  process.env.KONVERSIFY_JWKS_URL = `http://127.0.0.1:${
    (jwksServer.address() as AddressInfo).port
  }/jwks.json`;
});

afterEach(() => {
  vi.clearAllMocks();
});

afterAll(async () => {
  await new Promise<void>((resolve) => jwksServer.close(() => resolve()));
});

const mintToken = (
  claims: Record<string, unknown>,
  options: {
    audience?: string;
    issuer?: string;
    expiresIn?: string;
    kid?: string;
  } = {},
  key: nodeCrypto.KeyObject = signingKey
) =>
  new SignJWT(claims as never)
    .setProtectedHeader({ alg: "ES256", kid: options.kid ?? KID, typ: "JWT" })
    .setIssuedAt()
    .setIssuer(options.issuer ?? ISSUER)
    .setAudience(options.audience ?? AUDIENCE)
    .setExpirationTime(options.expiresIn ?? "2m")
    .sign(key);

const validClaims = () => ({
  sub: "cx-user-1",
  email: "owner@konversify.app",
  workspaceId: "ws_123",
  role: "owner",
});

// ---- in-memory stand-in for the prisma models the provisioning touches ----
type Team = { id: number; name: string; slug: string; parentId: number | null };
type User = {
  id: number;
  email: string;
  username: string;
  name: string;
  emailVerified: Date;
  verified: boolean;
};
type Membership = {
  id: number;
  userId: number;
  teamId: number;
  role: string;
  accepted: boolean;
};

class MemoryDb {
  teams: Team[] = [];
  users: User[] = [];
  memberships: Membership[] = [];
  idCounter = 0;
  // simulates a concurrent first login: the next lookup misses a team that
  // already exists
  skipNextTeamFind = false;

  asDb(): any {
    const db = this;
    return {
      user: {
        findFirst: async ({ where }: any) =>
          db.users.find(
            (u) => u.email.toLowerCase() === where.email.equals.toLowerCase()
          ) ?? null,
        create: async ({ data }: any) => {
          const user: User = {
            id: ++db.idCounter,
            email: data.email,
            username: data.username,
            name: data.name,
            emailVerified: data.emailVerified,
            verified: data.verified,
          };
          db.users.push(user);
          return user;
        },
      },
      team: {
        findFirst: async ({ where }: any) => {
          if (db.skipNextTeamFind) {
            db.skipNextTeamFind = false;
            return null;
          }
          return db.teams.find((t) => t.slug === where.slug) ?? null;
        },
        create: async ({ data }: any) => {
          const team: Team = {
            id: ++db.idCounter,
            name: data.name,
            slug: data.slug,
            parentId: null,
          };
          db.teams.push(team);
          return team;
        },
        delete: async ({ where }: any) => {
          const index = db.teams.findIndex((t) => t.id === where.id);
          db.teams.splice(index, 1);
        },
      },
      membership: {
        upsert: async ({ where, update, create }: any) => {
          const existing = db.memberships.find(
            (m) =>
              m.userId === where.userId_teamId.userId &&
              m.teamId === where.userId_teamId.teamId
          );
          if (existing) {
            Object.assign(existing, update);
            return existing;
          }
          const created = { id: ++db.idCounter, ...create };
          db.memberships.push(created);
          return created;
        },
      },
    };
  }
}

const login = (token: string, db: MemoryDb) => konversifySsoLogin(token, db.asDb());

describe("konversifySsoLogin", () => {
  beforeEach(() => {
    process.env.KONVERSIFY_SSO_ENABLED = "true";
  });

  it("a valid token yields a NextAuth session for the JIT user and workspace team", async () => {
    const db = new MemoryDb();
    const result = await login(await mintToken(validClaims()), db);

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");

    expect(db.teams).toHaveLength(1);
    expect(db.teams[0].slug).toBe(konversifyTeamSlug("ws_123"));
    expect(db.users).toHaveLength(1);
    expect(db.users[0].email).toBe("owner@konversify.app");
    expect(db.users[0].verified).toBe(true);
    expect(db.users[0].emailVerified).toBeInstanceOf(Date);
    // membership: accepted owner
    expect(db.memberships).toHaveLength(1);
    expect(db.memberships[0].role).toBe("OWNER");
    expect(db.memberships[0].accepted).toBe(true);
    expect(db.memberships[0].userId).toBe(db.users[0].id);
    expect(db.memberships[0].teamId).toBe(db.teams[0].id);

    // session issued through the login flow's jwt.encode with a minimal
    // token (sub/email), set on the secure next-auth session cookie
    expect(result.session.cookieName).toBe("__Secure-next-auth.session-token");
    expect(result.session.cookieOptions).toMatchObject({
      httpOnly: true,
      secure: true,
      sameSite: "none",
    });
    expect(result.session.cookieMaxAge).toBe(30 * 24 * 60 * 60);
    expect(encodeMock).toHaveBeenCalledTimes(1);
    const encodedArg = encodeMock.mock.calls[0][0];
    expect(encodedArg.token).toMatchObject({
      sub: String(db.users[0].id),
      email: "owner@konversify.app",
    });
    expect(encodedArg.secret).toBe("test-nextauth-secret");
    expect(result.session.sessionToken).toContain("ENCODED:");
  });

  it("maps a non-owner shell role to ADMIN, never OWNER", async () => {
    const db = new MemoryDb();
    await login(await mintToken({ ...validClaims(), role: "agent" }), db);

    expect(db.memberships).toHaveLength(1);
    expect(db.memberships[0].role).toBe("ADMIN");
  });

  it("a second login reuses the user, the team and the membership", async () => {
    const db = new MemoryDb();

    await login(await mintToken(validClaims()), db);
    await login(await mintToken(validClaims()), db);

    expect(db.users).toHaveLength(1);
    expect(db.teams).toHaveLength(1);
    expect(db.memberships).toHaveLength(1);
  });

  it("re-accepts and re-grades a membership of a returning user", async () => {
    const db = new MemoryDb();

    await login(await mintToken(validClaims()), db);
    db.memberships[0].accepted = false;

    await login(await mintToken({ ...validClaims(), role: "agent" }), db);

    expect(db.memberships[0].accepted).toBe(true);
    expect(db.memberships[0].role).toBe("ADMIN");
  });

  it("a concurrent first login keeps the older team as canonical", async () => {
    const db = new MemoryDb();
    db.teams.push({ id: 999, name: "Konversify ws_123", slug: konversifyTeamSlug("ws_123"), parentId: null });
    db.skipNextTeamFind = true;

    const result = await login(await mintToken(validClaims()), db);

    expect(db.teams).toHaveLength(1);
    expect(db.teams[0].id).toBe(999);
    expect(result.ok && db.memberships[0].teamId).toBe(999);
  });

  it("a token with the wrong audience is rejected with 401", async () => {
    const result = await login(
      await mintToken(validClaims(), { audience: "some-other-tool" }),
      new MemoryDb()
    );
    expect(result).toMatchObject({ ok: false, status: 401 });
  });

  it("an expired token is rejected with 401", async () => {
    const result = await login(
      await mintToken(validClaims(), { expiresIn: "-1m" }),
      new MemoryDb()
    );
    expect(result).toMatchObject({ ok: false, status: 401 });
  });

  it("a token from a different issuer is rejected with 401", async () => {
    const result = await login(
      await mintToken(validClaims(), { issuer: "https://evil.example" }),
      new MemoryDb()
    );
    expect(result).toMatchObject({ ok: false, status: 401 });
  });

  it("a token signed by a key that is not in the JWKS is rejected with 401", async () => {
    const stranger = nodeCrypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    const result = await login(
      await mintToken(validClaims(), { kid: "unknown-kid" }, stranger.privateKey),
      new MemoryDb()
    );
    expect(result).toMatchObject({ ok: false, status: 401 });
  });

  it("a token without an email claim is rejected with 401", async () => {
    const result = await login(
      await mintToken({ ...validClaims(), email: "" }),
      new MemoryDb()
    );
    expect(result).toMatchObject({ ok: false, status: 401 });
  });

  it("an unreachable JWKS endpoint is a server fault (503), not an invalid token (401)", async () => {
    const jwksUrl = process.env.KONVERSIFY_JWKS_URL;
    // nothing listens on this port
    process.env.KONVERSIFY_JWKS_URL = "http://127.0.0.1:9/jwks.json";
    try {
      const result = await login(await mintToken(validClaims()), new MemoryDb());
      expect(result).toMatchObject({ ok: false, status: 503 });
    } finally {
      process.env.KONVERSIFY_JWKS_URL = jwksUrl;
    }
  });

  it("a half-configured deployment is unavailable (503), never silently accepting", async () => {
    const issuer = process.env.KONVERSIFY_SSO_ISSUER;
    delete process.env.KONVERSIFY_SSO_ISSUER;
    try {
      const result = await login(await mintToken(validClaims()), new MemoryDb());
      expect(result).toMatchObject({ ok: false, status: 503 });
    } finally {
      process.env.KONVERSIFY_SSO_ISSUER = issuer!;
    }
  });

  it("a missing NEXTAUTH_SECRET cannot issue sessions (503)", async () => {
    const secret = process.env.NEXTAUTH_SECRET;
    delete process.env.NEXTAUTH_SECRET;
    try {
      const result = await login(await mintToken(validClaims()), new MemoryDb());
      expect(result).toMatchObject({ ok: false, status: 503 });
    } finally {
      process.env.NEXTAUTH_SECRET = secret!;
    }
  });

  it("the feature flag off hides the endpoint (404)", async () => {
    process.env.KONVERSIFY_SSO_ENABLED = "false";
    const result = await login(await mintToken(validClaims()), new MemoryDb());
    expect(result).toMatchObject({ ok: false, status: 404 });
  });
});
