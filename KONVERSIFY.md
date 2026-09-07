# Konversify SSO

Single-sign-on from the Konversify shell (ChatbotX) into this cal.diy
deployment. Purely additive: one module under
`packages/features/auth/lib/konversify-sso`, one API route, one page. No
changes to existing auth internals.

## Flow

```
ChatbotX shell (my.konversify.app)
  └─ iframe src: https://booking.konversify.app/sso#t=<jwt>   (fragment, never query)
       └─ /sso page reads location.hash, POSTs { token } to POST /api/konversify/sso
            └─ backend: JWKS + iss + aud + exp verification (ES256, jose)
                 └─ JIT user by email → ensure team → ensure membership
                      └─ NextAuth JWT session issued exactly as the login flow does
                         (same jwt.encode wrapper, same session-token cookie)
                           └─ /sso page redirects to /
```

The shell mints a short-lived (120s) ES256 access token with BetterAuth's JWT
plugin. Claims: `sub` (ChatbotX user id), `email`, `workspaceId`, `role`,
`iss`, `aud`, `iat`, `exp`. The token only ever travels in the URL fragment
(fragments are not sent to servers or written to proxy logs) and is stripped
from the URL/history as soon as the `/sso` page reads it. Tokens are never
logged; every rejection logs one token-safe reason string only (jose error
messages embed received claim values and are never surfaced).

## Endpoint

`POST /api/konversify/sso` with body `{ "token": "<jwt>" }`

- `404` when `KONVERSIFY_SSO_ENABLED` is not `true` (endpoint hidden when off)
- `400` malformed body (missing/empty token)
- `401` when the token itself fails verification (bad signature / unknown
  `kid`, wrong issuer, wrong audience, expired, missing `email` or
  `workspaceId`)
- `503` when the handoff cannot be evaluated because of a server-side fault:
  the JWKS endpoint is unreachable/timing out, the SSO envs (or
  `NEXTAUTH_SECRET`) are half-configured. A missing issuer/audience env must
  never fall back to jose's "skip claim check" — it rejects. Distinct from
  `401` so monitoring can alert on outages.
- `200` + the NextAuth session cookie on success

The page at `/sso` is public (it authenticates with the Konversify token
itself); no middleware exception is needed — cal.diy gates auth per page, and
`/sso` performs no session check.

## Workspace → team mapping

One ChatbotX workspace maps to one cal.diy **team** (booking team, not an
organization — orgs in cal.com-land are a heavier concept with domains and
settings). The deterministic key is the team **slug**:
`konversify-ws-<workspaceId>` (slugified; see `konversifyTeamSlug` in
`packages/features/auth/lib/konversify-sso/provision.ts`). First SSO login
for a workspace creates the team (display name `Konversify <workspaceId>`);
later logins find-or-create by exact slug. The database does not enforce
slug uniqueness for top-level teams (`@@unique([slug, parentId])` with NULL
`parentId`), so two concurrent first logins can both pass the lookup — after
creating, the module re-checks and deletes the newer duplicate before
anything can reference it, keeping the oldest team canonical.

## Role mapping

The shell mints the token with the member's role in the target workspace
(`owner` | `agent`). Membership is ensured with:

- `owner` → `MembershipRole.OWNER`
- anything else → `MembershipRole.ADMIN` (the manage-team grade; `MEMBER`
  could not edit team event types). Matches the Postiz SSO adapter's mapping
  (owner → SUPERADMIN, member → ADMIN).

Returning members are re-accepted (`accepted: true`) and re-graded to their
current shell role.

## JIT users

Created exactly like OAuth users in `next-auth-options.ts`: slugified
username from the email local-part with a random 6-char suffix, `emailVerified`
now, `verified` true, `CreationSource.WEBAPP`. **No `UserPassword` row is
created** — dashboard password login is impossible for SSO users (the
credentials provider has no password to compare, same as OAuth users); they
sign in through Konversify only. `email` is the join key (`@@unique([email])`).

## Session mechanism (reused, not reinvented)

`issueKonversifySession` calls the very same `getOptions().jwt.encode`
wrapper the login flow uses (it honors a user's `sessionTimeout` metadata)
with a minimal `{ sub, name, email, picture }` token and 30-day maxAge, and
sets the same `next-auth.session-token` cookie (name + options from
`defaultCookies`). The `jwt` callback's `autoMergeIdentities` rebuilds the
full session (profile, `upId`, org, `belongsToActiveTeam`) from the database
on the next `/api/auth/session` request — the e2e suite relies on the same
self-healing for its programmatic logins.

## Environment variables

| Variable | Purpose |
|---|---|
| `KONVERSIFY_SSO_ENABLED` | Must be `true` to enable the endpoint; anything else → 404 |
| `KONVERSIFY_JWKS_URL` | JWKS endpoint of the shell, e.g. `https://my.konversify.app/api/auth/jwks` |
| `KONVERSIFY_SSO_ISSUER` | Required `iss`, e.g. `https://my.konversify.app` |
| `KONVERSIFY_SSO_AUDIENCE` | Required `aud`, e.g. `konversify-tools` |

All four live in the web app environment (they are read from `process.env` at
request time; `NEXTAUTH_SECRET` is already required by cal.diy). Set them in
`.env` / the container environment.

## Tests

`yarn vitest run packages/features/auth/lib/konversify-sso` — spins up a
local JWKS server with a locally generated ES256 keypair (the real
NextAuth/cookie layer is mocked) and covers: valid token → session, wrong
audience → 401, expired → 401, flag off → 404, unreachable JWKS → 503,
half-configured env → 503, missing `NEXTAUTH_SECRET` → 503, JIT idempotence,
membership re-accept/re-grade, role mapping both grades, and the
concurrent-first-login team race.
