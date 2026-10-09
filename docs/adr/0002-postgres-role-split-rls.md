# 0002. Postgres least-privilege role split + RLS

**Status:** Accepted
**Related:** ADR [0001](0001-three-runtime-split.md); review ISSUE-05, ISSUE-12, ISSUE-13

## Context

The runtime split (ADR [0001](0001-three-runtime-split.md)) is a process boundary. An in-process compromise (RCE) bypasses it unless the database enforces the same boundary independently.

## Decision

Each runtime connects as a distinct least-privilege Postgres role:

- **`helix_portal`** — full DML runtime role for the control plane. It is **not** the schema owner: migrations run as the `helix` owner (Prisma), so a portal RCE holds DML but cannot `DROP TABLE` or bypass RLS as owner/superuser.
- **`helix_edge`** — explicit per-table grants only: read the registry projection, append-only metering, INSERT-only on collection items, RLS-partitioned `app_data`. **No grant on `app_secrets` at all.**
- **`helix_egress`** — `SELECT` on secrets + `UPDATE` on one `lastUsedAt` column.

App-data isolation uses Row-Level Security with `FORCE ROW LEVEL SECURITY` and `SET LOCAL` GUCs (`app.app_id`, `app.user_oid`) derived from the verified session, set via parameterized `set_config` inside the request transaction. `helix_edge` is `NOBYPASSRLS`.

## Consequences

- An edge RCE cannot read a secret, write the registry, or enumerate another tenant's `app_data` — the grant simply isn't there.
- `SET LOCAL` is transaction-scoped, so a pooled connection can't leak one request's tenant context into the next.
- Cost: hand-managed grants/migrations and RLS policies; mistakes are silent (a missing grant fails closed, an over-broad grant fails open).

## Review notes (2026-06-25)

Verified **sound**: `set_config` is parameterized (no injection), RLS fails closed (missing GUC → NULL → zero rows), `app_secrets` deny confirmed by integration test. Residual hardening, not breaches:
- ~~No `statement_timeout` on edge pools → pool-exhaustion DoS (ISSUE-05).~~ **Resolved (2026-07-21):** every edge pg pool is built through `createEdgePool` (`apps/edge/src/db/pool.ts`), which applies a per-query `statement_timeout` (Postgres-enforced, so it holds even under a starved event loop). Default 10 s, `EDGE_STATEMENT_TIMEOUT_MS` to tune; covers all five stores plus the registry listener's pool and LISTEN client. **Egress's two pools followed (2026-09-23):** the burn store and secret resolver build through egress's own `createEgressPool` (`apps/egress/src/pool.ts`) — same ceiling, default 10 s, `EGRESS_STATEMENT_TIMEOUT_MS` to tune — rather than re-actively importing the edge's factory, whose `withPooledClient`/SINKS machinery is edge-only (egress runs `Pool.query()` only).
- ~~`gateway_calls` global SELECT, no RLS → cross-tenant read (ISSUE-12).~~ **Resolved (2026-07-21):** `gateway_calls` now carries the same `app.app_id`-partitioned FORCE RLS as `app_data` (migration `20260721033820_rls_gateway_calls_collection_items`). The edge sets the GUC on every metering path via the shared `withPartition` helper (`apps/edge/src/db/partition.ts`; `usage.ts` wraps the budget SUMs + the per-call INSERT). See the framing note below — this is a fail-closed backstop, not RCE containment. Isolation asserted in `usage.rls.integration.test.ts`; the control plane's cross-app reads (usage rollups/audit) keep working via a permissive `gateway_calls_portal_all` policy (`portal-rls.integration.test.ts`).
- ~~`app_collection_items` has no RLS → cross-app write pollution (ISSUE-13).~~ **Resolved (2026-07-21):** same migration adds a `WITH CHECK` partition policy so an INSERT can only land in the GUC's app — an appId-confusion bug fails closed instead of polluting another app's collection. INSERT-only grant (the §3.2 write-only containment) is unchanged; `appendCollection` now runs through `withPartition` (`apps/edge/src/gateway/data.ts`). Tested in `data.integration.test.ts`; the owner-facing drain reads via `app_collection_items_portal_all`.
- ~~`sessions` full DML, no RLS → cross-tenant read (ISSUE-12).~~ **Resolved (2026-07-21):** `sessions` now has `app.app_id`-partitioned RLS (migration `20260721035543_rls_sessions_definer_lookup`). Two wrinkles made it unlike the other two tables: (a) the **hot read path** — `PgSessionStore.lookup` runs in the gate on every request of a gated app — reads through a `SECURITY DEFINER` function `session_lookup(tokenHash, appId)` instead of the raw table, so it stays one round-trip with no partition transaction while a bare `SELECT * FROM sessions` as `helix_edge` scopes to zero rows; (b) the **global GC sweeper** likewise runs through `session_sweep()` (a `FOR DELETE` carve-out policy can't work — the sweep's WHERE reads columns, so SELECT-applicable policies also gate it and hide every row when no GUC is set). Both functions are owner-owned, `search_path`-pinned, `EXECUTE` revoked from `PUBLIC` and granted only to `helix_edge`. The write paths (createPending/createActive/redeem/delete) set the GUC via `withPartition`. Note this table uses **`ENABLE`, not `FORCE`**, on purpose: under `FORCE` the owner is also subject to RLS and — since every policy is role-scoped — the owner-run definer functions would match no policy and be denied; `ENABLE` leaves the owner exempt so they read unimpeded, while `helix_edge` (non-owner) is fully constrained. Tested in `sessions.rls.integration.test.ts`.
- ~~Make `NOBYPASSRLS` explicit in the role bootstrap.~~ **Resolved (2026-07-21):** all three runtime roles are now created `NOINHERIT NOBYPASSRLS` in both the dev bootstrap (`.devcontainer/db-init/01-roles.sql`) and a committed **prod** role bootstrap (`infra/azure/sql/01-roles.sql`, wired into the infra README step 4 in place of the old inline-comment placeholder). `NOBYPASSRLS` is already the `CREATE ROLE` default, so this is hygiene, not a behaviour change — it states the property the partition-RLS backstop leans on at the point of role creation so a later edit can't silently flip it, and covers `helix_portal` too (its cross-app reads route through the permissive `*_portal_all` policies, which only hold if it doesn't bypass).

**Framing (2026-07-21):** the RLS on `gateway_calls` / `app_collection_items` / `sessions` (like `app_data`'s) is keyed on a `SET LOCAL` GUC the edge sets itself. That is a **fail-closed backstop against application bugs** — a forgotten/wrong `WHERE "appId"` matches zero rows / fails the `WITH CHECK` — and it defeats a naive no-GUC smash-and-grab (`SELECT * FROM gateway_calls` → 0 rows). It is **not** RCE containment: an RCE owns the connection and can `set_config('app.app_id', …)` to any app itself (for `sessions`, an RCE can likewise invoke `session_lookup`/`session_sweep` with any argument). The genuine RCE boundary in this system is **grant-absence** (no SELECT on `app_secrets`, no registry write), which is unchanged. Earlier "cross-tenant read under edge RCE" phrasing overstated what a GUC-keyed policy delivers. For `sessions` specifically the read path is also self-scoping regardless of RLS — `tokenHash` is a random 256-bit unique token — so the RLS win there is the naive-dump / forged-INSERT backstop, not the per-request lookup.

## Challenge outcome (2026-06-26)

WEAKEN — code claims verified; two **undisclosed** gaps to add (the `statement_timeout` / `sessions`-DML / `NOBYPASSRLS` items are already above):
- An **owner-DSN fallback** — `apps/edge/src/config.ts:304` `EDGE_DATABASE_URL ?? DATABASE_URL`, where `DATABASE_URL` is the schema **owner**. If the role DSN is unset the edge connects as owner and the split is silently defeated. The running compose *does* set the role DSN, so this is a latent footgun — **boot-fail when the role DSN is absent** rather than fall back.
- ~~The **portal connects as the schema owner**, not `helix_portal` (no `PORTAL_DATABASE_URL` exists), so the `helix_portal` grants are effectively dead code.~~ **Resolved (2026-07-21):** the portal runtime now connects as `helix_portal` via `PORTAL_DATABASE_URL` (`apps/portal/src/db/client.ts` `resolvePortalRuntimeUrl`, wired in the dev compose; required in production, owner-DSN fallback refused there — the same prod-strict shape as the edge's `EDGE_DATABASE_URL`). Migrations still run as the `helix` owner. The `helix_portal` grants are now live; the only remaining owner-bypass path in ADR-0002's model is closed. (The "split is silently defeated" thesis was otherwise an overstatement — the live config already ran least-privilege for the edge and the role-split test passed.)

### Shared-table RLS is *not* the classic foot-gun (2026-06-26)

A review flagged "shared-table RLS is a cross-app leak foot-gun." True as a *pattern* (pool tenancy is the most fragile model; some sources avoid RLS), but **not for this implementation** (5-model red-team + best-practice grounding). The classic foot-gun fails *open* (a forgotten `WHERE tenant_id` exposes all rows); Helix's `app_data` policy fails **closed**: a missing GUC → `current_setting(...,true)` is NULL → **zero rows**, INSERT fails the WITH CHECK (`migrations/20260616231036_app_data/migration.sql:35-37`). Combined with `FORCE` + `ENABLE` RLS, `helix_edge` non-owner/NOBYPASSRLS, a **server-derived** predicate, and `SET LOCAL` in an explicit txn (`gateway/data.ts:83-89`) — this is exactly the AWS-recommended pool-model hardening. The two best-practice CI guards already exist: a cross-app isolation test (`data.integration.test.ts:52`) and a forgotten-GUC zero-rows test (`:143`).

The only *present* cross-tenant read path is the **owner/superuser bypass** (a superuser bypasses RLS even with `FORCE`) — i.e. the portal-as-owner / edge owner-DSN items above, not the shared-table choice. **Physical isolation (schema/DB-per-app) is not warranted** — it trades a fail-closed risk for migration explosion + dynamic DDL from the trusted path and doesn't fix the owner bypass. Severity of the shared-table design itself: **Minor** (pattern-awareness). Only additive hygiene: a lint/banned-import forbidding raw `app_data` queries outside `withPartition` (still open), and codifying explicit `NOBYPASSRLS` on `helix_edge` in the prod role bootstrap (**done** — see the review-notes item above).

## Amendment (2026-09-21) — the permissive `sessions_portal_all` policy is now load-bearing

The admin session-revocation feature (portal Sessions screen; ADR-0004's 2026-09-21 amendment)
is the "future portal read" the `sessions_portal_all` policy was left permissive for. The
control plane now SELECTs live session rows (the admin list) and DELETEs them (the user-level
kill) through that `USING (true)` policy. The verb set was tightened to match at the same time:
migration `20260921120000` revoked `helix_portal`'s INSERT/UPDATE on `sessions`, so the portal
holds SELECT+DELETE only — it cannot mint a session or rebind a `tokenHash` (either is a
credential power: the latter is how a session would be *stolen*), and the handoff's atomic
redeem UPDATE stays edge-only by grant, not just by convention. Same carve-out mechanism as
`20260721120000` (which made `gateway_calls` append-only for every runtime role). Pinned in
`role-split.integration.test.ts`; the kill's effect on the edge's uncached lookup is asserted in
`sessions.rls.integration.test.ts`.

## Amendment (2026-10-09): the platform spend aggregate

Migration `20261009223800_platform_llm_spend_definer` adds `platform_llm_spend_micro_usd(p_env text)`, a
`SECURITY DEFINER` SQL function with `SET search_path = pg_catalog, public`. It returns two
aggregates — `today` and `hour`, both in micro-USD — summing `gateway_calls."costMicroUsd"` for
`capability = 'llm'` in the requested env over the same day and rolling-hour windows the per-app
budget uses (`PgUsageStore.llmSpendMicroUsd`). It exposes no per-app breakdown. `EXECUTE` is
revoked from `PUBLIC` and granted to `helix_edge` only; `helix_dev` has no grant (the dev gateway
does not enforce the platform ceiling).

`gateway_calls` uses `FORCE ROW LEVEL SECURITY`, so the table owner is subject to RLS like any
other role. Every existing policy is scoped to a runtime role, so a definer function owned by the
migration role would match no policy and return zero rows — silently disabling a platform ceiling.
The migration therefore adds `gateway_calls_owner_read` (`FOR SELECT TO <migration owner> USING
(true)`), with the role name bound at apply time via `format('%I', current_user)`. Production
migrations run as `helixadmin` (`postgresAdminLogin` in `infra/azure/main.bicep`); the dev
container runs them as `helix` (the `POSTGRES_USER` object owner).

This does not widen the RCE boundary stated in **Framing (2026-07-21)**: an edge compromise can
already `set_config('app.app_id', …)` and read any app's metering rows one partition at a time.
The function returns only a platform-wide aggregate to the same role; grant absence on
`app_secrets` and registry writes remains the real containment. Pinned in
`usage.rls.integration.test.ts` (including a non-superuser owner probe that fails closed when the
owner policy is removed) and `role-split.integration.test.ts`.

Migration `20261009230444_inflight_leases` adds `inflight_leases` for in-flight concurrency caps
(wired to handlers in a follow-on task). The edge inserts one row per
scope per admitted call and deletes on completion; `expiresAt` bounds leak time when a replica dies
without releasing. `helix_edge` has `SELECT`, `INSERT`, and `DELETE` only (no `UPDATE`); `REVOKE
ALL` on `helix_portal` undoes the blanket owner default grant; `helix_egress` and `helix_dev` have
no grant. No RLS: the `scope` string embeds the app id the way `rate_counters.bucketKey` does, and
the table holds no app payload. An edge compromise could already exhaust its own rate-counter keys;
inserting lease rows to fill caps is the same blast radius. Pinned in `role-split.integration.test.ts`
and `leaseStore.integration.test.ts`.

ADR-0011's spend-containment pointer and ADR-0051 remain for the docs task in the same sequence.
