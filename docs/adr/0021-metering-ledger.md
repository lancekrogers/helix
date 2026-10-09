# 0021. Metering/audit ledger: `gateway_calls`, append-only, token budgets + frozen cost

**Status:** Accepted _(recorded retroactively 2026-06-26 — coverage audit; shipped in M4)_
**Related:** `docs/features/llm-gateway.md`; `packages/shared/src/{usage,pricing}.ts`; `apps/edge/src/gateway/usage.ts`; `apps/portal/prisma/schema.prisma`; ADR [0002](0002-postgres-role-split-rls.md)

## Context

Every gateway call (LLM, data, fetch) must be metered, audited, and budget-enforced. Pricing may change over time, and the audit trail must resist tampering by a compromised edge.

## Decision

One **append-only** `gateway_calls` row per call: `(appId, userOid, userName, userEmail, capability, model, inputTokens, outputTokens, outcome)` plus a **frozen, as-charged `costMicroUsd`** priced at write time from a **code-resident rate table** (`@azx-pbc/shared/pricing.ts`). `helix_edge` has **INSERT-only** (+ `SELECT` for budget sums) — no `UPDATE`/`DELETE` — so integrity rests on the DB grant set, not a hash chain.

- **Daily budgets are USD-denominated** (`dollarsPerDay` on the LLM grant), with a frozen `costMicroUsd` per row priced from the code-resident rate table at write time.
- **Quota is block-new / finish-in-flight:** an admitted request always runs to completion; the *next* request is the one blocked once the budget is crossed.
- The portal recomputes `costUsd` for dashboards from the same rate table at read time.

## Consequences

- Append-only-by-grant resists edge-RCE tampering; it is **not** cryptographically tamper-evident, and no immutable sink is committed — the grant set is the integrity boundary (see the 2026-09-17 amendment).
- Cost is **frozen per call**, so a later rate change never rewrites history; pricing lives in versioned code.
- Budget enforcement reads the frozen `costMicroUsd` column; token counts on the row are the audit view, and portal dollar figures can be recomputed from the same rate table at read time.
- The ledger is a metering + budget primitive, deliberately narrow (no latency/error-detail/size) — not an observability sink.

> Note: `docs/features/llm-gateway.md` was reconciled (2026-07) to document the frozen `costMicroUsd` column — the earlier "tokens, not dollars / no cost column" wording is gone.

## Challenge outcome (2026-06-26)

Challenged on integrity grounds (filed as **#17**, Important): this ledger is not tamper-evident, and "append-only by grant" proved weaker than the Decision implies. The tamper-evidence demand traced to a Phase-1 PM brief engineering never ratified and is **withdrawn** (amendment, 2026-09-17); the grant finding below stood on its own merits and was fixed.

- **"Append-only" binds only the edge.** `helix_edge` is INSERT-only, but **`helix_portal` has `UPDATE`/`DELETE`** on `gateway_calls` (`migration.sql:30-31`), so the control-plane role / schema owner / a portal RCE can rewrite or delete history. (The `schema.prisma:187` comment claiming the portal "never writes" these rows contradicts that grant.)
- **Hash-chaining alone is not the fix.** It's the right primitive (RFC 9162 CT, QLDB), but against a *privileged writer* an in-DB chain is forgeable — the writer recomputes every downstream hash. **External anchoring** of the chain head to a write-only sink outside the writer's control (the §8 immutable sink, `platform-architecture.md:285`) is the **load-bearing** part. Tamper-evident ≠ tamper-proof.
- **GDPR:** two defensible paths, not one — crypto-shredding (per-subject key, hashes over ciphertext) for content/PII rows; a documented legal-obligation/legitimate-interest retention basis (Art. 17(3)) for the metering tuple.

**Sequenced fix:** (1) pre-M5, one line — revoke `helix_portal` `UPDATE`/`DELETE` on `gateway_calls` (makes append-only true for every writer role, aligns the grant with the `schema.prisma:187` comment) — **landed**, migration `20260721120000`; (2) fast-follow before any external audit — hash chain + Merkle + external anchoring — **withdrawn 2026-09-17** with the unratified tamper-evidence requirement (amendment below); (3) GDPR per above — **retained**. Severity Important (the single-trusted-operator pilot bounds insider risk today).

## Amendment (2026-08-28): the metering tuple now includes a request path

The fetch-proxy records the proxied request's `path` and `method`
(`docs/features/fetch-proxy.md`). This widens "the metering tuple" that the
challenge outcome above rests an Art. 17(3) retention basis on, and the widening
is not neutral for the GDPR question:

- A third-party request path routinely embeds personal data — `/users/<email>`,
  `/customers/<id>`, `/documents/<doc-id>`. The rest of the tuple (app, user oid,
  capability, model, tokens, outcome) is platform-generated; a path is not.
- The "it is already logged" argument does **not** fully carry. `redactFetchTarget`
  does keep `origin + pathname` in request logs, but those expire (30-day Log
  Analytics retention, ADR-0037), whereas `gateway_calls` has no `DELETE` grant
  for any role and no pruning job. This moves the value from an expiring store
  into a non-expiring one.

Accepted, with the mitigations below. The erasure path stays open under sequenced
fix (3) — `path` is a reason to prefer crypto-shredding over the retention-basis
argument alone if the ledger ever holds a subject's data that Art. 17 reaches.

**Correction (same date): excluding the query string does not make `path`
credential-free.** An earlier draft of this amendment, and several code comments,
framed the query-string exclusion as the mitigation *for credentials*. That is
wrong, and the claim has been removed everywhere it appeared. The query is where
credentials are *conventionally* placed, but a real class of APIs puts the secret
in a path segment — Telegram `/bot<TOKEN>/sendMessage`, Slack and Discord webhooks
`/services/T…/B…/<secret>`, various signed-URL schemes. Those are now retained.

**No detection heuristic will be added**, and this is a decision rather than an
omission. A token segment and a REST resource id are the same shape: any entropy
or length test that catches `/bot<TOKEN>` also catches `/customers/<uuid>/orders`,
which is precisely the value the column exists to capture. A heuristic would
degrade the feature while still missing structured tokens — the worst of both.

The mitigations are therefore **bounding, not detection**, and none of them is a
substitute for retention:

- The query string is still excluded — it removes the largest and most
  conventional share of the exposure, just not all of it.
- `path` is truncated at write time (`fetchPathOf`), and `model`/`errorDetail`
  are truncated in the store (`clampRecord`), because all three are app-controlled.
- Allowlist-denial rows — the ones whose paths cleared no authorization check at
  all — are rate-capped per (app, env) by `DenialThrottle`, so an app cannot
  append to this table at line rate.

**That cap bounds the rate, not the total.** N per window forever is still
unbounded growth on a table with no `DELETE` grant for any role and no pruning
job. Retention (sequenced fix 3, and the deferred item in `TODO.md`) remains the
actual fix; nothing in the fetch-path work closes it.

## Amendment (2026-08-31) — the captured display half, and what it does to this table

`gateway_calls` gained `userName`/`userEmail`: the caller's directory claims as
captured at the moment of the call. The reason is that `userOid` never attributed
anything. It is Entra's `sub`, which is **pairwise per client id** — a different
value for the same person in every app registration — so it resolves through no
lookup we hold, and `GroupMember.Read.All` (ADR-0040 decision 2) grants no
`/users` read even if it did. An audit log whose subject column names nobody is
an audit log in shape only. The claims are *captured* rather than resolved
because the only id→name map the platform holds is the `sessions` row, swept at
expiry, while these rows are forever — and because "who this was at the time" is
the correct audit semantic anyway. It is the `App.ownerId` vs
`ownerName`/`ownerEmail` split, one table over.

**Two consequences worth stating plainly, because they cut against this ADR.**

**1. This table now holds directly-identifying personal data.** Everything the
2026-08-28 amendment says about the `path` column was still about data that was
*pseudonymous* at the subject level: `userOid` is a pairwise pseudonymous
identifier, and that unresolvability — the defect this amendment fixes — was also
what kept the ledger's subject column at arm's length from a person. An email
address is a direct identifier. That is a change in kind, not degree, on a table
with **no `DELETE` grant for any role** and no pruning job, which means these
labels are unerasable by design. Nothing here closes that; retention (sequenced
fix 3) is still the actual fix, and this strengthens the case for it —
crypto-shredding now looks clearly preferable to arguing a retention basis.

**2. There is no backfill, and there must not be.** Rows predating the columns
keep rendering their raw `userOid`. A maintenance script cannot fix them —
`helix_portal` is REVOKEd from `INSERT`/`UPDATE`/`DELETE` here (migration
`20260721120000`), so it gets `permission denied`, which is this ADR's
append-only-by-grant property doing precisely its job. It could only be done as
the schema owner inside a migration, and that would be the one write that
bypasses the guarantee the grant set exists to make: a tool able to retroactively
edit attributions on the audit log is exactly what "integrity rests on the DB
grant set" promises does not exist. Nobody captured a label at the time; inventing
one later is not a repair. (`app_collection_items` is different in kind — an
owner's own submitted data, which the portal already exports and deletes — so
`helix_portal` holds `UPDATE` there and the operator script
`backfill-user-labels.ts` covers that table alone.)

The labels are truncated in `clampRecord` like the other free-text columns, but
for a **different reason**, and the distinction matters for anyone reading the
cap as a security control: `path`, `model` and `errorDetail` are app-controlled,
and their caps bound what untrusted hosted code can append. `userName`/`userEmail`
arrive in a signed ID token the hosted app cannot influence at all, so their cap
(`apps/edge/src/auth/identity.ts`) is row-size hygiene against an absurd
directory attribute, not a containment boundary.

Finally: the labels stop at the edge. `mintInstruction` and `LlmProvider.stream`
carry the opaque `userOid` alone, because egress is a separate trust boundary and
`AttestedInstructionSchema` deliberately conveys no display half.

## Amendment (2026-09-17): the tamper-evidence requirement is withdrawn

The demand that opened the challenge outcome — a Phase-1 P0 admin story
requiring a **tamper-evident** audit log — traced to *Phase 1 User
Stories.docx*, a PM brief that was never in the repo. The in-repo translation
of it (`docs/phase-1-user-stories.md`) was deleted 2026-08-06 for mapping
against a brief that isn't in the repo, and engineering never ratified the
story as a requirement. It is withdrawn.

What this does and doesn't change:

- **Sequenced fix (1) stands, and has landed.** The grant defect the challenge
  surfaced was real on its own merits, independent of the brief: `helix_portal`
  held `UPDATE`/`DELETE` on `gateway_calls` while the Decision claimed
  append-only. Migration `20260721120000` revoked it to SELECT-only, so
  append-only by grant holds for every runtime role.
- **Sequenced fix (2) is descoped.** Hash chain + Merkle + external anchoring
  was the answer to the withdrawn demand; with no ratified requirement behind
  it, "append-only by grant for every runtime role" is the chosen integrity
  posture, not a gap awaiting work. The challenge analysis above (an in-DB
  chain is forgeable by a privileged writer; anchoring, not chaining, is the
  load-bearing part) stays as the record of *how* to build it if a concrete
  compliance driver ever arrives — that arrival would be a new ADR.
- **Sequenced fix (3) is untouched.** The GDPR/retention question stands on the
  ledger's own contents — `path` (2026-08-28) and the directly-identifying
  `userName`/`userEmail` (2026-08-31) on a table with no `DELETE` grant and no
  pruning job — not on the PM brief. It remains tracked in `TODO.md`.

## Amendment (2026-10-09): cut and failed calls are charged

1. A frozen `costMicroUsd` may be an **estimate** for a call that ended without a final vendor usage block. The row says so: `errorDetail` ends with `;usage=measured`, `;usage=estimated`, or `;usage=mixed`, and `stopReason` is `null`.
2. The Decision bullets above were stale (token-denominated budgets); they now state that LLM daily budgets are **USD-denominated**, aligned with `docs/features/llm-gateway.md` and the gate implementation.
3. **Block-new is unchanged.** An abort by the client or by the wall-clock call deadline is **not** a quota cut — an admitted request is never cut by the budget; only the next request is blocked once spend crosses the cap. Append-only grants are unchanged.

## Amendment (2026-09-22): `userOid` provenance changed — ADR-0048

The 2026-08-31 amendment above describes `userOid` as "Entra's `sub`, pairwise
per client id". ADR-0048 re-based the canonical principal identifier onto
Entra's `oid` claim in both planes, so rows written after that change carry the
directory object id instead — still an opaque id this table only stores, never
renders. Nothing about this amendment's reasoning moves: the display half
stays captured at write, the ledger keeps its historical subjects (a row
records what was true at write time, so pre-re-base rows keep their pairwise
subs — `COUNT(DISTINCT "userOid")` rollups double-count a user straddling the
cutover, cosmetic, once), and the platform still holds no Graph `/users`
grant, so the id still resolves to nobody *by policy* rather than by
pairwise-ness. The erasure analysis in `docs/runbooks/user-labels-and-erasure.md`
is unchanged in every particular.
