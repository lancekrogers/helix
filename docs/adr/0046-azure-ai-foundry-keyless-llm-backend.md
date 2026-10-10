# ADR-0046 — Azure AI Foundry as a keyless LLM backend

## Status

Accepted.

## Context

The LLM gateway (ADR-0008, ADR-0033) defaults to the first-party vendors:
`api.anthropic.com` for the `claude-*` family, `api.openai.com` for `gpt-*`/`o*`.
A primary use case for the platform is **deployment into a customer's Azure
subscription**, where the customer wants inference billed to and contained in
their own estate — [Azure AI Foundry](https://learn.microsoft.com/en-us/azure/foundry/)
(Microsoft's model hosting, including both Azure OpenAI and Anthropic's Claude
models), not a call out to a first-party API.

What Foundry offers at the resource level (verified against Microsoft Learn,
2026-09):

- **Both wire protocols we already speak.** One account serves the Anthropic
  Messages API at `https://<account>.services.ai.azure.com/anthropic/v1/messages`
  (same `anthropic-version` header contract) and the versionless v1
  OpenAI API at `https://<account>.services.ai.azure.com/openai/v1/chat/completions`
  (no `api-version`; GA since 2025-08). The `model` field routes by
  **deployment name**.
- **Keyless auth via Microsoft Entra ID.** Tokens scoped
  `https://ai.azure.com/.default`, presented as `Authorization: Bearer`, gated by
  RBAC on the account (`Cognitive Services User` for the Foundry Models plane,
  `Cognitive Services OpenAI User` for the Azure OpenAI plane). Microsoft's
  recommended posture; some Claude models are Entra-**only**. API keys
  (`x-api-key` / `api-key` headers) remain available unless the account has
  `disableLocalAuth`.

What the platform already had: the two vendor upstreams are env-configured
**origins** (`EDGE_LLM_ENDPOINT`, `EDGE_LLM_OPENAI_ENDPOINT`), and the vendor
credential is a `platform`-scoped connection secret resolved and injected by
egress — the edge holds nothing (ADR-0008). What was missing: the upstream
**path** was hardcoded per vendor (`/v1/messages`, `/v1/chat/completions`), which
cannot express Foundry's prefixed paths; and a keyless credential needs a
mechanism, because there is no secret to seal.

## Decision

1. **The upstream path is config, like the origin.** New optional env
   `EDGE_LLM_ANTHROPIC_PATH` / `EDGE_LLM_OPENAI_PATH` (defaults unchanged), parsed
   in the edge's config block and carried by the `EgressLlmVendor` descriptor.
   Endpoints stay origin-only; a query in a path is refused at boot (the
   egress path-binding check could never see it). This is the **entire edge
   change**: routing stays catalog-driven (`providerForModel`), and because the
   Foundry deployment name is set equal to the catalog model id
   (`packages/shared/src/pricing.ts`), there is no model-mapping layer — apps,
   per-app allowlists, and USD metering are oblivious to the substrate.

2. **Keyless credentials are minted by egress, per call, behind an explicit
   allowlist.** New env `EGRESS_MANAGED_IDENTITY_CONNECTIONS` =
   comma-separated `connection=host-suffix` pairs (e.g.
   `foundry=contoso.services.ai.azure.com`). In `ManagedIdentityResolver`
   (wrapping the Postgres resolver): a **stored row always wins** (explicit
   config beats ambient identity — and it is what keeps local dev, which has no
   managed identity, on the same code path); absent a row, egress mints an Entra
   token via the existing zero-dependency `ManagedIdentityTokenProvider` seam
   (`resource: https://ai.azure.com`) and injects it as
   `Authorization: Bearer` — the one header shape both Foundry endpoint families
   accept. The mint path refuses unless all of: the capability is `llm` (a
   `fetch` instruction can never mint, the same wall that bars it from
   `platform` secrets); the connection name is allowlisted; and the
   instruction's origin host matches the rule's suffix. That last pin is the
   exfiltration guard: a forged instruction naming the connection but a foreign
   origin would otherwise draw a live platform-identity token onto any host —
   pin the exact account host (`contoso.services.ai.azure.com`), not the shared
   zone, which is what the Bicep derives and the docs show. Boot fails loudly
   when the list is set without the managed-identity env, **or** without a
   custody store (a null inner resolver would turn every other secret-backed
   call's clear "502 store not configured" into a misleading "403 connection
   not found") — the same crash-rather-than-degrade posture as the Key Vault
   wiring. The token audience is a code constant with an
   `EGRESS_MANAGED_IDENTITY_RESOURCE` env override — a spike/sovereign escape
   hatch (validated as a bare https origin), not a supported second path; if
   the Azure OpenAI plane proves to want a different audience, the flip is an
   env change, not a rebuild.

3. **One-stop Bicep.** `infra/azure/modules/foundry.bicep` behind
   `param deployFoundry`, deployed into the account's own resource group via
   `modules/foundry-rg.bicep` (the cost-axis split — see Consequences): one
   `Microsoft.CognitiveServices/accounts` (kind
   `AIServices`, `customSubDomainName` — required for token auth,
   `disableLocalAuth: true` by default), one serverless `GlobalStandard`
   deployment per `foundryModels` entry (deployment name == catalog model id;
   serverless = pay-per-token, nothing billed idle; quota pools are per model
   per subscription so the entries don't compete), the Anthropic marketplace
   attestation (`modelProviderData`) from `foundryAttestation`, and the egress
   identity's two inference role assignments (declared *before* the deployments
   so the provisioning time doubles as RBAC propagation). `main.bicep` then
   wires both families' endpoint/path/connection env on the edge + dev-gateway
   and sets `EGRESS_MANAGED_IDENTITY_CONNECTIONS` on egress — **no seeding
   step**.    Bring-your-own Foundry is first-class params (`llmOpenAiEndpoint` is
   new, plus the path and connection-name knobs); the template exports
   `egressIdentityPrincipalId` so a BYO customer can grant the same roles on
   their own account, and takes `egressManagedIdentityConnections` so BYO
   keyless is declared in the template too — an out-of-band
   `az containerapp update` env edit would be silently reverted by the next
   apply.

4. **Key mode stays** for local dev and key-only BYO: the seed script
   (`seed:llm`) takes `--name`/`--recipe` (`x-api-key` for the `/anthropic`
   family, `api-key` for the `/openai` family — one Foundry account key seeds
   both). Rotation is re-seed, as today.

5. **Telemetry ships with the seam:** the egress span records
   `helix.credential_source` ∈ {`secret`, `managed-identity`} — two bounded
   values, added to the egress attribute *allowlist* (ADR-0037 decision 6). A
   token-endpoint failure surfaces as the same opaque 502 as a custody failure
   (its message carries no credential); the mint is awaited inside the existing
   proxy span, no new span.

## Consequences

- **The trust model holds, unchanged.** The edge still holds no vendor
  credential and has no new outbound route; egress's identity gains one new
  token audience (`ai.azure.com`). The minted token's blast radius is inference
  on the one account the rule pins to — narrower than the stored-secret
  residual ADR-0013 already accepts (a forged instruction can *use* but not
  *relocate* the credential).
- **Catalog coupling is deliberate.** `foundryModels`' default mirrors
  `MODEL_PRICING`; a catalog addition does not retro-provision (operator adds a
  deployment), and a catalog model with no deployment 404s upstream → app sees
  a 502. The 32-deployments-per-account Azure limit bounds the catalog-on-one-
  account pattern; sharding to a second account is the documented escape.
- **Verified-by-reading, spike to confirm.** The stream mappers already handle
  Azure's RAI `finish_reason: content_filter` (mapped to `refusal`) and the
  Anthropic-shaped envelopes are vendor-identical per the docs — but no live
  Foundry call has been made from this codebase yet. Before calling this done
  for a customer: deploy with the flag, run `examples/chatbot` against both
  families, confirm structured output (`response_format` json_schema) and cache
  accounting behave. Region availability, Claude marketplace terms, and
  pay-as-you-go Claude default quotas (40 RPM, and 0 for the Fable line) are
  operator realities documented in `infra/azure/README.md`, not code.
- **Deliberately not done:** private endpoints for the Foundry account (a PE
  resolves to a private IP, which the egress SSRF connector blocks wholesale —
  a per-origin exception is its own ADR); per-customer model aliasing (the
  deployment-name==catalog-id convention exists precisely to avoid it);
  per-model Azure list-price drift vs the platform price book (the catalog is
  the platform's price book; the customer's Azure bill is theirs).
- **Cost-axis isolation is topological.** The account deploys into its own
  resource group (`modules/foundry-rg.bicep`, `<namePrefix>-foundry-rg`)
  because consumption-budget filters are a conjunction of `In` comparisons
  with no `not` (verified against the `Microsoft.Consumption/budgets`
  2024-08-01 schema, 2026-09): "the platform's groups except Foundry" is not
  expressible. Both billing planes roll up under the account's group —
  first-party account meters for Azure-sold (OpenAI-family) models,
  Marketplace `<model>-<guid>` entries for Anthropic — so the platform budget
  keeps zero filter surface and one group-scoped budget
  (`modules/alerts-cost-foundry.bicep`, `llmMonthlyBudgetUsd`, default 1000 to
  match the portal's `platformMonthlyUsdCap` watch line) covers all LLM spend.
  Azure offers **no native hard spend cap** for Foundry — Microsoft's own docs
  say so, and the only documented enforcement route (budget → action group →
  custom automation) is a new subsystem riding on cost data that lands 8–24h
  late; deliberately not built. The real caps stay where they were: the
  per-app daily token budgets (synchronous, at the edge) and the
  per-deployment TPM `capacity`, which is the hard, real-time, Azure-side
  bound on burn rate.

## Amendment (2026-10-10): the firewall allow-list

When `egressFqdnMode` is `allowlist` and `deployFirewall` is true, the Foundry account host (`<foundryAccountName>.services.ai.azure.com`, derived in `main.bicep` from `deployFoundry` or from `egressManagedIdentityConnections`) must appear in the egress product FQDN list the firewall enforces. A private-endpoint Foundry account remains unsupported: a PE resolves to a private address the SSRF connector blocks (the "Deliberately not done" bullet above).
