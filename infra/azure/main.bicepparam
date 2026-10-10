using './main.bicep'

// Non-secret configuration. Edit the resource names to globally-unique values
// before first deploy (storage / Key Vault / Postgres names are global).
param namePrefix = 'helix-prod'
param location = 'eastus2'
param storageAccountName = 'helixprodbundles'
param platformVaultName = 'helix-prod-kvp'
param connectionsVaultName = 'helix-prod-kvc'
param delegatedVaultName = 'helix-prod-kvd'
param postgresServerName = 'helix-prod-pg'
// Postgres compute. Burstable (Standard_B1ms / Standard_B2s) is plenty for light
// or smoketest installs; GeneralPurpose Standard_D2ds_v5 is the default here.
// skuTier must match the SKU family: Burstable | GeneralPurpose | MemoryOptimized.
param postgresSkuName = 'Standard_D2ds_v5'
param postgresSkuTier = 'GeneralPurpose'
param postgresStorageSizeGB = 32
param appsDomain = 'azx.helix.azxlabs.io'

// Entra / OIDC. Fill in once the app registrations exist (operator step, or the
// infra/entra Bicep). portalOidcAudience is the bare helix-portal client-id GUID
// (v2 tokens); portalAdminGroupId is the App Role value (e.g. "platform-admin").
param edgeOidcClientId = readEnvironmentVariable('HELIX_EDGE_OIDC_CLIENT_ID', '')
param portalOidcAudience = readEnvironmentVariable('HELIX_PORTAL_OIDC_AUDIENCE', '')
param portalAdminGroupId = readEnvironmentVariable('HELIX_PORTAL_ADMIN_GROUP_ID', '')
param azxCliClientId = readEnvironmentVariable('HELIX_AZX_CLI_CLIENT_ID', '')
param azxWebClientId = readEnvironmentVariable('HELIX_AZX_WEB_CLIENT_ID', '')

// Phase gate. Leave false for the first apply (infra only), flip to true once the
// three images are published to GHCR by CI (see README step 3).
param deployApps = false
// GHCR registry + owner for the CI-built images. Override for a fork.
param imageRegistry = readEnvironmentVariable('HELIX_IMAGE_REGISTRY', 'ghcr.io/azx-pbc-oss')
param imageTag = readEnvironmentVariable('HELIX_IMAGE_TAG', 'latest')

// Opt-in dev-gateway (docs/features/dev-mode.md). Off by default; flip to true
// (with deployApps) to stand up dev-api.<appsDomain>. Needs devDbPassword + the
// helix_dev role (README step 4) and the pre-deploy riders in the feature doc.
param deployDevGateway = false

// Egress firewall (ADR-0001/0005). true = deploy the Azure Firewall that enforces
// the egress-only network zone (the PRIMARY SSRF/egress control). Secure default.
// false skips it to save ~$900/mo but drops that control (a compromised edge can
// then reach the internet; only the egress app-level denylist remains). Data
// services stay private either way. Disable ONLY for dev/smoketest/trusted
// installs — see README "Optional: the egress firewall".
param deployFirewall = true

// Wildcard TLS automation (apps/certbot, ADR-0029). true = deploy the certbot
// scheduled job that issues/renews *.appsDomain via ACME DNS-01 and binds the
// edge wildcard custom domain. Needs acmeEmail (skipped when empty). acmeServer
// defaults to LE staging — flip to the prod directory once validated. Bootstrap:
// trigger the job once after deploy (see README "Wildcard TLS").
param deployCertbot = true
param acmeEmail = readEnvironmentVariable('HELIX_ACME_EMAIL', '')
param acmeServer = readEnvironmentVariable('HELIX_ACME_SERVER', 'https://acme-staging-v02.api.letsencrypt.org/directory')
// Wildcard TLS bindings become declarative (ADR-0044) once the certbot
// bootstrap has run — a cert must exist in the ACA env store before a hostname
// can bind, and this flag bridges that one-time ordering. Leave false for the
// apps-phase apply on a fresh install; flip to true after the first certbot
// job run (README "Wildcard TLS") and never look back. LITERAL on purpose: do
// not readEnvironmentVariable this one — a set-but-blank env var renders ''
// (= false), and the blank direction is the silent-wipe one.
param wildcardTlsBound = false

// Portal access. false = internal ingress (secure default). true = expose the
// control plane at portal.<appsDomain> on the public LB, gated by Entra OIDC
// (per-app authz via ownsApp, ADR-0007). A customer-run install (ADR-0028)
// generally needs this — the portal is the control plane + azx-cli target. See
// README "Portal access".
param portalExternal = false

// App visibility policy. Each sets a MATCHED PAIR of app env vars (edge serves,
// portal authors) — deliberately one knob per mode so the two planes cannot
// disagree. Both default false, matching the app-level default: an install
// serves only Entra-authenticated apps until an operator opts in. Review
// ADR-0010 (anonymous shared writes) before enabling public apps.
param allowPublicApps = false
param allowPasswordApps = false

// Azure AI Foundry (ADR-0046) — LLM inference in this subscription instead of
// first-party Anthropic/OpenAI. false (default) keeps the first-party vendors
// (seed their keys per README). true deploys a Foundry account + the default
// foundryModels list (the deployable-on-a-fresh-subscription subset of the
// platform catalog — audited eastus2 2026-09-16; the Deprecating-default and
// zero-quota entries are deliberately NOT in it, see main.bicep), grants the
// egress identity inference RBAC, and points both model families at it —
// keyless, no vendor key anywhere. Deployments are serverless pay-per-token
// (nothing billed when idle). Notes:
//  - foundryAttestation is REQUIRED when foundryModels includes Anthropic
//    entries on a subscription that has never accepted the Anthropic offer
//    (industry is lowercase: technology|finance|healthcare|education|retail|
//    manufacturing|government|media|other).
//  - Model availability is regional; Claude is narrower than GPT. The default
//    foundryLocation (the platform location) may need overriding. Quota is per
//    model per subscription: run the two pre-apply checks in README "Azure AI
//    Foundry" before committing to a list.
//  - BYO Foundry instead: leave this false and set llmEndpoint/llmOpenAiEndpoint
//    (+ llmAnthropicPath/llmOpenAiPath and the connection names) — see README
//    "Azure AI Foundry".
param deployFoundry = false
// param pinPrivateEndpointAddresses = true  // new installs: static snet-pe IPs for egress NSG rules; existing installs leave false until live addresses are listed
// param privateEndpointAddresses = { kvConnections: '10.0.7.20' }  // optional overrides when pinning; defaults are .4-.7 of snet-pe
// param foundryAccountName = ''            // default ${namePrefix}-foundry; must be globally unique
// param foundryResourceGroupName = ''      // default ${namePrefix}-foundry-rg — the account's OWN group: the split that keeps LLM spend out of the platform budget (README "Azure AI Foundry")
// param foundryLocation = 'eastus2'
// param foundryAttestation = { organizationName: 'Contoso', countryCode: 'US', industry: 'technology' }
// param llmMonthlyBudgetUsd = 1000         // notify-only LLM budget on the Foundry group; 0 = none. Default matches platformMonthlyUsdCap so the Azure mail and the portal watch line agree
// param llmPlatformDollarsPerDay = -1      // enforced daily LLM ceiling on the edge (-1 = one tenth of platformMonthlyUsdCap; 0 = off)
// param llmDefaultDollarsPerDay = 50      // enforced daily cap for apps with no manifest dollarsPerDay (EDGE_LLM_DEFAULT_DOLLARS_PER_DAY); 0 = unset is unlimited

// Servable-model policy (ADR-0047) — what the portal catalogue / rendered
// skill / model picker ADVERTISE. Empty allowlist = the seeded-secret
// heuristic, or — on a deployFoundry install — an auto-derivation from
// foundryModels (the catalogue reads exactly what you deployed). Set the
// allowlist explicitly to override both (e.g. BYO Foundry serving a subset).
// The blocklist subtracts in either mode — the first-party knob for "everything
// except these". Ids must come from the platform catalog
// (packages/shared/src/pricing.ts); unknown ids are ignored (warn-logged).
// param llmModelAllowlist = ['claude-opus-5', 'claude-haiku-4-5', 'gpt-5.1']
// param llmModelBlocklist = ['claude-fable-5', 'claude-fable-5-1']

// Fastify trustProxy for the edge — the ACA Envoy ingress ADDRESS, not a hop
// count (fastify 5.12.1 removed the count form; GHSA-3m5p-2c4r-xxw2). 'auto'
// resolves to 100.64.0.0/10 — the RFC 6598 space ACA draws its ingress pod
// addresses from, which is the peer ingress connects from, and NOT the apps
// subnet the edge itself runs in (issue #13); 'false' (or an explicitly-empty param)
// means trust nothing. Set this only if something else fronts the edge (CDN,
// WAF), and verify req.ip against the live deployment when you do. A stale
// HELIX_EDGE_TRUST_PROXY=1 left over from the hop-count era is REJECTED by
// main.bicep — unset it rather than deploying it. The blank normalization below
// is load-bearing: readEnvironmentVariable falls back only on UNDEFINED, so a
// sourced .env's one-keystroke "remove the export" (HELIX_EDGE_TRUST_PROXY=)
// would otherwise land as '' = trust nothing, with /health green. Blank reads
// as "not set" here; 'false' is the explicit off switch.
var trustProxyEnv = readEnvironmentVariable('HELIX_EDGE_TRUST_PROXY', 'auto')
param edgeTrustProxy = trustProxyEnv == '' ? 'auto' : trustProxyEnv

// --- Secrets — steady state sources every one from the platform vault with
// az.getSecret(). Resolution happens server-side at ARM, so the runner's
// network position is irrelevant and the vault stays publicNetworkAccess:
// Disabled; the deploy principal needs Microsoft.KeyVault/vaults/deploy/action
// (Owner/Contributor include it) and the vault needs enabledForTemplateDeployment
// (the template sets it). getSecret must be a DIRECT param assignment — it
// cannot be nested in any other expression (compile error BCP351), which is why
// there is no env-var fallback here: the fresh-install path is a separate file,
// main.bootstrap.bicepparam. Use it until the vault exists and is seeded, then
// switch to this file. Replace the subscription id / RG / vault name literals
// with your install's. ---
param postgresAdminPassword = az.getSecret('00000000-0000-0000-0000-000000000000', 'rg-helix-prod', 'helix-prod-kvp', 'postgres-admin-password')
param portalDatabaseUrl = az.getSecret('00000000-0000-0000-0000-000000000000', 'rg-helix-prod', 'helix-prod-kvp', 'portal-database-url')
param edgeDatabaseUrl = az.getSecret('00000000-0000-0000-0000-000000000000', 'rg-helix-prod', 'helix-prod-kvp', 'edge-database-url')
param egressDatabaseUrl = az.getSecret('00000000-0000-0000-0000-000000000000', 'rg-helix-prod', 'helix-prod-kvp', 'egress-database-url')
// Only on a deployDevGateway=true install — kv-secrets writes
// edge-dev-database-url only when the dev surface deploys, so on a stock
// install this getSecret would fail the deployment at param evaluation:
// param edgeDevDatabaseUrl = az.getSecret('…', 'rg-…', '…-kvp', 'edge-dev-database-url')
param edgeAuthSecret = az.getSecret('00000000-0000-0000-0000-000000000000', 'rg-helix-prod', 'helix-prod-kvp', 'edge-auth-secret')
param portalSecret = az.getSecret('00000000-0000-0000-0000-000000000000', 'rg-helix-prod', 'helix-prod-kvp', 'portal-secret')
param instructionSecret = az.getSecret('00000000-0000-0000-0000-000000000000', 'rg-helix-prod', 'helix-prod-kvp', 'helix-instruction-secret')
param internalSecret = az.getSecret('00000000-0000-0000-0000-000000000000', 'rg-helix-prod', 'helix-prod-kvp', 'helix-internal-secret')
param exchangeSecret = az.getSecret('00000000-0000-0000-0000-000000000000', 'rg-helix-prod', 'helix-prod-kvp', 'helix-exchange-secret')
// Edge cert (private_key_jwt) — the tenant blocks client secrets. PEM or base64 PEM.
param edgeOidcPrivateKey = az.getSecret('00000000-0000-0000-0000-000000000000', 'rg-helix-prod', 'helix-prod-kvp', 'edge-oidc-private-key')
param edgeOidcCertificate = az.getSecret('00000000-0000-0000-0000-000000000000', 'rg-helix-prod', 'helix-prod-kvp', 'edge-oidc-certificate')
