// Registry and trusted-proxy alerts (ADR-0025, ADR-0037, ADR-0011).
// - Stale registry: helix.registry.stale_for_ms exceeds the error threshold.
// - Never loaded: registry.never_loaded log event. No freshness gauge exists
//   before the first load, and a cumulative failure counter does not indicate
//   whether the service has recovered.
// - Unresolved proxy: forwarded traffic never resolves beyond the socket peer,
//   combining per-IP limits into ingress-wide buckets.
// - LLM platform ceiling: helix.gateway.admission_denied with reason platform_ceiling.
//
// Query the shared Log Analytics workspace. Its metric table is AppMetrics,
// with Sum/ItemCount/Min/Max columns, not customMetrics.value.
@description('Azure region.')
param location string

@description('Resource name prefix, matching the rest of the deployment.')
param namePrefix string

@description('Log Analytics workspace the rules query — the one the apps environment ships stdout to, and the one the Application Insights component is workspace-based onto.')
param workspaceId string

@description('Resource id of the shared action group (modules/action-group.bicep), or empty. EMPTY deploys the rules with NO notification target — they still evaluate and still show up in the portal\'s fired-alerts list, but they notify nobody.')
param actionGroupId string = ''

@description('Create the staleness rule. Requires the telemetry pipeline, because the rule reads a metric — with `deployTelemetry=false` nothing writes `helix.registry.stale_for_ms` and the rule would sit permanently green. The never-loaded rule is log-based and deploys either way.')
param includeMetricRule bool = true

@description('Staleness that fires the alert, in ms. Default 1200000 (20 minutes) matches the `error` line ADR-0025 grades at 20x the 60s default reconcile interval — the point at which the edge itself calls the projection an error rather than merely degraded. Lower it to 300000 to fire at the `degraded` line instead, accepting more noise from transient DB blips.')
param registryStalenessThresholdMs int = 1200000

@description('How often the rules evaluate (ISO 8601 duration).')
param evaluationFrequency string = 'PT5M'

@description('How far back each evaluation looks (ISO 8601 duration). Must be >= evaluationFrequency. Wider than the frequency on purpose: metric export is batched, so a window equal to the frequency can straddle a gap and read as no data.')
param windowSize string = 'PT15M'

@description('Alert severity: 0 critical .. 4 verbose. Both rules default to 1 (error) — a projection this stale is serving wrong access decisions, which is not a warning.')
@allowed([0, 1, 2, 3, 4])
param severity int = 1

@description('Alert severity for the trust-proxy rule: 0 critical .. 4 verbose. Defaults to 2 — the edge keeps serving correctly while it fires (only per-IP fairness and throttling are gone), so it must not page at the same level as a stale projection, but it is louder than a warning because the fix is a deploy parameter, not a blip.')
@allowed([0, 1, 2, 3, 4])
param trustProxySeverity int = 2

// The action group itself lives in modules/action-group.bicep — one group shared
// by every alert module in the deployment, so a recipient is added in one place.
var actionGroupIds = empty(actionGroupId) ? [] : [actionGroupId]

// ---------------------------------------------------------------------------
// Rule 1 — the projection is stale past the error line
// ---------------------------------------------------------------------------
// `max(Max)` per role: the gauge is read at collection time from every replica,
// and one replica serving a stale copy is the condition worth waking for even
// when its siblings are fresh. Grouping by AppRoleName keeps the edge and the
// dev-gateway (which shares the edge image) from masking each other.
//
// KQL on one line deliberately: Bicep's ''' strings do not interpolate, and the
// threshold has to come from a parameter.
var staleQuery = 'AppMetrics | where Name == "helix.registry.stale_for_ms" | summarize StaleForMs = max(Max) by AppRoleName | where StaleForMs > ${registryStalenessThresholdMs}'

resource registryStaleRule 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = if (includeMetricRule) {
  name: '${namePrefix}-alert-registry-stale'
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: '${namePrefix} registry projection stale'
    description: 'The edge is serving a registry projection older than the ADR-0025 error line, which means it may be enforcing an out-of-date access rule. Read /health\'s registry-projection sub-check and the registry.load_failed log events for the detail.'
    severity: severity
    enabled: true
    scopes: [workspaceId]
    evaluationFrequency: evaluationFrequency
    windowSize: windowSize
    criteria: {
      allOf: [
        {
          query: staleQuery
          // Any row returned is a role over the threshold, so the row count is
          // the condition. No metricMeasureColumn: the query has already done
          // the comparison, which keeps the threshold in one place.
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    // Resolve on its own once the projection reloads — this is a condition, not
    // an event, and it self-heals the moment a load succeeds.
    autoMitigate: true
    actions: {
      actionGroups: actionGroupIds
    }
  }
}

// ---------------------------------------------------------------------------
// Rule 2 — the projection has never loaded
// ---------------------------------------------------------------------------
// Log-based on purpose (see the header). Every app host is 503ing in this
// state, so it is strictly worse than rule 1 and gets the same severity floor.
var neverLoadedQuery = 'ContainerAppConsoleLogs_CL | extend p = parse_json(Log_s) | where tostring(p.event) == "registry.never_loaded" | project TimeGenerated, ContainerAppName_s, ConsecutiveFailures = toint(p.consecutiveLoadFailures)'

resource registryNeverLoadedRule 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = {
  name: '${namePrefix}-alert-registry-never-loaded'
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: '${namePrefix} registry projection has never loaded'
    description: 'The edge has not loaded its registry projection since boot, so every app host is serving 503. Usually the DB is unreachable or the helix_edge role\'s grants are wrong.'
    severity: severity
    enabled: true
    scopes: [workspaceId]
    evaluationFrequency: evaluationFrequency
    windowSize: windowSize
    criteria: {
      allOf: [
        {
          query: neverLoadedQuery
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    autoMitigate: true
    actions: {
      actionGroups: actionGroupIds
    }
  }
}

// ---------------------------------------------------------------------------
// Rule 3 — the trust-proxy walk never resolved (EDGE_TRUST_PROXY wrong)
// ---------------------------------------------------------------------------
// ADR-0011's 2026-09-23 amendment. The edge's trust-proxy /health sub-check
// grades `degraded` once the last 50 forwarded-header requests have all had
// `req.ip === socket peer` — i.e. the configured EDGE_TRUST_PROXY does not name
// the address the ingress actually presents, and every per-IP bucket (anon
// limiter, login throttle, audit hash) has collapsed to one per proxy. A
// `degraded` /health alone alerts nobody (the availability tests fail only on
// `error`), so — like staleness — the condition also rides an observable gauge
// (`helix.edge.trust_proxy.unresolved`: 1 degraded, 0 verified healthy,
// ABSENT while fewer than 50 proxied requests have been seen, so a fresh or
// quiet replica cannot claim health nobody has measured). A gauge absent in
// the unknown state means the rule fires only on real observations.
//
// `max(Max)` per role: one replica going bad is the condition, even when its
// siblings are fine; grouping by AppRoleName keeps the edge and the dev-gateway
// (which shares the edge image and the same env) from masking each other. When
// traffic resolves again the gauge returns to 0 and autoMitigate closes it.
var trustProxyQuery = 'AppMetrics | where Name == "helix.edge.trust_proxy.unresolved" | summarize Unresolved = max(Max) by AppRoleName | where Unresolved > 0'

resource trustProxyRule 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = if (includeMetricRule) {
  name: '${namePrefix}-alert-trust-proxy'
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: '${namePrefix} trust-proxy never resolved'
    description: 'The edge has proxied traffic but `req.ip` never resolves past the socket peer — EDGE_TRUST_PROXY does not name the address the ingress presents, so per-IP rate limiting and throttling have collapsed to one bucket per proxy. Read /health\'s trust-proxy sub-check; see ADR-0011 and issue #13.'
    severity: trustProxySeverity
    enabled: true
    scopes: [workspaceId]
    evaluationFrequency: evaluationFrequency
    windowSize: windowSize
    criteria: {
      allOf: [
        {
          query: trustProxyQuery
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    autoMitigate: true
    actions: {
      actionGroups: actionGroupIds
    }
  }
}

// ---------------------------------------------------------------------------
// Rule 4 — platform LLM daily ceiling reached
// ---------------------------------------------------------------------------
// Unverified in Azure: Properties["helix.reason"] and sum(Sum) on AppMetrics counters.
var platformCeilingQuery = 'AppMetrics | where Name == "helix.gateway.admission_denied" | where tostring(Properties["helix.reason"]) == "platform_ceiling" | summarize Denied = sum(Sum) by AppRoleName | where Denied > 0'

resource platformCeilingRule 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = if (includeMetricRule) {
  name: '${namePrefix}-alert-llm-platform-ceiling'
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: 'LLM platform ceiling reached'
    description: 'The platform-wide daily LLM spend ceiling was reached and new LLM calls are being refused with 503 until local midnight.'
    severity: severity
    enabled: true
    scopes: [workspaceId]
    evaluationFrequency: evaluationFrequency
    windowSize: windowSize
    criteria: {
      allOf: [
        {
          query: platformCeilingQuery
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    autoMitigate: true
    actions: {
      actionGroups: actionGroupIds
    }
  }
}

@description('Whether these rules will actually reach a human. False means they deploy, evaluate and fire silently.')
output notifies bool = !empty(actionGroupId)
