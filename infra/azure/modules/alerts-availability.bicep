// alerts-availability.bicep — "email me if the site is down", from outside.
//
// Every other rule in this deployment reads a signal the platform emitted about
// itself, which means all of them share one blind spot: a platform that is not
// running emits nothing, and silence is indistinguishable from health. These are
// the only rules that look at the platform from OUTSIDE the platform.
//
// Azure calls this an Application Insights **availability test**. Two kinds
// exist and only one is usable: the old free `ping` test RETIRES 30 SEPTEMBER
// 2026 (existing ones are deleted from the resource), so these are `standard`
// tests — billed per execution, and worth it for the three things ping could not
// do: a body content match, TLS certificate validation, and a proactive check on
// how many days the certificate has left.
//
// WHAT IT PROBES, and why that URL. `/health` on an APP host serves app content
// (a deployed file called `/health`, or the SPA fallback) — the edge's host
// router mounts platform routes on platform hosts only. `auth.<appsDomain>` is
// the auth host and answers the platform health JSON, so that is the control
// certificate's probe URL; when the domain split is live, `www.<hostedAppsDomain>`
// probes the apps-domain certificate the same way. `dev-api.<appsDomain>` deliberately is NOT probed even when the
// dev-gateway is deployed: `dev-api` is a valid app slug and is not in
// RESERVED_SUBDOMAINS, so the edge image classifies that host as an app and
// serves assets from it — a probe there gets a 404, not a health body.
//
// EGRESS CANNOT BE PROBED AT ALL. It lives in an internal-only environment with
// no public load balancer, which is the ADR-0001 boundary working as designed.
// An availability test runs from public Azure regions, so nothing here can reach
// it; egress liveness is inferred from the edge's fetch-proxy spans instead. The
// portal is only probed when `portalExternal` put it on the public LB.
//
// READING THE BODY IS THE POINT. `/health` always answers 200, in every state,
// on purpose (ADR-0025: a non-200 would let a liveness probe restart a replica
// that is serving correctly from a stale projection). That is exactly why no ACA
// probe can grade it and why `TODO.md` carried "nothing probes the
// registry-projection sub-check" as an open residual. A standard test's content
// validation reads the body, so this is the probe that residual wanted.

@description('Azure region. The web tests are created here; the alert rules on them are global, as Azure requires.')
param location string

@description('Resource name prefix, matching the rest of the deployment.')
param namePrefix string

@description('Resource id of the Application Insights component the tests report into. Availability tests are not standalone — the results land in the component\'s `availabilityResults` table, and the hidden-link tag below is what associates them.')
param appInsightsId string

@description('What to probe: an array of `{ name, url }`. `name` becomes the test and rule name (keep it a short DNS-ish label), `url` must be reachable from the PUBLIC internet — an availability test runs from Azure regions, not from inside the VNet.')
param targets array

@description('Availability test location ids (the "population tags", not Azure region names — e.g. `us-va-ash-azr`). Azure recommends a MINIMUM OF FIVE so a network blip in one region cannot be mistaken for an outage, and allows up to 16.')
param testLocations array

@description('How many locations must fail simultaneously to fire the alert. Azure\'s guidance is (locations - 2), floor 1 — 3 of 5 by default. It is clamped to the number of locations below, because a threshold larger than the location count is a rule that can never fire, which looks exactly like a healthy platform.')
param failedLocationCount int = 3

@description('Seconds between test runs FROM EACH LOCATION. 300 (the Azure default) with five locations means the platform is probed roughly every minute. This is the knob that multiplies the bill — halve it and you double the executions.')
param frequencySeconds int = 300

@description('Seconds before a test run counts as failed. Lower it to be alerted on slow responses.')
param timeoutSeconds int = 30

@description('Validate the TLS certificate. MUST BE FALSE ON A STAGING ACME CERT: Let\'s Encrypt staging issues from an untrusted root, so every run would fail on the certificate and never tell you anything about the platform. The caller derives this from `acmeServer` for exactly that reason.')
param tlsCheck bool = true

@description('Fail the test this many days BEFORE the certificate expires. This is the cheapest possible monitor on ADR-0029\'s certbot job: the job renewing on schedule is the mechanism, a certificate with days left is the outcome, and the outcome is what an operator actually needs to hear about. Ignored when tlsCheck is false.')
param tlsExpiryWarningDays int = 14

@description('Body text whose PRESENCE fails the test (`PassIfTextFound: false`). Default `"status":"error"` — the health roll-up\'s hard-error state, which the platform reports with a 200 body by design. `degraded` is deliberately NOT here: the projection-staleness rule already owns that condition from the inside, and duplicating it would page twice for one soft failure. Empty disables content validation, leaving a reachability-only probe.')
param failIfBodyContains string = '"status":"error"'

@description('Alert severity: 0 critical .. 4 verbose. 1 (error) — an endpoint failing from three regions at once is not a warning.')
@allowed([0, 1, 2, 3, 4])
param severity int = 1

@description('Resource id of the shared action group, or empty. Empty deploys the tests and rules with NO notification target: they run, they fire, and they tell nobody but the portal.')
param actionGroupId string = ''

var actionGroupIds = empty(actionGroupId) ? [] : [actionGroupId]

// A threshold above the location count can never be met. Clamp instead of
// failing the deploy: the operator asked for "alert when most locations fail",
// and a silently-unfirable rule is the worst of the three outcomes.
var effectiveFailedLocationCount = min(failedLocationCount, length(testLocations))

// ---------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------
// `kind` and `properties.Kind` both have to say `standard`, and
// `SyntheticMonitorId` has to match the resource name — Azure treats the trio as
// one identity and the portal's Availability blade keys off it.
//
// FollowRedirects is false: every URL here is an exact endpoint we control, and
// a redirect appearing where none should be is a routing failure worth catching
// rather than following. ParseDependentRequests is false for the same reason —
// these probe an API, not a page, and it would make the test fail on any asset.
resource tests 'Microsoft.Insights/webtests@2022-06-15' = [
  for t in targets: {
    name: '${namePrefix}-avail-${t.name}'
    location: location
    kind: 'standard'
    // Mandatory. An availability test with no hidden-link tag has no component
    // to report into and does not appear in the Availability blade at all.
    tags: {
      'hidden-link:${appInsightsId}': 'Resource'
    }
    properties: {
      Name: '${namePrefix}-avail-${t.name}'
      SyntheticMonitorId: '${namePrefix}-avail-${t.name}'
      Kind: 'standard'
      Description: 'Helix ${t.name} probed from ${length(testLocations)} Azure regions.'
      Enabled: true
      Frequency: frequencySeconds
      Timeout: timeoutSeconds
      // On failure, retry after a short interval and only report after three
      // consecutive failures — per-location. Azure measures ~80% of failures as
      // transient, and this is the difference between an alert and a pager.
      RetryEnabled: true
      Locations: [for loc in testLocations: { Id: loc }]
      Request: {
        RequestUrl: t.url
        HttpVerb: 'GET'
        FollowRedirects: false
        ParseDependentRequests: false
      }
      // Built with union() so a disabled check is ABSENT rather than present-and-
      // null: SSLCertRemainingLifetimeCheck is only valid alongside SSLCheck.
      ValidationRules: union(
        {
          ExpectedHttpStatusCode: 200
          SSLCheck: tlsCheck
        },
        tlsCheck ? { SSLCertRemainingLifetimeCheck: tlsExpiryWarningDays } : {},
        empty(failIfBodyContains)
          ? {}
          : {
              ContentValidation: {
                ContentMatch: failIfBodyContains
                // Case-sensitive, matching how the platform serialises it. The
                // match is a single `"key":"value"` pair rather than a wider
                // slice of JSON on purpose — it holds whatever order the
                // serialiser emits the object's keys in.
                IgnoreCase: false
                PassIfTextFound: false
              }
            }
      )
    }
  }
]

// ---------------------------------------------------------------------------
// The rules on the tests
// ---------------------------------------------------------------------------
// A web test on its own notifies nobody — it only records results. The alert is
// a separate metric rule with the webtest-specific criteria type, and it has
// three shape requirements that are easy to get wrong and fail at deploy:
// `location` must be 'global', `scopes` must list BOTH the test and the
// component, and `actions` is an ARRAY of `{ actionGroupId }` (scheduled query
// rules take an object with an `actionGroups` array — the two are not
// interchangeable).
resource availabilityAlerts 'Microsoft.Insights/metricAlerts@2018-03-01' = [
  for (t, i) in targets: {
    name: '${namePrefix}-alert-avail-${t.name}'
    location: 'global'
    tags: {
      'hidden-link:${appInsightsId}': 'Resource'
      'hidden-link:${tests[i].id}': 'Resource'
    }
    properties: {
      description: 'Helix ${t.name} is failing its availability test from ${effectiveFailedLocationCount} or more Azure regions: it is unreachable, answering non-200, presenting a bad or near-expired TLS certificate, or reporting a hard error in its own health body.'
      severity: severity
      enabled: true
      scopes: [
        tests[i].id
        appInsightsId
      ]
      evaluationFrequency: 'PT1M'
      windowSize: 'PT5M'
      criteria: {
        'odata.type': 'Microsoft.Azure.Monitor.WebtestLocationAvailabilityCriteria'
        webTestId: tests[i].id
        componentId: appInsightsId
        failedLocationCount: effectiveFailedLocationCount
      }
      // State-based: one alert when it goes down, one resolution when it comes
      // back, not a mail every five minutes for the duration of an outage.
      autoMitigate: true
      actions: [
        for id in actionGroupIds: {
          actionGroupId: id
        }
      ]
    }
  }
]

@description('The URLs actually being probed, in order — the deploy-time record of what "the site is up" means for this install.')
output probedUrls array = [for t in targets: t.url]

@description('Locations that must fail together to fire, after clamping to the number of test locations.')
output failedLocationThreshold int = effectiveFailedLocationCount
