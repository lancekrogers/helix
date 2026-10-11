// alerts-netprobe.bicep — log alerts on the egress network probe job.
//
// Reads the EGRESS environment's Log Analytics workspace (each ACA environment
// has its own). Job console output is assumed to land in ContainerAppConsoleLogs_CL
// with JSON in Log_s, the same table alerts.bicep uses for apps — but a job is a
// different resource kind, so table name, column names, and whether stdout
// appears there are unverified in Azure until an operator runs net-verify.
//
// Two rules by design: a failure line catches a run that executed and reported
// ok=false; the absence rule catches a job that never started (bad image tag,
// disabled schedule, bad env) because those produce no failure line.

@description('Azure region.')
param location string

@description('Resource name prefix, matching the rest of the deployment.')
param namePrefix string

@description('Log Analytics workspace the egress environment ships stdout to.')
param workspaceId string

@description('Resource id of the shared action group, or empty. Empty deploys the rules with NO notification target.')
param actionGroupId string = ''

@description('Alert severity: 0 critical .. 4 verbose.')
@allowed([0, 1, 2, 3, 4])
param severity int = 2

@description('How far back the no-success rule looks. Default PT36H — daily schedule plus slack.')
param noSuccessWindow string = 'PT36H'

var actionGroupIds = empty(actionGroupId) ? [] : [actionGroupId]

var failedQuery = 'ContainerAppConsoleLogs_CL | extend p = parse_json(Log_s) | where tostring(p.event) == "egress.netprobe_result" | where tobool(p.ok) == false | project TimeGenerated, Failed = toint(p.failed)'

var successQuery = 'ContainerAppConsoleLogs_CL | extend p = parse_json(Log_s) | where tostring(p.event) == "egress.netprobe_result" | where tobool(p.ok) == true | project TimeGenerated'

resource probeFailedRule 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = {
  name: '${namePrefix}-alert-netprobe-failed'
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: '${namePrefix} network probe reported failure'
    description: 'A netprobe job run logged egress.netprobe_result with ok=false. In the egress Log Analytics workspace, read the egress.netprobe_check lines from the same execution for which check failed. A TCP reset is counted as reachable, not blocked — only a connect timeout counts as blocked — so a failure is a real posture mismatch. Then run `just infra net-verify` on the install (exit 3 when checks match but denyProven=false on an unpinned install). Wire-server (168.63.129.16) and IMDS checks are informational only; Azure does not apply NSG rules to those host-node paths the way the rule table assumes. denyProven in the summary is true only when a scored in-VNet deny check (blob-pe-443 with pinned endpoints) matched; it does not fail the job on default unpinned installs.'
    severity: severity
    enabled: true
    scopes: [workspaceId]
    evaluationFrequency: 'PT1H'
    windowSize: 'PT1H'
    criteria: {
      allOf: [
        {
          query: failedQuery
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

resource probeNoSuccessRule 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = {
  name: '${namePrefix}-alert-netprobe-no-success'
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: '${namePrefix} network probe has not succeeded recently'
    description: 'No egress.netprobe_result with ok=true in the lookback window. Confirm the <prefix>-netprobe Container Apps Job exists, its schedule is enabled, and the egress image tag includes the probe script; then start a run by hand or wait for the schedule and run `just infra net-verify`. On a fresh deployment this rule fires until the first run, so start one with `just infra net-verify` after deploying. Whether a Count-below-threshold rule fires when the log table has no matching rows at all is unverified in Azure.'
    severity: severity
    enabled: true
    scopes: [workspaceId]
    evaluationFrequency: 'PT1H'
    windowSize: noSuccessWindow
    criteria: {
      allOf: [
        {
          query: successQuery
          timeAggregation: 'Count'
          operator: 'LessThan'
          threshold: 1
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
