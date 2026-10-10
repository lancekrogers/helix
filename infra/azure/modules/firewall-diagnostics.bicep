// Firewall logs and egress-subnet application-rule denial alert.
// Lives outside firewall.bicep because the diagnostic setting targets the apps
// environment Log Analytics workspace while the apps environment depends on the
// firewall (routes must exist before ACA wires egress).

@description('Azure region.')
param location string

@description('Resource name prefix.')
param namePrefix string

@description('Name of the firewall resource (<namePrefix>-fw).')
param firewallName string

@description('Log Analytics workspace id the logs and the alert use (the apps environment workspace).')
param workspaceId string

@description('Address prefix of snet-egress (denial alert source filter).')
param egressSubnetPrefix string

@description('Action group id, or empty (the rule then notifies nobody; see alerts.bicep).')
param actionGroupId string = ''

@description('Deploy the scheduled-query alert on application-rule denials from the egress subnet.')
param includeDenialAlert bool = true

var actionGroupIds = empty(actionGroupId) ? [] : [actionGroupId]

resource firewall 'Microsoft.Network/azureFirewalls@2024-05-01' existing = {
  name: firewallName
}

resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${namePrefix}-fw-logs'
  scope: firewall
  properties: {
    workspaceId: workspaceId
    logAnalyticsDestinationType: 'Dedicated'
    logs: [
      { category: 'AZFWApplicationRule', enabled: true }
      { category: 'AZFWNetworkRule', enabled: true }
      { category: 'AZFWThreatIntel', enabled: true }
    ]
  }
}

// Table and column names (AZFWApplicationRule, Action, SourceIp, Fqdn) are from
// the Azure Monitor reference and are unverified in Azure until an operator sees
// a denial row in the workspace.
var deniedQuery = 'AZFWApplicationRule | where Action == "Deny" | where ipv4_is_in_range(SourceIp, "${egressSubnetPrefix}") | project TimeGenerated, SourceIp, Fqdn'

resource egressFirewallDenialRule 'Microsoft.Insights/scheduledQueryRules@2022-06-15' = if (includeDenialAlert) {
  name: '${namePrefix}-alert-egress-fw-denial'
  location: location
  kind: 'LogAlert'
  properties: {
    displayName: '${namePrefix} egress subnet firewall application-rule denial'
    description: 'Azure Firewall denied an application rule from the egress subnet. Usually an approved fetch origin or connection-provider host is missing from egressAllowedFqdns — run `just infra egress-hosts` against the deployed list and add MISSING hosts before redeploying.'
    severity: 2
    enabled: true
    scopes: [workspaceId]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      allOf: [
        {
          query: deniedQuery
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
