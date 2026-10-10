// firewall.bicep — Azure Firewall, its policy, and the default routes.
//
// This is where the egress-zone property is *enforced*:
//   - snet-egress (10.0.4.0/23) is allowed outbound to the internet.
//   - snet-apps   (10.0.2.0/23) is NOT — Azure Firewall is deny-by-default, so
//     the absence of an allow rule for it means edge/portal cannot egress.
//   - Both subnets are allowed to reach the small set of FQDNs that Azure
//     Container Apps itself needs to pull system images and report health;
//     without these the managed environment cannot run. Review this list
//     against the current ACA networking docs before each deploy.
//
// The two default routes (0.0.0.0/0 → firewall private IP) are added here
// because they depend on the firewall's allocated private IP — see routing.bicep
// for why the route tables themselves are created earlier and empty.

@description('Azure region.')
param location string

@description('Resource name prefix.')
param namePrefix string

@description('Resource id of AzureFirewallSubnet.')
param firewallSubnetId string

@description('Address prefix of snet-apps (rule source matching).')
param appsSubnetPrefix string

@description('Address prefix of snet-egress (rule source matching).')
param egressSubnetPrefix string

@allowed(['any', 'allowlist'])
@description('any = snet-egress may reach every FQDN on 80/443 (the behavior before the allow-list existed). allowlist = only the platform hosts (aca-platform collection) and egressProductFqdns.')
param egressFqdnMode string = 'any'

@description('Hosts the egress app legitimately calls beyond the platform: the LLM vendor hosts and the operator additions (connection providers, approved fetch origins). Used only in allowlist mode.')
param egressProductFqdns array = []

@description('Name of the apps route table (default route is added to it).')
param appsRouteTableName string

@description('Name of the egress route table (default route is added to it).')
param egressRouteTableName string

@description('''
  Threat intelligence mode for the firewall policy. Default Deny drops traffic to known-bad destinations (stricter than Alert). A false positive on a vendor IP is possible — use firewall application-rule denial logs to diagnose; set Alert to log only without blocking. Whether Azure Firewall Basic tier supports Deny is unverified in Azure (this module uses Standard tier). Existing installs that relied on Alert can set threatIntelMode = 'Alert' to preserve prior behavior on template update.''')
@allowed(['Alert', 'Deny', 'Off'])
param threatIntelMode string = 'Deny'

@description('FQDNs the apps-subnet workloads need: ACA platform plumbing (MCR, GHCR, monitoring, App Insights), Entra for tokens and OIDC, Microsoft Graph (portal directory client), Azure Resource Manager (certbot) and the ACME directory host. Review against current ACA networking docs before deploying.')
param appsPlatformFqdns array = [
  'mcr.microsoft.com'
  '*.data.mcr.microsoft.com'
  '*.cdn.mscr.io'
  // App images are pulled from GHCR (not ACR): the registry/token host plus the
  // githubusercontent host that serves the layer blobs. Without both, the apps
  // subnet (deny-by-default here) cannot pull and every deploy fails.
  'ghcr.io'
  'pkg-containers.githubusercontent.com'
  #disable-next-line no-hardcoded-env-urls
  '*.blob.core.windows.net'
  '*.monitoring.azure.com'
  // Application Insights ingestion, for the self-hosted OpenTelemetry collector
  // (ADR-0037). `*.monitoring.azure.com` above does NOT cover this — the ADR
  // says so explicitly, and it is the trap worth knowing: `snet-apps` is
  // deny-by-default outbound and the ABSENCE of a rule is the enforcement, so a
  // missing entry here drops every span with no error anywhere. It fails as
  // silence. Verify a trace actually arrives; never infer it from a green deploy.
  '*.in.applicationinsights.azure.com'
  // Live Metrics. The azuremonitor exporter reaches for it; without the rule it
  // retries and logs rather than failing, but the noise is not worth saving one
  // allowlist line.
  '*.livediagnostics.monitor.azure.com'
  #disable-next-line no-hardcoded-env-urls
  'login.microsoftonline.com' // portal OIDC discovery + JWKS; edge OIDC against Entra issuer
  'packages.microsoft.com'
  'graph.microsoft.com' // packages/directory/src/entra.ts: group and user lookups
  #disable-next-line no-hardcoded-env-urls
  'management.azure.com' // certbot: az login, certificate upload, hostname bind, DNS TXT writes
  #disable-next-line no-hardcoded-env-urls
  'login.microsoft.com' // managed-identity token issuance for Key Vault references
]

@description('ACME directory host (from the acmeServer parameter). Added to the apps list: certbot runs in the apps environment.')
param acmeServerHost string

@description('FQDNs the egress subnet needs for the platform itself: MCR, GHCR (egress image pulls), monitoring and App Insights, Entra. NOT Graph, ACME or Resource Manager, which only the apps subnet uses.')
param egressPlatformFqdns array = [
  'mcr.microsoft.com'
  '*.data.mcr.microsoft.com'
  '*.cdn.mscr.io'
  // Egress image is ghcr.io/azx-pbc-oss/helix-egress; ACA infrastructure may pull
  // layers through the subnet route — keep GHCR until net-verify confirms otherwise.
  'ghcr.io'
  'pkg-containers.githubusercontent.com'
  #disable-next-line no-hardcoded-env-urls
  '*.blob.core.windows.net'
  '*.monitoring.azure.com'
  '*.in.applicationinsights.azure.com'
  '*.livediagnostics.monitor.azure.com'
  #disable-next-line no-hardcoded-env-urls
  'login.microsoftonline.com'
  // Container Apps Key Vault references behind Azure Firewall need login.microsoft.com (manage-secrets doc).
  #disable-next-line no-hardcoded-env-urls
  'login.microsoft.com'
  'packages.microsoft.com'
]

var internetRule = egressFqdnMode == 'any'
  ? {
      ruleType: 'ApplicationRule'
      name: 'egress-to-any-https'
      sourceAddresses: [egressSubnetPrefix]
      targetFqdns: ['*']
      protocols: [
        { protocolType: 'Https', port: 443 }
        { protocolType: 'Http', port: 80 }
      ]
    }
  : {
      ruleType: 'ApplicationRule'
      name: 'egress-to-product-fqdns'
      sourceAddresses: [egressSubnetPrefix]
      targetFqdns: empty(egressProductFqdns)
        ? fail('egressFqdnMode is allowlist but the product host list is empty; egress would have no internet access. Set egressAllowedFqdns or the LLM endpoints.')
        : egressProductFqdns
      protocols: [
        { protocolType: 'Https', port: 443 }
        { protocolType: 'Http', port: 80 }
      ]
    }

resource firewallPip 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${namePrefix}-fw-pip'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource firewallPolicy 'Microsoft.Network/firewallPolicies@2024-05-01' = {
  name: '${namePrefix}-fw-policy'
  location: location
  properties: {
    sku: {
      tier: 'Standard'
    }
    threatIntelMode: threatIntelMode
  }
}

resource ruleCollectionGroup 'Microsoft.Network/firewallPolicies/ruleCollectionGroups@2024-05-01' = {
  parent: firewallPolicy
  name: 'helix-egress-rules'
  properties: {
    priority: 200
    ruleCollections: [
      {
        // Egress internet: any = one rule to * on 80/443; allowlist = product hosts only
        // (platform plumbing is the aca-platform collection below).
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'egress-internet'
        priority: 100
        action: {
          type: 'Allow'
        }
        rules: [
          internetRule
        ]
      }
      {
        // Platform plumbing both ACA environments require. Deliberately narrow:
        // it does NOT give the apps subnet general internet access.
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'aca-platform'
        priority: 200
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'ApplicationRule'
            name: 'aca-required-fqdns-apps'
            sourceAddresses: [appsSubnetPrefix]
            targetFqdns: concat(appsPlatformFqdns, [acmeServerHost])
            protocols: [
              { protocolType: 'Https', port: 443 }
              { protocolType: 'Http', port: 80 }
            ]
          }
          {
            ruleType: 'ApplicationRule'
            name: 'aca-required-fqdns-egress'
            sourceAddresses: [egressSubnetPrefix]
            targetFqdns: egressPlatformFqdns
            protocols: [
              { protocolType: 'Https', port: 443 }
              { protocolType: 'Http', port: 80 }
            ]
          }
        ]
      }
      {
        // Key Vault reference resolution is not an FQDN rule: it needs the AzureKeyVault service tag.
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        name: 'aca-platform-network'
        priority: 300
        action: {
          type: 'Allow'
        }
        rules: [
          {
            ruleType: 'NetworkRule'
            name: 'key-vault-reference-resolution'
            ipProtocols: ['TCP']
            sourceAddresses: [appsSubnetPrefix, egressSubnetPrefix]
            destinationAddresses: ['AzureKeyVault']
            destinationPorts: ['443']
          }
        ]
      }
    ]
  }
}

resource firewall 'Microsoft.Network/azureFirewalls@2024-05-01' = {
  name: '${namePrefix}-fw'
  location: location
  properties: {
    sku: {
      name: 'AZFW_VNet'
      tier: 'Standard'
    }
    firewallPolicy: {
      id: firewallPolicy.id
    }
    ipConfigurations: [
      {
        name: 'fw-ipconfig'
        properties: {
          subnet: {
            id: firewallSubnetId
          }
          publicIPAddress: {
            id: firewallPip.id
          }
        }
      }
    ]
  }
  dependsOn: [
    ruleCollectionGroup
  ]
}

// Default routes: force all internet-bound traffic from both app subnets through
// the firewall. The apps subnet is denied there; the egress subnet is allowed.
resource appsRouteTable 'Microsoft.Network/routeTables@2024-05-01' existing = {
  name: appsRouteTableName
}
resource egressRouteTable 'Microsoft.Network/routeTables@2024-05-01' existing = {
  name: egressRouteTableName
}

resource appsDefaultRoute 'Microsoft.Network/routeTables/routes@2024-05-01' = {
  parent: appsRouteTable
  name: 'default-to-firewall'
  properties: {
    addressPrefix: '0.0.0.0/0'
    nextHopType: 'VirtualAppliance'
    nextHopIpAddress: firewall.properties.ipConfigurations[0].properties.privateIPAddress
  }
}

resource egressDefaultRoute 'Microsoft.Network/routeTables/routes@2024-05-01' = {
  parent: egressRouteTable
  name: 'default-to-firewall'
  properties: {
    addressPrefix: '0.0.0.0/0'
    nextHopType: 'VirtualAppliance'
    nextHopIpAddress: firewall.properties.ipConfigurations[0].properties.privateIPAddress
  }
}

output firewallPrivateIp string = firewall.properties.ipConfigurations[0].properties.privateIPAddress
output firewallName string = firewall.name
