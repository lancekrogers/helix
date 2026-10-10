// network.bicep — the VNet and its subnets.
//
// The whole egress-zone security property (architecture §3) is enforced at this
// layer: edge + portal live in `snet-apps`, egress lives alone in `snet-egress`,
// and the two subnets get different route tables (see routing.bicep) so only the
// egress subnet can reach the public internet. ACA binds one infrastructure
// subnet per managed environment, which is *why* there are two app subnets and
// two environments rather than one.
//
// Route tables are attached here (passed in by id) so the subnet definition and
// its UDR stay in one place — Azure rejects late association if a subnet already
// holds ACA infrastructure.

@description('Azure region for all network resources.')
param location string

@description('Resource name prefix, e.g. "helix-prod".')
param namePrefix string

@description('Resource id of the route table for snet-apps (deny-egress).')
param appsRouteTableId string

@description('Resource id of the route table for snet-egress (allow-egress).')
param egressRouteTableId string

@description('Address space for the VNet.')
param vnetAddressPrefix string

@description('AzureFirewallSubnet prefix. Must be /26 or larger.')
param firewallSubnetPrefix string

@description('snet-apps prefix (/23 minimum for a workload-profile environment).')
param appsSubnetPrefix string

param egressSubnetPrefix string
param postgresSubnetPrefix string
param privateEndpointSubnetPrefix string

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${namePrefix}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [vnetAddressPrefix]
    }
    subnets: [
      {
        // Azure Firewall requires this exact subnet name.
        name: 'AzureFirewallSubnet'
        properties: {
          addressPrefix: firewallSubnetPrefix
        }
      }
      {
        // ACA environment "apps" (edge + portal). UDR forces 0.0.0.0/0 through
        // the firewall, which denies outbound internet.
        name: 'snet-apps'
        properties: {
          addressPrefix: appsSubnetPrefix
          routeTable: {
            id: appsRouteTableId
          }
          delegations: [
            {
              name: 'aca-apps'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        // ACA environment "egress" (egress only). UDR forces 0.0.0.0/0 through
        // the firewall, which ALLOWS outbound internet — the one network zone
        // with a route to the public internet.
        name: 'snet-egress'
        properties: {
          addressPrefix: egressSubnetPrefix
          routeTable: {
            id: egressRouteTableId
          }
          delegations: [
            {
              name: 'aca-egress'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        // Postgres Flexible Server private access (VNet injection) needs a
        // dedicated delegated subnet.
        name: 'snet-postgres'
        properties: {
          addressPrefix: postgresSubnetPrefix
          delegations: [
            {
              name: 'pg-flexible'
              properties: {
                serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'
              }
            }
          ]
        }
      }
      {
        // Private endpoints for blob and the three Key Vaults.
        name: 'snet-pe'
        properties: {
          addressPrefix: privateEndpointSubnetPrefix
          privateEndpointNetworkPolicies: 'Disabled'
        }
      }
    ]
  }
}

// Subnets are declared inline above (so Azure creates them atomically with the
// VNet); these `existing` references just expose stable resource ids as outputs.
resource firewallSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  parent: vnet
  name: 'AzureFirewallSubnet'
}
resource appsSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  parent: vnet
  name: 'snet-apps'
}
resource egressSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  parent: vnet
  name: 'snet-egress'
}
resource postgresSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  parent: vnet
  name: 'snet-postgres'
}
resource peSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  parent: vnet
  name: 'snet-pe'
}

output vnetId string = vnet.id
output vnetName string = vnet.name
output firewallSubnetId string = firewallSubnet.id
output appsSubnetId string = appsSubnet.id
output egressSubnetId string = egressSubnet.id
output postgresSubnetId string = postgresSubnet.id
output privateEndpointSubnetId string = peSubnet.id
output appsSubnetPrefix string = appsSubnetPrefix
output egressSubnetPrefix string = egressSubnetPrefix
output privateEndpointSubnetPrefix string = privateEndpointSubnetPrefix
output vnetAddressPrefix string = vnetAddressPrefix
