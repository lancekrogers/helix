// private-endpoint.bicep — reusable: one private endpoint + its DNS zone group.
//
// Shared by storage.bicep and keyvault.bicep so the PE wiring
// (which is identical apart from the target resource, the groupId, and the DNS
// zone) lives in one place.

@description('Azure region.')
param location string

@description('Private endpoint name.')
param name string

@description('Subnet id to place the private endpoint NIC in (snet-pe).')
param subnetId string

@description('Resource id of the service the PE connects to.')
param targetResourceId string

@description('groupId / sub-resource of the target (e.g. "blob", "vault", "registry").')
param groupId string

@description('Resource id of the private DNS zone for this service.')
param privateDnsZoneId string

@description('Static private IP for the endpoint NIC, inside the endpoint subnet. Empty keeps today\'s behavior: Azure picks one. The NSG on snet-egress names the Key Vault endpoints by address, so the callers that matter pass one. Whether API version 2024-05-01 accepts ipConfigurations for these target types is unverified in Azure.')
param privateIpAddress string = ''

@description('memberName for the static IP configuration. Defaults to groupId; Key Vault uses "default" and Blob uses "blob". Only read when privateIpAddress is set. memberName values are unverified in Azure.')
param memberName string = groupId

resource privateEndpoint 'Microsoft.Network/privateEndpoints@2024-05-01' = {
  name: name
  location: location
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: name
        properties: {
          privateLinkServiceId: targetResourceId
          groupIds: [groupId]
        }
      }
    ]
    // Spread, not `ipConfigurations: null`: with no pinned address the property is omitted
    // entirely, so the request matches an endpoint created before pinning existed.
    ...(empty(privateIpAddress)
      ? {}
      : {
          ipConfigurations: [
            {
              name: 'ipconfig-${name}'
              properties: {
                groupId: groupId
                memberName: memberName
                privateIPAddress: privateIpAddress
              }
            }
          ]
        })
  }
}

resource dnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2024-05-01' = {
  parent: privateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: replace(groupId, '.', '-')
        properties: {
          privateDnsZoneId: privateDnsZoneId
        }
      }
    ]
  }
}

output privateEndpointId string = privateEndpoint.id
