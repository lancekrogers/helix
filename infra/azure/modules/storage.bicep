// storage.bicep — the Blob account holding versioned app bundles.
//
// Public network access is disabled; the edge (read) and portal (write) reach
// it over a private endpoint through privatelink.blob.*. The `app-bundles`
// container matches the BLOB_CONTAINER default the apps expect.
//
// Both apps authenticate to Blob with their **managed identity** (issue #15):
// the edge with Storage Blob Data Reader, the portal with Data Contributor
// (granted in rbac.bicep). The account key is never listed or handed to either
// container — only the blob endpoint is exported, so an edge compromise can't
// rewrite or delete any tenant's bundle.

@description('Azure region.')
param location string

@description('Globally-unique storage account name (3-24 lowercase alphanumerics).')
param storageAccountName string

@description('Blob container name for app bundles.')
param containerName string = 'app-bundles'

@description('Subnet id for the private endpoint (snet-pe).')
param privateEndpointSubnetId string

@description('Resource id of the privatelink.blob.* private DNS zone.')
param blobPrivateDnsZoneId string

param privateIpAddress string = ''

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storageAccount
  name: 'default'
}

resource bundlesContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: containerName
  properties: {
    publicAccess: 'None'
  }
}

module privateEndpoint 'private-endpoint.bicep' = {
  name: 'pe-${storageAccountName}'
  params: {
    location: location
    name: '${storageAccountName}-pe'
    subnetId: privateEndpointSubnetId
    targetResourceId: storageAccount.id
    groupId: 'blob'
    privateDnsZoneId: blobPrivateDnsZoneId
    privateIpAddress: privateIpAddress
    memberName: 'blob'
  }
}

output storageAccountId string = storageAccount.id
output storageAccountName string = storageAccount.name
// Blob endpoint for the apps' managed-identity auth (no account key). Consumed by
// main.bicep as AZURE_STORAGE_BLOB_ENDPOINT for both edge and portal.
output blobEndpoint string = storageAccount.properties.primaryEndpoints.blob
