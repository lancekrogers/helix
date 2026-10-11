// keyvault.bicep — the three Key Vaults.
//
// The split mirrors the database role split (architecture §3, secrets design):
//   - kv-platform     : infra config secrets surfaced to the container apps as
//                       ACA secretRefs (per-role PG connection strings, the blob
//                       connection string, EDGE_AUTH_SECRET, PORTAL_SECRET,
//                       HELIX_INSTRUCTION_SECRET, the OIDC client secret).
//   - kv-connections  : the prod KeyVaultSecretStore for *app connection
//                       secrets* (third-party API credentials). Portal writes
//                       them, egress reads them, EDGE NEVER TOUCHES THIS VAULT —
//                       no role assignment for the edge MI exists (rbac.bicep),
//                       so an edge RCE can't read a single credential.
//   - kv-delegated    : user-delegated OAuth token material (ADR-0031).
//                       Egress seals/opens/destroys with Secrets Officer and
//                       is the ONLY principal with any role on it — the portal
//                       gets no role, so "the control plane never opens a
//                       delegated token" is enforced by RBAC absence
//                       (rbac.bicep), not convention.
//
// All three vaults: RBAC authorization (no access policies), purge protection
// on, public access disabled, reached over private endpoints through
// privatelink.vaultcore.azure.net.

@description('Azure region.')
param location string

@description('Globally-unique name for the platform vault (3-24 chars).')
param platformVaultName string

@description('Globally-unique name for the connections vault (3-24 chars).')
param connectionsVaultName string

@description('Globally-unique name for the delegated-custody vault (3-24 chars).')
param delegatedVaultName string

@description('Subnet id for the private endpoints (snet-pe).')
param privateEndpointSubnetId string

@description('Resource id of the privatelink.vaultcore.azure.net private DNS zone.')
param keyVaultPrivateDnsZoneId string

param platformPrivateIp string = ''
param connectionsPrivateIp string = ''
param delegatedPrivateIp string = ''

var commonProperties = {
  sku: {
    family: 'A'
    name: 'standard'
  }
  tenantId: tenant().tenantId
  enableRbacAuthorization: true
  enableSoftDelete: true
  softDeleteRetentionInDays: 90
  enablePurgeProtection: true
  publicNetworkAccess: 'Disabled'
  networkAcls: {
    defaultAction: 'Deny'
    bypass: 'AzureServices'
  }
}

resource platformVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: platformVaultName
  location: location
  // enabledForTemplateDeployment admits the ARM template-deployment trusted
  // service, which is what lets bicepparam `az.getSecret()` source params from
  // this vault at deploy time. The trusted-services bypass survives
  // publicNetworkAccess: Disabled (KV network-security docs), and the deploy
  // principal additionally needs Microsoft.KeyVault/vaults/deploy/action
  // (Owner/Contributor include it). Verified live 2026-09-17 against this
  // RBAC-mode, PNA-Disabled vault. Platform vault only: kv-connections holds
  // customer app secrets that no deployment sources.
  properties: union(commonProperties, { enabledForTemplateDeployment: true })
}

resource connectionsVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: connectionsVaultName
  location: location
  properties: commonProperties
}

// No enabledForTemplateDeployment here: nothing sources deploy-time params
// from this vault (kv-platform is the only one the bicepparam reads), and the
// narrower surface is the point of the dedicated vault.
resource delegatedVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: delegatedVaultName
  location: location
  properties: commonProperties
}

module platformPe 'private-endpoint.bicep' = {
  name: 'pe-${platformVaultName}'
  params: {
    location: location
    name: '${platformVaultName}-pe'
    subnetId: privateEndpointSubnetId
    targetResourceId: platformVault.id
    groupId: 'vault'
    privateDnsZoneId: keyVaultPrivateDnsZoneId
    privateIpAddress: platformPrivateIp
    memberName: 'default'
  }
}

module connectionsPe 'private-endpoint.bicep' = {
  name: 'pe-${connectionsVaultName}'
  params: {
    location: location
    name: '${connectionsVaultName}-pe'
    subnetId: privateEndpointSubnetId
    targetResourceId: connectionsVault.id
    groupId: 'vault'
    privateDnsZoneId: keyVaultPrivateDnsZoneId
    privateIpAddress: connectionsPrivateIp
    memberName: 'default'
  }
}

module delegatedPe 'private-endpoint.bicep' = {
  name: 'pe-${delegatedVaultName}'
  params: {
    location: location
    name: '${delegatedVaultName}-pe'
    subnetId: privateEndpointSubnetId
    targetResourceId: delegatedVault.id
    groupId: 'vault'
    privateDnsZoneId: keyVaultPrivateDnsZoneId
    privateIpAddress: delegatedPrivateIp
    memberName: 'default'
  }
}

output platformVaultId string = platformVault.id
output platformVaultName string = platformVault.name
output platformVaultUri string = platformVault.properties.vaultUri
output connectionsVaultId string = connectionsVault.id
output connectionsVaultName string = connectionsVault.name
output connectionsVaultUri string = connectionsVault.properties.vaultUri
output delegatedVaultId string = delegatedVault.id
output delegatedVaultName string = delegatedVault.name
output delegatedVaultUri string = delegatedVault.properties.vaultUri
