// nsg.bicep — network security group for snet-egress only.
//
// Created before the VNet (like routing.bicep) so the subnet can reference it
// inline at creation time. Azure rejects late association on a subnet that
// already holds Container Apps infrastructure — the same limit documented for
// route tables in network.bicep — and whether a populated ACA subnet accepts an
// NSG as an update is unverified in Azure.
//
// Edge, portal, dev-gateway, certbot and migrate share snet-apps on one ACA
// environment, so an NSG there cannot separate them (decision N5); egress is
// alone on snet-egress apart from its OTel collector, so layer-2 control lands
// here first. snet-pe has privateEndpointNetworkPolicies Disabled, so an NSG
// there would not filter endpoint traffic anyway.
//
// The NSG cannot stop SSRF to Postgres or the two vaults egress legitimately
// uses (rules allow them); only the application filter and absent credentials on
// a bare request limit reachability there.
//
// Rules load from ../nsg-egress-rules.json (shared with the local net simulation).
// Rows marked hypothesis in that file — platform flows (100, 140–143), the
// 100.64.0.0/10 deny, ILB source addresses, service-tag membership — are
// unverified in Azure until an operator runs net-verify. Prefix denies on
// 168.63.129.16 and 169.254.169.254 do not filter Azure's documented host-node
// paths; ssrf.ts is the control there (see ADR-0005 amendment).

@description('Azure region.')
param location string

@description('Resource name prefix.')
param namePrefix string

@allowed(['deny-list-only', 'enforce'])
@description('deny-list-only activates every rule except the closing deny-all (row 4000); enforce activates all of them.')
param mode string

param vnetAddressPrefix string
param egressSubnetPrefix string
param appsSubnetPrefix string
param postgresSubnetPrefix string
param privateEndpointSubnetPrefix string

@description('When true, rule 120 targets pinned kv-connections and kv-delegated IPs; when false, a single allow targets the whole private-endpoint subnet (weaker).')
param pinPrivateEndpointAddresses bool

param kvConnectionsIp string
param kvDelegatedIp string

@description('TCP destination ports the internet allow (row 300) opens, e.g. ["80", "443"]. Approved origins on other ports stop working once rules 300 and 4000 are active.')
param allowedPorts array

var refs = {
  '$vnet': vnetAddressPrefix
  '$egressSubnet': egressSubnetPrefix
  '$appsSubnet': appsSubnetPrefix
  '$postgresSubnet': postgresSubnetPrefix
  '$privateEndpointSubnet': privateEndpointSubnetPrefix
  '$kvConnectionsIp': kvConnectionsIp
  '$kvDelegatedIp': kvDelegatedIp
}

var allRules = loadJsonContent('../nsg-egress-rules.json').rules

func includeNsgRule(rule object, enforceMode string, usePinnedPe bool) bool =>
  contains(rule.modes, enforceMode)
    ? (contains(rule, 'pePinning')
      ? ((rule.pePinning == 'pinned' && usePinnedPe) || (rule.pePinning == 'unpinned' && !usePinnedPe))
      : true)
    : false

var active = filter(allRules, rule => includeNsgRule(rule, mode, pinPrivateEndpointAddresses))

var resolved = [for r in active: {
  name: r.name
  priority: r.priority
  direction: r.direction
  access: r.access
  protocol: r.protocol
  src: map(r.sourcePrefixes, p => contains(refs, p) ? refs[p]! : p)
  dst: map(r.destinationPrefixes, p => contains(refs, p) ? refs[p]! : p)
  ports: flatten(map(r.destinationPorts, p => p == '$allowedPorts' ? allowedPorts : [p]))
}]

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${namePrefix}-nsg-egress'
  location: location
  properties: {
    securityRules: [for r in resolved: {
      name: r.name
      properties: {
        priority: r.priority
        direction: r.direction
        access: r.access
        protocol: r.protocol
        sourcePortRange: '*'
        sourceAddressPrefix: length(r.src) == 1 ? r.src[0] : null
        sourceAddressPrefixes: length(r.src) > 1 ? r.src : null
        destinationAddressPrefix: length(r.dst) == 1 ? r.dst[0] : null
        destinationAddressPrefixes: length(r.dst) > 1 ? r.dst : null
        destinationPortRange: length(r.ports) == 1 ? r.ports[0] : null
        destinationPortRanges: length(r.ports) > 1 ? r.ports : null
      }
    }]
  }
}

output nsgId string = nsg.id
