// dns.bicep — the public DNS zone for the apps domain.
//
// All hosted apps live at <app>.azx.helix.azxlabs.io, the central OIDC callback at
// auth.azx.helix.azxlabs.io, and the (internal) control plane is fronted at
// portal.azx.helix.azxlabs.io. The wildcard + auth + portal records point at the apps
// environment's public static IP (the edge takes external ingress there).
//
// A domain split uses two zones: the control zone (auth, portal, dev-api, asuid; wildcard
// only while legacy redirect is on) and a hosted-apps zone (* and asuid only).
//
// TLS: the wildcard cert (*.azx.helix.azxlabs.io) and the ACA custom-domain bindings are
// handled separately — issuance/renewal is the portal's ACME DNS-01 job
// (deferred, M5 tail). `domainVerificationId`, when supplied, writes the asuid
// TXT record ACA needs to verify ownership before a custom-domain binding.
//
// NOTE: azx.helix.azxlabs.io is a SUBDOMAIN of azxlabs.io (the parent zone lives
// in Cloudflare). Delegate it by adding NS records for `azx.helix` in the
// azxlabs.io Cloudflare zone, pointing at this zone's name servers (output
// `nameServers`) — not at the registrar. The records resolve publicly once that
// delegation is in place.

@description('Apps domain, e.g. azx.helix.azxlabs.io.')
param appsDomain string

@description('Public static IP of the apps Container Apps environment (edge ingress).')
param edgeStaticIp string

@description('ACA custom-domain verification id (asuid TXT). Empty = skip.')
param domainVerificationId string = ''

@description('Add the dev-gateway host (dev-api) record. Off unless the opt-in surface is deployed.')
param deployDevGateway bool = false

@description('Add the control-plane records (auth, portal, dev-api). False for a hosted-apps zone, which holds only the wildcard and the verification record.')
param hostsControlPlane bool = true

@description('Add the wildcard record. False for a control zone once the legacy app redirect is off: auth, portal and dev-api have their own records.')
param hostsWildcard bool = true

resource zone 'Microsoft.Network/dnsZones@2018-05-01' = {
  name: appsDomain
  location: 'global'
}

resource wildcardRecord 'Microsoft.Network/dnsZones/A@2018-05-01' = if (hostsWildcard) {
  parent: zone
  name: '*'
  properties: {
    TTL: 3600
    ARecords: [
      { ipv4Address: edgeStaticIp }
    ]
  }
}

resource authRecord 'Microsoft.Network/dnsZones/A@2018-05-01' = if (hostsControlPlane) {
  parent: zone
  name: 'auth'
  properties: {
    TTL: 3600
    ARecords: [
      { ipv4Address: edgeStaticIp }
    ]
  }
}

resource portalRecord 'Microsoft.Network/dnsZones/A@2018-05-01' = if (hostsControlPlane) {
  parent: zone
  name: 'portal'
  properties: {
    TTL: 3600
    ARecords: [
      { ipv4Address: edgeStaticIp }
    ]
  }
}

// dev-api — the opt-in cross-origin dev surface (dev-mode design §3). Lives on
// the control-plane base of this deployment, never an app subdomain, and shares
// the apps env static IP (the dev-gateway takes external ingress there like the
// edge). A CORS surface, so it is deliberately its own host.
resource devApiRecord 'Microsoft.Network/dnsZones/A@2018-05-01' = if (deployDevGateway && hostsControlPlane) {
  parent: zone
  name: 'dev-api'
  properties: {
    TTL: 3600
    ARecords: [
      { ipv4Address: edgeStaticIp }
    ]
  }
}

resource verificationRecord 'Microsoft.Network/dnsZones/TXT@2018-05-01' = if (!empty(domainVerificationId)) {
  parent: zone
  name: 'asuid'
  properties: {
    TTL: 3600
    TXTRecords: [
      { value: [domainVerificationId] }
    ]
  }
}

output zoneName string = zone.name
output nameServers array = zone.properties.nameServers
