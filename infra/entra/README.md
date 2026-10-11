# Helix Entra ID registrations — Bicep (reference)

The three OIDC clients (architecture §4.2) as Infrastructure-as-Code, via the
[Microsoft Graph Bicep extension](https://learn.microsoft.com/graph/templates/bicep/)
(GA 2025-07-29). This is the IaC counterpart of the manual
[`docs/runbooks/entra-app-registration.md`](../../docs/runbooks/entra-app-registration.md).

> **Status: reference, not yet wired into a pipeline.** The pilot tenant's three
> apps were created by hand. This module is "our best shot" for the **production
> deployment** (`azx.helix.azxlabs.io`), where reproducibility pays. It is intentionally a
> sibling of `../azure` (the Azure resources), not folded into it — Entra apps
> are tenant objects with a different lifecycle and scope than a resource group.

## What it declares

| Registration                                                                                                                                                                                                                                                                                | Bicep highlights                                                                                                                                                           |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `*-edge`                                                                                                                                                                                                                                                                                    | web redirect URIs, `email` optional claim, **certificate** keyCredential (private_key_jwt — the tenant blocks secrets), **`groupMembershipClaims: SecurityGroup`**         |
| `*-portal`                                                                                                                                                                                                                                                                                  | SPA redirect URIs, **`requestedAccessTokenVersion: 2`**, the `access` scope, the **`platform-admin`** app role, `email` claims, **`groupMembershipClaims: SecurityGroup`** |
| `*-cli`                                                                                                                                                                                                                                                                                     | `isFallbackPublicClient: true` (device code), delegated permission to the portal `access` scope                                                                            |
| + service principals, an optional `platform-admin` role assignment, optional **sign-in restrictions** (`edgeAccessPrincipalIds` / `portalAccessPrincipalIds` flip `appRoleAssignmentRequired` on), optional admin consent, and the portal identity's **`GroupMember.Read.All`** Graph grant |

Its outputs (`edgeOidcClientId`, `portalOidcAudience`, `azxWebClientId`,
`azxCliClientId`) are exactly the params the `../azure` stack needs — deploy this
first, capture the outputs, pass them in.

A **new** install's `edgeRedirectUris` use the **control** domain
(`https://auth.<control domain>/callback`); the portal SPA uses `portal.<control domain>`. An
existing install that adds `hostedAppsDomain` later does **not** change Entra registrations —
sign-in and vendor callbacks stay on the control domain.

## Why each non-obvious property is there

Every one of these is a gotcha we hit by hand (see the runbook for the war
stories):

- **`requestedAccessTokenVersion: 2`** — without it Entra issues v1 access tokens
  (`iss = sts.windows.net/…`) that the v2-pinned portal rejects with 401.
- **Audience = the bare client-id GUID** — a v2 access token's `aud` is the client
  id, not the `api://` URI, so `portalOidcAudience` output is `portalApp.appId`.
- **App role `platform-admin`** (not a security group) — human-readable `roles`
  claim, no GUIDs/Graph/overage.
- **Certificate, not secret** — `keyCredentials`, because the tenant policy blocks
  client secrets.
- **`groupMembershipClaims: 'SecurityGroup'`** on both edge and portal — per-app group
  visibility reads security groups, not App Roles ([ADR-0040](../../docs/adr/0040-entra-group-visibility-directory-seam.md)
  decision 1), because a role-per-group would make "scope this app to a group" an
  infrastructure deploy. On the edge it feeds `visibilityAllows`; on the portal it
  feeds the picker's "groups you're a member of" default from a token the portal
  already verifies. **The portal half has an ordering dependency** — see wart #5.
- **`GroupMember.Read.All` on the portal's managed identity**, not on any registration
  here and not as a client secret. One permission, app-only, narrowest that answers
  `$search` (proven by probe, not by docs — `Group.Read.All` had zero incremental
  capability across sixteen calls). Declaring the `appRoleAssignedTo` **is** the admin
  consent.

## Known warts (read before deploying)

1. **`identifierUris` can't self-reference `appId`.** Clients request
   `api://<portal-appId>/access`, which needs the portal's identifier URI set to
   `api://<appId>` — but Bicep can't reference a resource's own `appId` inline.
   After the first deploy, run once:
   `az ad app update --id <portalClientId> --identifier-uris api://<portalClientId>`
   (the portal UI does this automatically when you add a scope; Bicep doesn't).
2. **Deploy-principal permissions.** Creating these needs Graph app-management
   rights — e.g. the **Application Administrator** role (or
   `Application.ReadWrite.All`). The role assignment + admin consent need more
   (Privileged Role Admin / `AppRoleAssignment.ReadWrite.All`). A tenant locked
   down enough to block client secrets may resist this — verify first.
3. **No clean import of the hand-made pilot apps.** The extension keys
   `applications` on `uniqueName`, which portal-created apps don't have — a deploy
   would create duplicates, not adopt. So use this for a _fresh_ environment;
   don't point it at the existing pilot registrations.
4. **Federated identity credential** (the cleanest edge auth — no key material)
   is sketched in `main.bicep` but disabled: it needs an edge code change to
   present a managed-identity token as the OIDC `client_assertion`.
5. **The Graph grant needs a second pass, and the portal claim needs a deployed
   portal.** `portalIdentityPrincipalId` names an identity created by `../azure`,
   which cannot exist until this stack has produced the client ids — so the order is
   **entra → azure → entra**, with the second pass carrying
   `HELIX_PORTAL_IDENTITY_PRINCIPAL_ID`. Separately, `groupMembershipClaims` on the
   _portal_ registration must not be applied until the **running** portal image
   unions the `groups` and `roles` claims (`unionClaimArrays`, commit `abb6912`);
   against an older image it silently strips `platform-admin` and locks every admin
   out of approvals. Both gates are sequenced in
   [`docs/runbooks/entra-group-claims-rollout.md`](../../docs/runbooks/entra-group-claims-rollout.md).
6. **Consent rights, again.** The `appRoleAssignedTo` against Microsoft Graph needs
   `AppRoleAssignment.ReadWrite.All` (Privileged Role Administrator / Global
   Administrator) — the same bar as `grantAdminConsent`, and above what wart #2's
   Application Administrator gives you.

## Deploy (when the time comes)

```bash
cd infra/entra
az bicep build --file main.bicep            # compile check (needs the extension)
az deployment group create -g <rg> -f main.bicep -p main.bicepparam
# then the identifierUris one-liner (wart #1), then feed outputs to ../azure

# ...and once ../azure has deployed, a second pass to grant the Graph permission:
export HELIX_PORTAL_IDENTITY_PRINCIPAL_ID=$(az identity show \
  -g <rg> -n <namePrefix>-portal-id --query principalId -o tsv)
az deployment group create -g <rg> -f main.bicep -p main.bicepparam
```

The `<rg>` is incidental — the Graph objects are tenant-scoped; the resource
group just hosts the deployment record.
