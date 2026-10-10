# connections browser lane

The real-browser acceptance lane for the OAuth-connections journey —
ADR-0010 part 2, spec criteria 51–53. A real Chromium drives the assembled
feature the way a user reaches it: a hosted app served by the real edge, the
`window.helix.connect()` helper granted by the manifest, and a consent popup
that travels start route → consult → fixture vendor → callback through the
reverse proxy → egress exchange + seal → connection row → completion message →
the app's own retry → the delegated call at the fixture's API destination.

This lane is **not part of the vitest run**. It boots the real edge, portal,
egress, dev IdP and fixture vendor in-process (the integration-suite
composition, `apps/edge/src/routing/connectionsJourney.integration.test.ts`)
on ephemeral ports against its own scratch database, fronts every
browser-facing hop with a TLS terminator (the edge's dev hosts and the vendor's
authorize screen), and drives a real browser.

## Split-domain mode

Set `HELIX_APPS_DOMAIN` (for example `helix-apps.localhost`) to serve hosted apps on a
second loopback domain while auth and the connections callback stay on
`auth.local.helix.azxlabs.io`. The opener page is then cross-origin with the
popup and callback; where the browser classifies the pair as cross-site, the
consent popup journey exercises that layout.

```sh
HELIX_APPS_DOMAIN=helix-apps.localhost pnpm lane:connections
```

## Run it (dev container)

```sh
pnpm lane:connections            # = xvfb-run -a pnpm --filter @azx-pbc/connections-lane test
# or, with playwright's own CLI passthrough (filters, --ui, …):
xvfb-run -a pnpm --filter @azx-pbc/connections-lane test
xvfb-run -a pnpm --filter @azx-pbc/connections-lane test -- --ui
```

Headed under Xvfb is deliberate (see `playwright.config.ts`): with Playwright's
CDP defaults the popup blocker never fires — headless Chromium under automation
leaves popups unblocked even with the `--disable-popup-blocking` default removed
(measured) — and the blocked-open journey must be engine evidence. The lane
removes that default and runs headed so Chromium's real one-popup-per-gesture
blocker does the blocking (criterion 26).

Requirements: Postgres with the least-privilege runtime roles
(`.devcontainer/db-init/01-roles.sql` — the dev container provisions them;
the suite fails loudly without them), `psql`, `openssl`, `xvfb-run`, and the
Playwright chromium binary (`pnpm exec playwright install chromium` — the dev
container's post-create pre-caches it).

## Journeys (spec criterion 53)

| Journey                                                                    | Spec   | Where                                          |
| -------------------------------------------------------------------------- | ------ | ---------------------------------------------- |
| Explicit successful consent, Bearer placement                              | 52, 53 | `journeys.spec.ts`                             |
| Explicit successful consent, named-header placement                        | 52, 53 | `journeys.spec.ts`                             |
| Blocked opening (the real popup blocker)                                   | 25, 26 | `journeys.spec.ts`                             |
| Denial (distinct outcome; keyboard-completable popup, managed focus)       | 25, 51 | `journeys.spec.ts`                             |
| Cancellation (popup closed mid-journey → cancel ack)                       | 25, 29 | `journeys.spec.ts`                             |
| Timeout (already-expired attempt, arranged via the row's expiry)           | 25     | `failures.spec.ts`                             |
| Lost completion signaling (message dropped after the save)                 | 29     | `failures.spec.ts`                             |
| Forged success from the app's own window / the vendor's page               | 28     | `failures.spec.ts`                             |
| No automatic replay + the app's explicit retry after success               | 31, 53 | `journeys.spec.ts` (network-level observation) |
| Disconnection through the real My Connections page → `connection_required` | 43     | `my-connections.spec.ts`                       |

Determinism: every wait is Playwright's polling (`expect.poll`), the fixture
vendor's modes are per-instance knobs, and the timeout leg backdates the
attempt's `expiresAt` through the row itself (arrange state) rather than
waiting the five-minute wall clock — the five-minute **value** is asserted in
the shared contract's own suite (`packages/shared/src/consent.test.ts`,
`CONSENT_ATTEMPT_TTL_SECONDS === 300`).

## What is arrange and what is act

Arranged (setup, through real surfaces): the app, its live version, the
provider row (credentials sealed by the portal's own create path), the manifest
binding + approval, the app page in Blob (the edge really serves it and really
injects the helper under `shim.connect`), and the app user's session row. The
browser's token for the My Connections leg comes from a real OIDC login through
the dev IdP; the edge session's `oid` is the fixture user's `oid`, so both
planes agree on the principal without any row being supplied.

Act (never arranged): every step of the consent journey, the delegated calls,
the disconnection.

## Watched fail (criterion 52's bar — the lane must detect an unwired join)

With the lane green, the edge's consult join was unwired once — the
composition's `portal` dep (`HttpPortalProvider`) pointed at a dead port. Every
journey went red immediately: the start route's consult call failed, the popup
landed on the edge's "Couldn't start" terminal page, the app's result was
`error`/`service_unavailable` instead of `connected`, no connection row
appeared, and the My Connections leg never got a connection to disconnect. (A
first attempt broke `config.portalUrl` instead — a value the edge's request
path never reads; the seam that carries the consult is the composition's
`portal` dep, and that is the join the lane proved.) Restored and re-run green.
Every asserted hop is a real production join; none is supplied by the lane.

## CI

The `browser-lane` job in `.github/workflows/ci.yml` runs this lane gated
behind the `static` and `test` jobs, with Postgres provisioned the same way the
test job provisions it, the chromium binary installed (+ cached) per run, and
traces/screenshots/videos uploaded on failure. The fixture vendor and dev IdP
are in-repo services booted by the lane itself — not containers.
