# @genome-security/sdk-web

Browser SDK for GENOME Security's continuous adaptive authentication: device-bound
WebAuthn passkeys, RFC 9449 DPoP proof-of-possession, and keystroke/mouse telemetry
capture wired into a small public API.

## Install (within this monorepo)

```bash
cd sdk-web
npm install
npm run build   # emits dist/ (ESM + CJS + .d.ts) consumed by demo-app
```

## Quick start

```ts
import { GenomeClient } from "@genome-security/sdk-web";

const client = new GenomeClient({ serverUrl: "http://localhost:8080" });

// 1. Register a device-bound passkey.
await client.register("alice", "Alice Example");

// 2. Log in. A successful WebAuthn assertion is the system's sole
//    high-assurance anchor event (see ../docs/THREAT_MODEL.md) and mints
//    a session token cryptographically bound to a fresh DPoP keypair.
await client.login("alice");

// 3. Start capturing keystroke + mouse timing telemetry on the page and
//    stream trust-score updates.
client.startTelemetry();
client.onTrustUpdate((update) => {
  console.log(update.trustScore, update.decision); // 0-100, "allow"|"stepup"|"deny"
});
```

## What this SDK does NOT do

- It does not claim to verify that input events originated from a physical
  input bus rather than a software injection point -- see
  `../research/synthetic_input_detection/attested_input_pipeline.md` and
  `../docs/THREAT_MODEL.md` for the honest limitations here. The only
  synthetic-input defense wired up end-to-end is the statistical/ML
  timing detector running server-side.
- It does not request a resident/discoverable or attested credential, so
  it cannot cryptographically prove the authenticator is non-syncable --
  see the module doc comment in `server/src/auth.rs` for the trade-off.

## Modules

| Module | Purpose |
|---|---|
| `dpop.ts` | WebCrypto ES256 keypair generation, RFC 7638 JWK thumbprint, RFC 9449 proof signing. |
| `webauthn.ts` | `navigator.credentials.create/get` wrappers that speak the server's JSON wire format. |
| `telemetry/keystroke.ts` | Captures inter-keydown interval timing only (no key values). |
| `telemetry/mouse.ts` | Captures inter-`mousemove` interval timing only (no cursor position). |
| `telemetry/simulate.ts` | Demo-only synthetic-keystroke generator used by the demo app's "inject synthetic input" button. |
| `client.ts` | `GenomeClient` -- the public API gluing the above together. |

## Testing

```bash
npm run typecheck   # tsc --noEmit
npm test            # vitest -- covers DPoP proof generation + base64url helpers (pure logic, no DOM needed)
```

WebAuthn/DOM-dependent paths (`webauthn.ts`, `telemetry/*Capture`) are exercised via the
demo app in a real browser rather than headless unit tests, since `navigator.credentials`
has no meaningful jsdom/node shim.
