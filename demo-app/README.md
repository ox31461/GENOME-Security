# demo-app

Minimal end-to-end demo wiring `@genome-security/sdk-web` to the Rust risk-engine
server: register a device-bound passkey, log in, then watch a live trust-score dial
update from real keystroke/mouse timing telemetry as you type and move the mouse.
Includes a button to simulate a synthetic-input injection attack so you can watch
the server-side detector and decision react.

## Prerequisites

- The server running locally (see `../server/README.md` if present, or just run
  `cargo run` from `server/` — see the root README's "portable toolchain" notes if
  you hit an OpenSSL/C-compiler build error on Windows).
- Node.js 20+ and `@genome-security/sdk-web` built (`cd ../sdk-web && npm install && npm run build`).
- A browser with WebAuthn support and a usable authenticator: a platform authenticator
  (Windows Hello, Touch ID, Android/Chrome OS biometric unlock) or a security key.

## Run it

```bash
# 1. Build the SDK (only needed once, or after SDK changes)
cd ../sdk-web
npm install
npm run build

# 2. Start the server (separate terminal)
cd ../server
cargo run
# listens on http://localhost:8080 (bind addr is 127.0.0.1:8080, but the HTTP
# Host header / htu checks are keyed off GENOME_PUBLIC_URL, default
# "http://localhost:8080" — load the demo via "localhost", not "127.0.0.1")

# 3. Start the demo app (separate terminal)
cd demo-app
npm install
npm run dev
# Vite prints a URL, normally http://localhost:5173
```

Open the printed URL **as `localhost`, not `127.0.0.1`** — this matters because the
server's WebAuthn relying-party ID is configured as `"localhost"`
(`GENOME_RP_ID` in `server/src/main.rs`), and WebAuthn requires the page's effective
domain to match the RP ID. The SDK and server ports may differ (5173 vs 8080); only
the hostname needs to match.

## Using the demo

1. Enter a username (defaults to `alice`) and click **Register passkey**. Your
   browser/OS will prompt you to create a passkey (Windows Hello, Touch ID,
   security key, etc.) — approve it.
2. Click **Log in** and approve the resulting passkey assertion prompt. This is
   the system's sole high-assurance "anchor" event (see
   `../docs/THREAT_MODEL.md`): it mints a session bound to a fresh DPoP keypair,
   and telemetry capture starts automatically.
3. Type and move your mouse anywhere on the page. Batches of interval-timing
   telemetry stream to `/api/telemetry`, and the dial, decision badge, and metric
   tiles update with each response (trust score, risk, synthetic-input
   probability, baseline z-score, and the Asymmetric Learning Gate's outcome if
   the quarantine buffer took an action this batch).
4. Click **Inject synthetic input (simulate attack)** to send an i.i.d.-Gaussian
   synthetic keystroke-timing batch through the same pipeline a naive injection
   attack would use, and watch `synthetic_probability` and the decision react.

## Honest limitations (read this)

This demo's defense against synthetic/injected input is a **statistical timing
detector only** (ported from `research/synthetic_input_detection/`). It does **not**
verify that input events originated from a physical input-bus interrupt rather than
a software injection point — that remains a partially solved problem on commodity
OSes today. See `../research/synthetic_input_detection/attested_input_pipeline.md`
for the honest, per-OS breakdown of what is and isn't feasible, and
`../docs/THREAT_MODEL.md` for how this limitation is scoped into the overall threat
model. A sufficiently sophisticated injection attack that matches the detector's
statistical fingerprint (not just the simple generator wired into this demo's
"inject" button) would not be caught by this layer alone.

Similarly, this demo requests an ordinary (non-attested) WebAuthn credential, so the
server cannot cryptographically prove the authenticator is hardware-bound /
non-syncable — see the module doc comment in `server/src/auth.rs`.

## Ports and config

| What | Default | Override |
|---|---|---|
| Server bind address | `127.0.0.1:8080` | `GENOME_BIND_ADDR` env var |
| Server public URL (RP origin, DPoP `htu` base) | `http://localhost:8080` | `GENOME_PUBLIC_URL` env var |
| WebAuthn RP ID | `localhost` | `GENOME_RP_ID` env var |
| Demo dev server | `http://localhost:5173` (Vite default) | `vite --port <n>` |

If you change `GENOME_PUBLIC_URL`/`GENOME_RP_ID`, also update `SERVER_URL` in
`src/main.ts`.
