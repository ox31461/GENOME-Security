# server — GENOME Security risk engine

Rust (axum + tokio) production risk engine: ports of the Phase 1 Asymmetric
Learning Gate and synthetic-input detector, RFC 9449 DPoP verification,
FIDO2/WebAuthn (via `webauthn-rs`), and a telemetry ingestion endpoint that
returns CARTA-style `allow`/`stepup`/`deny` decisions.

## Build & run

```bash
cargo build
cargo test   # 23/23 unit tests
cargo run    # trains both detectors, then listens on http://127.0.0.1:8080
```

### Windows-specific build note

`webauthn-rs-core` depends unconditionally on `openssl`/`openssl-sys`. If you
don't have a system OpenSSL + C toolchain + Perl + `pkg-config` already set
up (common on a fresh Windows machine without admin rights to run installers),
this crate is built here with OpenSSL's **vendored** feature
(`server/Cargo.toml` adds `openssl = { version = "0.10", features =
["vendored"] }` to force feature unification), which compiles OpenSSL from
source. That in turn requires, in order:

1. A real C compiler — e.g. a portable
   [WinLibs MinGW-w64](https://winlibs.com/) build (zip, no installer, no
   admin rights). The GNU-target Rust toolchain's own bundled
   "self-contained" `gcc.exe` is linker-only and **cannot** compile C (see
   its own `GCC-WARNING.txt`).
2. A Perl that produces **Unix-style paths** for OpenSSL's `Configure`
   script — Strawberry/ActivePerl (even portable zip editions) fail this
   with `"This perl implementation doesn't produce Unix like paths"`. A
   portable [MSYS2 base](https://github.com/msys2/msys2-installer/releases)
   archive's bundled Perl works; no installer, no admin rights.
3. `make` — install into the MSYS2 tree via
   `pacman -S --noconfirm --needed make` (works without admin: MSYS2's own
   package manager only writes within its own extracted directory tree).

Once those are available, prepend them to `PATH` for the build (do **not**
set a `PERL` environment variable — this breaks `make`'s invocation of Perl
via backslash-path mangling; let `Configure` auto-detect Perl via `$^X`):

```powershell
$env:Path = '<path-to>\mingw64\bin;<path-to>\msys64\usr\bin;' + $env:Path
cargo build
```

## Configuration (env vars)

| Variable | Default | Purpose |
|---|---|---|
| `GENOME_BIND_ADDR` | `127.0.0.1:8080` | TCP bind address |
| `GENOME_PUBLIC_URL` | `http://localhost:8080` | WebAuthn RP origin + DPoP `htu` base |
| `GENOME_RP_ID` | `localhost` | WebAuthn relying-party ID |

## API summary

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /api/health` | none | liveness check |
| `POST /api/register/start` | none | begin WebAuthn passkey registration |
| `POST /api/register/finish` | none | complete registration |
| `POST /api/login/start` | none | begin WebAuthn assertion (login) |
| `POST /api/login/finish` | `DPoP` header (no `ath`) | complete login; mints a session bound to the DPoP key's `jkt`; this is the system's sole high-assurance anchor event |
| `POST /api/telemetry` | `DPoP` header with `ath` = hash of `session_token` | ingest a keystroke/mouse timing batch; runs detector + Asymmetric Learning Gate; returns trust score + decision |

See `src/auth.rs` and `src/telemetry.rs` module doc comments for exact
request/response JSON shapes, and `docs/THREAT_MODEL.md` /
`docs/ARCHITECTURE.md` for how each piece maps to a specific threat.

## Persistence

SQLite-backed (`src/store.rs`) behind a `Mutex`, sufficient for a
single-instance demo. **A real deployment needs a proper multi-instance-safe
datastore** (e.g. Postgres) plus a shared replay-cache/session store (e.g.
Redis) for the ephemeral WebAuthn ceremony state and DPoP replay cache this
demo keeps in-memory.
