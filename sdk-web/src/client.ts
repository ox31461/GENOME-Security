/**
 * Public SDK entry point: `GenomeClient` wires WebAuthn registration/login,
 * RFC 9449 DPoP proof generation, and keystroke/mouse telemetry capture
 * into a small, documented API any web app can integrate in a few lines:
 *
 * ```ts
 * import { GenomeClient } from "@genome-security/sdk-web";
 *
 * const client = new GenomeClient({ serverUrl: "http://localhost:8080" });
 * await client.register("alice", "Alice Example");
 * await client.login("alice");
 * client.startTelemetry(document.body);
 * client.onTrustUpdate((update) => console.log(update));
 * ```
 */

import { createDpopKeyPair, signDpopProof, type DpopKeyPair } from "./dpop";
import { createCredential, getCredential } from "./webauthn";
import { KeystrokeCapture } from "./telemetry/keystroke";
import { MouseCapture } from "./telemetry/mouse";
import { generateSyntheticKeystrokeBatch } from "./telemetry/simulate";

export interface GenomeClientOptions {
  /** Base URL of the GENOME Security risk-engine server, e.g. "http://localhost:8080".
   * Must share a hostname with the page the SDK runs on (WebAuthn RP ID rules) --
   * ports may differ. */
  serverUrl: string;
}

export type Decision = "allow" | "stepup" | "deny";

export interface TrustUpdate {
  kind: "keystroke" | "mouse";
  trustScore: number;
  risk: number;
  decision: Decision;
  syntheticProbability: number;
  baselineZ: number;
  gateOutcome: string | null;
}

export type TrustUpdateListener = (update: TrustUpdate) => void;
export type ErrorListener = (error: Error, context: string) => void;

interface SessionState {
  sessionToken: string;
  userId: string;
  username: string;
}

export class GenomeClient {
  private readonly serverUrl: string;
  private dpopKeyPair: DpopKeyPair | null = null;
  private session: SessionState | null = null;
  private keystrokeCapture: KeystrokeCapture | null = null;
  private mouseCapture: MouseCapture | null = null;
  private trustListeners: Set<TrustUpdateListener> = new Set();
  private errorListeners: Set<ErrorListener> = new Set();

  constructor(options: GenomeClientOptions) {
    this.serverUrl = options.serverUrl.replace(/\/+$/, "");
  }

  /** Register a new device-bound passkey for `username`. */
  async register(username: string, displayName: string = username): Promise<{ userId: string }> {
    const startRes = await fetch(`${this.serverUrl}/api/register/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, display_name: displayName }),
    });
    if (!startRes.ok) throw new Error(`register/start failed: ${await startRes.text()}`);
    const { registration_id, options } = await startRes.json();

    const { credentialJSON } = await createCredential(options.publicKey);

    const finishRes = await fetch(`${this.serverUrl}/api/register/finish`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ registration_id, credential: credentialJSON }),
    });
    if (!finishRes.ok) throw new Error(`register/finish failed: ${await finishRes.text()}`);
    const { user_id } = await finishRes.json();
    return { userId: user_id };
  }

  /**
   * Authenticate with an existing passkey. A successful assertion is the
   * system's sole high-assurance anchor event (see docs/THREAT_MODEL.md);
   * it mints a session token cryptographically bound (RFC 9449 `cnf.jkt`)
   * to a fresh DPoP keypair generated here.
   */
  async login(username: string): Promise<{ sessionToken: string }> {
    const startRes = await fetch(`${this.serverUrl}/api/login/start`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username }),
    });
    if (!startRes.ok) throw new Error(`login/start failed: ${await startRes.text()}`);
    const { auth_id, options } = await startRes.json();

    const { credentialJSON } = await getCredential(options.publicKey);

    this.dpopKeyPair = await createDpopKeyPair();
    const htu = `${this.serverUrl}/api/login/finish`;
    const proof = await signDpopProof(this.dpopKeyPair, { htm: "POST", htu });

    const finishRes = await fetch(htu, {
      method: "POST",
      headers: { "Content-Type": "application/json", DPoP: proof },
      body: JSON.stringify({ auth_id, credential: credentialJSON }),
    });
    if (!finishRes.ok) throw new Error(`login/finish failed: ${await finishRes.text()}`);
    const body = await finishRes.json();

    this.session = { sessionToken: body.session_token, userId: body.user_id, username: body.username };
    return { sessionToken: body.session_token };
  }

  /** Subscribe to trust-score updates emitted after every telemetry batch. Returns an unsubscribe function. */
  onTrustUpdate(listener: TrustUpdateListener): () => void {
    this.trustListeners.add(listener);
    return () => this.trustListeners.delete(listener);
  }

  /** Subscribe to non-fatal errors (e.g. a telemetry batch failing to send). */
  onError(listener: ErrorListener): () => void {
    this.errorListeners.add(listener);
    return () => this.errorListeners.delete(listener);
  }

  /** Start capturing keystroke + mouse telemetry on `target` (defaults to `document`) and streaming trust scores. */
  startTelemetry(target: EventTarget = document): void {
    if (!this.session || !this.dpopKeyPair) {
      throw new Error("GenomeClient.startTelemetry() called before a successful login()");
    }
    this.keystrokeCapture?.stop();
    this.mouseCapture?.stop();

    this.keystrokeCapture = new KeystrokeCapture(target, {
      onBatch: (samples) => this.sendTelemetry("keystroke", samples),
    });
    this.mouseCapture = new MouseCapture(target, {
      onBatch: (samples) => this.sendTelemetry("mouse", samples),
    });
    this.keystrokeCapture.start();
    this.mouseCapture.start();
  }

  stopTelemetry(): void {
    this.keystrokeCapture?.stop();
    this.mouseCapture?.stop();
    this.keystrokeCapture = null;
    this.mouseCapture = null;
  }

  /**
   * Demo-only helper: inject a batch of synthetic-looking keystroke
   * timing (see telemetry/simulate.ts) as if it were real telemetry, to
   * show the server-side detector and trust dial react. This exists so
   * the demo app can have a "simulate an injection attack" button; it is
   * NOT part of the SDK's production surface and should not be wired up
   * in a real integration.
   */
  async simulateSyntheticInjection(): Promise<void> {
    await this.sendTelemetry("keystroke", generateSyntheticKeystrokeBatch());
  }

  private async sendTelemetry(kind: "keystroke" | "mouse", samples: number[]): Promise<void> {
    if (!this.session || !this.dpopKeyPair) return;
    try {
      const htu = `${this.serverUrl}/api/telemetry`;
      const proof = await signDpopProof(this.dpopKeyPair, {
        htm: "POST",
        htu,
        accessToken: this.session.sessionToken,
      });
      const res = await fetch(htu, {
        method: "POST",
        headers: { "Content-Type": "application/json", DPoP: proof },
        body: JSON.stringify({ session_token: this.session.sessionToken, kind, samples }),
      });
      if (!res.ok) throw new Error(`telemetry ingest failed: ${await res.text()}`);
      const body = await res.json();
      const update: TrustUpdate = {
        kind,
        trustScore: body.trust_score,
        risk: body.risk,
        decision: body.decision,
        syntheticProbability: body.synthetic_probability,
        baselineZ: body.baseline_z,
        gateOutcome: body.gate_outcome ?? null,
      };
      for (const listener of this.trustListeners) listener(update);
    } catch (err) {
      for (const listener of this.errorListeners) {
        listener(err instanceof Error ? err : new Error(String(err)), "telemetry");
      }
    }
  }
}
