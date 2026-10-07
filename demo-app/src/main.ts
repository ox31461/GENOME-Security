import "./style.css";
import { GenomeClient, type TrustUpdate } from "@genome-security/sdk-web";

// The server's WebAuthn relying-party ID defaults to "localhost" (see
// server/src/main.rs GENOME_RP_ID). This demo MUST be loaded as
// http://localhost:<port>, not http://127.0.0.1:<port>, or passkey
// registration/login will fail with an RP ID mismatch. Vite's dev server
// listens on localhost by default, so this normally just works.
const SERVER_URL = "http://localhost:8080";

const app = document.querySelector<HTMLDivElement>("#app")!;
app.innerHTML = `
  <header>
    <h1>GENOME Security — Live Demo</h1>
    <p>Continuous adaptive biometric authentication: passkey login, then a live trust score driven by keystroke/mouse timing telemetry.</p>
  </header>

  <section class="panel">
    <h2>1. Account</h2>
    <div class="row">
      <input id="username" type="text" placeholder="username (e.g. alice)" value="alice" />
      <button id="btn-register">Register passkey</button>
      <button id="btn-login" class="secondary">Log in</button>
    </div>
    <div id="status-line">Not registered or logged in yet.</div>
  </section>

  <section class="panel">
    <h2>2. Live trust score</h2>
    <div class="dial-wrap">
      <svg id="dial" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r="68" fill="none" stroke="#223041" stroke-width="14" />
        <circle id="dial-arc" cx="80" cy="80" r="68" fill="none" stroke="#3fb950" stroke-width="14"
          stroke-dasharray="427.3" stroke-dashoffset="427.3" stroke-linecap="round"
          transform="rotate(-90 80 80)" />
      </svg>
      <div class="dial-readout">
        <div id="trust-number">--</div>
        <span id="decision-badge" class="decision-badge">idle</span>
        <div class="metric-grid">
          <div class="metric"><div class="label">Synthetic prob.</div><div class="value" id="m-synthetic">--</div></div>
          <div class="metric"><div class="label">Baseline z-score</div><div class="value" id="m-baseline">--</div></div>
          <div class="metric"><div class="label">Risk</div><div class="value" id="m-risk">--</div></div>
          <div class="metric"><div class="label">Gate outcome</div><div class="value" id="m-gate">--</div></div>
        </div>
      </div>
    </div>
  </section>

  <section class="panel">
    <h2>3. Try it</h2>
    <p style="color: var(--muted); margin-top: 0;">
      Type and move your mouse anywhere on this page after logging in — telemetry batches are
      sent automatically and the dial above updates in real time.
    </p>
    <div class="row">
      <button id="btn-inject" class="danger" disabled>Inject synthetic input (simulate attack)</button>
    </div>
    <div class="honest-note" style="margin-top: 0.9rem;">
      <strong>Honest limitation:</strong> the button above sends i.i.d.-Gaussian synthetic
      keystroke timing through the same pipeline a real injection attack would use. The server's
      defense here is a <em>statistical timing detector only</em> — this demo does not verify
      that input events originated from a physical input-bus interrupt, which remains a
      partially-open problem on commodity OSes. See
      <code>research/synthetic_input_detection/attested_input_pipeline.md</code>.
    </div>
  </section>

  <section class="panel">
    <h2>Event log</h2>
    <div id="log"></div>
  </section>

  <footer>
    Server: <code>${SERVER_URL}</code> &middot; SDK: <code>@genome-security/sdk-web</code> &middot;
    See <a href="https://github.com/ox31461/GENOME-Security" target="_blank" rel="noreferrer">repo docs</a> for architecture and threat model.
  </footer>
`;

const usernameInput = document.querySelector<HTMLInputElement>("#username")!;
const btnRegister = document.querySelector<HTMLButtonElement>("#btn-register")!;
const btnLogin = document.querySelector<HTMLButtonElement>("#btn-login")!;
const btnInject = document.querySelector<HTMLButtonElement>("#btn-inject")!;
const statusLine = document.querySelector<HTMLDivElement>("#status-line")!;
const dialArc = document.querySelector<SVGCircleElement>("#dial-arc")!;
const trustNumber = document.querySelector<HTMLDivElement>("#trust-number")!;
const decisionBadge = document.querySelector<HTMLSpanElement>("#decision-badge")!;
const mSynthetic = document.querySelector<HTMLDivElement>("#m-synthetic")!;
const mBaseline = document.querySelector<HTMLDivElement>("#m-baseline")!;
const mRisk = document.querySelector<HTMLDivElement>("#m-risk")!;
const mGate = document.querySelector<HTMLDivElement>("#m-gate")!;
const logEl = document.querySelector<HTMLDivElement>("#log")!;

const DIAL_CIRCUMFERENCE = 2 * Math.PI * 68;

function log(message: string): void {
  const line = document.createElement("div");
  const ts = new Date().toLocaleTimeString();
  line.textContent = `[${ts}] ${message}`;
  logEl.prepend(line);
  while (logEl.childElementCount > 60) logEl.lastChild?.remove();
}

function setStatus(message: string): void {
  statusLine.textContent = message;
}

const client = new GenomeClient({ serverUrl: SERVER_URL });

client.onError((err, context) => log(`error (${context}): ${err.message}`));

client.onTrustUpdate((update: TrustUpdate) => {
  const pct = Math.max(0, Math.min(100, update.trustScore));
  const offset = DIAL_CIRCUMFERENCE * (1 - pct / 100);
  dialArc.setAttribute("stroke-dashoffset", offset.toFixed(2));
  dialArc.setAttribute(
    "stroke",
    update.decision === "allow" ? "#3fb950" : update.decision === "stepup" ? "#d29922" : "#f85149",
  );
  trustNumber.textContent = pct.toFixed(0);
  decisionBadge.textContent = update.decision;
  decisionBadge.className = `decision-badge decision-${update.decision}`;
  mSynthetic.textContent = update.syntheticProbability.toFixed(3);
  mBaseline.textContent = update.baselineZ.toFixed(2);
  mRisk.textContent = update.risk.toFixed(3);
  mGate.textContent = update.gateOutcome ?? "n/a";
  log(
    `telemetry(${update.kind}) -> trust=${pct.toFixed(1)} decision=${update.decision} ` +
      `synthetic_p=${update.syntheticProbability.toFixed(3)} gate=${update.gateOutcome ?? "n/a"}`,
  );
});

btnRegister.addEventListener("click", async () => {
  const username = usernameInput.value.trim();
  if (!username) return;
  btnRegister.disabled = true;
  try {
    setStatus("Registering passkey — follow your browser/OS prompt...");
    const { userId } = await client.register(username);
    setStatus(`Registered "${username}" (user_id=${userId}). Now click "Log in".`);
    log(`register ok: username=${username} user_id=${userId}`);
  } catch (err) {
    setStatus(`Registration failed: ${(err as Error).message}`);
    log(`register failed: ${(err as Error).message}`);
  } finally {
    btnRegister.disabled = false;
  }
});

btnLogin.addEventListener("click", async () => {
  const username = usernameInput.value.trim();
  if (!username) return;
  btnLogin.disabled = true;
  try {
    setStatus("Logging in — follow your browser/OS passkey prompt...");
    const { sessionToken } = await client.login(username);
    setStatus(`Logged in as "${username}". Telemetry capture is live — type or move the mouse.`);
    log(`login ok: session_token=${sessionToken.slice(0, 12)}...`);
    client.startTelemetry();
    btnInject.disabled = false;
  } catch (err) {
    setStatus(`Login failed: ${(err as Error).message}`);
    log(`login failed: ${(err as Error).message}`);
  } finally {
    btnLogin.disabled = false;
  }
});

btnInject.addEventListener("click", async () => {
  btnInject.disabled = true;
  try {
    log("injecting synthetic (i.i.d. Gaussian) keystroke-timing batch...");
    await client.simulateSyntheticInjection();
  } finally {
    btnInject.disabled = false;
  }
});
