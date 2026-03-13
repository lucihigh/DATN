TEST_UI_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AI Service Test UI</title>
  <style>
    :root {
      --bg: #0f172a;
      --panel: #111827;
      --panel-2: #1f2937;
      --text: #e5e7eb;
      --muted: #9ca3af;
      --ok: #16a34a;
      --warn: #d97706;
      --danger: #dc2626;
      --line: #374151;
      --accent: #38bdf8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
      background: radial-gradient(circle at top right, #1e293b 0%, var(--bg) 60%);
      color: var(--text);
      min-height: 100vh;
    }
    .wrap {
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
    }
    h1 { margin: 0 0 6px; font-size: 26px; }
    p { margin: 0; color: var(--muted); }
    .grid {
      margin-top: 18px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 14px;
    }
    .card {
      background: linear-gradient(180deg, var(--panel) 0%, #0b1220 100%);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px;
    }
    .card h2 {
      margin: 0 0 10px;
      font-size: 16px;
    }
    .row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      margin-bottom: 8px;
    }
    .row.single { grid-template-columns: 1fr; }
    label {
      display: block;
      font-size: 12px;
      color: var(--muted);
      margin-bottom: 4px;
    }
    input, textarea, button {
      width: 100%;
      border-radius: 8px;
      border: 1px solid var(--line);
      background: var(--panel-2);
      color: var(--text);
      padding: 8px 10px;
      font-size: 13px;
    }
    textarea {
      min-height: 130px;
      resize: vertical;
      font-family: Consolas, "Courier New", monospace;
      line-height: 1.35;
    }
    button {
      cursor: pointer;
      background: #0b2a3a;
      border-color: #1b4f66;
      font-weight: 600;
    }
    button:hover { border-color: var(--accent); }
    .btn-row {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 8px;
      margin-top: 8px;
    }
    .status {
      margin-top: 12px;
      font-size: 12px;
      color: var(--muted);
    }
    .ok { color: var(--ok); }
    .warn { color: var(--warn); }
    .danger { color: var(--danger); }
    pre {
      margin: 0;
      max-height: 440px;
      overflow: auto;
      border-radius: 10px;
      border: 1px solid var(--line);
      background: #020617;
      color: #cbd5e1;
      padding: 12px;
      font-size: 12px;
      line-height: 1.45;
      font-family: Consolas, "Courier New", monospace;
    }
    .hint { color: var(--muted); font-size: 12px; margin-top: 6px; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>AI Service Test UI</h1>
    <p>Interactive test page for /health, /ai/*, /ai/tx/* endpoints.</p>

    <div class="grid">
      <section class="card">
        <h2>Auth and Common</h2>
        <div class="row single">
          <div>
            <label>X-AI-API-KEY</label>
            <input id="apiKey" value="local-dev-key" />
          </div>
        </div>
        <div class="row single">
          <div>
            <label>Bearer Token (optional, without "Bearer " prefix)</label>
            <input id="bearerToken" placeholder="jwt token..." />
          </div>
        </div>
        <div class="row">
          <div>
            <label>Login idempotency key</label>
            <input id="loginIdem" value="idem-login-ui-1" />
          </div>
          <div>
            <label>Transaction idempotency key</label>
            <input id="txIdem" value="idem-tx-ui-1" />
          </div>
        </div>
        <div class="btn-row">
          <button onclick="callSimple('GET','/health')">GET /health</button>
          <button onclick="callSimple('GET','/ai/status')">GET /ai/status</button>
          <button onclick="callSimple('GET','/ai/metrics')">GET /ai/metrics</button>
        </div>
        <div class="btn-row">
          <button onclick="callSimple('GET','/ai/admin/alerts')">GET /ai/admin/alerts</button>
          <button onclick="callSimple('GET','/ai/admin/stats')">GET /ai/admin/stats</button>
          <button onclick="callSimple('POST','/ai/reload-model')">POST /ai/reload-model</button>
        </div>
        <div id="statusLine" class="status">Ready.</div>
      </section>

      <section class="card">
        <h2>Login Model</h2>
        <label>Train events JSON array</label>
        <textarea id="loginTrainEvents"></textarea>
        <div class="row">
          <div>
            <label>Model version (optional)</label>
            <input id="loginModelVersion" placeholder="runtime_login_ui_v1" />
          </div>
          <div>
            <label>Persist + Promote</label>
            <input id="loginPersistPromote" value="true" />
          </div>
        </div>
        <div class="btn-row">
          <button onclick="fillLoginTrainSample()">Fill login train sample</button>
          <button onclick="trainLogin()">POST /ai/train</button>
          <button onclick="callSimple('GET','/ai/status')">Refresh status</button>
        </div>
        <label style="margin-top:10px;">Login score event JSON object</label>
        <textarea id="loginScoreEvent"></textarea>
        <div class="btn-row">
          <button onclick="fillLoginScoreSample()">Fill login score sample</button>
          <button onclick="scoreLogin()">POST /ai/score</button>
          <button onclick="clearOutput()">Clear output</button>
        </div>
        <label style="margin-top:10px;">Login simulation form</label>
        <div class="row">
          <div>
            <label>Username</label>
            <input id="loginFormUser" value="demo-user" />
          </div>
          <div>
            <label>Password (for UI only)</label>
            <input id="loginFormPassword" type="password" value="secret123" />
          </div>
        </div>
        <div class="row">
          <div>
            <label>IP</label>
            <input id="loginFormIp" value="88.88.88.88" />
          </div>
          <div>
            <label>Country</label>
            <input id="loginFormCountry" value="RU" />
          </div>
        </div>
        <div class="row">
          <div>
            <label>Device / User-Agent</label>
            <input id="loginFormDevice" value="VeryStrangeBot/9.9" />
          </div>
          <div>
            <label>success (0 or 1)</label>
            <input id="loginFormSuccess" value="0" />
          </div>
        </div>
        <div class="row">
          <div>
            <label>failed_10m</label>
            <input id="loginFormFailed10m" value="8" />
          </div>
          <div>
            <label>bot_score (0..1)</label>
            <input id="loginFormBotScore" value="0.96" />
          </div>
        </div>
        <div class="btn-row">
          <button onclick="fillLoginFormNormal()">Fill normal profile</button>
          <button onclick="fillLoginFormRisky()">Fill risky profile</button>
          <button onclick="scoreLoginFromForm()">Simulate Login -> /ai/score</button>
        </div>
        <div class="hint">Password is not sent to AI endpoint; it is for login-like UI simulation only.</div>
        <label style="margin-top:10px;">Login attack demo</label>
        <div class="row">
          <div>
            <label>Attack attempts</label>
            <input id="attackAttempts" value="8" />
          </div>
          <div>
            <label>Delay per attempt (ms)</label>
            <input id="attackDelayMs" value="250" />
          </div>
        </div>
        <div class="row">
          <div>
            <label>Attacker country</label>
            <input id="attackCountry" value="RU" />
          </div>
          <div>
            <label>Attacker device</label>
            <input id="attackDevice" value="CredentialStuffingBot/1.0" />
          </div>
        </div>
        <div class="btn-row">
          <button onclick="runLoginAttackDemo(true)">Run attack demo (auto train)</button>
          <button onclick="runLoginAttackDemo(false)">Run attack only</button>
          <button onclick="fillLoginFormRisky()">Preset risky</button>
        </div>
        <div class="hint">Demo flow: normal baseline login, then burst suspicious attempts from attacker profile.</div>
      </section>

      <section class="card">
        <h2>Transaction Model</h2>
        <label>Train events JSON array</label>
        <textarea id="txTrainEvents"></textarea>
        <div class="row">
          <div>
            <label>Model version (optional)</label>
            <input id="txModelVersion" placeholder="runtime_tx_ui_v1" />
          </div>
          <div>
            <label>Persist + Promote</label>
            <input id="txPersistPromote" value="true" />
          </div>
        </div>
        <div class="btn-row">
          <button onclick="fillTxTrainSample()">Fill tx train sample</button>
          <button onclick="trainTx()">POST /ai/tx/train</button>
          <button onclick="callSimple('GET','/ai/status')">Refresh status</button>
        </div>
        <label style="margin-top:10px;">Transaction score event JSON object</label>
        <textarea id="txScoreEvent"></textarea>
        <div class="btn-row">
          <button onclick="fillTxScoreSample()">Fill tx score sample</button>
          <button onclick="scoreTx()">POST /ai/tx/score</button>
          <button onclick="clearOutput()">Clear output</button>
        </div>
        <label style="margin-top:10px;">Transaction anomaly demo</label>
        <div class="row">
          <div>
            <label>Anomaly attempts</label>
            <input id="txAttackAttempts" value="6" />
          </div>
          <div>
            <label>Delay per attempt (ms)</label>
            <input id="txAttackDelayMs" value="250" />
          </div>
        </div>
        <div class="row">
          <div>
            <label>Demo user_id</label>
            <input id="txAttackUser" value="demo-user" />
          </div>
          <div>
            <label>Anomaly country</label>
            <input id="txAttackCountry" value="RU" />
          </div>
        </div>
        <div class="row">
          <div>
            <label>Payment method</label>
            <input id="txAttackMethod" value="crypto" />
          </div>
          <div>
            <label>Merchant category</label>
            <input id="txAttackMerchant" value="gambling" />
          </div>
        </div>
        <div class="btn-row">
          <button onclick="runTxAnomalyDemo(true)">Run anomaly demo (auto train)</button>
          <button onclick="runTxAnomalyDemo(false)">Run anomaly only</button>
          <button onclick="fillTxScoreSample()">Preset anomaly</button>
        </div>
        <div class="hint">Demo flow: baseline normal transaction, then burst abnormal transactions (high amount + risky behavior).</div>
      </section>

      <section class="card" style="grid-column: 1 / -1;">
        <h2>Output</h2>
        <pre id="output">{}</pre>
        <div class="hint">
          Tips: train each model first before scoring to avoid 503 ("model is not trained yet").
        </div>
      </section>
    </div>
  </div>

  <script>
    const outputEl = document.getElementById("output");
    const statusEl = document.getElementById("statusLine");

    function setStatus(text, level) {
      statusEl.textContent = text;
      statusEl.className = "status " + (level || "");
    }

    function pretty(value) {
      return JSON.stringify(value, null, 2);
    }

    function clearOutput() {
      outputEl.textContent = "{}";
      setStatus("Output cleared.", "");
    }

    function baseHeaders() {
      const headers = { "Content-Type": "application/json" };
      const apiKey = document.getElementById("apiKey").value.trim();
      const token = document.getElementById("bearerToken").value.trim();
      if (apiKey) headers["X-AI-API-KEY"] = apiKey;
      if (token) headers["Authorization"] = token.startsWith("Bearer ") ? token : ("Bearer " + token);
      return headers;
    }

    async function sendRequestRaw(method, path, body, extraHeaders) {
      const headers = { ...baseHeaders(), ...(extraHeaders || {}) };
      const init = { method, headers };
      if (body !== undefined && body !== null) {
        init.body = JSON.stringify(body);
      }
      try {
        const response = await fetch(path, init);
        const contentType = response.headers.get("content-type") || "";
        let data;
        if (contentType.includes("application/json")) {
          data = await response.json();
        } else {
          data = { text: await response.text() };
        }
        return {
          ok: response.ok,
          status: response.status,
          data: data,
          error: null
        };
      } catch (error) {
        return {
          ok: false,
          status: 0,
          data: null,
          error: String(error)
        };
      }
    }

    async function sendRequest(method, path, body, extraHeaders) {
      setStatus(method + " " + path + " ...", "warn");
      const result = await sendRequestRaw(method, path, body, extraHeaders);
      outputEl.textContent = pretty({
        request: { method, path, body: body || null },
        response: { status: result.status, ok: result.ok, data: result.data, error: result.error }
      });
      if (result.error) {
        setStatus(method + " " + path + " -> network error", "danger");
        return;
      }
      if (result.ok) {
        setStatus(method + " " + path + " -> " + result.status, "ok");
      } else {
        setStatus(method + " " + path + " -> " + result.status, "danger");
      }
    }

    function parseJsonField(id, fallback) {
      const raw = document.getElementById(id).value.trim();
      if (!raw) return fallback;
      return JSON.parse(raw);
    }

    function buildTrainQuery(modelVersionId, persistPromoteId) {
      const params = new URLSearchParams();
      const modelVersion = document.getElementById(modelVersionId).value.trim();
      const persistPromote = document.getElementById(persistPromoteId).value.trim().toLowerCase();
      if (persistPromote === "true" || persistPromote === "1" || persistPromote === "yes") {
        params.set("persist", "true");
        params.set("promote", "true");
      }
      if (modelVersion) params.set("model_version", modelVersion);
      const query = params.toString();
      return query ? ("?" + query) : "";
    }

    async function callSimple(method, path) {
      await sendRequest(method, path, null, {});
    }

    async function trainLogin() {
      let events;
      try {
        events = parseJsonField("loginTrainEvents", []);
        if (!Array.isArray(events)) throw new Error("Train payload must be a JSON array.");
      } catch (error) {
        outputEl.textContent = pretty({ error: String(error) });
        setStatus("Invalid login train JSON.", "danger");
        return;
      }
      const path = "/ai/train" + buildTrainQuery("loginModelVersion", "loginPersistPromote");
      await sendRequest("POST", path, { events }, {});
    }

    async function scoreLogin() {
      let event;
      try {
        event = parseJsonField("loginScoreEvent", {});
        if (!event || Array.isArray(event)) throw new Error("Score payload must be a JSON object.");
      } catch (error) {
        outputEl.textContent = pretty({ error: String(error) });
        setStatus("Invalid login score JSON.", "danger");
        return;
      }
      const idem = document.getElementById("loginIdem").value.trim();
      await sendRequest("POST", "/ai/score", event, idem ? { "X-Idempotency-Key": idem } : {});
    }

    function buildLoginFormPayload() {
      const userId = document.getElementById("loginFormUser").value.trim();
      const ip = document.getElementById("loginFormIp").value.trim();
      const country = document.getElementById("loginFormCountry").value.trim();
      const device = document.getElementById("loginFormDevice").value.trim();
      const success = Number(document.getElementById("loginFormSuccess").value);
      const failed10m = Number(document.getElementById("loginFormFailed10m").value);
      const botScore = Number(document.getElementById("loginFormBotScore").value);

      if (!userId || !ip || !country || !device) {
        throw new Error("username, ip, country, device are required.");
      }
      if (!Number.isFinite(success) || !Number.isFinite(failed10m) || !Number.isFinite(botScore)) {
        throw new Error("success, failed_10m, bot_score must be numeric.");
      }

      return {
        user_id: userId,
        timestamp: new Date().toISOString(),
        ip: ip,
        country: country,
        device: device,
        success: Math.max(0, Math.min(1, Math.round(success))),
        failed_10m: Math.max(0, Math.round(failed10m)),
        bot_score: Math.max(0, Math.min(1, botScore))
      };
    }

    async function scoreLoginFromForm() {
      let event;
      try {
        event = buildLoginFormPayload();
      } catch (error) {
        outputEl.textContent = pretty({ error: String(error) });
        setStatus("Invalid login simulation form.", "danger");
        return;
      }

      document.getElementById("loginScoreEvent").value = pretty(event);
      const idem = document.getElementById("loginIdem").value.trim();
      await sendRequest("POST", "/ai/score", event, idem ? { "X-Idempotency-Key": idem } : {});
    }

    function makeDemoTrainEvents(userId) {
      const now = Date.now();
      const events = [];
      for (let i = 0; i < 12; i += 1) {
        const ts = new Date(now - i * 10 * 60 * 1000).toISOString();
        events.push({
          user_id: userId,
          timestamp: ts,
          ip: "1.1.1." + ((i % 3) + 1),
          country: "VN",
          device: "Mozilla/5.0 Chrome",
          success: 1,
          failed_10m: 0,
          bot_score: 0.08
        });
      }
      return events;
    }

    function sleep(ms) {
      return new Promise((resolve) => setTimeout(resolve, ms));
    }

    function riskSummary(items) {
      const summary = { LOW: 0, MEDIUM: 0, HIGH: 0, UNKNOWN: 0 };
      for (const item of items) {
        const level = item && item.risk_level ? String(item.risk_level).toUpperCase() : "UNKNOWN";
        if (summary[level] === undefined) summary.UNKNOWN += 1;
        else summary[level] += 1;
      }
      return summary;
    }

    async function runLoginAttackDemo(autoTrain) {
      const userId = document.getElementById("loginFormUser").value.trim() || "demo-user";
      const attempts = Math.max(3, Math.min(30, Number(document.getElementById("attackAttempts").value) || 8));
      const delayMs = Math.max(0, Math.min(2000, Number(document.getElementById("attackDelayMs").value) || 250));
      const attackerCountry = (document.getElementById("attackCountry").value.trim() || "RU").toUpperCase();
      const attackerDevice = document.getElementById("attackDevice").value.trim() || "CredentialStuffingBot/1.0";
      const demoId = Date.now();
      const baselinePayload = {
        user_id: userId,
        timestamp: new Date().toISOString(),
        ip: "1.1.1.9",
        country: "VN",
        device: "Mozilla/5.0 Chrome",
        success: 1,
        failed_10m: 0,
        bot_score: 0.08
      };

      setStatus("Starting login attack demo...", "warn");
      const output = {
        scenario: {
          user_id: userId,
          attempts: attempts,
          delay_ms: delayMs,
          attacker_country: attackerCountry,
          attacker_device: attackerDevice,
          auto_train: autoTrain
        },
        steps: {}
      };

      if (autoTrain) {
        const trainPath = "/ai/train?model_version=demo_login_attack_" + demoId;
        const trainEvents = makeDemoTrainEvents(userId);
        const trainResult = await sendRequestRaw("POST", trainPath, { events: trainEvents }, {});
        output.steps.train = {
          request_path: trainPath,
          train_size: trainEvents.length,
          status: trainResult.status,
          ok: trainResult.ok,
          data: trainResult.data,
          error: trainResult.error
        };
        if (!trainResult.ok) {
          outputEl.textContent = pretty(output);
          setStatus("Attack demo failed at training step.", "danger");
          return;
        }
      }

      const baselineResult = await sendRequestRaw(
        "POST",
        "/ai/score",
        baselinePayload,
        { "X-Idempotency-Key": "demo-baseline-" + demoId }
      );
      output.steps.baseline = {
        payload: baselinePayload,
        status: baselineResult.status,
        ok: baselineResult.ok,
        data: baselineResult.data,
        error: baselineResult.error
      };
      if (!baselineResult.ok) {
        outputEl.textContent = pretty(output);
        setStatus("Attack demo failed at baseline score step.", "danger");
        return;
      }

      const attemptsResult = [];
      for (let i = 0; i < attempts; i += 1) {
        setStatus("Running attack attempt " + (i + 1) + "/" + attempts + "...", "warn");
        const attackPayload = {
          user_id: userId,
          timestamp: new Date().toISOString(),
          ip: "88.88.88." + ((i % 100) + 1),
          country: attackerCountry,
          device: attackerDevice,
          success: 0,
          failed_10m: 3 + i,
          bot_score: Math.min(0.99, 0.85 + i * 0.02)
        };
        const attemptResult = await sendRequestRaw(
          "POST",
          "/ai/score",
          attackPayload,
          { "X-Idempotency-Key": "demo-attack-" + demoId + "-" + i }
        );
        attemptsResult.push({
          attempt: i + 1,
          status: attemptResult.status,
          ok: attemptResult.ok,
          risk_level: attemptResult.data ? attemptResult.data.risk_level : null,
          anomaly_score: attemptResult.data ? attemptResult.data.anomaly_score : null,
          reasons: attemptResult.data ? attemptResult.data.reasons : null,
          error: attemptResult.error
        });
        if (delayMs > 0 && i < attempts - 1) {
          await sleep(delayMs);
        }
      }

      output.steps.attack_attempts = attemptsResult;
      output.result = {
        baseline_risk: baselineResult.data ? baselineResult.data.risk_level : null,
        attack_risk_counts: riskSummary(attemptsResult),
        high_risk_attempts: attemptsResult.filter((x) => x.risk_level === "HIGH").length,
        total_attempts: attemptsResult.length
      };

      outputEl.textContent = pretty(output);
      setStatus("Login attack demo completed.", "ok");
    }

    function makeDemoTxTrainEvents(userId) {
      const now = Date.now();
      const events = [];
      for (let i = 0; i < 12; i += 1) {
        const ts = new Date(now - i * 12 * 60 * 1000).toISOString();
        events.push({
          user_id: userId,
          transaction_id: "tx-demo-train-" + i,
          timestamp: ts,
          amount: 120 + i * 20,
          currency: "USD",
          country: "US",
          payment_method: "card",
          merchant_category: "retail",
          device: "Mozilla/5.0 Chrome",
          failed_tx_24h: 0,
          velocity_1h: 1
        });
      }
      return events;
    }

    async function runTxAnomalyDemo(autoTrain) {
      const userId = document.getElementById("txAttackUser").value.trim() || "demo-user";
      const attempts = Math.max(3, Math.min(30, Number(document.getElementById("txAttackAttempts").value) || 6));
      const delayMs = Math.max(0, Math.min(2000, Number(document.getElementById("txAttackDelayMs").value) || 250));
      const anomalyCountry = (document.getElementById("txAttackCountry").value.trim() || "RU").toUpperCase();
      const anomalyMethod = (document.getElementById("txAttackMethod").value.trim() || "crypto").toLowerCase();
      const anomalyMerchant = (document.getElementById("txAttackMerchant").value.trim() || "gambling").toLowerCase();
      const demoId = Date.now();

      setStatus("Starting transaction anomaly demo...", "warn");
      const output = {
        scenario: {
          user_id: userId,
          attempts: attempts,
          delay_ms: delayMs,
          anomaly_country: anomalyCountry,
          anomaly_method: anomalyMethod,
          anomaly_merchant: anomalyMerchant,
          auto_train: autoTrain
        },
        steps: {}
      };

      if (autoTrain) {
        const trainPath = "/ai/tx/train?model_version=demo_tx_anomaly_" + demoId;
        const trainEvents = makeDemoTxTrainEvents(userId);
        const trainResult = await sendRequestRaw("POST", trainPath, { events: trainEvents }, {});
        output.steps.train = {
          request_path: trainPath,
          train_size: trainEvents.length,
          status: trainResult.status,
          ok: trainResult.ok,
          data: trainResult.data,
          error: trainResult.error
        };
        if (!trainResult.ok) {
          outputEl.textContent = pretty(output);
          setStatus("Transaction demo failed at training step.", "danger");
          return;
        }
      }

      const baselinePayload = {
        user_id: userId,
        transaction_id: "tx-demo-baseline-" + demoId,
        timestamp: new Date().toISOString(),
        amount: 180,
        currency: "USD",
        country: "US",
        payment_method: "card",
        merchant_category: "retail",
        device: "Mozilla/5.0 Chrome",
        failed_tx_24h: 0,
        velocity_1h: 1
      };

      const baselineResult = await sendRequestRaw(
        "POST",
        "/ai/tx/score",
        baselinePayload,
        { "X-Idempotency-Key": "demo-tx-baseline-" + demoId }
      );
      output.steps.baseline = {
        payload: baselinePayload,
        status: baselineResult.status,
        ok: baselineResult.ok,
        data: baselineResult.data,
        error: baselineResult.error
      };
      if (!baselineResult.ok) {
        outputEl.textContent = pretty(output);
        setStatus("Transaction demo failed at baseline score step.", "danger");
        return;
      }

      const attemptsResult = [];
      for (let i = 0; i < attempts; i += 1) {
        setStatus("Running anomaly attempt " + (i + 1) + "/" + attempts + "...", "warn");
        const anomalyPayload = {
          user_id: userId,
          transaction_id: "tx-demo-anomaly-" + demoId + "-" + i,
          timestamp: new Date().toISOString(),
          amount: 3500 + i * 2200,
          currency: "USD",
          country: anomalyCountry,
          payment_method: anomalyMethod,
          merchant_category: anomalyMerchant,
          device: "AutomationBot/2.0",
          failed_tx_24h: Math.min(10, 1 + i),
          velocity_1h: Math.min(12, 3 + i)
        };
        document.getElementById("txScoreEvent").value = pretty(anomalyPayload);

        const attemptResult = await sendRequestRaw(
          "POST",
          "/ai/tx/score",
          anomalyPayload,
          { "X-Idempotency-Key": "demo-tx-anomaly-" + demoId + "-" + i }
        );
        attemptsResult.push({
          attempt: i + 1,
          status: attemptResult.status,
          ok: attemptResult.ok,
          risk_level: attemptResult.data ? attemptResult.data.risk_level : null,
          anomaly_score: attemptResult.data ? attemptResult.data.anomaly_score : null,
          reasons: attemptResult.data ? attemptResult.data.reasons : null,
          error: attemptResult.error
        });
        if (delayMs > 0 && i < attempts - 1) {
          await sleep(delayMs);
        }
      }

      output.steps.anomaly_attempts = attemptsResult;
      output.result = {
        baseline_risk: baselineResult.data ? baselineResult.data.risk_level : null,
        anomaly_risk_counts: riskSummary(attemptsResult),
        high_risk_attempts: attemptsResult.filter((x) => x.risk_level === "HIGH").length,
        total_attempts: attemptsResult.length
      };

      outputEl.textContent = pretty(output);
      setStatus("Transaction anomaly demo completed.", "ok");
    }

    function fillLoginFormNormal() {
      document.getElementById("loginFormUser").value = "demo-user";
      document.getElementById("loginFormPassword").value = "secret123";
      document.getElementById("loginFormIp").value = "1.1.1.10";
      document.getElementById("loginFormCountry").value = "VN";
      document.getElementById("loginFormDevice").value = "Mozilla/5.0 Chrome";
      document.getElementById("loginFormSuccess").value = "1";
      document.getElementById("loginFormFailed10m").value = "0";
      document.getElementById("loginFormBotScore").value = "0.10";
      setStatus("Filled normal login profile.", "");
    }

    function fillLoginFormRisky() {
      document.getElementById("loginFormUser").value = "demo-user";
      document.getElementById("loginFormPassword").value = "secret123";
      document.getElementById("loginFormIp").value = "88.88.88.88";
      document.getElementById("loginFormCountry").value = "RU";
      document.getElementById("loginFormDevice").value = "VeryStrangeBot/9.9";
      document.getElementById("loginFormSuccess").value = "0";
      document.getElementById("loginFormFailed10m").value = "8";
      document.getElementById("loginFormBotScore").value = "0.96";
      setStatus("Filled risky login profile.", "");
    }

    async function trainTx() {
      let events;
      try {
        events = parseJsonField("txTrainEvents", []);
        if (!Array.isArray(events)) throw new Error("Train payload must be a JSON array.");
      } catch (error) {
        outputEl.textContent = pretty({ error: String(error) });
        setStatus("Invalid transaction train JSON.", "danger");
        return;
      }
      const path = "/ai/tx/train" + buildTrainQuery("txModelVersion", "txPersistPromote");
      await sendRequest("POST", path, { events }, {});
    }

    async function scoreTx() {
      let event;
      try {
        event = parseJsonField("txScoreEvent", {});
        if (!event || Array.isArray(event)) throw new Error("Score payload must be a JSON object.");
      } catch (error) {
        outputEl.textContent = pretty({ error: String(error) });
        setStatus("Invalid transaction score JSON.", "danger");
        return;
      }
      const idem = document.getElementById("txIdem").value.trim();
      await sendRequest("POST", "/ai/tx/score", event, idem ? { "X-Idempotency-Key": idem } : {});
    }

    function fillLoginTrainSample() {
      const now = Date.now();
      const events = [];
      for (let i = 0; i < 12; i += 1) {
        const ts = new Date(now - i * 15 * 60 * 1000).toISOString();
        events.push({
          user_id: "user-" + (i % 3),
          timestamp: ts,
          ip: "1.1.1." + ((i % 5) + 1),
          country: "VN",
          device: "Mozilla/5.0 Chrome",
          success: 1,
          failed_10m: 0,
          bot_score: 0.1
        });
      }
      document.getElementById("loginTrainEvents").value = pretty(events);
      setStatus("Filled login train sample.", "");
    }

    function fillLoginScoreSample() {
      const event = {
        user_id: "user-risk",
        timestamp: new Date().toISOString(),
        ip: "88.88.88.88",
        country: "RU",
        device: "VeryStrangeBot/9.9",
        success: 0,
        failed_10m: 8,
        bot_score: 0.96
      };
      document.getElementById("loginScoreEvent").value = pretty(event);
      setStatus("Filled login score sample.", "");
    }

    function fillTxTrainSample() {
      const now = Date.now();
      const events = [];
      for (let i = 0; i < 12; i += 1) {
        const ts = new Date(now - i * 20 * 60 * 1000).toISOString();
        events.push({
          user_id: "user-" + (i % 3),
          transaction_id: "tx-train-" + i,
          timestamp: ts,
          amount: 100 + i * 15,
          currency: "USD",
          country: "US",
          payment_method: "card",
          merchant_category: "retail",
          device: "Mozilla/5.0 Chrome",
          failed_tx_24h: 0,
          velocity_1h: 1
        });
      }
      document.getElementById("txTrainEvents").value = pretty(events);
      setStatus("Filled transaction train sample.", "");
    }

    function fillTxScoreSample() {
      const event = {
        user_id: "user-risk",
        transaction_id: "tx-risk-ui-1",
        timestamp: new Date().toISOString(),
        amount: 12500,
        currency: "USD",
        country: "RU",
        payment_method: "crypto",
        merchant_category: "gambling",
        device: "VeryStrangeBot/9.9",
        failed_tx_24h: 3,
        velocity_1h: 7
      };
      document.getElementById("txScoreEvent").value = pretty(event);
      setStatus("Filled transaction score sample.", "");
    }

    fillLoginTrainSample();
    fillLoginScoreSample();
    fillLoginFormRisky();
    fillTxTrainSample();
    fillTxScoreSample();
  </script>
</body>
</html>
"""
