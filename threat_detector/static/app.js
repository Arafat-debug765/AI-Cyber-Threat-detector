/* UI logic for the threat detector.
 *
 * Every value rendered here originates from captured network traffic, i.e.
 * from attacker-influenced input, so results are built with DOM APIs and
 * textContent only — never string-concatenated into innerHTML.
 */
(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const global_Charts = window.Charts;

  function setMessage(text, kind) {
    const box = $("message");
    box.textContent = text;
    box.className = "message message--" + (kind || "info");
    box.hidden = !text;
  }

  function setBusy(busy) {
    for (const id of ["train-btn", "detect-btn", "refresh-btn"]) {
      $(id).disabled = busy;
    }
  }

  /* The API token, when the instance is configured with one.
   *
   * Held in sessionStorage rather than a cookie: a cookie would be attached to
   * cross-site requests automatically, which is exactly the property that makes
   * CSRF possible. This is sent explicitly, and only by this page.
   */
  const TOKEN_KEY = "threat-detector-token";

  // "sessions" in flow mode, "packets" in packet mode; set from /api/summary.
  let unitLabel = "rows";

  function storedToken() {
    try {
      return sessionStorage.getItem(TOKEN_KEY) || null;
    } catch (err) {
      return null; // private mode, or storage disabled
    }
  }

  function rememberToken(token) {
    try {
      sessionStorage.setItem(TOKEN_KEY, token);
    } catch (err) {
      /* not fatal: the token just will not survive a reload */
    }
  }

  function askForToken() {
    const token = window.prompt(
      "This instance requires an API token (API_TOKEN on the server)."
    );
    if (token) rememberToken(token.trim());
    return token ? token.trim() : null;
  }

  /** Fetch JSON and surface server-reported errors instead of silently succeeding.
   *
   * The X-Requested-With header is required by the server on state-changing
   * requests: it forces a CORS preflight, which a cross-origin page cannot
   * satisfy, so a site the operator visits cannot POST to this service.
   */
  async function request(url, options, retrying) {
    const settings = Object.assign({}, options);
    settings.headers = Object.assign(
      { "X-Requested-With": "threat-detector" },
      settings.headers || {}
    );
    const token = storedToken();
    if (token) settings.headers["X-API-Token"] = token;

    const response = await fetch(url, settings);

    // 401 means a token is configured and ours is missing or stale. Ask once,
    // then retry; a second failure is a wrong token, not a missing one.
    if (response.status === 401 && !retrying && askForToken()) {
      return request(url, options, true);
    }

    let payload = {};
    try {
      payload = await response.json();
    } catch (err) {
      throw new Error("Server returned a non-JSON response (HTTP " + response.status + ").");
    }
    if (!response.ok) {
      throw new Error(payload.error || "Request failed (HTTP " + response.status + ").");
    }
    return payload;
  }

  async function refreshStatus() {
    try {
      const data = await request("/api/status");
      $("status-model").textContent = data.model_trained ? "trained" : "not trained";
      $("status-model").className = data.model_trained ? "ok" : "warn";
      $("status-data").textContent = data.dataset_present ? "present" : "missing";
      $("status-data").className = data.dataset_present ? "ok" : "warn";
      $("status-trained").textContent = data.trained_at
        ? new Date(data.trained_at).toLocaleString()
        : "—";
    } catch (err) {
      $("status-model").textContent = "unavailable";
      $("status-data").textContent = "unavailable";
    }
  }

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  /** Training is a background job, so the POST only starts it. */
  async function trainModel() {
    setBusy(true);
    setMessage("Starting training…", "info");
    try {
      await request("/api/train", { method: "POST" });
      const record = await pollTraining();
      if (record.state === "failed") {
        setMessage(record.error || "Training failed.", "error");
      } else {
        const result = record.result || {};
        setMessage(
          `Trained on ${result.rows_trained} rows from ${result.fitted_on}. ` +
            (result.fitted_on_baseline
              ? `Threshold ${result.threshold}.`
              : "Fitted on the traffic being inspected — set BASELINE_FILE to " +
                "known-good traffic for real detection."),
          result.fitted_on_baseline ? "success" : "info"
        );
      }
    } catch (err) {
      setMessage(err.message, "error");
    } finally {
      setBusy(false);
      refreshStatus();
    }
  }

  /** Poll until the job leaves the running state, backing off as it goes. */
  async function pollTraining() {
    let delay = 250;
    const deadline = Date.now() + 10 * 60 * 1000;
    while (Date.now() < deadline) {
      await sleep(delay);
      delay = Math.min(delay * 1.5, 3000);
      const status = await request("/api/status");
      const training = status.training || {};
      if (training.state !== "running") return training;
      const elapsed = Math.round((Date.now() - training.started_at * 1000) / 1000);
      setMessage(`Training… (${elapsed}s)`, "info");
    }
    throw new Error("Training is taking unusually long — check the server log.");
  }

  function renderAnomalies(data) {
    const container = $("results");
    container.replaceChildren();

    const badge = $("anomaly-count");
    badge.textContent = `${data.count} of ${data.total_packets} ${unitLabel} flagged`;
    badge.hidden = false;

    if (!data.anomalies.length) {
      const p = document.createElement("p");
      p.className = "empty";
      p.textContent = "No anomalies detected.";
      container.append(p);
      return;
    }

    // Flow mode returns sessions, packet mode returns packets — different
    // shapes. Prefer the known-good column order, then append anything else
    // the payload carries, so neither mode needs a hard-coded schema.
    const preferred = [
      "src_ip", "window_start", "packets", "bytes_total", "distinct_dst_ips",
      "distinct_dst_ports", "mean_interarrival", "std_interarrival",
      "timestamp", "dst_ip", "protocol", "packet_length", "anomaly_score",
    ];
    const present = new Set(Object.keys(data.anomalies[0]));
    const columns = preferred.filter((c) => present.has(c));
    const table = document.createElement("table");
    table.className = "results-table";

    const head = table.createTHead().insertRow();
    for (const col of columns) {
      const th = document.createElement("th");
      th.textContent = col.replace(/_/g, " ");
      head.append(th);
    }

    const body = table.createTBody();
    for (const row of data.anomalies) {
      const tr = body.insertRow();
      for (const col of columns) {
        const td = tr.insertCell();
        const value = row[col];
        td.textContent = formatCell(col, value);
      }
    }
    container.append(table);

    if (data.truncated) {
      const note = document.createElement("p");
      note.className = "hint";
      note.textContent = `Showing the ${data.returned} most anomalous packets.`;
      container.append(note);
    }
  }

  function renderDashboard(summary) {
    unitLabel = summary.unit || "rows";
    $("stat-total-label").textContent = summary.unit === "sessions"
      ? "Sessions analysed" : "Packets analysed";
    $("chart-protocols-title").textContent = summary.breakdown_label === "source"
      ? "Activity by source" : "Traffic by protocol";
    $("chart-scores-sub").textContent =
      `Where the model drew its line. Flagged ${unitLabel} cluster in the low-score tail.`;
    $("chart-protocols-sub").textContent = summary.breakdown_label === "source"
      ? "Which hosts the flagged sessions belong to."
      : "Which protocols carry the flagged packets.";
    $("stat-total").textContent = summary.total_packets.toLocaleString();
    $("stat-flagged").textContent = summary.flagged.toLocaleString();
    $("stat-rate").textContent = (summary.flag_rate * 100).toFixed(1) + "%";
    $("stat-min").textContent = summary.min_score.toFixed(3);
    global_Charts.scoreHistogram($("chart-scores"), summary.score_histogram);
    global_Charts.protocolBreakdown($("chart-protocols"), summary.protocols);
    $("dashboard").hidden = false;
  }

  function formatCell(column, value) {
    if (value === undefined || value === null) return "—";
    if (typeof value !== "number") return String(value);
    if (column === "anomaly_score") return value.toFixed(4);
    if (column === "window_start") return new Date(value).toLocaleTimeString();
    if (Number.isInteger(value)) return value.toLocaleString();
    return value.toFixed(2);
  }

  async function detectAnomalies() {
    setBusy(true);
    setMessage("Scoring packets…", "info");
    try {
      const [data, summary] = await Promise.all([
        request("/api/anomalies"),
        request("/api/summary"),
      ]);
      renderDashboard(summary);
      renderAnomalies(data);
      setMessage(`Detection complete — ${data.count} anomalies found.`, "success");
    } catch (err) {
      setMessage(err.message, "error");
      $("results").replaceChildren();
      $("anomaly-count").hidden = true;
      $("dashboard").hidden = true;
    } finally {
      setBusy(false);
    }
  }

  $("train-btn").addEventListener("click", trainModel);
  $("detect-btn").addEventListener("click", detectAnomalies);
  $("refresh-btn").addEventListener("click", refreshStatus);
  refreshStatus();
})();
