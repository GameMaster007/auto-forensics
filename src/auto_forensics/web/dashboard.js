"use strict";

const apiKeyInput = document.getElementById("apiKey");
const logEl = document.getElementById("log");
const casesEl = document.getElementById("cases");
const overviewEl = document.getElementById("overview");
const timelineEl = document.getElementById("timeline");
const heatmapEl = document.getElementById("heatmap");
const timelineFilterEl = document.getElementById("timelineFilter");
let lastOverview = null;

// Mirrors server-side validate_case_id pattern.
const CASE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$/;

function validateCaseId(value, fieldName) {
  const trimmed = (value || "").trim();
  if (!trimmed) {
    return fieldName + " is required.";
  }
  if (!CASE_ID_RE.test(trimmed)) {
    return fieldName + " must be 2-64 characters: letters, numbers, dot, underscore, or hyphen.";
  }
  return null;
}

function validateSourceDir(value) {
  const trimmed = (value || "").trim();
  if (!trimmed) {
    return "Source directory is required.";
  }
  // Must look like an absolute path (Windows or POSIX).
  if (!/^([A-Za-z]:[/\\]|\/|\\\\.+\\)/.test(trimmed)) {
    return "Source directory must be an absolute path (e.g. C:\\evidence or /mnt/evidence).";
  }
  return null;
}

function showFieldError(inputEl, message) {
  let errEl = inputEl.nextElementSibling;
  if (!errEl || !errEl.classList.contains("field-error")) {
    errEl = document.createElement("span");
    errEl.className = "field-error";
    inputEl.parentNode.insertBefore(errEl, inputEl.nextSibling);
  }
  errEl.textContent = message || "";
  inputEl.setAttribute("aria-invalid", message ? "true" : "false");
}

function clearFieldError(inputEl) {
  showFieldError(inputEl, "");
  inputEl.removeAttribute("aria-invalid");
}

function appendLog(message, payload) {
  const stamp = new Date().toISOString();
  let line = "[" + stamp + "] " + message;
  if (payload !== undefined) {
    line += "\n" + JSON.stringify(payload, null, 2);
  }
  logEl.textContent = line + "\n\n" + logEl.textContent;
}

async function api(path, method, body) {
  const headers = { "Content-Type": "application/json" };
  const key = apiKeyInput.value.trim();
  if (key) {
    headers["X-API-Key"] = key;
  }
  const res = await fetch(path, {
    method: method,
    headers: headers,
    body: body ? JSON.stringify(body) : undefined
  });
  const text = await res.text();
  let parsed = text;
  try {
    parsed = JSON.parse(text);
  } catch (_err) {
    parsed = text;
  }
  if (!res.ok) {
    throw new Error((parsed && parsed.detail) ? parsed.detail : ("HTTP " + res.status));
  }
  return parsed;
}

function renderCases(items) {
  if (!items.length) {
    casesEl.innerHTML = "<p>No cases found.</p>";
    return;
  }
  const html = items.map(function (c) {
    return (
      '<div class="case-item">' +
      "<strong>" + c.case_id + "</strong>" +
      '<div class="case-meta">status=' + c.status + " | updated=" + c.updated_at + "</div>" +
      "</div>"
    );
  }).join("");
  casesEl.innerHTML = '<div class="case-list">' + html + "</div>";
}

function renderTimeline(items, filterText) {
  const needle = (filterText || "").trim().toLowerCase();
  const filtered = items.filter(function (item) {
    if (!needle) return true;
    const blob = [item.timestamp, item.source, item.event_type, item.description].join(" ").toLowerCase();
    return blob.includes(needle);
  });
  const rows = filtered.map(function (item) {
    return (
      "<tr>" +
      "<td>" + (item.timestamp || "") + "</td>" +
      "<td>" + (item.event_type || "") + "</td>" +
      "<td>" + (item.source || "") + "</td>" +
      "<td>" + (item.description || "") + "</td>" +
      "</tr>"
    );
  }).join("");

  timelineEl.innerHTML =
    '<table class="timeline-table">' +
    "<thead><tr><th>Timestamp</th><th>Type</th><th>Source</th><th>Description</th></tr></thead>" +
    "<tbody>" + (rows || "<tr><td colspan=\"4\">No timeline events.</td></tr>") + "</tbody>" +
    "</table>";
}

function renderHeatmap(items) {
  const byHour = new Array(24).fill(0);
  items.forEach(function (item) {
    if (!item.timestamp) return;
    const d = new Date(item.timestamp);
    if (Number.isNaN(d.getTime())) return;
    byHour[d.getUTCHours()] += 1;
  });

  const peak = byHour.reduce(function (acc, value) { return Math.max(acc, value); }, 0) || 1;
  const html = byHour.map(function (count, hour) {
    const width = Math.round((count / peak) * 100);
    return (
      '<div class="heat-cell">' +
      '<div class="heat-label">' + String(hour).padStart(2, "0") + ':00Z (' + count + ")</div>" +
      '<div class="heat-bar-wrap"><div class="heat-bar" style="width:' + width + '%"></div></div>' +
      "</div>"
    );
  }).join("");
  heatmapEl.innerHTML = '<div class="heatmap">' + html + "</div>";
}

async function refreshCases() {
  try {
    const data = await api("/api/cases", "GET");
    renderCases(data);
    appendLog("Case list refreshed", { count: data.length });
  } catch (err) {
    appendLog("Refresh failed: " + err.message);
  }
}

async function waitForCaseCompletion(caseId) {
  for (let attempt = 0; attempt < 1800; attempt += 1) {
    const status = await api("/api/cases/" + encodeURIComponent(caseId) + "/status", "GET");
    appendLog("Case status", status);
    if (status.state === "complete" || status.state === "failed" || status.state === "not_found") {
      return status;
    }
    await new Promise(function (resolve) {
      setTimeout(resolve, 1000);
    });
  }
  return { case_id: caseId, state: "timeout", progress: 0, message: "Status polling timed out" };
}

document.getElementById("createCaseBtn").addEventListener("click", async function () {
  const inputEl = document.getElementById("newCaseId");
  const caseId = inputEl.value.trim();
  const err = validateCaseId(caseId, "Case ID");
  if (err) { showFieldError(inputEl, err); return; }
  clearFieldError(inputEl);
  try {
    const data = await api("/api/cases", "POST", { case_id: caseId });
    appendLog("Case created", data);
    await refreshCases();
  } catch (apiErr) {
    appendLog("Create failed: " + apiErr.message);
  }
});

document.getElementById("ingestBtn").addEventListener("click", async function () {
  const caseIdEl = document.getElementById("ingestCaseId");
  const sourceDirEl = document.getElementById("sourceDir");
  const caseId = caseIdEl.value.trim();
  const sourceDir = sourceDirEl.value.trim();
  const caseErr = validateCaseId(caseId, "Case ID");
  const dirErr = validateSourceDir(sourceDir);
  if (caseErr) showFieldError(caseIdEl, caseErr); else clearFieldError(caseIdEl);
  if (dirErr) showFieldError(sourceDirEl, dirErr); else clearFieldError(sourceDirEl);
  if (caseErr || dirErr) return;
  try {
    const data = await api("/api/cases/" + encodeURIComponent(caseId) + "/ingest", "POST", {
      source_dir: sourceDir
    });
    appendLog("Ingestion complete", data);
    await refreshCases();
  } catch (apiErr) {
    appendLog("Ingest failed: " + apiErr.message);
  }
});

document.getElementById("analyzeBtn").addEventListener("click", async function () {
  const inputEl = document.getElementById("analyzeCaseId");
  const caseId = inputEl.value.trim();
  const enableLlama = document.getElementById("enableLlama").checked;
  const err = validateCaseId(caseId, "Case ID");
  if (err) { showFieldError(inputEl, err); return; }
  clearFieldError(inputEl);
  try {
    const data = await api("/api/cases/" + encodeURIComponent(caseId) + "/analyze/async", "POST", {
      enable_llama: enableLlama
    });
    appendLog("Analysis started", data);
    const finalStatus = await waitForCaseCompletion(caseId);
    appendLog("Analysis status final", finalStatus);
    await refreshCases();
  } catch (apiErr) {
    appendLog("Analyze failed: " + apiErr.message);
  }
});

document.getElementById("inspectBtn").addEventListener("click", async function () {
  const inputEl = document.getElementById("inspectCaseId");
  const caseId = inputEl.value.trim();
  const err = validateCaseId(caseId, "Case ID");
  if (err) { showFieldError(inputEl, err); return; }
  clearFieldError(inputEl);
  try {
    const data = await api("/api/cases/" + encodeURIComponent(caseId), "GET");
    lastOverview = data;
    overviewEl.textContent = JSON.stringify(data, null, 2);
    renderTimeline(Array.isArray(data.timeline) ? data.timeline : [], timelineFilterEl.value);
    renderHeatmap(Array.isArray(data.timeline) ? data.timeline : []);
    appendLog("Case overview loaded", { case_id: caseId });
  } catch (apiErr) {
    appendLog("Inspect failed: " + apiErr.message);
  }
});

document.getElementById("refreshBtn").addEventListener("click", refreshCases);
timelineFilterEl.addEventListener("input", function () {
  if (!lastOverview || !Array.isArray(lastOverview.timeline)) {
    return;
  }
  renderTimeline(lastOverview.timeline, timelineFilterEl.value);
});
refreshCases();
