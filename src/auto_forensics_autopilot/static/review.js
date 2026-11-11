// Auto Forensics review page.
// Everything that came from a case is placed with textContent. Nothing is
// written as HTML, so a file name or finding title cannot add markup or script.
"use strict";

(function () {
  const KILL_CHAIN = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
  ];
  const SHORT = { "reconnaissance": "recon", "resource-development": "resource dev", "privilege-escalation": "privilege escalation",
    "command-and-control": "command and control" };
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const $ = (id) => document.getElementById(id);

  function store(kind, key, value) {
    try {
      const s = kind === "session" ? window.sessionStorage : window.localStorage;
      if (value === undefined) return s.getItem(key);
      s.setItem(key, value);
    } catch (e) { /* storage blocked: keep going without it */ }
    return null;
  }

  // The token arrives in the URL fragment, which browsers never send to a server.
  let token = null;
  const match = /(?:^#|&)token=([A-Za-z0-9_-]{20,})/.exec(window.location.hash);
  if (match) {
    token = match[1];
    store("session", "af-token", token);
    history.replaceState(null, "", window.location.pathname);
  } else {
    token = store("session", "af-token");
  }

  function el(tag, cls, text) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  async function api(method, path, body) {
    const opts = { method, headers: { "X-Session-Token": token || "" }, cache: "no-store" };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (res.status === 401) { show("none"); $("no-token").hidden = false; throw new Error("No session"); }
    if (!res.ok) {
      const detail = data && data.detail;
      throw new Error(typeof detail === "string" ? detail : "The server refused the request (" + res.status + ")");
    }
    return data;
  }

  // Disable a form's buttons while its request is in flight (no double submits).
  async function busy(scope, fn) {
    const buttons = scope.querySelectorAll("button");
    if (scope.dataset.busy) return;
    scope.dataset.busy = "1";
    buttons.forEach((b) => { b.disabled = true; });
    try { await fn(); } finally {
      delete scope.dataset.busy;
      buttons.forEach((b) => { b.disabled = false; });
    }
  }

  function show(view) {
    for (const name of ["home", "running", "case"]) $("view-" + name).hidden = name !== view;
    $("tape").hidden = view === "home" || view === "none";
    window.scrollTo(0, 0);
  }

  function runStarted(runId) {
    const m = /-(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})\d{2}Z$/.exec(runId);
    return m ? m[1] + "-" + m[2] + "-" + m[3] + " " + m[4] + ":" + m[5] + " UTC" : "";
  }

  function whoIs() { return $("who").value.trim(); }
  $("who").value = store("local", "af-actor") || "";
  $("who").addEventListener("change", () => store("local", "af-actor", whoIs()));

  // ---------- Home ----------
  async function loadHome() {
    clearTimeout(pollTimer);
    current = null;
    store("session", "af-run", "");
    show("home");
    let data;
    try { data = await api("GET", "/api/runs"); } catch (e) { return; }
    $("workspace").textContent = "Workspace: " + data.workspace;
    const body = $("runs").tBodies[0];
    body.replaceChildren();
    $("runs-empty").hidden = data.runs.length > 0;
    $("runs").hidden = data.runs.length === 0;
    for (const run of data.runs) {
      const tr = el("tr");
      const name = el("td");
      const link = el("a", "", run.case_id || run.run_id.replace(/-\d{8}T\d{6}Z$/, ""));
      link.href = "#";
      link.addEventListener("click", (ev) => { ev.preventDefault(); openRun(run.run_id); });
      name.append(link);
      tr.append(name, el("td", "", runStarted(run.run_id)));
      tr.append(el("td", "", run.total === undefined ? "" : run.total));
      let label = "Draft, " + run.pending + " to decide";
      let cls = "pending";
      if (run.state === "running") { label = "Running"; cls = ""; }
      else if (run.state === "failed" || run.state === "error") { label = "Failed: " + (run.error || ""); cls = "failed"; }
      else if (run.state === "incomplete") { label = "Incomplete run folder"; cls = "failed"; }
      else if (run.exported) { label = "Signed and exported"; cls = "signed"; }
      else if (run.signed) { label = "Signed"; cls = "signed"; }
      else if (run.pending === 0) { label = "Ready to sign"; cls = "pending"; }
      tr.append(el("td", "state " + cls, label));
      tr.addEventListener("click", (ev) => { if (ev.target.tagName !== "A") openRun(run.run_id); });
      body.append(tr);
    }
  }

  $("start-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    $("start-error").textContent = "";
    const form = ev.target;
    const actor = whoIs();
    if (!actor) { $("start-error").textContent = "Add your name at the top of the page first."; $("who").focus(); return; }
    await busy(form, async () => { try {
      const res = await api("POST", "/api/runs", {
        input_dir: $("f-input").value.trim(),
        case_id: $("f-case").value.trim(),
        actor,
        llm: form.querySelector("input[name=llm]:checked").value,
      });
      openRun(res.run_id);
    } catch (e) {
      $("start-error").textContent = e.message;
    } });
  });

  $("home-link").addEventListener("click", (ev) => { ev.preventDefault(); loadHome(); });

  // ---------- Case ----------
  let current = null;   // {run_id, draft, status}
  let filter = "pending";
  const picked = new Set();
  let pollTimer = null;

  async function openRun(runId) {
    clearTimeout(pollTimer);
    store("session", "af-run", runId);
    let data;
    try { data = await api("GET", "/api/runs/" + encodeURIComponent(runId)); } catch (e) {
      if (e.message !== "No session") { await loadHome(); $("start-error").textContent = e.message; }
      return;
    }
    if (data.state === "running") {
      show("running");
      $("running-case").textContent = runId.replace(/-\d{8}T\d{6}Z$/, "");
      pollTimer = setTimeout(() => openRun(runId), 1500);
      return;
    }
    if (data.state === "failed") {
      await loadHome();
      $("start-error").textContent = "The run failed. " + data.error;
      return;
    }
    const firstOpen = !current || current.run_id !== runId;
    current = data;
    if (firstOpen) {
      picked.clear();
      filter = data.status.pending.length ? "pending" : "all";
      // Nothing typed or ticked for one case may carry over to another.
      for (const id of ["d-note", "s-fp", "s-statement", "e-sig"]) $(id).value = "";
      for (const id of ["d-override", "s-gaps"]) $(id).checked = false;
      for (const id of ["decide-error", "sign-error", "export-error"]) $(id).textContent = "";
    }
    const held = data.fingerprints || {};
    if (held.signature_fingerprint) showOnce("signature_fingerprint", held.signature_fingerprint);
    else if (held.run_fingerprint) showOnce("run_fingerprint", held.run_fingerprint);
    else $("once").hidden = true;
    renderCase();
    show("case");
  }

  function showOnce(kind, value) {
    $("once").hidden = false;
    $("once").dataset.kind = kind;
    $("once-value").textContent = value;
    if (kind === "run_fingerprint") {
      $("once-title").textContent = "Copy the run fingerprint";
      $("once-text").textContent = "You paste it back to sign. Keep it with your case notes, outside the case folder: it proves the draft you sign is the one this run wrote. It stays here until you confirm you saved it, and the server window printed it too.";
    } else {
      $("once-title").textContent = "Copy the signature fingerprint";
      $("once-text").textContent = "You paste it back to export the final report. Keep it with your case notes, outside the case folder. It stays here until you export or confirm you saved it.";
    }
  }

  $("once-done").addEventListener("click", async () => {
    const kind = $("once").dataset.kind;
    try {
      await api("POST", "/api/runs/" + encodeURIComponent(current.run_id) + "/copied", { kind });
      $("once").hidden = true;
    } catch (e) { /* the box stays; nothing lost */ }
  });

  $("once-copy").addEventListener("click", async () => {
    const text = $("once-value").textContent;
    try {
      await navigator.clipboard.writeText(text);
      $("once-copy").textContent = "Copied";
    } catch (e) {
      const range = document.createRange();
      range.selectNodeContents($("once-value"));
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      $("once-copy").textContent = "Selected: press Ctrl+C";
    }
    setTimeout(() => { $("once-copy").textContent = "Copy"; }, 2500);
  });

  function citeText(c) {
    if (c.row) return c.source_file + " row " + c.row;
    if (c.offset !== null && c.offset !== undefined) return c.source_file + " byte " + c.offset;
    return c.source_file;
  }

  function renderCase() {
    const { draft, status } = current;
    $("tape-case").textContent = draft.case_id;
    let state = "Draft, not signed";
    if (current.final) state = "Signed and exported";
    else if (status.signed) state = "Signed by " + status.signed_by;
    $("tape-state").textContent = state;

    $("headline").textContent = status.signed
      ? status.accepted + " finding(s) confirmed by the analyst, " + status.rejected + " rejected."
      : draft.headline;
    const counts = $("counts");
    counts.replaceChildren();
    for (const [label, n] of [["Findings", status.total], ["Accepted", status.accepted], ["Rejected", status.rejected], ["To decide", status.pending.length]]) {
      const box = el("div");
      box.append(el("dt", "", label), el("dd", "", n));
      counts.append(box);
    }

    $("hostile").hidden = !draft.hostile_files.length;
    $("hostile-list").replaceChildren(...draft.hostile_files.map((p) => { const li = el("li"); li.append(el("code", "", p)); return li; }));
    $("gaps").hidden = !draft.coverage_gaps.length;
    $("gaps-list").replaceChildren(...draft.coverage_gaps.map((g) => {
      const li = el("li");
      li.append(el("code", "", g.what), document.createTextNode(": " + g.why));
      return li;
    }));

    const byTactic = {};
    for (const step of draft.attack_chain) byTactic[step.tactic] = step;
    $("chain").replaceChildren(...KILL_CHAIN.map((tactic) => {
      const step = byTactic[tactic];
      const li = el("li", step ? "hit" : "");
      li.append(document.createTextNode(SHORT[tactic] || tactic.replace(/-/g, " ")));
      if (step) {
        li.style.setProperty("--sev", "var(--" + (SEVERITIES.includes(step.top_severity) ? step.top_severity : "info") + ")");
        li.title = step.titles.join("\n");
        li.append(el("span", "n", step.findings));
      }
      return li;
    }));

    renderFindings();
    renderSteps();
  }

  function renderFindings() {
    const all = current.draft.findings;
    const shown = all.filter((f) => filter === "all" || f.decision === filter);
    const visible = new Set(shown.map((f) => f.finding_id));
    for (const id of Array.from(picked)) if (!visible.has(id)) picked.delete(id);
    for (const btn of document.querySelectorAll(".filter")) btn.setAttribute("aria-pressed", String(btn.dataset.filter === filter));
    const body = $("findings").tBodies[0];
    body.replaceChildren();
    const signed = current.status.signed;
    for (const f of shown) {
      const tr = el("tr", picked.has(f.finding_id) ? "chosen" : "");
      const pick = el("td", "pick");
      const box = el("input");
      box.type = "checkbox";
      box.checked = picked.has(f.finding_id);
      box.disabled = signed;
      box.setAttribute("aria-label", "Select " + f.title);
      box.addEventListener("change", () => {
        if (box.checked) picked.add(f.finding_id); else picked.delete(f.finding_id);
        tr.className = box.checked ? "chosen" : "";
        updateBar();
      });
      pick.append(box);

      const sev = el("td");
      const sevName = SEVERITIES.includes(f.severity) ? f.severity : "info";
      sev.append(el("span", "sev sev-" + sevName, f.severity));

      const what = el("td");
      what.append(el("div", "title", f.title));
      const meta = [f.tactic && f.tactic !== "unknown" ? f.tactic.replace(/-/g, " ") : null, f.technique_id, "found by " + f.worker].filter(Boolean);
      what.append(el("div", "meta", meta.join(", ")));
      if (f.recommendation) what.append(el("div", "rec", f.recommendation));
      for (const w of f.warnings || []) what.append(el("div", "warn", w));

      const where = el("td", "where");
      for (const c of f.citations) {
        const line = el("div", "", citeText(c));
        line.title = "SHA-256 " + c.sha256;
        where.append(line);
      }

      const checked = el("td", "checked" + (f.verification ? "" : " none"), f.verification || "Not re-checked");

      const dec = el("td", "decision " + f.decision, f.decision === "pending" ? "Not decided" : (f.decision === "accept" ? "Accepted" : "Rejected"));
      if (f.decided_by) dec.append(el("span", "who", f.decided_by + (f.note ? ": " + f.note : "")));

      tr.append(pick, sev, what, where, checked, dec);
      body.append(tr);
    }
    const empty = $("findings-empty");
    empty.hidden = shown.length > 0;
    $("findings").hidden = shown.length === 0;
    empty.textContent = all.length === 0 ? "The run found nothing it could cite. You can still sign to record that." :
      (filter === "pending" ? "Every finding has a decision." : "Nothing here.");
    $("pick-all").checked = shown.length > 0 && shown.every((f) => picked.has(f.finding_id));
    $("pick-all").disabled = signed || shown.length === 0;
    updateBar();
  }

  function updateBar() {
    const n = picked.size;
    $("decide-bar").hidden = n === 0 || current.status.signed;
    $("picked").textContent = n + (n === 1 ? " finding selected" : " findings selected");
  }

  $("pick-all").addEventListener("change", (ev) => {
    const all = current.draft.findings.filter((f) => filter === "all" || f.decision === filter);
    for (const f of all) { if (ev.target.checked) picked.add(f.finding_id); else picked.delete(f.finding_id); }
    renderFindings();
  });

  for (const btn of document.querySelectorAll(".filter")) {
    btn.addEventListener("click", () => { filter = btn.dataset.filter; picked.clear(); renderFindings(); });
  }

  async function decide(decision) {
    $("decide-error").textContent = "";
    const actor = whoIs();
    const note = $("d-note").value.trim();
    if (!actor) { $("decide-error").textContent = "Add your name at the top of the page first."; return; }
    if (decision === "reject" && !note) { $("decide-error").textContent = "Write a reason to reject."; $("d-note").focus(); return; }
    let failed = "";
    await busy($("decide-bar"), async () => {
      try {
        await api("POST", "/api/runs/" + encodeURIComponent(current.run_id) + "/decide", {
          finding_ids: Array.from(picked), decision, actor, note, override: $("d-override").checked,
        });
        picked.clear();
        $("d-note").value = "";
        $("d-override").checked = false;
      } catch (e) {
        failed = e.message;
      }
      await openRun(current.run_id);
    });
    $("decide-error").textContent = failed;
  }
  $("d-accept").addEventListener("click", () => decide("accept"));
  $("d-reject").addEventListener("click", () => decide("reject"));
  $("decide-bar").addEventListener("submit", (ev) => ev.preventDefault());

  function renderSteps() {
    const { status, draft } = current;
    const pending = status.pending.length;
    const failed = draft.agents.filter((a) => a.status !== "ok");
    const set = (id, cls) => { $(id).className = cls; };
    $("step-decide-text").textContent = pending ? pending + " of " + status.total + " still need a decision." :
      "All " + status.total + " decided: " + status.accepted + " accepted, " + status.rejected + " rejected.";
    set("step-decide", pending ? "current" : "done");

    $("s-gaps-row").hidden = failed.length === 0;
    if (status.signed) {
      set("step-sign", "done");
      $("sign-form").hidden = true;
      $("signed-text").hidden = false;
      $("signed-text").textContent = "Signed by " + status.signed_by + ".";
    } else {
      set("step-sign", pending ? "locked" : "current");
      $("sign-form").hidden = false;
      $("signed-text").hidden = true;
    }

    if (current.final) {
      set("step-export", "done");
      $("export-form").hidden = true;
      $("exported-text").hidden = false;
      $("exported-text").replaceChildren(document.createTextNode("Final report written to "), el("code", "", current.final.folder));
    } else {
      set("step-export", status.signed ? "current" : "locked");
      $("export-form").hidden = false;
      $("exported-text").hidden = true;
    }
  }

  $("sign-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    $("sign-error").textContent = "";
    const actor = whoIs();
    if (!actor) { $("sign-error").textContent = "Add your name at the top of the page first."; return; }
    await busy(ev.target, async () => {
      try {
        await api("POST", "/api/runs/" + encodeURIComponent(current.run_id) + "/sign", {
          actor, fingerprint: $("s-fp").value.trim(), statement: $("s-statement").value.trim(), accept_gaps: $("s-gaps").checked,
        });
        $("s-fp").value = "";
        await openRun(current.run_id);
      } catch (e) {
        $("sign-error").textContent = e.message;
      }
    });
  });

  $("export-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    $("export-error").textContent = "";
    await busy(ev.target, async () => {
      try {
        await api("POST", "/api/runs/" + encodeURIComponent(current.run_id) + "/export", { signature: $("e-sig").value.trim() });
        $("e-sig").value = "";
        await openRun(current.run_id);
      } catch (e) {
        $("export-error").textContent = e.message;
      }
    });
  });

  // ---------- Start ----------
  if (!token) { show("none"); $("no-token").hidden = false; return; }
  const lastRun = store("session", "af-run");
  if (lastRun) openRun(lastRun); else loadHome();
})();
