// Auto Forensics review page.
// Everything that came from a case is placed with textContent. Nothing is
// written as HTML, so a file name, finding title or evidence line cannot add
// markup or script to the page.
"use strict";

(function () {
  // ---------- Fixed wording ----------
  const KILL_CHAIN = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
  ];
  // [short label for the track, plain name, plain explanation]
  const TACTICS = {
    "reconnaissance": ["recon", "Looking around", "Someone gathering information before an attack."],
    "resource-development": ["resource dev", "Getting tools ready", "Setting up tools or accounts to use in an attack."],
    "initial-access": ["initial access", "Getting in", "How someone first got into the system."],
    "execution": ["execution", "Running programs", "Commands or programs being run, possibly ones that should not be."],
    "persistence": ["persistence", "Staying in", "Setting things up to keep access after a restart or a password change."],
    "privilege-escalation": ["privilege escalation", "Gaining more power", "Getting higher permissions, such as administrator rights."],
    "defense-evasion": ["defense evasion", "Hiding tracks", "Trying not to be noticed: clearing logs, switching off protection or disguising files."],
    "credential-access": ["credential access", "Stealing passwords", "Trying to get passwords or other login secrets."],
    "discovery": ["discovery", "Exploring", "Looking around the computer and network to see what is there."],
    "lateral-movement": ["lateral movement", "Moving between computers", "Using one computer to reach others on the same network."],
    "collection": ["collection", "Gathering data", "Pulling together files or information, often before taking it out."],
    "command-and-control": ["command and control", "Talking to an outside controller", "The computer contacting a system the attacker controls."],
    "exfiltration": ["exfiltration", "Taking data out", "Data leaving for somewhere it should not go: a USB stick, cloud storage or e-mail."],
    "impact": ["impact", "Causing damage", "Destroying, encrypting or tampering with data or systems."],
  };
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
  const WORKERS = {
    core_pipeline: "Main detectors",
    injection_sentinel: "Planted-instruction check",
    secrets_sweep: "Password and key search",
    memory: "Memory analysis",
    archive: "ZIP archives",
    disk_image: "Disk images",
    disk_artifacts: "Disk activity (USB, files, browsing)",
  };
  const STAGES = ["hashing", "planning", "analysing", "checking", "writing"];
  const PAGE = 200;

  // ---------- Small helpers ----------
  const $ = (id) => document.getElementById(id);

  function store(kind, key, value) {
    try {
      const s = kind === "session" ? window.sessionStorage : window.localStorage;
      if (value === undefined) return s.getItem(key);
      s.setItem(key, value);
    } catch (e) { /* storage blocked: keep going without it */ }
    return null;
  }

  // el("p", "cls", "text") or el("div", "cls", [children])
  function el(tag, cls, content) {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (Array.isArray(content)) node.append(...content.filter((c) => c !== null && c !== undefined));
    else if (content !== undefined && content !== null) node.textContent = String(content);
    return node;
  }
  const text = (s) => document.createTextNode(String(s));
  const sevOf = (s) => (SEVERITIES.includes(s) ? s : "info");
  const plural = (n, one, many) => n + " " + (n === 1 ? one : many);
  const caseOf = (runId) => runId.replace(/-\d{8}T\d{6}Z$/, "");

  function fmtTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    if (isNaN(d)) return String(iso).slice(0, 40);
    return d.toISOString().slice(0, 19).replace("T", " ") + " UTC";
  }
  function runStarted(run) {
    if (run.started_at) return fmtTime(run.started_at);
    const m = /-(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})\d{2}Z$/.exec(run.run_id);
    return m ? m[1] + "-" + m[2] + "-" + m[3] + " " + m[4] + ":" + m[5] + " UTC" : "";
  }
  function fmtBytes(n) {
    if (typeof n !== "number") return "";
    const units = ["bytes", "KB", "MB", "GB", "TB"];
    let i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
    return (i === 0 ? n : n.toFixed(n < 10 ? 1 : 0)) + " " + units[i];
  }
  function fmtElapsed(s) {
    if (typeof s !== "number") return "";
    return s < 60 ? s + " seconds" : Math.floor(s / 60) + " min " + (s % 60) + " s";
  }

  function toast(message, bad) {
    const t = el("div", "toast" + (bad ? " bad" : ""), message);
    $("toasts").append(t);
    setTimeout(() => t.remove(), bad ? 7000 : 3500);
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

  async function api(method, path, body) {
    const opts = { method, headers: { "X-Session-Token": token || "" }, cache: "no-store" };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    let res;
    try { res = await fetch(path, opts); } catch (e) {
      throw new Error("The page cannot reach Auto Forensics. Is its window still open?");
    }
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (res.status === 401) { show("none"); $("no-token").hidden = false; throw new Error("No session"); }
    if (!res.ok) {
      const detail = data && data.detail;
      const err = new Error(typeof detail === "string" ? detail : "The request was refused (" + res.status + ")");
      err.status = res.status;
      throw err;
    }
    return data;
  }

  // Disable a group's buttons while its request is in flight (no double submits).
  async function busy(scope, fn) {
    if (scope.dataset.busy) return;
    const buttons = Array.from(scope.querySelectorAll("button")).filter((b) => !b.disabled);
    scope.dataset.busy = "1";
    buttons.forEach((b) => { b.disabled = true; });
    try { await fn(); } finally {
      delete scope.dataset.busy;
      buttons.forEach((b) => { b.disabled = false; });
    }
  }

  // ---------- Theme ----------
  const THEMES = ["auto", "light", "dark"];
  function applyTheme(theme) {
    if (theme === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    $("theme-btn").textContent = "Theme: " + theme;
  }
  let theme = store("local", "af-theme");
  if (!THEMES.includes(theme)) theme = "auto";
  applyTheme(theme);
  $("theme-btn").addEventListener("click", () => {
    theme = THEMES[(THEMES.indexOf(theme) + 1) % THEMES.length];
    store("local", "af-theme", theme);
    applyTheme(theme);
  });

  // ---------- Reviewer name ----------
  function whoIs() { return $("who").value.trim(); }
  $("who").value = store("local", "af-actor") || "";
  $("who").addEventListener("change", () => store("local", "af-actor", whoIs()));
  function needName(errorNode) {
    if (whoIs()) return true;
    errorNode.textContent = "Type your name in the box at the top of the page first.";
    $("who").focus();
    return false;
  }

  // ---------- Views ----------
  let current = null;       // the open case: {run_id, draft, status, fingerprints, final, ...}
  let pollTimer = null;
  let homeTimer = null;
  const ui = { tab: "overview", filter: "pending", sevs: new Set(SEVERITIES), q: "", sort: "severity", tactic: null, open: null, limit: PAGE };
  const picked = new Set();
  const excerpts = new Map();

  function show(view) {
    for (const name of ["home", "running", "case"]) $("view-" + name).hidden = name !== view;
    $("tape").hidden = view !== "case" && view !== "running";
    $("tabs").hidden = view !== "case";
    if (view !== "case") { $("decide-bar").hidden = true; }
  }

  function sevBar(counts, cls) {
    const bar = el("div", "sevbar" + (cls ? " " + cls : ""));
    fillSevBar(bar, counts);
    return bar;
  }
  function fillSevBar(bar, counts) {
    bar.replaceChildren();
    const parts = [];
    for (const sev of SEVERITIES) {
      const n = (counts && counts[sev]) || 0;
      if (!n) continue;
      const seg = el("span", sev);
      seg.style.flexGrow = String(n);
      seg.style.flexBasis = "0";
      bar.append(seg);
      parts.push(n + " " + sev);
    }
    bar.setAttribute("aria-label", parts.length ? "Findings by seriousness: " + parts.join(", ") : "No findings");
    bar.title = parts.join(", ");
    return parts;
  }

  // ---------- Home ----------
  async function loadHome() {
    clearTimeout(pollTimer);
    clearTimeout(homeTimer);
    current = null;
    store("session", "af-run", "");
    show("home");
    let data;
    try { data = await api("GET", "/api/runs"); } catch (e) { return; }
    $("workspace").textContent = "Cases and reports are kept in " + data.workspace;
    const list = $("cases");
    list.replaceChildren();
    $("howto").hidden = data.runs.length > 0;
    $("home-lede").textContent = data.runs.length
      ? "Each case stays a draft until you have checked every finding and signed it."
      : "No cases yet. Here is how it works.";
    let anyRunning = false;
    for (const run of data.runs) list.append(caseRow(run));
    for (const run of data.runs) if (run.state === "running") anyRunning = true;
    if (anyRunning) homeTimer = setTimeout(() => { if (!$("view-home").hidden) loadHome(); }, 4000);
  }

  function caseRow(run) {
    let label = "Draft";
    let sub = plural(run.pending || 0, "finding", "findings") + " to decide";
    let cls = "pending";
    if (run.state === "running") { label = "Running"; sub = "Open to watch progress"; cls = ""; }
    else if (run.state === "failed" || run.state === "error") { label = "Did not finish"; sub = run.error || ""; cls = "failed"; }
    else if (run.state === "incomplete") { label = "Did not finish"; sub = "The window was closed during the run"; cls = "failed"; }
    else if (run.exported) { label = "Finished"; sub = "Signed and exported"; cls = "signed"; }
    else if (run.signed) { label = "Signed"; sub = "Ready to export"; cls = "signed"; }
    else if (run.pending === 0) { label = "Ready to sign"; sub = "Every finding is decided"; }

    const li = el("li", "case s-" + (cls || "running"));
    const open = el("button", "case-open");
    open.type = "button";
    open.append(el("div", "case-name", run.case_id || caseOf(run.run_id)));
    const where = run.evidence_folder ? "  from " + run.evidence_folder : "";
    open.append(el("div", "case-sub", "Started " + runStarted(run) + where));
    open.addEventListener("click", () => openRun(run.run_id));

    const mid = el("div");
    if (run.severity_counts && run.total) {
      mid.append(sevBar(run.severity_counts));
      mid.append(el("div", "sevnote", plural(run.total, "finding", "findings")));
    } else if (run.total !== undefined) {
      mid.append(el("div", "sevnote", plural(run.total, "finding", "findings")));
    }

    const state = el("div", "case-state " + cls, [text(label), el("small", "", sub)]);
    if (run.can_remove) {
      const rm = el("button", "case-remove", "Remove");
      rm.type = "button";
      rm.addEventListener("click", async () => {
        try {
          await api("DELETE", "/api/runs/" + encodeURIComponent(run.run_id));
          toast("Moved to the removed folder in the workspace.");
        } catch (e) { toast(e.message, true); }
        loadHome();
      });
      state.append(rm);
    }
    li.append(open, mid, state);
    return li;
  }

  $("start-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    $("start-error").textContent = "";
    const form = ev.target;
    if (!needName($("start-error"))) return;
    await busy(form, async () => {
      try {
        const res = await api("POST", "/api/runs", {
          input_dir: $("f-input").value.trim(),
          case_id: $("f-case").value.trim(),
          actor: whoIs(),
          llm: form.querySelector("input[name=llm]:checked").value,
        });
        $("f-input").value = "";
        $("f-case").value = "";
        openRun(res.run_id);
      } catch (e) {
        $("start-error").textContent = e.message;
      }
    });
  });

  $("home-link").addEventListener("click", (ev) => { ev.preventDefault(); loadHome(); });

  // ---------- Folder browser ----------
  let browseAt = "";
  function suggestCase(path) {
    if ($("f-case").value.trim()) return;
    const name = path.replace(/[\\/]+$/, "").split(/[\\/]/).pop() || "";
    const clean = name.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);
    if (clean.length >= 2) $("f-case").value = clean;
  }
  async function browseTo(path) {
    $("browse-error").textContent = "";
    let data;
    try { data = await api("GET", "/api/browse?path=" + encodeURIComponent(path || "")); } catch (e) {
      $("browse-error").textContent = e.status === 404
        ? "Browsing is not available in this version. Type or paste the folder path instead."
        : e.message;
      return;
    }
    browseAt = data.path || "";
    $("browse-here").textContent = browseAt;
    $("browse-up").disabled = !data.parent;
    $("browse-up").onclick = () => browseTo(data.parent);
    $("browse-error").textContent = data.error || "";
    const roots = $("browse-roots");
    roots.replaceChildren();
    for (const r of data.roots || []) {
      const b = el("button", "chip", r.name);
      b.type = "button";
      b.addEventListener("click", () => browseTo(r.path));
      roots.append(b);
    }
    const list = $("browse-list");
    list.replaceChildren();
    for (const f of data.folders || []) {
      const b = el("button", "", f.name);
      b.type = "button";
      b.addEventListener("click", () => browseTo(f.path));
      list.append(el("li", "", [b]));
    }
    if (!(data.folders || []).length) list.append(el("li", "none", "No folders inside this one."));
    if (data.truncated) list.append(el("li", "none", "Only the first 500 folders are shown."));
    const count = typeof data.file_count === "number" ? plural(data.file_count, "file", "files") + " directly in this folder" : "";
    const size = typeof data.total_bytes === "number" ? ", " + fmtBytes(data.total_bytes) : "";
    $("browse-count").textContent = count + size;
  }
  $("browse-btn").addEventListener("click", () => {
    $("browse").showModal();
    browseTo($("f-input").value.trim());
  });
  $("browse-close").addEventListener("click", () => $("browse").close());
  $("browse-use").addEventListener("click", () => {
    if (browseAt) { $("f-input").value = browseAt; suggestCase(browseAt); }
    $("browse").close();
    $("f-case").focus();
  });
  $("f-input").addEventListener("change", () => suggestCase($("f-input").value.trim()));

  // ---------- Help and installed features ----------
  $("help-btn").addEventListener("click", async () => {
    $("help").showModal();
    const list = $("installed");
    try {
      const info = await api("GET", "/api/info");
      const f = info.features || {};
      const line = (name, on, extra) => el("li", "", [el("b", "", name + ": "), text(on ? "yes" + (extra ? " (" + extra + ")" : "") : "not installed")]);
      list.replaceChildren(
        el("li", "", [el("b", "", "Version: "), text(info.version || "")]),
        line("Windows event log files", !!f.evtx, f.evtx),
        line("Disk images", !!f.disk_images),
        line("YARA malware rules", !!f.yara),
        el("li", "", [el("b", "", "Ollama on this computer: "), text(f.ollama ? "running" : "not found")]),
      );
      if (f.ollama === false) $("llm-ollama").disabled = true;
    } catch (e) {
      list.replaceChildren(el("li", "", "This version does not report what is installed."));
    }
  });
  $("help-close").addEventListener("click", () => $("help").close());

  // ---------- Opening a case ----------
  async function openRun(runId, keep) {
    clearTimeout(pollTimer);
    clearTimeout(homeTimer);
    store("session", "af-run", runId);
    let data;
    try { data = await api("GET", "/api/runs/" + encodeURIComponent(runId)); } catch (e) {
      if (e.message !== "No session") { await loadHome(); toast(e.message, true); }
      return;
    }
    if (data.state === "running") {
      renderRunning(runId, data.progress);
      pollTimer = setTimeout(() => openRun(runId), 1500);
      return;
    }
    if (data.state === "failed") {
      await loadHome();
      toast("The run did not finish. " + (data.error || ""), true);
      return;
    }
    const firstOpen = !current || current.run_id !== runId;
    current = data;
    if (firstOpen) {
      picked.clear();
      excerpts.clear();
      Object.assign(ui, { tab: "overview", filter: data.status.pending.length ? "pending" : "all", sevs: new Set(SEVERITIES),
        q: "", sort: "severity", tactic: null, open: null, limit: PAGE });
      // Nothing typed or ticked for one case may carry over to another.
      for (const id of ["b-note", "s-fp", "s-statement", "e-sig", "d-reason", "q"]) $(id).value = "";
      for (const id of ["b-override", "s-gaps"]) $(id).checked = false;
      for (const id of ["decide-error", "sign-error", "export-error", "d-error", "report-error"]) $(id).textContent = "";
      $("sort").value = "severity";
      loadDisks(runId);
    }
    const held = data.fingerprints || {};
    if (held.signature_fingerprint) showOnce("signature_fingerprint", held.signature_fingerprint);
    else if (held.run_fingerprint) showOnce("run_fingerprint", held.run_fingerprint);
    else $("once").hidden = true;
    show("case");
    renderCase();
    if (!keep) window.scrollTo(0, 0);
  }

  function renderRunning(runId, progress) {
    show("running");
    $("tape-case").textContent = caseOf(runId);
    $("tape-state").textContent = "Run in progress";
    $("running-case").textContent = caseOf(runId);
    const p = progress || {};
    $("running-label").textContent = p.stage_label || "Reading the evidence. Large folders take a few minutes.";
    const at = STAGES.indexOf(p.stage);
    for (const li of $("stages").children) {
      const i = STAGES.indexOf(li.dataset.stage);
      li.className = at < 0 ? "" : (i < at ? "done" : (i === at ? "now" : ""));
    }
    const hasBytes = typeof p.bytes_total === "number" && p.bytes_total > 0 && typeof p.bytes_done === "number";
    $("meter").hidden = !hasBytes;
    const bits = [];
    if (hasBytes) {
      $("meter-fill").style.width = Math.min(100, Math.round((p.bytes_done / p.bytes_total) * 100)) + "%";
      bits.push(fmtBytes(p.bytes_done) + " of " + fmtBytes(p.bytes_total) + " read");
    }
    if (typeof p.files_total === "number") bits.push(plural(p.files_total, "file", "files"));
    if (typeof p.elapsed_seconds === "number") bits.push(fmtElapsed(p.elapsed_seconds) + " so far");
    $("meter-text").textContent = bits.join(", ");
    const words = { waiting: "Waiting", running: "Working", ok: "Done", failed: "Failed", skipped: "Not needed" };
    $("run-agents").replaceChildren(...(p.agents || []).map((a) =>
      el("li", "", [el("span", "", a.label || WORKERS[a.name] || a.name), el("span", "st " + a.status, words[a.status] || a.status)])));
  }

  function showOnce(kind, value) {
    $("once").hidden = false;
    $("once").dataset.kind = kind;
    $("once-value").textContent = value;
    if (kind === "run_fingerprint") {
      $("once-title").textContent = "Save the run fingerprint";
      $("once-text").textContent = "You paste it back when you sign. Keep it with your case notes, outside the case folder: it proves the draft you sign is the one this run wrote. It stays here until you say you have saved it, and the Auto Forensics window printed it too.";
    } else {
      $("once-title").textContent = "Save the signature fingerprint";
      $("once-text").textContent = "You paste it back to export the final report. Keep it with your case notes, outside the case folder. It stays here until you export or say you have saved it.";
    }
  }
  $("once-done").addEventListener("click", async () => {
    try {
      await api("POST", "/api/runs/" + encodeURIComponent(current.run_id) + "/copied", { kind: $("once").dataset.kind });
      $("once").hidden = true;
    } catch (e) { /* the box stays; nothing lost */ }
  });
  async function copyText(value, button, selectNode) {
    try {
      await navigator.clipboard.writeText(value);
      button.textContent = "Copied";
    } catch (e) {
      if (selectNode) {
        const range = document.createRange();
        range.selectNodeContents(selectNode);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        button.textContent = "Selected: press Ctrl+C";
      }
    }
    setTimeout(() => { button.textContent = "Copy"; }, 2500);
  }
  $("once-copy").addEventListener("click", () => copyText($("once-value").textContent, $("once-copy"), $("once-value")));

  // ---------- Tabs ----------
  function setTab(tab) {
    ui.tab = tab;
    for (const b of $("tabs").querySelectorAll("button")) {
      if (b.dataset.tab === tab) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
    }
    for (const name of ["overview", "findings", "timeline", "computer", "sign"]) $("panel-" + name).hidden = name !== tab;
    updateBar();
  }
  for (const b of $("tabs").querySelectorAll("button")) {
    b.addEventListener("click", () => { setTab(b.dataset.tab); window.scrollTo(0, 0); });
  }

  // ---------- Case rendering ----------
  function renderCase() {
    const { draft, status } = current;
    $("tape-case").textContent = draft.case_id;
    let state = "Draft, not signed";
    if (current.final) state = "Signed and exported";
    else if (status.signed) state = "Signed by " + status.signed_by;
    $("tape-state").textContent = state;
    const pending = status.pending.length;
    $("tab-pending").hidden = pending === 0;
    $("tab-pending").textContent = pending;
    renderOverview();
    renderFindings();
    renderTimeline();
    renderSteps();
    setTab(ui.tab);
  }

  function renderOverview() {
    const { draft, status } = current;
    const pending = status.pending.length;
    let nextText, nextLabel, nextTab;
    if (pending) {
      nextText = plural(pending, "finding needs", "findings need") + " your decision.";
      nextLabel = "Review findings"; nextTab = "findings";
    } else if (!status.signed) {
      nextText = status.total ? "Every finding has a decision. Sign the draft to lock it." : "Nothing was found. Sign the draft to record that.";
      nextLabel = "Go to signing"; nextTab = "sign";
    } else if (!current.final) {
      nextText = "The draft is signed. Export the final report."; nextLabel = "Go to export"; nextTab = "sign";
    } else {
      nextText = "This case is finished. The final report is saved."; nextLabel = "See the report"; nextTab = "sign";
    }
    $("next-text").textContent = nextText;
    $("next-btn").textContent = nextLabel;
    $("next-btn").onclick = () => {
      if (nextTab === "findings") { ui.filter = "pending"; ui.limit = PAGE; renderFindings(); }
      setTab(nextTab);
      window.scrollTo(0, 0);
    };

    $("headline").textContent = status.signed
      ? plural(status.accepted, "finding", "findings") + " confirmed by the analyst, " + status.rejected + " rejected."
      : draft.headline;
    $("counts").replaceChildren(...[["Findings", status.total], ["Accepted", status.accepted], ["Rejected", status.rejected], ["To decide", pending]]
      .map(([label, n]) => el("div", "", [el("dt", "", label), el("dd", "", n)])));
    fillSevBar($("sevbar"), draft.severity_counts);
    $("sevbar").hidden = !status.total;
    $("sevkey").replaceChildren(...SEVERITIES.filter((s) => (draft.severity_counts || {})[s]).map((s) => {
      const li = el("li", "sev-" + s, [el("b", "", draft.severity_counts[s]), text(" " + SEV_LABEL[s].toLowerCase())]);
      return li;
    }));

    $("hostile").hidden = !draft.hostile_files.length;
    $("hostile-list").replaceChildren(...draft.hostile_files.map((p) => el("li", "", [el("code", "", p)])));
    const gaps = draft.coverage_gaps || [];
    $("gaps").hidden = !gaps.length;
    $("gaps").open = gaps.length <= 6;
    $("gaps-title").textContent = "Not fully analysed: " + plural(gaps.length, "item", "items");
    $("gaps-list").replaceChildren(...gaps.map((g) => el("li", "", [el("code", "", g.what), text(": " + g.why)])));

    const byTactic = {};
    for (const step of draft.attack_chain) byTactic[step.tactic] = step;
    $("chain").replaceChildren(...KILL_CHAIN.map((tactic) => {
      const step = byTactic[tactic];
      const info = TACTICS[tactic];
      const li = el("li", step ? "hit" : "");
      const stop = el(step ? "button" : "span", "stop", info[0]);
      if (step) {
        stop.type = "button";
        li.style.setProperty("--sev", "var(--" + sevOf(step.top_severity) + ")");
        stop.title = info[1] + ". " + info[2];
        stop.append(el("span", "n", step.findings));
        stop.setAttribute("aria-label", info[0] + ": " + plural(step.findings, "finding", "findings") + ". " + info[1]);
        stop.addEventListener("click", () => {
          Object.assign(ui, { tactic, filter: "all", limit: PAGE });
          renderFindings();
          setTab("findings");
          window.scrollTo(0, 0);
        });
      } else {
        stop.title = info[1] + ". Nothing found for this stage.";
      }
      li.append(stop);
      return li;
    }));

    const words = { ok: "Done", failed: "Failed", skipped: "Not needed", error: "Failed" };
    $("case-agents").replaceChildren(...draft.agents.map((a) => el("li", "", [
      el("span", "", (WORKERS[a.name] || a.name) + ", " + plural(a.finding_count || 0, "finding", "findings")),
      el("span", "st " + (a.status === "ok" ? "ok" : "failed"), words[a.status] || a.status),
    ])));
    const facts = [];
    if (current.evidence_folder) facts.push(["Evidence folder", current.evidence_folder]);
    if (current.started_at) facts.push(["Started", fmtTime(current.started_at)]);
    if (current.finished_at) facts.push(["Finished", fmtTime(current.finished_at)]);
    facts.push(["Run name", current.run_id]);
    $("case-facts").replaceChildren(...facts.flatMap(([k, v]) => [el("dt", "", k), el("dd", "", v)]));
  }

  // ---------- Findings list ----------
  function visibleFindings() {
    const q = ui.q.toLowerCase();
    const rank = (f) => SEVERITIES.indexOf(sevOf(f.severity));
    const out = current.draft.findings.filter((f) => {
      if (ui.filter !== "all" && f.decision !== ui.filter) return false;
      if (!ui.sevs.has(sevOf(f.severity))) return false;
      if (ui.tactic && f.tactic !== ui.tactic) return false;
      if (q) {
        const hay = [f.title, f.tactic, f.technique_id, f.worker, f.recommendation, f.note]
          .concat((f.citations || []).map((c) => c.source_file)).join(" ").toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    const file = (f) => ((f.citations || [])[0] || {}).source_file || "";
    const time = (f) => f.event_time || "9999";
    if (ui.sort === "time") out.sort((a, b) => time(a).localeCompare(time(b)) || rank(a) - rank(b));
    else if (ui.sort === "file") out.sort((a, b) => file(a).localeCompare(file(b)) || rank(a) - rank(b));
    else out.sort((a, b) => rank(a) - rank(b) || time(a).localeCompare(time(b)));
    return out;
  }
  const decisionWord = (d) => (d === "accept" ? "Accepted" : d === "reject" ? "Rejected" : "To decide");
  const tacticName = (t) => (TACTICS[t] ? TACTICS[t][1] : null);

  function renderFindings() {
    const all = current.draft.findings;
    const shown = visibleFindings();
    const ids = new Set(shown.map((f) => f.finding_id));
    for (const id of Array.from(picked)) if (!ids.has(id)) picked.delete(id);
    if (ui.open && !all.some((f) => f.finding_id === ui.open)) ui.open = null;

    for (const b of document.querySelectorAll(".filter")) b.setAttribute("aria-pressed", String(b.dataset.filter === ui.filter));
    const chips = $("sev-chips");
    chips.replaceChildren(...SEVERITIES.filter((s) => (current.draft.severity_counts || {})[s]).map((s) => {
      const b = el("button", "chip sevchip sev-" + s, SEV_LABEL[s] + " " + current.draft.severity_counts[s]);
      b.type = "button";
      b.setAttribute("aria-pressed", String(ui.sevs.has(s)));
      b.addEventListener("click", () => {
        if (ui.sevs.has(s)) ui.sevs.delete(s); else ui.sevs.add(s);
        ui.limit = PAGE;
        renderFindings();
      });
      return b;
    }));
    $("tactic-chip").hidden = !ui.tactic;
    if (ui.tactic) $("tactic-chip").textContent = "Stage: " + (TACTICS[ui.tactic] ? TACTICS[ui.tactic][0] : ui.tactic);

    const signed = current.status.signed;
    const list = $("flist");
    list.replaceChildren();
    for (const f of shown.slice(0, ui.limit)) {
      const sev = sevOf(f.severity);
      const li = el("li", "frow sev-" + sev + (ui.open === f.finding_id ? " open" : "") + (picked.has(f.finding_id) ? " chosen" : ""));
      li.dataset.id = f.finding_id;
      const pick = el("label", "pick");
      const box = el("input");
      box.type = "checkbox";
      box.checked = picked.has(f.finding_id);
      box.disabled = signed;
      box.setAttribute("aria-label", "Tick " + f.title + " for a group decision");
      box.addEventListener("change", () => {
        if (box.checked) picked.add(f.finding_id); else picked.delete(f.finding_id);
        updateBar();
      });
      pick.append(box);
      const main = el("button", "frow-main");
      main.type = "button";
      const meta = [tacticName(f.tactic), f.event_time ? fmtTime(f.event_time) : null, ((f.citations || [])[0] || {}).source_file].filter(Boolean);
      main.append(
        el("span", "frow-title", f.title),
        el("span", "frow-side", [el("span", "frow-sev", SEV_LABEL[sev]), el("span", "dec " + f.decision, decisionWord(f.decision))]),
        el("span", "frow-meta", meta.join(", ")),
      );
      main.addEventListener("click", () => openFinding(f.finding_id));
      li.append(pick, main);
      list.append(li);
    }
    list.hidden = shown.length === 0;
    $("more-btn").hidden = shown.length <= ui.limit;
    $("more-btn").textContent = "Show " + Math.min(PAGE, shown.length - ui.limit) + " more";
    $("list-count").textContent = shown.length === all.length
      ? plural(all.length, "finding", "findings")
      : shown.length + " of " + plural(all.length, "finding", "findings") + " shown";
    const empty = $("findings-empty");
    empty.hidden = shown.length > 0;
    if (!all.length) empty.textContent = "The run found nothing it could point to in the evidence. You can still sign to record that.";
    else if (ui.filter === "pending" && !ui.q && !ui.tactic && ui.sevs.size === SEVERITIES.length) empty.textContent = "Every finding has a decision. Go to Sign and export.";
    else empty.textContent = "No findings match. Clear the search or show more kinds.";
    $("pick-all").checked = shown.length > 0 && shown.every((f) => picked.has(f.finding_id));
    $("pick-all").disabled = signed || shown.length === 0;
    $("pick-all").parentElement.title = signed ? "This case is signed, so decisions are locked." : "Tick every finding shown";

    if (ui.open) renderDetail(); else closeDetail();
    updateBar();
  }

  function updateBar() {
    if (!current) return;
    const n = picked.size;
    $("decide-bar").hidden = n === 0 || current.status.signed || ui.tab !== "findings" || $("view-case").hidden;
    $("picked").textContent = plural(n, "finding", "findings") + " ticked";
    $("b-accept").textContent = n === 1 ? "Accept" : "Accept all " + n;
    $("b-reject").textContent = n === 1 ? "Reject" : "Reject all " + n;
  }

  $("pick-all").addEventListener("change", (ev) => {
    for (const f of visibleFindings()) { if (ev.target.checked) picked.add(f.finding_id); else picked.delete(f.finding_id); }
    renderFindings();
  });
  for (const b of document.querySelectorAll(".filter")) {
    b.addEventListener("click", () => { ui.filter = b.dataset.filter; ui.limit = PAGE; renderFindings(); });
  }
  $("q").addEventListener("input", () => { ui.q = $("q").value.trim(); ui.limit = PAGE; renderFindings(); });
  $("sort").addEventListener("change", () => { ui.sort = $("sort").value; renderFindings(); });
  $("tactic-chip").addEventListener("click", () => { ui.tactic = null; renderFindings(); });
  $("more-btn").addEventListener("click", () => { ui.limit += PAGE; renderFindings(); });
  $("b-clear").addEventListener("click", () => { picked.clear(); renderFindings(); });

  // ---------- Finding detail ----------
  function openFinding(id) {
    ui.open = id;
    $("d-reason").value = "";
    $("d-error").textContent = "";
    for (const li of $("flist").children) li.classList.toggle("open", li.dataset.id === id);
    renderDetail();
    if (window.matchMedia("(max-width: 1020px)").matches) $("d-close").focus();
  }
  function closeDetail() {
    ui.open = null;
    $("detail").hidden = true;
    document.querySelector(".review").classList.remove("split");
    for (const li of $("flist").children) li.classList.remove("open");
  }
  $("d-close").addEventListener("click", closeDetail);

  function checkedText(v) {
    if (!v) return "This finding could not be re-checked against the evidence. Look at the cited place yourself before accepting it.";
    const s = String(v);
    if (s.includes("re-read")) return "The tool opened the file again after the run and confirmed this exact line is there, in a file whose fingerprint has not changed.";
    if (s.includes("copied file")) return "The file was copied out of the disk image, its fingerprint was confirmed, and the main checker confirmed the cited row.";
    if (s === "supported") return "The main checker opened the cited row and confirmed it supports this finding.";
    return s;
  }

  function renderDetail() {
    const f = current.draft.findings.find((x) => x.finding_id === ui.open);
    if (!f) { closeDetail(); return; }
    $("detail").hidden = false;
    document.querySelector(".review").classList.add("split");
    const sev = sevOf(f.severity);
    $("d-sev").className = "sev sev-" + sev;
    $("d-sev").textContent = SEV_LABEL[sev];
    $("d-title").textContent = f.title;
    $("d-when").textContent = f.event_time ? "Happened " + fmtTime(f.event_time) : "No time was recorded for this finding.";

    const info = TACTICS[f.tactic];
    const means = [];
    if (info) means.push(info[1] + ". " + info[2]);
    else means.push("The tool could not match this to a stage of an attack.");
    if (f.technique_id) means.push("Reference: MITRE ATT&CK technique " + f.technique_id + ".");
    $("d-means").textContent = means.join(" ");
    $("d-warnings").replaceChildren(...(f.warnings || []).map((w) => el("p", "warn", w)));
    $("d-rec").textContent = f.recommendation || "Open the cited evidence and confirm it before acting.";
    $("d-checked").textContent = checkedText(f.verification);

    const facts = [["Found by", WORKERS[f.worker] || f.worker || "unknown"]];
    if (typeof f.confidence === "number") facts.push(["Confidence", Math.round(f.confidence * 100) + "%"]);
    facts.push(["Finding ID", f.finding_id]);
    $("d-facts").replaceChildren(...facts.flatMap(([k, v]) => [el("dt", "", k), el("dd", "", v)]));

    renderEvidence(f);

    const signed = current.status.signed;
    const decided = f.decision !== "pending";
    let line = "Not decided yet.";
    if (decided) line = decisionWord(f.decision) + " by " + (f.decided_by || "unknown") + (f.note ? ": " + f.note : ".");
    if (signed) line += " The case is signed, so this is locked.";
    $("d-current").textContent = line;
    $("d-current").className = "d-current dec " + f.decision;
    for (const id of ["d-accept", "d-reject", "d-reason", "d-reason-label"]) $(id).hidden = signed;
    $("d-accept").textContent = decided ? (f.decision === "accept" ? "Accepted" : "Change to accept") : "Accept";
    $("d-reject").textContent = decided ? (f.decision === "reject" ? "Rejected" : "Change to reject") : "Reject";
    $("d-accept").disabled = f.decision === "accept";
    $("d-reject").disabled = f.decision === "reject";
    const order = visibleFindings().map((x) => x.finding_id);
    const at = order.indexOf(f.finding_id);
    $("d-prev").disabled = at <= 0;
    $("d-next").disabled = at < 0 || at >= order.length - 1;
  }

  function citeWhere(c) {
    if (c.row) return "row " + c.row;
    if (c.offset !== null && c.offset !== undefined) return "byte " + c.offset;
    return "whole file";
  }

  function renderEvidence(f) {
    const box = $("d-evidence");
    const cached = excerpts.get(f.finding_id);
    const blocks = (f.citations || []).map((c, i) => {
      const block = el("div", "cite");
      block.append(el("div", "cite-head", [el("span", "cite-file", c.source_file), el("span", "", citeWhere(c))]));
      const got = cached && cached.citations && cached.citations[i];
      if (got) {
        if (got.excerpt) block.append(el("pre", "", got.excerpt));
        if (got.file_ok === false) block.append(el("p", "cite-note bad", "This file has changed since the run, so the line is not shown. " + (got.excerpt_note || "")));
        else if (got.excerpt_note) block.append(el("p", "cite-note", got.excerpt_note));
      } else if (cached && cached.error) {
        block.append(el("p", "cite-note", cached.error));
      } else {
        block.append(el("p", "cite-note", "Reading the evidence."));
      }
      block.append(el("div", "cite-hash", "File fingerprint (SHA-256) " + c.sha256));
      return block;
    });
    box.replaceChildren(...blocks);
    if (!(f.citations || []).length) box.append(el("p", "warn", "This finding does not point to a place in the evidence."));
    if (!cached) loadEvidence(f.finding_id);
  }

  async function loadEvidence(id) {
    const runId = current.run_id;
    let result;
    try {
      result = await api("GET", "/api/runs/" + encodeURIComponent(runId) + "/findings/" + encodeURIComponent(id) + "/evidence");
    } catch (e) {
      result = { error: e.status === 404 ? "Open the file at the place shown to see the line. This version cannot show it here." : e.message };
    }
    if (!current || current.run_id !== runId) return;
    excerpts.set(id, result);
    if (ui.open === id) {
      const f = current.draft.findings.find((x) => x.finding_id === id);
      if (f) renderEvidence(f);
    }
  }

  function step(delta) {
    const order = visibleFindings().map((x) => x.finding_id);
    if (!order.length) return;
    let at = order.indexOf(ui.open);
    at = at < 0 ? 0 : Math.min(order.length - 1, Math.max(0, at + delta));
    openFinding(order[at]);
    const row = $("flist").querySelector('[data-id="' + CSS.escape(order[at]) + '"]');
    if (row) row.scrollIntoView({ block: "nearest" });
  }
  $("d-prev").addEventListener("click", () => step(-1));
  $("d-next").addEventListener("click", () => step(1));

  // ---------- Decisions ----------
  async function sendDecision(ids, decision, note, override) {
    await api("POST", "/api/runs/" + encodeURIComponent(current.run_id) + "/decide", {
      finding_ids: ids, decision, actor: whoIs(), note, override,
    });
  }

  async function decideOpen(decision) {
    const f = current.draft.findings.find((x) => x.finding_id === ui.open);
    if (!f || current.status.signed) return;
    $("d-error").textContent = "";
    if (!needName($("d-error"))) return;
    const note = $("d-reason").value.trim();
    if (decision === "reject" && !note) {
      $("d-error").textContent = "Write why you are rejecting it, then press Reject.";
      $("d-reason").focus();
      return;
    }
    // Where to go next: the finding after this one in the list as it is now.
    const order = visibleFindings().map((x) => x.finding_id);
    const at = order.indexOf(f.finding_id);
    const nextId = order[at + 1] || order[at - 1] || null;
    await busy($("d-decide"), async () => {
      try {
        await sendDecision([f.finding_id], decision, note, f.decision !== "pending");
        toast(decision === "accept" ? "Accepted." : "Rejected.");
        $("d-reason").value = "";
        await openRun(current.run_id, true);
        const still = visibleFindings().some((x) => x.finding_id === f.finding_id);
        if (!still) { if (nextId && visibleFindings().some((x) => x.finding_id === nextId)) openFinding(nextId); else closeDetail(); }
      } catch (e) {
        $("d-error").textContent = e.message;
      }
    });
  }
  $("d-accept").addEventListener("click", () => decideOpen("accept"));
  $("d-reject").addEventListener("click", () => decideOpen("reject"));

  async function decideTicked(decision) {
    $("decide-error").textContent = "";
    if (!needName($("decide-error"))) return;
    const note = $("b-note").value.trim();
    if (decision === "reject" && !note) { $("decide-error").textContent = "Write a reason to reject."; $("b-note").focus(); return; }
    let failed = "";
    const n = picked.size;
    await busy($("decide-bar"), async () => {
      try {
        await sendDecision(Array.from(picked), decision, note, $("b-override").checked);
        picked.clear();
        $("b-note").value = "";
        $("b-override").checked = false;
        toast(plural(n, "finding", "findings") + (decision === "accept" ? " accepted." : " rejected."));
      } catch (e) {
        failed = e.message;
      }
      await openRun(current.run_id, true);
    });
    $("decide-error").textContent = failed;
    if (failed) $("decide-bar").hidden = false;
  }
  $("b-accept").addEventListener("click", () => decideTicked("accept"));
  $("b-reject").addEventListener("click", () => decideTicked("reject"));
  $("decide-bar").addEventListener("submit", (ev) => ev.preventDefault());

  // ---------- Timeline ----------
  function renderTimeline() {
    const box = $("timeline");
    const timed = current.draft.findings.filter((f) => f.event_time).sort((a, b) => a.event_time.localeCompare(b.event_time));
    const untimed = current.draft.findings.filter((f) => !f.event_time);
    const item = (f, showTime) => {
      const li = el("li", "tl-item sev-" + sevOf(f.severity));
      if (showTime) li.append(el("span", "tl-time", fmtTime(f.event_time).slice(11, 19)));
      const open = el("button", "tl-open", f.title);
      open.type = "button";
      open.addEventListener("click", () => {
        Object.assign(ui, { filter: "all", tactic: null, q: "", limit: Math.max(ui.limit, current.draft.findings.length) });
        ui.sevs = new Set(SEVERITIES);
        $("q").value = "";
        renderFindings();
        setTab("findings");
        openFinding(f.finding_id);
        const row = $("flist").querySelector('[data-id="' + CSS.escape(f.finding_id) + '"]');
        if (row) row.scrollIntoView({ block: "center" });
      });
      const meta = [SEV_LABEL[sevOf(f.severity)], tacticName(f.tactic), decisionWord(f.decision)].filter(Boolean).join(", ");
      li.append(open, el("div", "tl-meta", meta));
      return li;
    };
    const days = new Map();
    for (const f of timed) {
      const day = fmtTime(f.event_time).slice(0, 10);
      if (!days.has(day)) days.set(day, []);
      days.get(day).push(f);
    }
    const out = [];
    for (const [day, list] of days) {
      const d = new Date(day + "T00:00:00Z");
      const nice = isNaN(d) ? day : d.toLocaleDateString(undefined, { weekday: "long", year: "numeric", month: "long", day: "numeric", timeZone: "UTC" });
      out.push(el("section", "tl-day", [el("h3", "", nice), el("ol", "tl-list", list.map((f) => item(f, true)))]));
    }
    if (untimed.length) {
      out.push(el("section", "tl-day", [
        el("h3", "", timed.length ? "No time recorded" : "No times were recorded for these findings"),
        el("ol", "tl-list", untimed.map((f) => item(f, false))),
      ]));
    }
    if (!out.length) out.push(el("p", "empty", "There are no findings to put on a timeline."));
    box.replaceChildren(...out);
  }

  // ---------- This computer ----------
  async function loadDisks(runId) {
    $("tab-computer").hidden = true;
    $("disks").replaceChildren();
    let data;
    try { data = await api("GET", "/api/runs/" + encodeURIComponent(runId) + "/disks"); } catch (e) { return; }
    if (!current || current.run_id !== runId || !data.disks || !data.disks.length) return;
    $("tab-computer").hidden = false;
    $("disks").replaceChildren(...data.disks.map((d) => {
      const box = el("div", "disk");
      box.append(el("h2", "", d.hostname || d.image || "Disk image"));
      const facts = [["Image file", d.image], ["System", [d.os, d.version].filter(Boolean).join(" ")], ["Time zone", d.timezone]]
        .filter(([, v]) => v);
      box.append(el("dl", "facts", facts.flatMap(([k, v]) => [el("dt", "", k), el("dd", "", v)])));
      if ((d.users || []).length) box.append(el("h3", "", "User accounts"), el("ul", "taglist", d.users.map((u) => el("li", "", u))));
      if ((d.usb_devices || []).length) {
        const table = el("table");
        table.append(el("thead", "", [el("tr", "", ["Device", "Serial number", "First plugged in", "Last plugged in"].map((t) => { const th = el("th", "", t); th.scope = "col"; return th; }))]));
        table.append(el("tbody", "", d.usb_devices.map((u) => el("tr", "", [
          el("td", "", u.name || ""), el("td", "mono", u.serial || ""), el("td", "", fmtTime(u.first_seen)), el("td", "", fmtTime(u.last_seen)),
        ]))));
        box.append(el("h3", "", "USB devices that were plugged in"), table);
      }
      if ((d.volumes || []).length) box.append(el("h3", "", "Drives in the image"), el("ul", "taglist", d.volumes.map((v) => el("li", "", v))));
      if ((d.gaps || []).length) box.append(el("h3", "", "Could not be read"), el("ul", "", d.gaps.map((g) => el("li", "", g))));
      return box;
    }));
  }

  // ---------- Sign and export ----------
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
      $("exported-text").replaceChildren(text("The final report is saved in "), el("code", "", current.final.folder));
      $("report-btn").hidden = false;
    } else {
      set("step-export", status.signed ? "current" : "locked");
      $("export-form").hidden = false;
      $("exported-text").hidden = true;
      $("report-btn").hidden = true;
    }
  }

  $("sign-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    $("sign-error").textContent = "";
    if (!needName($("sign-error"))) return;
    await busy(ev.target, async () => {
      try {
        await api("POST", "/api/runs/" + encodeURIComponent(current.run_id) + "/sign", {
          actor: whoIs(), fingerprint: $("s-fp").value.trim(), statement: $("s-statement").value.trim(), accept_gaps: $("s-gaps").checked,
        });
        $("s-fp").value = "";
        toast("Signed.");
        await openRun(current.run_id, true);
        window.scrollTo(0, 0);
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
        toast("Final report exported.");
        await openRun(current.run_id, true);
      } catch (e) {
        $("export-error").textContent = e.message;
      }
    });
  });

  $("report-btn").addEventListener("click", async () => {
    $("report-error").textContent = "";
    // Open the tab during the click so the browser allows it, then point it at the one-time link.
    const tab = window.open("about:blank", "_blank");
    try {
      const res = await api("POST", "/api/runs/" + encodeURIComponent(current.run_id) + "/report-link", {});
      if (typeof res.url !== "string" || !res.url.startsWith("/report/")) throw new Error("Unexpected report link");
      if (tab) { tab.opener = null; tab.location.replace(res.url); } else window.location.assign(res.url);
    } catch (e) {
      if (tab) tab.close();
      $("report-error").textContent = e.status === 404
        ? "Open final_report.md in the folder above. This version cannot show the report here."
        : e.message;
    }
  });

  // ---------- Keyboard ----------
  document.addEventListener("keydown", (ev) => {
    if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
    if (document.querySelector("dialog[open]")) return;
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test((ev.target && ev.target.tagName) || "");
    if (ev.key === "Escape" && ui.open && !$("view-case").hidden) { closeDetail(); return; }
    if (typing || $("view-case").hidden || ui.tab !== "findings") return;
    const key = ev.key.toLowerCase();
    if (key === "j" || ev.key === "ArrowDown") { ev.preventDefault(); step(1); }
    else if (key === "k" || ev.key === "ArrowUp") { ev.preventDefault(); step(-1); }
    else if (key === "/") { ev.preventDefault(); $("q").focus(); }
    else if (!ui.open || current.status.signed) return;
    else if (key === "a") { ev.preventDefault(); decideOpen("accept"); }
    else if (key === "r") { ev.preventDefault(); $("d-reason").focus(); }
    else if (key === "x") {
      ev.preventDefault();
      if (picked.has(ui.open)) picked.delete(ui.open); else picked.add(ui.open);
      renderFindings();
    }
  });

  // ---------- Start ----------
  if (!token) { show("none"); $("no-token").hidden = false; return; }
  const lastRun = store("session", "af-run");
  if (lastRun) openRun(lastRun); else loadHome();
})();
