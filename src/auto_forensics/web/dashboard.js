'use strict';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function esc(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function fmtTs(ts) {
    if (!ts) return '—';
    try {
        const d = new Date(String(ts).endsWith('Z') ? ts : ts + 'Z');
        return d.toLocaleString(undefined, {
            year: 'numeric', month: '2-digit', day: '2-digit',
            hour: '2-digit', minute: '2-digit', second: '2-digit',
        });
    } catch (_) { return String(ts).slice(0, 19).replace('T', ' '); }
}

function statusBadge(s) {
    const st = (s || 'unknown').toLowerCase();
    const cls = ['complete', 'analyzing', 'ingesting', 'running', 'failed',
                 'created', 'pending', 'ready'].includes(st)
        ? `badge-${st}` : 'badge-default';
    return `<span class="badge ${cls}">${esc(st)}</span>`;
}

async function apiFetch(path) {
    const r = await fetch(path, { headers: { 'Accept': 'application/json' } });
    if (!r.ok) {
        const body = await r.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${r.status}`);
    }
    return r.json();
}

// ─── State ────────────────────────────────────────────────────────────────────

let allCases = [];
let refreshTimer = null;

// ─── DOM refs ─────────────────────────────────────────────────────────────────

const healthDot   = document.getElementById('health-dot');
const healthText  = document.getElementById('health-text');
const refreshBtn  = document.getElementById('refresh-btn');
const casesCtn    = document.getElementById('cases-container');
const searchInp   = document.getElementById('search-input');
const statusSel   = document.getElementById('status-filter');
const drawer      = document.getElementById('detail-drawer');
const drawerTitle = document.getElementById('drawer-title');
const drawerBody  = document.getElementById('drawer-body');
const drawerClose = document.getElementById('drawer-close');
const overlay     = document.getElementById('overlay');

// ─── Health ───────────────────────────────────────────────────────────────────

async function checkHealth() {
    try {
        await apiFetch('/api/health');
        healthDot.className = 'health-dot health-dot--ok';
        healthText.textContent = 'Connected';
    } catch (_) {
        healthDot.className = 'health-dot health-dot--err';
        healthText.textContent = 'API unreachable';
    }
}

// ─── Stats ────────────────────────────────────────────────────────────────────

async function loadStats() {
    try {
        const data = await apiFetch('/api/stats');
        const by = data.by_status || {};
        const total = data.total_cases ?? Object.values(by).reduce((a, b) => a + b, 0);
        document.getElementById('stat-total').textContent    = total;
        document.getElementById('stat-complete').textContent  = by.complete  ?? 0;
        document.getElementById('stat-analyzing').textContent = (by.analyzing ?? 0) + (by.ingesting ?? 0);
        document.getElementById('stat-failed').textContent    = by.failed    ?? 0;
        document.getElementById('stat-ready').textContent     = by.ready     ?? 0;
    } catch (_) {
        ['stat-total', 'stat-complete', 'stat-analyzing', 'stat-failed', 'stat-ready']
            .forEach(id => { document.getElementById(id).textContent = '?'; });
    }
}

// ─── Cases list ───────────────────────────────────────────────────────────────

function buildSevRow(findings) {
    if (!Array.isArray(findings) || findings.length === 0) return '<span class="ts">—</span>';
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
        const s = (f.severity || 'low').toLowerCase();
        if (s in counts) counts[s]++;
    }
    const parts = [];
    for (const [sev, label] of [['critical','C'], ['high','H'], ['medium','M'], ['low','L']]) {
        if (counts[sev]) {
            parts.push(
                `<span class="sev-pip">` +
                `<span class="sev-dot sev-dot--${sev}"></span>` +
                `<span class="sev-count">${counts[sev]}${label}</span>` +
                `</span>`
            );
        }
    }
    return parts.length ? `<span class="sev-row">${parts.join('')}</span>` : '<span class="ts">—</span>';
}

function renderCasesTable(cases) {
    if (!cases || cases.length === 0) {
        casesCtn.innerHTML = '<div class="empty-msg">No cases found. Use the CLI to initialize a case.</div>';
        return;
    }
    const rows = cases.map(c => `
        <tr data-case="${esc(c.case_id)}">
            <td><span class="case-id">${esc(c.case_id)}</span></td>
            <td>${statusBadge(c.status)}</td>
            <td>${buildSevRow(c.findings)}</td>
            <td><span class="ts">${fmtTs(c.created_at)}</span></td>
            <td><span class="ts">${fmtTs(c.updated_at)}</span></td>
        </tr>`).join('');

    casesCtn.innerHTML = `
        <table class="cases-table">
            <thead>
                <tr>
                    <th>Case ID</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>Created</th>
                    <th>Updated</th>
                </tr>
            </thead>
            <tbody>${rows}</tbody>
        </table>`;

    casesCtn.querySelectorAll('tbody tr').forEach(row => {
        row.addEventListener('click', () => openDrawer(row.dataset.case));
    });
}

async function loadCases() {
    try {
        allCases = await apiFetch('/api/cases');
        applyFilter();
    } catch (err) {
        casesCtn.innerHTML = `<div class="error-msg">Failed to load cases: ${esc(err.message)}</div>`;
    }
}

function applyFilter() {
    const q  = searchInp.value.trim().toLowerCase();
    const st = statusSel.value;
    let filtered = allCases;
    if (q)  filtered = filtered.filter(c => (c.case_id || '').toLowerCase().includes(q));
    if (st) filtered = filtered.filter(c => (c.status  || '') === st);
    renderCasesTable(filtered);
}

// ─── Drawer ───────────────────────────────────────────────────────────────────

function openDrawer(caseId) {
    drawerTitle.textContent = caseId;
    drawerBody.innerHTML = '<div class="placeholder">Loading…</div>';
    drawer.classList.remove('drawer--hidden');
    overlay.classList.remove('overlay--hidden');
    loadCaseDetail(caseId);
}

function closeDrawer() {
    drawer.classList.add('drawer--hidden');
    overlay.classList.add('overlay--hidden');
}

async function loadCaseDetail(caseId) {
    try {
        const d = await apiFetch(`/api/cases/${encodeURIComponent(caseId)}`);
        renderDrawer(d);
    } catch (err) {
        drawerBody.innerHTML = `<div class="error-msg">Failed to load: ${esc(err.message)}</div>`;
    }
}

function renderDrawer(d) {
    const overview  = d.case || d;
    const findings  = Array.isArray(d.findings)  ? d.findings  : [];
    const artifacts = Array.isArray(d.artifacts)  ? d.artifacts : [];
    const iocs      = Array.isArray(d.iocs)       ? d.iocs      : [];
    const timeline  = Array.isArray(d.timeline)   ? d.timeline  : [];

    // Overview section
    let html = `
        <div class="dsection">
            <div class="dsection-title">Overview</div>
            <div class="meta-grid">
                <div>
                    <div class="meta-key">Status</div>
                    <div class="meta-val">${statusBadge(overview.status || d.status)}</div>
                </div>
                <div>
                    <div class="meta-key">Created</div>
                    <div class="meta-val ts">${fmtTs(overview.created_at || d.created_at)}</div>
                </div>
                <div>
                    <div class="meta-key">Artifacts</div>
                    <div class="meta-val">${artifacts.length}</div>
                </div>
                <div>
                    <div class="meta-key">Timeline Events</div>
                    <div class="meta-val">${timeline.length}</div>
                </div>
                <div>
                    <div class="meta-key">Findings</div>
                    <div class="meta-val">${findings.length}</div>
                </div>
                <div>
                    <div class="meta-key">IOCs</div>
                    <div class="meta-val">${iocs.length}</div>
                </div>
            </div>
        </div>`;

    // Findings section
    if (findings.length > 0) {
        const order = { critical: 0, high: 1, medium: 2, low: 3 };
        const sorted = [...findings].sort(
            (a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4)
        );
        const shown = sorted.slice(0, 20);
        html += `
            <div class="dsection">
                <div class="dsection-title">Findings (${findings.length})</div>
                ${shown.map(f => {
                    const sev = (f.severity || 'low').toLowerCase();
                    const sub = [f.tactic, f.technique ? `· ${f.technique}` : '']
                        .filter(Boolean).join(' ');
                    return `
                        <div class="finding-item finding-item--${sev}">
                            <div class="finding-title">${esc(f.title || f.name || 'Finding')}</div>
                            ${sub ? `<div class="finding-sub">${esc(sub)}</div>` : ''}
                        </div>`;
                }).join('')}
                ${sorted.length > 20 ? `<div class="more-note">… and ${sorted.length - 20} more</div>` : ''}
            </div>`;
    }

    // IOCs section
    if (iocs.length > 0) {
        const shown = iocs.slice(0, 15);
        html += `
            <div class="dsection">
                <div class="dsection-title">IOCs (${iocs.length})</div>
                ${shown.map(i => `
                    <div class="row-item">
                        <span class="row-item-val">${esc(i.value || i.ioc_value || '')}</span>
                        <span class="row-item-type">${esc(i.ioc_type || i.type || '')}</span>
                    </div>`).join('')}
                ${iocs.length > 15 ? `<div class="more-note">… and ${iocs.length - 15} more</div>` : ''}
            </div>`;
    }

    // Artifacts section
    if (artifacts.length > 0) {
        const shown = artifacts.slice(0, 10);
        html += `
            <div class="dsection">
                <div class="dsection-title">Artifacts (${artifacts.length})</div>
                ${shown.map(a => `
                    <div class="row-item">
                        <span class="row-item-val">${esc(a.rel_path || a.path || '')}</span>
                        <span class="row-item-type">${esc(a.artifact_type || a.type || '')}</span>
                    </div>`).join('')}
                ${artifacts.length > 10 ? `<div class="more-note">… and ${artifacts.length - 10} more</div>` : ''}
            </div>`;
    }

    drawerBody.innerHTML = html;
}

// ─── Refresh ──────────────────────────────────────────────────────────────────

async function refresh() {
    const icon = refreshBtn.textContent;
    refreshBtn.innerHTML = '<span class="spinning">↻</span>';
    refreshBtn.disabled = true;
    try {
        await Promise.all([checkHealth(), loadStats(), loadCases()]);
    } finally {
        refreshBtn.textContent = icon;
        refreshBtn.disabled = false;
    }
    resetTimer();
}

function resetTimer() {
    clearInterval(refreshTimer);
    refreshTimer = setInterval(refresh, 30_000);
}

// ─── Init ─────────────────────────────────────────────────────────────────────

refreshBtn.addEventListener('click', refresh);
drawerClose.addEventListener('click', closeDrawer);
overlay.addEventListener('click', closeDrawer);
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeDrawer(); });

let searchTimeout;
searchInp.addEventListener('input', () => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(applyFilter, 200);
});
statusSel.addEventListener('change', applyFilter);

refresh();
