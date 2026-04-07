'use strict';

function $(id) { return document.getElementById(id); }
function esc(v) {
    return String(v == null ? '' : v)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
function fmtTs(v) {
    if (!v) return '-';
    try { return new Date(String(v).endsWith('Z') ? v : v + 'Z').toLocaleString(); }
    catch (_) { return String(v); }
}
function prettyLabel(value) {
    return String(value || '')
        .replace(/[_-]+/g, ' ')
        .replace(/\s+/g, ' ')
        .replace(/\b\w/g, function (m) { return m.toUpperCase(); })
        .trim();
}
function badge(v) {
    var s = String(v || 'unknown').toLowerCase();
    var tone = 'badge--neutral';
    if (/(fail|error|critical|danger)/.test(s)) tone = 'badge--danger';
    else if (/(warn|pending|ingest|analyz|review|attention)/.test(s)) tone = 'badge--warn';
    else if (/(complete|ready|active|ok|done|running|success)/.test(s)) tone = 'badge--accent';
    return '<span class="badge ' + tone + '">' + esc(prettyLabel(s)) + '</span>';
}
function metricCard(label, value) {
    return '<div class="inspector-metric"><span class="inspector-metric__label">'
        + esc(label) + '</span><span class="inspector-metric__value">'
        + esc(value == null || value === '' ? '-' : value) + '</span></div>';
}
function shortValue(value, limit) {
    var text = String(value == null ? '' : value);
    if (!text) return '-';
    if (!limit || text.length <= limit) return text;
    return text.slice(0, Math.max(0, limit - 1)).trim() + '…';
}
async function api(path, opts) {
    var req = Object.assign({ headers: { Accept: 'application/json' } }, opts || {});
    if (req.body && typeof req.body === 'object' && !(req.body instanceof FormData)) {
        req.headers['Content-Type'] = 'application/json';
        req.body = JSON.stringify(req.body);
    }
    var res = await fetch(path, req);
    if (!res.ok) {
        var body = await res.json().catch(function () { return {}; });
        throw new Error(body.detail || ('HTTP ' + res.status));
    }
    return res.status === 204 ? null : res.json();
}
function note(msg, bad) {
    var n = document.createElement('div');
    n.textContent = msg;
    n.style.cssText = 'position:fixed;right:24px;bottom:24px;padding:10px 14px;'
        + 'border-radius:12px;color:#fff;z-index:9999;background:'
        + (bad ? '#7f1d1d' : '#14532d') + ';box-shadow:0 12px 24px rgba(0,0,0,.15)';
    document.body.appendChild(n);
    window.setTimeout(function () { n.remove(); }, 3000);
}

var state = {
    cases: [],
    caseId: null,
    overview: null,
    activeTab: 'overview',
    page: 'dashboard',
    railCollapsed: false,
    inspectorCollapsed: false,
    commandOpen: false,
    commandResults: [],
    commandIndex: 0,
};

var UI_PREFS_KEY = 'auto-forensics-ui-prefs';

function loadUiPrefs() {
    try {
        var raw = window.localStorage.getItem(UI_PREFS_KEY);
        return raw ? JSON.parse(raw) : {};
    } catch (_) {
        return {};
    }
}

function saveUiPrefs() {
    try {
        window.localStorage.setItem(UI_PREFS_KEY, JSON.stringify({
            railCollapsed: state.railCollapsed,
            inspectorCollapsed: state.inspectorCollapsed,
        }));
    } catch (_) {}
}

var uiPrefs = loadUiPrefs();
state.railCollapsed = !!uiPrefs.railCollapsed;
state.inspectorCollapsed = !!uiPrefs.inspectorCollapsed;

function syncChromeBar() {
    var pageTitles = {
        dashboard: 'Dashboard',
        cases: 'Cases',
        workspace: 'Workspace',
        settings: 'Settings',
    };
    if ($('shell-page-pill')) {
        $('shell-page-pill').textContent = pageTitles[state.page] || 'Dashboard';
    }
    if ($('shell-case-pill')) {
        $('shell-case-pill').textContent = state.caseId ? ('Case: ' + state.caseId) : 'No active case';
    }
    if ($('shell-tab-pill')) {
        $('shell-tab-pill').textContent = state.caseId ? prettyLabel(state.activeTab || 'overview') : 'Overview';
    }
    if ($('shell-status-pill')) {
        var status = state.overview && state.overview.case && state.caseId
            ? prettyLabel(state.overview.case.status || 'ready')
            : 'Desktop';
        $('shell-status-pill').textContent = status;
    }
    if ($('sidebar-toggle-btn')) {
        $('sidebar-toggle-btn').textContent = state.railCollapsed ? 'Show Sidebar' : 'Hide Sidebar';
    }
    if ($('inspector-toggle-btn')) {
        $('inspector-toggle-btn').textContent = state.inspectorCollapsed ? 'Show Inspector' : 'Hide Inspector';
    }
    var shell = document.querySelector('.shell');
    if (shell) {
        shell.classList.toggle('shell--rail-collapsed', state.railCollapsed);
    }
    document.querySelectorAll('.workspace-layout').forEach(function (el) {
        el.classList.toggle('workspace-layout--inspector-collapsed', state.inspectorCollapsed);
    });
    document.querySelectorAll('.workspace-inspector').forEach(function (el) {
        el.classList.toggle('workspace-inspector--hidden', state.inspectorCollapsed);
    });
    saveUiPrefs();
}

function setRailCollapsed(value) {
    state.railCollapsed = !!value;
    syncChromeBar();
}

function setInspectorCollapsed(value) {
    state.inspectorCollapsed = !!value;
    syncChromeBar();
}

function showPage(name) {
    state.page = String(name || 'dashboard');
    ['dashboard', 'cases', 'workspace', 'settings'].forEach(function (id) {
        var page = $('page-' + id);
        if (page) page.classList.toggle('page--active', id === name);
    });
    document.querySelectorAll('.rail-link[data-page]').forEach(function (el) {
        el.classList.toggle('rail-link--active', el.dataset.page === name);
    });
    var titles = {
        dashboard: ['Operations', 'Dashboard'],
        cases: ['Registry', 'Cases'],
        workspace: ['Investigation', 'Workspace'],
        settings: ['Runtime', 'Settings'],
    };
    if ($('page-eyebrow')) $('page-eyebrow').textContent = titles[name][0];
    if ($('page-title')) $('page-title').textContent = titles[name][1];
    syncChromeBar();
}

function modal(id, open) {
    if (!$('modal-shell')) return;
    $('modal-shell').classList.toggle('modal-shell--hidden', !open);
    document.querySelectorAll('.modal').forEach(function (el) {
        el.classList.add('modal--hidden');
    });
    if (open && $(id)) $(id).classList.remove('modal--hidden');
}

function setWorkspaceTab(tabName) {
    var name = String(tabName || 'overview');
    var allowed = {
        overview: true,
        evidence: true,
        timeline: true,
        findings: true,
        iocs: true,
        notebook: true,
        agent: true,
    };
    state.activeTab = allowed[name] ? name : 'overview';
    document.querySelectorAll('.workspace-tab').forEach(function (x) {
        x.classList.toggle('workspace-tab--active', x.dataset.workspaceTab === state.activeTab);
    });
    document.querySelectorAll('.workspace-section').forEach(function (x) {
        x.classList.toggle('workspace-section--active', x.id === 'ws-' + state.activeTab);
    });
    if (state.caseId) syncUrlState();
}

function syncUrlState() {
    if (!window.history || !window.history.replaceState) return;
    var params = new URLSearchParams(window.location.search);
    if (state.caseId) {
        params.set('case', state.caseId);
        params.set('tab', state.activeTab || 'overview');
    } else {
        params.delete('case');
        params.delete('tab');
    }
    var qs = params.toString();
    var target = qs ? ('/?' + qs) : '/';
    if (target !== (window.location.pathname + window.location.search)) {
        window.history.replaceState({}, '', target);
    }
}

function parseInitialWorkspaceRoute() {
    var params = new URLSearchParams(window.location.search);
    var caseId = String(params.get('case') || '').trim();
    var tab = String(params.get('tab') || 'overview').trim().toLowerCase();
    if (!caseId) return null;
    return { caseId: caseId, tab: tab };
}

async function copyTextToClipboard(value) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(value);
    }
    var node = document.createElement('textarea');
    node.value = value;
    node.setAttribute('readonly', 'readonly');
    node.style.position = 'fixed';
    node.style.top = '-9999px';
    document.body.appendChild(node);
    node.focus();
    node.select();
    var copied = document.execCommand('copy');
    document.body.removeChild(node);
    if (!copied) throw new Error('Clipboard copy failed.');
}

function renderRailCases() {
    var root = $('rail-recent-cases');
    if (!root) return;
    var items = state.cases.slice(0, 4);
    if (!items.length) {
        root.innerHTML = '<div class="placeholder placeholder--small">No cases yet.</div>';
        return;
    }
    root.innerHTML = items.map(function (c) {
        return '<button class="case-card case-card--rail" data-case="' + esc(c.case_id)
            + '" type="button"><div><div class="case-card__title">' + esc(c.case_id)
            + '</div><div class="case-card__meta">' + esc(prettyLabel(c.status || 'unknown'))
            + '</div></div><div>' + badge(c.status) + '</div></button>';
    }).join('');
    root.querySelectorAll('[data-case]').forEach(function (el) {
        el.addEventListener('click', function () {
            openWorkspace(el.dataset.case, 'overview');
        });
    });
}

function renderDashboardActivity() {
    var root = $('dashboard-activity');
    if (!root) return;
    var items = state.cases.slice(0, 5);
    if (!items.length) {
        root.innerHTML = '<div class="placeholder">Create a case to start the workspace.</div>';
        return;
    }
    root.innerHTML = items.map(function (c, index) {
        var status = String(c.status || 'unknown');
        var updated = fmtTs(c.updated_at || c.created_at);
        var hint = 'Open the case workspace and continue the investigation.';
        if (/fail|error|failed/.test(status.toLowerCase())) {
            hint = 'This case needs analyst attention.';
        } else if (/analyz|ingest/.test(status.toLowerCase())) {
            hint = 'Analysis is still in motion.';
        } else if (/complete|ready/.test(status.toLowerCase())) {
            hint = 'Ready for review, conclusions, or export.';
        }
        return '<article class="signal-card"><div class="panel-kicker">'
            + (index === 0 ? 'Focus' : 'Recent Case') + '</div><div class="signal-card__title">'
            + esc(c.case_id) + '</div><p class="signal-card__body">'
            + esc(hint) + '</p><div class="workspace-meta">' + badge(status)
            + '<span class="chip">Updated ' + esc(updated) + '</span></div></article>';
    }).join('');
}

function renderWorkspaceInspector() {
    var d = state.overview;
    if (!d) return;
    var caseData = d.case || {};
    var summary = d.summary || {};
    var artifacts = d.artifacts || [];
    var findings = d.findings || [];
    var timeline = d.timeline || [];
    var iocs = d.iocs || [];
    var sessions = d.agent_sessions || [];

    if ($('inspector-case-id')) {
        $('inspector-case-id').textContent = state.caseId || 'No case selected';
    }
    if ($('inspector-case-status')) {
        var risk = summary.risk_score;
        var risk_badge = risk == null ? '' : '<span class="chip">Risk ' + esc(risk) + '</span>';
        $('inspector-case-status').innerHTML = badge(caseData.status) + risk_badge;
    }
    if ($('inspector-case-meta')) {
        $('inspector-case-meta').innerHTML = [
            metricCard('Artifacts', artifacts.length),
            metricCard('Findings', findings.length),
            metricCard('Timeline', timeline.length),
            metricCard('IOCs', iocs.length),
        ].join('');
    }

    var summaryItems = [];
    Object.keys(summary).forEach(function (key) {
        if (summaryItems.length >= 4) return;
        if (key === 'risk_score') return;
        var value = summary[key];
        if (value == null || typeof value === 'object') return;
        summaryItems.push({
            title: prettyLabel(key),
            meta: shortValue(value, 160),
        });
    });
    if (!summaryItems.length) {
        summaryItems.push({ title: 'Case status', meta: prettyLabel(caseData.status || 'unknown') });
    }

    if ($('inspector-summary')) {
        $('inspector-summary').innerHTML = summaryItems.map(function (item) {
            return '<article class="inspector-item"><div class="inspector-item__title">'
                + esc(item.title) + '</div><div class="inspector-item__meta">'
                + esc(item.meta) + '</div></article>';
        }).join('');
    }

    var activity = [];
    var audit = (d.audit_log || []).slice(-3).reverse();
    audit.forEach(function (entry) {
        activity.push({
            title: prettyLabel(entry.action || entry.event || 'Audit Event'),
            meta: (entry.actor || 'system') + ' · ' + fmtTs(entry.created_at || entry.timestamp || entry.logged_at),
            body: shortValue(JSON.stringify(entry.details || {}), 180),
        });
    });
    if (d.latest_job) {
        activity.push({
            title: prettyLabel(d.latest_job.job_type || 'Analysis Job'),
            meta: prettyLabel(d.latest_job.status || 'unknown') + ' · '
                + fmtTs(d.latest_job.updated_at || d.latest_job.created_at),
            body: shortValue(d.latest_job.message || d.latest_job.error || '', 180),
        });
    }
    if (d.latest_enrichment_job) {
        activity.push({
            title: 'IOC Enrichment',
            meta: prettyLabel(d.latest_enrichment_job.status || 'unknown') + ' · '
                + fmtTs(d.latest_enrichment_job.updated_at || d.latest_enrichment_job.created_at),
            body: shortValue(d.latest_enrichment_job.message || d.latest_enrichment_job.error || '', 180),
        });
    }
    var hashes = (d.evidence_hash_log || []).slice(-2).reverse();
    hashes.forEach(function (entry) {
        activity.push({
            title: 'Evidence Hash',
            meta: shortValue(entry.path || entry.file_path || entry.name || 'artifact', 48),
            body: shortValue(entry.sha256 || entry.hash || '', 180),
        });
    });

    if ($('inspector-activity')) {
        $('inspector-activity').innerHTML = activity.length ? activity.map(function (item) {
            return '<article class="inspector-item"><div class="inspector-item__title">'
                + esc(item.title) + '</div><div class="inspector-item__meta">'
                + esc(item.meta) + '</div><div class="inspector-item__meta">'
                + esc(item.body || 'No extra details.') + '</div></article>';
        }).join('') : '<div class="placeholder placeholder--small">No activity yet.</div>';
    }

    var next = [];
    if (!artifacts.length) {
        next.push({ title: 'Ingest evidence', meta: 'Import source files to begin analysis.' });
    } else if (!findings.length) {
        next.push({ title: 'Run analysis', meta: 'Generate findings and timeline context.' });
    } else {
        next.push({ title: 'Review findings', meta: 'Inspect high-confidence artifacts and timeline signals.' });
    }
    if (iocs.length && !(d.ioc_enrichments || []).length) {
        next.push({ title: 'Enrich IOCs', meta: 'Pull external context for indicators.' });
    }
    if (sessions.length) {
        next.push({ title: 'Review agent output', meta: 'Approve or rerun the next analyst actions.' });
    }

    if ($('inspector-next-step')) {
        $('inspector-next-step').innerHTML = next.map(function (item) {
            return '<article class="inspector-item"><div class="inspector-item__title">'
                + esc(item.title) + '</div><div class="inspector-item__meta">'
                + esc(item.meta) + '</div></article>';
        }).join('');
    }
}

function getCommandItems() {
    var items = [
        {
            label: 'Open Dashboard',
            group: 'Navigation',
            detail: 'Return to the case overview.',
            keywords: 'dashboard overview home',
            run: function () { showPage('dashboard'); },
        },
        {
            label: 'Open Cases',
            group: 'Navigation',
            detail: 'Browse the case registry.',
            keywords: 'cases registry list',
            run: function () { showPage('cases'); },
        },
        {
            label: 'Open Workspace',
            group: 'Navigation',
            detail: 'Jump back into the investigation canvas.',
            keywords: 'workspace case',
            run: function () { if (state.caseId) showPage('workspace'); else note('Open a case first.', true); },
        },
        {
            label: 'Open Settings',
            group: 'Navigation',
            detail: 'Adjust models and enrichment keys.',
            keywords: 'settings config runtime',
            run: function () { showPage('settings'); },
        },
        {
            label: 'Create New Case',
            group: 'Cases',
            detail: 'Start a fresh investigation.',
            keywords: 'new create init case',
            run: function () { $('new-case-btn').click(); },
        },
        {
            label: 'Refresh Dashboard',
            group: 'System',
            detail: 'Reload the case registry and current workspace.',
            keywords: 'refresh reload sync',
            run: function () { $('global-refresh-btn').click(); },
        },
    ];

    state.cases.slice(0, 12).forEach(function (c) {
        items.push({
            label: 'Open case ' + c.case_id,
            group: 'Cases',
            detail: 'Status ' + prettyLabel(c.status || 'unknown'),
            keywords: c.case_id + ' ' + (c.status || ''),
            run: function () { openWorkspace(c.case_id, 'overview'); },
        });
    });

    if (state.caseId) {
        items.push({
            label: 'Ingest evidence',
            group: 'Workspace',
            detail: 'Open the ingest dialog for the current case.',
            keywords: 'ingest evidence import',
            run: function () { $('workspace-ingest-btn').click(); },
        });
        items.push({
            label: 'Run analysis',
            group: 'Workspace',
            detail: 'Analyze the current case without Llama.',
            keywords: 'analyze analysis findings',
            run: function () { $('workspace-analyze-btn').click(); },
        });
        items.push({
            label: 'Share brief',
            group: 'Workspace',
            detail: 'Copy the share brief for the current case.',
            keywords: 'share brief report',
            run: function () { $('workspace-share-btn').click(); },
        });
        items.push({
            label: 'Start agent session',
            group: 'Workspace',
            detail: 'Launch the autonomous investigation agent.',
            keywords: 'agent session copilot',
            run: function () { $('workspace-agent-btn').click(); },
        });
    }

    return items;
}

function renderCommandPalette() {
    var root = $('command-results');
    if (!root) return;
    var query = String(state.commandQuery || '').toLowerCase().trim();
    var items = getCommandItems();
    var filtered = items.filter(function (item) {
        var haystack = [item.label, item.group, item.detail, item.keywords].join(' ').toLowerCase();
        return !query || haystack.indexOf(query) !== -1;
    });
    filtered.sort(function (a, b) {
        var aExact = query && a.label.toLowerCase().indexOf(query) === 0 ? -1 : 0;
        var bExact = query && b.label.toLowerCase().indexOf(query) === 0 ? -1 : 0;
        return aExact - bExact;
    });
    state.commandResults = filtered;
    if (state.commandIndex >= filtered.length) {
        state.commandIndex = filtered.length ? filtered.length - 1 : 0;
    }
    if (!filtered.length) {
        root.innerHTML = '<div class="placeholder">No commands matched.</div>';
        return;
    }
    root.innerHTML = filtered.map(function (item, index) {
        return '<button class="command-item' + (index === state.commandIndex ? ' command-item--active' : '')
            + '" type="button" data-command-index="' + index + '"><div><div class="signal-card__title">'
            + esc(item.label) + '</div><div class="inspector-item__meta">' + esc(item.detail)
            + '</div></div><div class="command-item__meta">' + esc(item.group) + '</div></button>';
    }).join('');
    root.querySelectorAll('[data-command-index]').forEach(function (el) {
        el.addEventListener('click', function () {
            var idx = Number(el.dataset.commandIndex || '0');
            var item = filtered[idx];
            if (!item) return;
            closeCommandPalette();
            item.run();
        });
    });
}

function openCommandPalette(prefill) {
    state.commandOpen = true;
    state.commandQuery = prefill || '';
    state.commandIndex = 0;
    var shell = $('command-shell');
    if (shell) shell.classList.remove('modal-shell--hidden');
    renderCommandPalette();
    var input = $('command-input');
    if (input) {
        input.value = state.commandQuery;
        input.focus();
        input.select();
    }
}

function closeCommandPalette() {
    state.commandOpen = false;
    state.commandQuery = '';
    state.commandResults = [];
    var shell = $('command-shell');
    if (shell) shell.classList.add('modal-shell--hidden');
}

function runSelectedCommand() {
    if (!state.commandResults.length) return;
    var item = state.commandResults[state.commandIndex] || state.commandResults[0];
    if (!item) return;
    closeCommandPalette();
    item.run();
}

function moveCommandSelection(delta) {
    if (!state.commandResults.length) return;
    state.commandIndex = (state.commandIndex + delta + state.commandResults.length)
        % state.commandResults.length;
    renderCommandPalette();
    var active = document.querySelector('.command-item--active');
    if (active && active.scrollIntoView) {
        active.scrollIntoView({ block: 'nearest' });
    }
}

function renderRecent() {
    var root = $('recent-cases');
    if (!root) return;
    if (!state.cases.length) {
        root.innerHTML = '<div class="placeholder">No cases yet.</div>';
        return;
    }
    root.innerHTML = state.cases.slice(0, 5).map(function (c) {
        return '<button class="case-card" data-case="' + esc(c.case_id) + '"><div class="case-card__head">'
            + '<span class="case-card__title">' + esc(c.case_id) + '</span>' + badge(c.status)
            + '</div><div class="case-card__meta">Updated ' + esc(fmtTs(c.updated_at || c.created_at))
            + '</div></button>';
    }).join('');
    root.querySelectorAll('[data-case]').forEach(function (el) {
        el.addEventListener('click', function () { openWorkspace(el.dataset.case); });
    });
}

function renderCases() {
    var root = $('cases-table');
    if (!root) return;
    var q = String(($('case-search-input') || {}).value || '').toLowerCase();
    var st = String(($('case-status-filter') || {}).value || '');
    var items = state.cases.filter(function (c) {
        return (!q || String(c.case_id || '').toLowerCase().indexOf(q) !== -1)
            && (!st || String(c.status || '') === st);
    });
    if (!items.length) {
        root.innerHTML = '<div class="placeholder">No cases matched the current filters.</div>';
        return;
    }
    root.innerHTML = '<table class="data-table"><thead><tr><th>Case</th><th>Status</th><th>Updated</th><th></th>'
        + '</tr></thead><tbody>' + items.map(function (c) {
            return '<tr><td><strong>' + esc(c.case_id) + '</strong></td><td>' + badge(c.status)
                + '</td><td>' + esc(fmtTs(c.updated_at || c.created_at))
                + '</td><td><button class="btn btn--ghost btn--mini" data-case="' + esc(c.case_id)
                + '">Open</button></td></tr>';
        }).join('') + '</tbody></table>';
    root.querySelectorAll('[data-case]').forEach(function (el) {
        el.addEventListener('click', function () { openWorkspace(el.dataset.case); });
    });
}

function renderWorkspace() {
    var d = state.overview;
    if (!d) return;
    var caseData = d.case || {};
    var artifacts = d.artifacts || [];
    var findings = d.findings || [];
    var timeline = d.timeline || [];
    var iocs = d.iocs || [];
    var threads = d.threads || [];

    $('workspace-case-title').textContent = state.caseId;
    $('workspace-case-subtitle').textContent = 'Updated '
        + fmtTs(caseData.updated_at || caseData.created_at);
    $('rail-current-case').textContent = state.caseId;
    $('workspace-meta').innerHTML = [
        badge(caseData.status),
        '<span class="chip">' + esc(artifacts.length) + ' artifacts</span>',
        '<span class="chip">' + esc(findings.length) + ' findings</span>',
        '<span class="chip">' + esc(timeline.length) + ' events</span>',
    ].join('');
    $('workspace-overview-cards').innerHTML = [
        ['Artifacts', artifacts.length], ['Findings', findings.length],
        ['IOCs', iocs.length], ['Threads', threads.length],
    ].map(function (i) {
        return '<article class="hero-card"><div class="hero-card__label">' + i[0]
            + '</div><div class="hero-card__value">' + i[1] + '</div></article>';
    }).join('');
    $('thread-list').innerHTML = threads.length ? threads.map(function (t) {
        return '<article class="list-card"><div class="list-card__title">' + esc(t.title || t.thread_id)
            + '</div><p class="list-card__body">' + esc(t.summary || '') + '</p></article>';
    }).join('') : '<div class="placeholder">No threads yet</div>';
    $('graph-summary').innerHTML = (d.graph && d.graph.nodes && d.graph.nodes.length)
        ? '<article class="list-card"><div class="list-card__title">Graph Summary</div><div class="list-card__meta">'
        + esc(d.graph.nodes.length) + ' nodes | ' + esc(d.graph.edges.length) + ' edges</div></article>'
        : '<div class="placeholder">Graph data will appear after analysis.</div>';
    $('artifact-table').innerHTML = '<table class="data-table"><thead><tr><th>Name</th><th>Type</th><th>Risk</th></tr>'
        + '</thead><tbody>' + (d.artifact_previews || []).map(function (a) {
            return '<tr><td>' + esc(a.display_name || a.rel_path || a.artifact_id) + '</td><td>'
                + esc(a.artifact_type || '-') + '</td><td>' + esc(a.risk_level || a.risk_score || 0)
                + '</td></tr>';
        }).join('') + '</tbody></table>';
    $('artifact-detail').innerHTML = '<div class="placeholder">Artifact detail uses the normalized preview data above.</div>';
    $('timeline-table').innerHTML = '<table class="data-table"><thead><tr><th>Time</th><th>Type</th><th>Description</th></tr>'
        + '</thead><tbody>' + timeline.map(function (e) {
            return '<tr><td>' + esc(fmtTs(e.timestamp)) + '</td><td>' + esc(e.event_type || '-')
                + '</td><td>' + esc(e.description || '-') + '</td></tr>';
        }).join('') + '</tbody></table>';
    $('timeline-detail').innerHTML = '<div class="placeholder">Use saved views and filters to refine the timeline.</div>';
    $('finding-list').innerHTML = findings.length ? findings.map(function (f) {
        return '<article class="list-card"><div class="list-card__title">' + esc(f.title || 'Finding')
            + '</div><div class="list-card__meta">' + esc(f.severity || '-') + '</div></article>';
    }).join('') : '<div class="placeholder">No findings yet</div>';
    $('ioc-table').innerHTML = '<table class="data-table"><thead><tr><th>Value</th><th>Type</th></tr></thead><tbody>'
        + iocs.map(function (i) {
            return '<tr><td>' + esc(i.value || i.ioc_value || '-') + '</td><td>'
                + esc(i.ioc_type || i.type || '-') + '</td></tr>';
        }).join('') + '</tbody></table>';
    $('notebook-list').innerHTML = (d.notebook_entries || []).length ? d.notebook_entries.map(function (n) {
        return '<article class="list-card"><div class="list-card__title">' + esc(n.title || n.kind)
            + '</div><p class="list-card__body">' + esc(n.body || '') + '</p></article>';
    }).join('') : '<div class="placeholder">Notebook entries will appear here.</div>';
    $('saved-views-list').innerHTML = (d.workspace_views || []).length ? d.workspace_views.map(function (v) {
        return '<button class="chip" data-view="' + esc(v.view_id) + '">' + esc(v.name) + '</button>';
    }).join('') : '<span class="placeholder placeholder--small">No saved views</span>';
    $('agent-session-list').innerHTML = (d.agent_sessions || []).length ? d.agent_sessions.map(function (s) {
        var buttons = (s.recommendations || []).filter(function (r) {
            return r.status === 'pending' && r.suggested_action && r.suggested_action.action;
        }).map(function (r) {
            return '<button class="btn btn--ghost btn--mini" data-session="' + esc(s.session_id)
                + '" data-action="' + esc(r.suggested_action.action) + '">Approve '
                + esc(r.suggested_action.action) + '</button>';
        }).join(' ');
        return '<article class="list-card"><div class="list-card__title">' + esc(s.goal || s.session_id)
            + '</div><div class="list-card__meta">' + badge(s.status) + '</div><p class="list-card__body">'
            + esc(s.summary || '') + '</p><div class="toolbar">' + buttons + '</div></article>';
    }).join('') : '<div class="placeholder">No agent sessions yet.</div>';
    $('agent-session-list').querySelectorAll('[data-session]').forEach(function (el) {
        el.addEventListener('click', async function () {
            try {
                await api('/api/cases/' + encodeURIComponent(state.caseId) + '/agent/sessions/'
                    + encodeURIComponent(el.dataset.session) + '/approve', {
                    method: 'POST', body: { action: el.dataset.action },
                });
                await loadWorkspace();
                note('Agent action approved.');
            } catch (err) { note(err.message, true); }
        });
    });
    renderWorkspaceInspector();
    syncChromeBar();
}

async function loadWorkspace() {
    state.overview = await api('/api/cases/' + encodeURIComponent(state.caseId));
    renderWorkspace();
}

async function openWorkspace(caseId, tabName) {
    state.caseId = caseId;
    if (tabName) setWorkspaceTab(tabName);
    showPage('workspace');
    await loadWorkspace();
    syncUrlState();
}

async function refreshHome() {
    state.cases = await api('/api/cases');
    var stats = await api('/api/stats');
    $('stat-total-cases').textContent = stats.total_cases || 0;
    $('stat-active-cases').textContent = stats.active_cases || 0;
    $('stat-failed-cases').textContent = (stats.by_status || {}).failed || 0;
    renderRecent();
    renderCases();
    renderRailCases();
    renderDashboardActivity();
    syncChromeBar();
}

document.querySelectorAll('.rail-link[data-page]').forEach(function (el) {
    el.addEventListener('click', function () {
        showPage(el.dataset.page);
        if (el.dataset.page === 'settings') {
            api('/api/settings').then(function (s) {
                $('settings-openai-endpoint').value = s.openai_endpoint || '';
                $('settings-openai-api-key').value = s.openai_api_key || '';
                $('settings-llama-model').value = s.llama_model || '';
                $('settings-virustotal-api-key').value = s.virustotal_api_key || '';
                $('settings-abuseipdb-api-key').value = s.abuseipdb_api_key || '';
                $('settings-data-dir').value = s.data_dir || '';
            }).catch(function (err) { note(err.message, true); });
        }
    });
});
document.querySelectorAll('[data-nav-target]').forEach(function (el) {
    el.addEventListener('click', function () {
        showPage(el.dataset.navTarget);
    });
});
if ($('command-palette-btn')) {
    $('command-palette-btn').addEventListener('click', function () { openCommandPalette(); });
}
if ($('quick-command-btn')) {
    $('quick-command-btn').addEventListener('click', function () { openCommandPalette(); });
}
if ($('rail-palette-btn')) {
    $('rail-palette-btn').addEventListener('click', function () { openCommandPalette(); });
}
if ($('sidebar-toggle-btn')) {
    $('sidebar-toggle-btn').addEventListener('click', function () {
        setRailCollapsed(!state.railCollapsed);
    });
}
if ($('inspector-toggle-btn')) {
    $('inspector-toggle-btn').addEventListener('click', function () {
        setInspectorCollapsed(!state.inspectorCollapsed);
    });
}
document.querySelectorAll('.workspace-tab').forEach(function (el) {
    el.addEventListener('click', function () {
        setWorkspaceTab(el.dataset.workspaceTab);
    });
});
document.querySelectorAll('[data-close-modal]').forEach(function (el) {
    el.addEventListener('click', function () { modal('', false); });
});
document.querySelectorAll('[data-close-command]').forEach(function (el) {
    el.addEventListener('click', function () { closeCommandPalette(); });
});
if ($('command-shell')) {
    $('command-shell').addEventListener('click', function (e) {
        if (e.target === $('command-shell')) closeCommandPalette();
    });
}
$('new-case-btn').addEventListener('click', function () { modal('modal-new-case', true); });
$('global-refresh-btn').addEventListener('click', function () {
    refreshHome().catch(function (err) { note(err.message, true); });
    if (state.caseId) loadWorkspace().catch(function (err) { note(err.message, true); });
});
$('case-search-input').addEventListener('input', renderCases);
$('case-status-filter').addEventListener('change', renderCases);
$('workspace-refresh-btn').addEventListener('click', function () {
    if (state.caseId) loadWorkspace().catch(function (err) { note(err.message, true); });
});
if ($('inspector-refresh-btn')) {
    $('inspector-refresh-btn').addEventListener('click', function () {
        if (state.caseId) loadWorkspace().catch(function (err) { note(err.message, true); });
    });
}
if ($('inspector-ingest-btn')) {
    $('inspector-ingest-btn').addEventListener('click', function () { modal('modal-ingest', true); });
}
if ($('inspector-analyze-btn')) {
    $('inspector-analyze-btn').addEventListener('click', function () {
        $('workspace-analyze-btn').click();
    });
}
if ($('inspector-share-btn')) {
    $('inspector-share-btn').addEventListener('click', function () {
        $('workspace-share-btn').click();
    });
}
$('workspace-ingest-btn').addEventListener('click', function () { modal('modal-ingest', true); });
$('workspace-analyze-btn').addEventListener('click', async function () {
    if (!state.caseId) return;
    try { await api('/api/cases/' + encodeURIComponent(state.caseId) + '/analyze', { method: 'POST', body: { enable_llama: false } }); await loadWorkspace(); note('Analysis complete.'); }
    catch (err) { note(err.message, true); }
});
$('workspace-share-btn').addEventListener('click', async function () {
    if (!state.caseId) return;
    try {
        var payload = await api('/api/cases/' + encodeURIComponent(state.caseId) + '/share/brief');
        await copyTextToClipboard(String(payload.share_text || ''));
        await api('/api/cases/' + encodeURIComponent(state.caseId) + '/share/events', {
            method: 'POST',
            body: { event: 'share_copied', channel: 'clipboard' },
        });
        note('Share brief copied.');
    } catch (err) { note(err.message, true); }
});
$('workspace-agent-btn').addEventListener('click', function () { $('agent-form').requestSubmit(); });
$('new-case-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    try { await api('/api/cases', { method: 'POST', body: { case_id: $('new-case-id').value.trim() } }); modal('', false); $('new-case-id').value = ''; await refreshHome(); note('Case created.'); }
    catch (err) { note(err.message, true); }
});
$('ingest-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    if (!state.caseId) return;
    try { await api('/api/cases/' + encodeURIComponent(state.caseId) + '/ingest', { method: 'POST', body: { source_dir: $('ingest-source-dir').value.trim() } }); modal('', false); $('ingest-source-dir').value = ''; await loadWorkspace(); await refreshHome(); note('Evidence ingested.'); }
    catch (err) { note(err.message, true); }
});
$('settings-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    try {
        await api('/api/settings', { method: 'PUT', body: {
            openai_endpoint: $('settings-openai-endpoint').value,
            openai_api_key: $('settings-openai-api-key').value,
            llama_model: $('settings-llama-model').value,
            virustotal_api_key: $('settings-virustotal-api-key').value,
            abuseipdb_api_key: $('settings-abuseipdb-api-key').value,
        } });
        $('settings-status').textContent = 'Saved';
        note('Settings updated.');
    } catch (err) { $('settings-status').textContent = err.message; note(err.message, true); }
});
$('notebook-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    if (!state.caseId) return;
    try {
        await api('/api/cases/' + encodeURIComponent(state.caseId) + '/notebook', { method: 'POST', body: {
            kind: $('notebook-kind').value,
            title: $('notebook-title').value || 'Notebook entry',
            body: $('notebook-body').value,
            links: {},
        } });
        $('notebook-title').value = '';
        $('notebook-body').value = '';
        await loadWorkspace();
        note('Notebook entry added.');
    } catch (err) { note(err.message, true); }
});
$('agent-form').addEventListener('submit', async function (e) {
    e.preventDefault();
    if (!state.caseId) return;
    try {
        await api('/api/cases/' + encodeURIComponent(state.caseId) + '/agent/sessions', { method: 'POST', body: {
            goal: $('agent-goal').value || 'Investigate this case and prioritize the next analyst actions.',
        } });
        await loadWorkspace();
        note('Agent session started.');
    } catch (err) { note(err.message, true); }
});
$('save-view-btn').addEventListener('click', async function () {
    if (!state.caseId) return;
    var name = window.prompt('Saved view name');
    if (!name) return;
    try {
        await api('/api/cases/' + encodeURIComponent(state.caseId) + '/views', { method: 'POST', body: {
            name: name, section: state.activeTab, filters: {}, sort: { field: 'risk', direction: 'desc' }, layout: {},
        } });
        await loadWorkspace();
        note('View saved.');
    } catch (err) { note(err.message, true); }
});

if ($('command-input')) {
    $('command-input').addEventListener('input', function () {
        state.commandQuery = this.value;
        state.commandIndex = 0;
        renderCommandPalette();
    });
    $('command-input').addEventListener('keydown', function (e) {
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            moveCommandSelection(1);
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            moveCommandSelection(-1);
        } else if (e.key === 'Enter') {
            e.preventDefault();
            runSelectedCommand();
        } else if (e.key === 'Escape') {
            e.preventDefault();
            closeCommandPalette();
        }
    });
}

window.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (state.commandOpen) closeCommandPalette(); else openCommandPalette();
        return;
    }
    if (!state.commandOpen) return;
    if (e.key === 'Escape') {
        e.preventDefault();
        closeCommandPalette();
    }
});

var initialRoute = parseInitialWorkspaceRoute();
setWorkspaceTab(state.activeTab);
showPage('dashboard');
syncChromeBar();
refreshHome().then(function () {
    if (initialRoute && initialRoute.caseId) {
        return openWorkspace(initialRoute.caseId, initialRoute.tab);
    }
    return null;
}).catch(function (err) { note(err.message, true); });
