'use strict';

var TimelineVisualization = (function() {
    // Configuration
    var config = {
        margin: { top: 20, right: 30, bottom: 40, left: 60 },
        eventRadius: 6,
        clusterRadius: 15,
        colors: {
            process: '#6ee7db',
            network: '#f59e0b',
            file: '#7dd3fc',
            registry: '#34d399',
            binary: '#fbbf24',
            default: '#91a4bd'
        }
    };

    // State
    var state = {
        caseId: null,
        events: [],
        filteredEvents: [],
        selectedEvent: null,
        zoomTransform: d3.zoomIdentity,
        filters: {
            after: null,
            before: null,
            eventType: '',
            minRisk: 0,
            mitreTechnique: ''
        }
    };

    // Helper functions
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
        try { 
            var d = new Date(String(v).endsWith('Z') ? v : v + 'Z');
            return d.toLocaleString(); 
        } catch (_) { 
            return String(v); 
        }
    }

    function parseTs(v) {
        if (!v) return null;
        try {
            return new Date(String(v).endsWith('Z') ? v : v + 'Z');
        } catch (_) {
            return null;
        }
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

    // Event type categorization
    function getEventCategory(eventType) {
        if (!eventType) return 'default';
        var t = eventType.toLowerCase();
        if (t.includes('process') || t.includes('execution')) return 'process';
        if (t.includes('network') || t.includes('dns') || t.includes('http') || t.includes('c2')) return 'network';
        if (t.includes('file') || t.includes('create') || t.includes('modify') || t.includes('delete')) return 'file';
        if (t.includes('registry')) return 'registry';
        if (t.includes('binary')) return 'binary';
        return 'default';
    }

    // Cluster events by time period
    function clusterEvents(events, timeWindowMs) {
        var clusters = [];
        var processed = new Set();

        events.forEach(function(event, i) {
            if (processed.has(i)) return;
            
            var ts = parseTs(event.timestamp);
            if (!ts) return;

            var cluster = [event];
            processed.add(i);

            // Find nearby events
            for (var j = i + 1; j < events.length; j++) {
                if (processed.has(j)) continue;
                var otherTs = parseTs(events[j].timestamp);
                if (!otherTs) continue;
                
                if (Math.abs(otherTs - ts) <= timeWindowMs) {
                    cluster.push(events[j]);
                    processed.add(j);
                }
            }

            if (cluster.length > 1) {
                clusters.push({
                    id: 'cluster_' + i,
                    events: cluster,
                    timestamp: cluster[0].timestamp,
                    count: cluster.length,
                    avgRisk: cluster.reduce(function(sum, e) { return sum + (e.risk_score || 0); }, 0) / cluster.length
                });
            }
        });

        return clusters;
    }

    // Initialize the timeline visualization
    function initTimeline() {
        var container = $('timeline-chart');
        if (!container) return;

        var width = container.clientWidth - config.margin.left - config.margin.right;
        var height = container.clientHeight - config.margin.top - config.margin.bottom;

        // Clear existing
        container.innerHTML = '';

        // Create SVG
        var svg = d3.select(container)
            .append('svg')
            .attr('width', width + config.margin.left + config.margin.right)
            .attr('height', height + config.margin.top + config.margin.bottom)
            .attr('class', 'timeline-svg');

        // Create defs for gradients/clip paths
        var defs = svg.append('defs');
        
        // Clip path for chart area
        defs.append('clipPath')
            .attr('id', 'chart-clip')
            .append('rect')
            .attr('width', width)
            .attr('height', height);

        // Gradient for events
        var gradient = defs.append('linearGradient')
            .attr('id', 'event-gradient')
            .attr('x1', '0%')
            .attr('y1', '0%')
            .attr('x2', '0%')
            .attr('y2', '100%');
        gradient.append('stop').attr('offset', '0%').attr('stop-color', '#6ee7db');
        gradient.append('stop').attr('offset', '100%').attr('stop-color', '#4fc3aa');

        // Main chart group
        var g = svg.append('g')
            .attr('transform', 'translate(' + config.margin.left + ',' + config.margin.top + ')');

        // Scales
        var xScale = d3.scaleTime().range([0, width]);
        var yScale = d3.scaleBand().range([0, height]).padding(0.2);

        // Grid lines
        var xGrid = g.append('g')
            .attr('class', 'timeline-grid')
            .attr('transform', 'translate(0,' + height + ')');

        var yGrid = g.append('g')
            .attr('class', 'timeline-grid');

        // Axes
        var xAxis = g.append('g')
            .attr('class', 'timeline-axis')
            .attr('transform', 'translate(0,' + height + ')');

        var yAxis = g.append('g')
            .attr('class', 'timeline-axis');

        // Chart area (clipped)
        var chartArea = g.append('g')
            .attr('clip-path', 'url(#chart-clip)');

        // Event groups
        var eventsGroup = chartArea.append('g').attr('class', 'events-layer');
        var clustersGroup = chartArea.append('g').attr('class', 'clusters-layer');

        // Brush for zoom
        var brush = d3.brushX()
            .extent([[0, 0], [width, height]])
            .on('end', brushed);

        var brushGroup = g.append('g')
            .attr('class', 'timeline-brush');

        // Zoom
        var zoom = d3.zoom()
            .scaleExtent([0.1, 100])
            .on('zoom', zoomed);

        svg.call(zoom);

        // Mini-map
        initMiniMap();

        return {
            svg: svg,
            g: g,
            xScale: xScale,
            yScale: yScale,
            xAxis: xAxis,
            yAxis: yAxis,
            xGrid: xGrid,
            yGrid: yGrid,
            eventsGroup: eventsGroup,
            clustersGroup: clustersGroup,
            brush: brush,
            brushGroup: brushGroup,
            zoom: zoom,
            width: width,
            height: height
        };
    }

    // Initialize mini-map
    function initMiniMap() {
        var container = $('timeline-minimap');
        if (!container) return;

        var width = container.clientWidth;
        var height = container.clientHeight;

        container.innerHTML = '';

        var svg = d3.select(container)
            .append('svg')
            .attr('width', width)
            .attr('height', height);

        var margin = { top: 4, right: 4, bottom: 4, left: 4 };
        var g = svg.append('g')
            .attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

        return {
            svg: svg,
            g: g,
            width: width - margin.left - margin.right,
            height: height - margin.top - margin.bottom
        };
    }

    // Update timeline with data
    function updateTimeline(chart, data) {
        if (!chart || !data || !data.length) {
            if (chart && chart.svg) {
                chart.svg.select('.events-layer').selectAll('*').remove();
            }
            return;
        }

        // Parse timestamps
        var parsedData = data.map(function(d) {
            return Object.assign({}, d, { _date: parseTs(d.timestamp) });
        }).filter(function(d) { return d._date; });

        // Sort by time
        parsedData.sort(function(a, b) { return a._date - b._date; });

        // Update scales
        var timeExtent = d3.extent(parsedData, function(d) { return d._date; });
        chart.xScale.domain(timeExtent);

        var eventTypes = Array.from(new Set(parsedData.map(function(d) { return d.event_type; })));
        chart.yScale.domain(eventTypes);

        // Update axes
        chart.xAxis.call(d3.axisBottom(chart.xScale).tickFormat(d3.timeFormat('%H:%M:%S')));
        chart.yAxis.call(d3.axisLeft(chart.yScale));

        // Update grid
        chart.xGrid.call(d3.axisBottom(chart.xScale).tickSize(-chart.height).tickFormat(''));
        chart.yGrid.call(d3.axisLeft(chart.yScale).tickSize(-chart.width).tickFormat(''));

        // Cluster events if zoomed out
        var timeWindow = (timeExtent[1] - timeExtent[0]) / 100; // 1% of time range
        var clusters = clusterEvents(parsedData, timeWindow);

        // Draw events
        var events = chart.eventsGroup.selectAll('.timeline-event')
            .data(parsedData, function(d) { return d.timestamp + d.event_type; });

        events.exit().remove();

        var eventsEnter = events.enter()
            .append('circle')
            .attr('class', function(d) {
                var cat = getEventCategory(d.event_type);
                var risk = d.risk_score || 0;
                var riskClass = risk >= 7 ? 'timeline-event--high-risk' : 
                               risk >= 4 ? 'timeline-event--medium-risk' : '';
                return 'timeline-event timeline-event--' + cat + ' ' + riskClass;
            })
            .attr('r', config.eventRadius)
            .attr('fill', function(d) {
                var cat = getEventCategory(d.event_type);
                return config.colors[cat] || config.colors.default;
            })
            .on('click', function(event, d) {
                event.stopPropagation();
                selectEvent(d);
            })
            .on('mouseover', function(event, d) {
                showTooltip(event, d);
            })
            .on('mouseout', hideTooltip);

        eventsEnter.merge(events)
            .attr('cx', function(d) { return chart.xScale(d._date); })
            .attr('cy', function(d) { return chart.yScale(d.event_type) + chart.yScale.bandwidth() / 2; });

        // Draw clusters
        var clusterSelection = chart.clustersGroup.selectAll('.timeline-cluster')
            .data(clusters);

        clusterSelection.exit().remove();

        clusterSelection.enter()
            .append('circle')
            .attr('class', 'timeline-cluster')
            .merge(clusterSelection)
            .attr('cx', function(d) { return chart.xScale(parseTs(d.timestamp)); })
            .attr('cy', chart.height / 2)
            .attr('r', function(d) { return Math.min(config.clusterRadius, 5 + d.count * 2); });

        // Update mini-map
        updateMiniMap(parsedData);
    }

    // Update mini-map
    function updateMiniMap(data) {
        var mini = initMiniMap();
        if (!mini || !data.length) return;

        var x = d3.scaleTime()
            .domain(d3.extent(data, function(d) { return d._date; }))
            .range([0, mini.width]);

        mini.g.selectAll('.minimap-dot')
            .data(data)
            .enter()
            .append('circle')
            .attr('class', 'minimap-dot')
            .attr('cx', function(d) { return x(d._date); })
            .attr('cy', mini.height / 2)
            .attr('r', 2)
            .attr('fill', function(d) {
                var cat = getEventCategory(d.event_type);
                return config.colors[cat];
            })
            .attr('opacity', 0.6);
    }

    // Brush handler
    function brushed(event) {
        if (!event.selection) return;
        // Handle brush selection for filtering
    }

    // Zoom handler
    function zoomed(event) {
        state.zoomTransform = event.transform;
        // Update scales based on zoom transform
    }

    // Select event
    function selectEvent(event) {
        state.selectedEvent = event;
        renderEventDetail(event);
    }

    // Render event detail panel
    function renderEventDetail(event) {
        var container = $('timeline-detail');
        if (!container || !event) {
            if (container) {
                container.innerHTML = '<div class="placeholder">Select an event to view details</div>';
            }
            return;
        }

        var cat = getEventCategory(event.event_type);
        var related = event.related || {};
        var tags = event.tags || [];
        var risk = event.risk_score || 0;

        var html = '<div class="event-detail-header">';
        html += '<div class="event-detail-type event-detail-type--' + cat + '">' + esc(event.event_type) + '</div>';
        html += '<h3 class="event-detail-title">' + esc(event.description || 'No description') + '</h3>';
        html += '<div class="event-detail-time">' + fmtTs(event.timestamp) + '</div>';
        html += '</div>';

        html += '<div class="event-detail-section">';
        html += '<div class="event-detail-section-title">Risk Score</div>';
        html += '<div class="event-detail-value">' + risk.toFixed(2) + '</div>';
        html += '</div>';

        if (tags.length) {
            html += '<div class="event-detail-section">';
            html += '<div class="event-detail-section-title">Tags</div>';
            html += '<div class="event-detail-tags">';
            tags.forEach(function(tag) {
                html += '<span class="event-detail-tag">' + esc(tag) + '</span>';
            });
            html += '</div>';
            html += '</div>';
        }

        if (Object.keys(related).length) {
            html += '<div class="event-detail-section">';
            html += '<div class="event-detail-section-title">Related Information</div>';
            Object.keys(related).forEach(function(key) {
                html += '<div class="event-detail-field">';
                html += '<span class="event-detail-label">' + esc(key) + '</span>';
                html += '<span class="event-detail-value event-detail-value--code">' + esc(JSON.stringify(related[key], null, 2)) + '</span>';
                html += '</div>';
            });
            html += '</div>';
        }

        if (event.mitre_technique) {
            html += '<div class="event-detail-section">';
            html += '<div class="event-detail-section-title">MITRE ATT&CK</div>';
            html += '<div class="mitre-badge">';
            html += '<span class="mitre-technique">' + esc(event.mitre_technique) + '</span>';
            html += '</div>';
            html += '</div>';
        }

        container.innerHTML = html;
    }

    // Tooltip functions
    function showTooltip(event, d) {
        // Implementation for tooltip display
    }

    function hideTooltip() {
        // Implementation for tooltip hide
    }

    // Load timeline data
    async function loadTimelineData() {
        if (!state.caseId) return;

        try {
            var response = await api('/api/cases/' + encodeURIComponent(state.caseId) + '/timeline/query?limit=5000');
            state.events = response.events || [];
            applyFilters();
            updateEventStats();
            populateFilterOptions();
        } catch (err) {
            console.error('Failed to load timeline:', err);
        }
    }

    // Apply filters
    function applyFilters() {
        state.filteredEvents = state.events.filter(function(event) {
            var ts = parseTs(event.timestamp);
            
            if (state.filters.after && ts && ts < state.filters.after) return false;
            if (state.filters.before && ts && ts > state.filters.before) return false;
            if (state.filters.eventType && event.event_type !== state.filters.eventType) return false;
            if ((event.risk_score || 0) < state.filters.minRisk) return false;
            if (state.filters.mitreTechnique && event.mitre_technique !== state.filters.mitreTechnique) return false;
            
            return true;
        });

        var chart = initTimeline();
        updateTimeline(chart, state.filteredEvents);
    }

    // Update event stats in sidebar
    function updateEventStats() {
        var container = $('event-stats');
        if (!container || !state.events.length) {
            if (container) {
                container.innerHTML = '<div class="placeholder placeholder--small">No events</div>';
            }
            return;
        }

        var stats = {};
        state.events.forEach(function(e) {
            var cat = getEventCategory(e.event_type);
            stats[cat] = (stats[cat] || 0) + 1;
        });

        var html = '';
        Object.keys(stats).forEach(function(cat) {
            html += '<div class="mini-stat" style="margin-bottom: 0.5rem;">';
            html += '<span class="mini-stat__label">' + esc(cat) + '</span>';
            html += '<span class="mini-stat__value">' + stats[cat] + '</span>';
            html += '</div>';
        });

        container.innerHTML = html;
    }

    // Populate filter options
    function populateFilterOptions() {
        var eventTypes = Array.from(new Set(state.events.map(function(e) { return e.event_type; })));
        var mitreTechniques = Array.from(new Set(
            state.events.filter(function(e) { return e.mitre_technique; })
                .map(function(e) { return e.mitre_technique; })
        ));

        var typeSelect = $('filter-event-type');
        if (typeSelect) {
            var currentValue = typeSelect.value;
            typeSelect.innerHTML = '<option value="">All Types</option>';
            eventTypes.forEach(function(type) {
                var option = document.createElement('option');
                option.value = type;
                option.textContent = type;
                typeSelect.appendChild(option);
            });
            typeSelect.value = currentValue;
        }

        var mitreSelect = $('filter-mitre');
        if (mitreSelect) {
            var currentValue = mitreSelect.value;
            mitreSelect.innerHTML = '<option value="">All Techniques</option>';
            mitreTechniques.forEach(function(technique) {
                var option = document.createElement('option');
                option.value = technique;
                option.textContent = technique;
                mitreSelect.appendChild(option);
            });
            mitreSelect.value = currentValue;
        }
    }

    // Export functions
    function exportPNG() {
        var svg = document.querySelector('.timeline-svg');
        if (!svg) return;

        var svgData = new XMLSerializer().serializeToString(svg);
        var canvas = document.createElement('canvas');
        var ctx = canvas.getContext('2d');
        var img = new Image();

        canvas.width = svg.clientWidth;
        canvas.height = svg.clientHeight;

        img.onload = function() {
            ctx.fillStyle = '#0b0f17';
            ctx.fillRect(0, 0, canvas.width, canvas.height);
            ctx.drawImage(img, 0, 0);
            var pngFile = canvas.toDataURL('image/png');
            var downloadLink = document.createElement('a');
            downloadLink.download = 'timeline-' + state.caseId + '-' + Date.now() + '.png';
            downloadLink.href = pngFile;
            downloadLink.click();
        };

        img.src = 'data:image/svg+xml;base64,' + btoa(svgData);
    }

    function exportSVG() {
        var svg = document.querySelector('.timeline-svg');
        if (!svg) return;

        var svgData = new XMLSerializer().serializeToString(svg);
        var blob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
        var url = URL.createObjectURL(blob);
        var downloadLink = document.createElement('a');
        downloadLink.download = 'timeline-' + state.caseId + '-' + Date.now() + '.svg';
        downloadLink.href = url;
        downloadLink.click();
        URL.revokeObjectURL(url);
    }

    // Event handlers
    function setupEventListeners() {
        // Filter inputs
        var afterInput = $('filter-after');
        var beforeInput = $('filter-before');
        var typeSelect = $('filter-event-type');
        var riskRange = $('filter-risk');
        var mitreSelect = $('filter-mitre');
        var applyBtn = $('apply-filters-btn');
        var clearBtn = $('clear-filters-btn');
        var resetViewBtn = $('reset-view-btn');
        var exportPngBtn = $('export-png-btn');
        var exportSvgBtn = $('export-svg-btn');
        var refreshBtn = $('refresh-btn');

        if (riskRange) {
            riskRange.addEventListener('input', function() {
                var riskValue = $('risk-value');
                if (riskValue) riskValue.textContent = parseFloat(this.value).toFixed(1);
            });
        }

        if (applyBtn) {
            applyBtn.addEventListener('click', function() {
                state.filters.after = afterInput && afterInput.value ? new Date(afterInput.value) : null;
                state.filters.before = beforeInput && beforeInput.value ? new Date(beforeInput.value) : null;
                state.filters.eventType = typeSelect ? typeSelect.value : '';
                state.filters.minRisk = riskRange ? parseFloat(riskRange.value) : 0;
                state.filters.mitreTechnique = mitreSelect ? mitreSelect.value : '';
                applyFilters();
            });
        }

        if (clearBtn) {
            clearBtn.addEventListener('click', function() {
                if (afterInput) afterInput.value = '';
                if (beforeInput) beforeInput.value = '';
                if (typeSelect) typeSelect.value = '';
                if (riskRange) {
                    riskRange.value = 0;
                    var riskValue = $('risk-value');
                    if (riskValue) riskValue.textContent = '0.0';
                }
                if (mitreSelect) mitreSelect.value = '';
                state.filters = { after: null, before: null, eventType: '', minRisk: 0, mitreTechnique: '' };
                applyFilters();
            });
        }

        if (resetViewBtn) {
            resetViewBtn.addEventListener('click', function() {
                var chart = initTimeline();
                if (chart && chart.svg) {
                    chart.svg.transition().duration(750).call(chart.zoom.transform, d3.zoomIdentity);
                }
            });
        }

        if (exportPngBtn) {
            exportPngBtn.addEventListener('click', exportPNG);
        }

        if (exportSvgBtn) {
            exportSvgBtn.addEventListener('click', exportSVG);
        }

        if (refreshBtn) {
            refreshBtn.addEventListener('click', loadTimelineData);
        }

        // Navigation
        document.querySelectorAll('[data-nav]').forEach(function(el) {
            el.addEventListener('click', function() {
                var target = el.dataset.nav;
                if (target === 'dashboard') {
                    window.location.href = '/';
                }
            });
        });
    }

    // Initialize
    function init() {
        // Get case ID from URL
        var params = new URLSearchParams(window.location.search);
        state.caseId = params.get('case');
        
        if (!state.caseId) {
            console.error('No case ID provided');
            return;
        }

        // Update UI
        var casePill = $('shell-case-pill');
        if (casePill) casePill.textContent = 'Case: ' + state.caseId;
        
        var railCase = $('rail-current-case');
        if (railCase) railCase.textContent = state.caseId;

        setupEventListeners();
        loadTimelineData();

        // Handle resize
        window.addEventListener('resize', function() {
            var chart = initTimeline();
            updateTimeline(chart, state.filteredEvents);
        });
    }

    // Public API
    return {
        init: init,
        loadTimelineData: loadTimelineData
    };
})();

// Initialize on load
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', TimelineVisualization.init);
} else {
    TimelineVisualization.init();
}