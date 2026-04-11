export function renderSigintData(deps, container, data, knownSsids) {
    const {
        escapeHtml,
        reconState,
        reconHintLabel,
        normalizeReconSecurityLabel,
        formatReconDeviceLabel,
        formatReconSourceLabel,
        formatSigintVendor,
        enableDynamicSectionCollapse,
        loadSigintExtensions,
        debounce,
        downloadFile,
    } = deps;

    const shapeLabels = {
        human: 'Human',
        uuid_like: 'UUID-like',
        hex_like: 'Hex-like',
        generated_like: 'Generated',
    };

    const shapeHints = {
        human: 'Readable network name with no strong generated pattern.',
        uuid_like: 'Looks like a UUID-style generated identifier.',
        hex_like: 'Looks like a long hexadecimal token rather than a human-readable SSID.',
        generated_like: 'Looks auto-generated from a device or hotspot naming pattern.',
    };

    function formatShapeLabel(shape) {
        return shapeLabels[String(shape || '').trim().toLowerCase()] || 'Human';
    }

    function renderShapeBadge(shape) {
        const normalized = String(shape || 'human').trim().toLowerCase() || 'human';
        return `<span class="recon-sigint-shape recon-sigint-shape--${escapeHtml(normalized)}" title="${escapeHtml(shapeHints[normalized] || shapeHints.human)}">
            ${escapeHtml(formatShapeLabel(normalized))}
        </span>`;
    }

    function formatKnownContext(context) {
        if (!context || !context.network_count) return 'No known match';
        const parts = [];
        if (context.dominant_encryption) parts.push(normalizeReconSecurityLabel(context.dominant_encryption));
        if (context.dominant_device_type) parts.push(formatReconDeviceLabel(context.dominant_device_type));
        if (Array.isArray(context.sources) && context.sources.length) {
            parts.push(context.sources.slice(0, 2).map((src) => formatReconSourceLabel(src)).join('/'));
        }
        return parts.join(' · ') || 'Known network';
    }

    function renderKnownContext(context) {
        if (!context || !context.network_count) {
            return '<div class="recon-sigint-context"><strong>No known match</strong><span>Not present in the current Recon dataset.</span></div>';
        }
        const detailBits = [];
        if (context.sample_mac) detailBits.push(context.sample_mac);
        detailBits.push(`${context.network_count} known net${context.network_count === 1 ? '' : 's'}`);
        return `<div class="recon-sigint-context">
            <strong>${escapeHtml(formatKnownContext(context))}</strong>
            <span>${escapeHtml(detailBits.join(' · '))}</span>
        </div>`;
    }

    function renderKnownBadge(item) {
        const isKnown = Boolean(item?.is_known);
        return `<span class="recon-sigint-known-pill${isKnown ? ' recon-sigint-known-pill--known' : ''}">
            ${isKnown ? 'Known network' : 'Unmatched'}
        </span>`;
    }

    function renderClientVendor(client) {
        return `<div class="recon-sigint-vendor">
            <strong>${escapeHtml(formatSigintVendor(client))}</strong>
            <span>${escapeHtml(client?.oui_prefix || 'Unknown OUI')}</span>
        </div>`;
    }

    function renderClientMatchSummary(client) {
        const knownCount = Number(client?.known_ssid_count) || 0;
        const unmatchedCount = Number(client?.unmatched_ssid_count) || 0;
        const knownPreview = Array.isArray(client?.known_ssid_preview) ? client.known_ssid_preview : [];
        const unmatchedPreview = Array.isArray(client?.unmatched_ssid_preview) ? client.unmatched_ssid_preview : [];
        return `<div class="recon-sigint-match">
            <div class="recon-sigint-match-pills">
                <span class="recon-sigint-match-pill recon-sigint-match-pill--known">${knownCount} known</span>
                <span class="recon-sigint-match-pill">${unmatchedCount} unmatched</span>
            </div>
            <span>${escapeHtml(knownPreview.length ? `Known: ${knownPreview.join(', ')}` : 'No known SSID matches')}</span>
            <span>${escapeHtml(unmatchedPreview.length ? `Unmatched: ${unmatchedPreview.join(', ')}` : 'No unmatched SSIDs')}</span>
        </div>`;
    }

    if (!knownSsids) knownSsids = new Set();
    const s = data.summary || {};
    const searchTerm = reconState.sigintSearch.toLowerCase();
    const filteredSsids = (data.ssids || []).filter((ss) => {
        if (!searchTerm) return true;
        const haystack = [
            ss.ssid,
            ss.name_shape,
            ss.is_known ? 'known network' : 'unmatched',
            ss.known_context?.dominant_encryption,
            ss.known_context?.dominant_device_type,
            ...(ss.known_context?.sources || []),
        ].filter(Boolean).join(' ').toLowerCase();
        return haystack.includes(searchTerm);
    });
    const filteredClients = (data.clients || []).filter((cl) => {
        if (!searchTerm) return true;
        const haystack = [
            cl.client_mac,
            cl.vendor,
            cl.oui_prefix,
            ...(cl.ssids_probed || []),
            ...(cl.known_ssid_preview || []),
            ...(cl.unmatched_ssid_preview || []),
        ].filter(Boolean).join(' ').toLowerCase();
        return haystack.includes(searchTerm);
    });
    const hiddenCandidates = filteredSsids.filter((ss) => ss.ssid && !ss.is_known);

    let html = `<div class="recon-kpi-row">
        <div class="recon-kpi"><span class="recon-kpi-val">${s.total_probes || 0}</span><span class="recon-kpi-label">PROBES</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${s.unique_clients || 0}</span><span class="recon-kpi-label">CLIENTS</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${s.unique_ssids || 0}</span><span class="recon-kpi-label">SSIDs</span></div>
        <div class="recon-kpi"><span class="recon-kpi-val">${s.broadcast_probes || 0}</span><span class="recon-kpi-label">BROADCAST</span></div>
    </div>`;

    html += `<div class="recon-sigint-meta">${s.pcaps_scanned || 0} PCAPs scanned</div>`;
    html += `<div class="recon-section-note">${reconHintLabel('Probe Intelligence view', 'probe_intel_scope')}</div>`;
    html += `<div class="recon-surface-search"><input type="text" class="recon-search-input" id="sigint-search" placeholder="Search SSID / client / vendor…" value="${escapeHtml(reconState.sigintSearch)}"></div>`;
    html += `<div class="recon-intel-filters"><button class="recon-export-btn" id="sigint-export-btn" title="Export CSV"><i class="fa-solid fa-download"></i> EXPORT</button></div>`;

    if (hiddenCandidates.length) {
        html += `<div class="recon-section-title">${reconHintLabel('UNMATCHED TARGET SSIDs', 'unmatched_target_ssids')} <span class="recon-badge">${hiddenCandidates.length}</span></div>`;
        html += '<div class="recon-sigint-table-wrap"><table class="recon-sigint-table recon-sigint-table--dense">';
        html += `<thead><tr>
            <th>SSID</th>
            <th>${reconHintLabel('SHAPE', 'ssid_shape')}</th>
            <th>CLIENTS</th>
            <th>PROBES</th>
            <th>KNOWN CONTEXT</th>
        </tr></thead><tbody>`;
        for (const ss of hiddenCandidates.slice(0, 15)) {
            html += `<tr>
                <td class="recon-td-ssid">${escapeHtml(ss.ssid)}</td>
                <td>${renderShapeBadge(ss.name_shape)}</td>
                <td>${ss.client_count}</td>
                <td>${ss.probe_count}</td>
                <td>${renderKnownContext(ss.known_context)}</td>
            </tr>`;
        }
        html += '</tbody></table></div>';
    }

    if (filteredSsids.length) {
        html += `<div class="recon-section-title">${reconHintLabel('MOST PROBED SSIDs', 'most_probed_ssids')}</div>`;
        html += '<div class="recon-sigint-table-wrap"><table class="recon-sigint-table">';
        html += '<thead><tr><th>SSID</th><th>KNOWN</th><th>CONTEXT</th><th>SHAPE</th><th>CLIENTS</th><th>PROBES</th><th>RATE</th></tr></thead><tbody>';
        const topSsids = filteredSsids.slice(0, 20);
        for (const ss of topSsids) {
            const rate = ss.client_count > 0 ? (ss.probe_count / ss.client_count).toFixed(1) : '—';
            html += `<tr>
                <td class="recon-td-ssid">${escapeHtml(ss.ssid)}</td>
                <td>${renderKnownBadge(ss)}</td>
                <td>${renderKnownContext(ss.known_context)}</td>
                <td>${renderShapeBadge(ss.name_shape)}</td>
                <td>${ss.client_count}</td>
                <td>${ss.probe_count}</td>
                <td>${rate}</td>
            </tr>`;
        }
        html += '</tbody></table></div>';
    }

    if (filteredClients.length) {
        html += `<div class="recon-section-title">${reconHintLabel('TOP PROBING CLIENTS', 'top_probing_clients')}</div>`;
        html += '<div class="recon-sigint-table-wrap"><table class="recon-sigint-table">';
        html += '<thead><tr><th>CLIENT MAC</th><th>VENDOR / OUI</th><th>KNOWN VS UNMATCHED</th><th>SSIDs</th><th>PROBES</th><th>AVG SIG</th></tr></thead><tbody>';
        const topClients = filteredClients.slice(0, 20);
        for (const cl of topClients) {
            const sigStr = cl.avg_signal != null ? `${cl.avg_signal} dBm` : '—';
            let sigColor = '';
            if (cl.avg_signal != null) {
                if (cl.avg_signal >= -50) sigColor = '#22c55e';
                else if (cl.avg_signal >= -70) sigColor = '#e6b422';
                else sigColor = '#e63946';
            }
            const ssidChips = cl.ssids_probed.slice(0, 5).map((ssid) => {
                const known = knownSsids.has(ssid.toLowerCase());
                return `<span class="recon-sigint-ssid-chip${known ? ' recon-ssid-known' : ''}">${escapeHtml(ssid)}${known ? ' ✓' : ''}</span>`;
            }).join('');
            const hasMore = cl.ssids_probed.length > 5;
            const isExpanded = reconState.sigintExpanded.has(cl.client_mac);
            let moreHtml = '';
            if (hasMore && !isExpanded) {
                moreHtml = ` <button class="recon-expand-btn recon-expand-btn--inline" data-expand-client="${escapeHtml(cl.client_mac)}">+${cl.ssids_probed.length - 5}</button>`;
            }
            let expandedChips = '';
            if (isExpanded && hasMore) {
                expandedChips = cl.ssids_probed.slice(5).map((ssid) => {
                    const known = knownSsids.has(ssid.toLowerCase());
                    return `<span class="recon-sigint-ssid-chip${known ? ' recon-ssid-known' : ''}">${escapeHtml(ssid)}${known ? ' ✓' : ''}</span>`;
                }).join('');
                expandedChips += ` <button class="recon-expand-btn recon-expand-btn--inline" data-collapse-client="${escapeHtml(cl.client_mac)}">less</button>`;
            }

            let timelineHtml = '';
            if (isExpanded && cl.first_seen && cl.last_seen) {
                timelineHtml = `<tr class="recon-client-timeline-row"><td colspan="6"><div class="recon-client-timeline">
                    <span class="recon-tl-label">First: ${new Date(cl.first_seen * 1000).toLocaleString()}</span>
                    <span class="recon-tl-bar"></span>
                    <span class="recon-tl-label">Last: ${new Date(cl.last_seen * 1000).toLocaleString()}</span>
                    <span class="recon-tl-probes">${cl.probe_count} probes over ${Math.ceil((cl.last_seen - cl.first_seen) / 3600)} hrs</span>
                </div></td></tr>`;
            }

            html += `<tr class="recon-client-row" data-client="${escapeHtml(cl.client_mac)}">
                <td><span class="recon-sigint-mac">${escapeHtml(cl.client_mac)}</span></td>
                <td>${renderClientVendor(cl)}</td>
                <td>${renderClientMatchSummary(cl)}</td>
                <td>${ssidChips}${moreHtml}${expandedChips}</td>
                <td>${cl.probe_count}</td>
                <td${sigColor ? ` style="color:${sigColor};font-weight:700"` : ''}>${sigStr}</td>
            </tr>${timelineHtml}`;
        }
        html += '</tbody></table></div>';
    }

    if (!filteredSsids.length && !filteredClients.length) {
        html += `<div class="recon-empty">${searchTerm ? 'No Probe Intelligence rows matched the current search.' : 'No probe requests found in available PCAPs. This area is populated by Probe Intelligence, not Deep Analysis.'}</div>`;
    }

    html += `<div class="recon-section-title">${reconHintLabel('LIKELY DEVICE GROUPS', 'derandomization')} <span class="recon-badge recon-badge--dim">MAC de-randomization</span></div>`;
    html += '<div id="sigint-derandom" class="recon-derandom-wrap"><span class="recon-loading-sm">Loading…</span></div>';
    html += `<div class="recon-section-title">${reconHintLabel('PROBE GEO-CORRELATION', 'geocorrelation')}</div>`;
    html += '<div id="sigint-geocorr" class="recon-geocorr-wrap"><span class="recon-loading-sm">Loading…</span></div>';

    container.innerHTML = html;

    enableDynamicSectionCollapse(container, {
        titleSelector: '.recon-section-title',
        stateSet: reconState.sigintCollapsed,
        keyPrefix: 'sigint',
        dataAttr: 'sigint-section',
        rerender: () => { renderSigintData(deps, container, data, knownSsids); },
    });

    loadSigintExtensions();

    const searchInput = container.querySelector('#sigint-search');
    if (searchInput) {
        searchInput.addEventListener('input', debounce(() => {
            reconState.sigintSearch = searchInput.value;
            renderSigintData(deps, container, data, knownSsids);
        }, 200));
    }

    container.querySelectorAll('.recon-expand-btn').forEach((btn) => {
        if (btn.dataset.expandClient) {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                reconState.sigintExpanded.add(btn.dataset.expandClient);
                renderSigintData(deps, container, data, knownSsids);
            });
        }
        if (btn.dataset.collapseClient) {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                reconState.sigintExpanded.delete(btn.dataset.collapseClient);
                renderSigintData(deps, container, data, knownSsids);
            });
        }
    });

    const exportBtn = container.querySelector('#sigint-export-btn');
    if (exportBtn) {
        exportBtn.addEventListener('click', () => {
            const lines = ['Type,Name,Count,Extra'];
            if (data.ssids) {
                for (const ss of data.ssids) {
                    lines.push(`SSID,"${ss.ssid}",${ss.probe_count},${ss.client_count} clients`);
                }
            }
            if (data.clients) {
                for (const cl of data.clients) {
                    lines.push(`Client,"${cl.client_mac}",${cl.probe_count},"${cl.ssids_probed.join('; ')}"`);
                }
            }
            downloadFile('sigint_probes.csv', lines.join('\n'), 'text/csv');
        });
    }
}

export function createSigintRenderer(deps) {
    const {
        API,
        addProcess,
        log,
        escapeHtml,
        reconState,
        tdcGet,
        tdcSet,
        buildKnownReconSsidsFromState,
        bindSigintGeocorrelationActions,
        renderSigintGeocorrelationPanel,
    } = deps;

    async function loadSigintDerandomization() {
        const deWrap = document.getElementById('sigint-derandom');
        if (!deWrap) return;
        try {
            const dr = await API.getReconProbeDerandom();
            const groups = (dr && dr.groups) || [];
            if (!groups.length) {
                deWrap.innerHTML = '<span class="recon-muted">No likely device groups detected from shared probe fingerprints.</span>';
                return;
            }

            let h = '<div class="recon-derandom-grid">';
            for (const g of groups) {
                const badge = g.confidence === 'high' ? 'recon-mini-badge--pmkid' : '';
                const timeWindow = deps.formatSigintGeoWindow(g);
                const memberRows = (g.members || []).map((m) => `
                    <div class="recon-derandom-member">
                        <div class="recon-derandom-member-main">
                            <span class="recon-sigint-mac${m.is_random ? ' recon-random-mac' : ''}">${deps.escapeHtml(m.mac)}</span>
                            <span class="recon-sigint-match-pill${m.is_random ? ' recon-sigint-match-pill--warn' : ' recon-sigint-match-pill--known'}">${m.is_random ? 'Randomized' : 'Global'}</span>
                        </div>
                        <div class="recon-derandom-member-meta">
                            <span>${deps.escapeHtml(m.vendor || 'Unknown vendor')}</span>
                            <span>${m.probe_count || 0} probes</span>
                            <span>${m.avg_signal != null ? `${m.avg_signal} dBm` : 'No RSSI'}</span>
                        </div>
                    </div>
                `).join('');
                h += `<div class="recon-derandom-card">
                    <div class="recon-derandom-header">
                        <div>
                            <div class="recon-derandom-title">${deps.escapeHtml(g.group_label || 'Likely Device')}</div>
                            <div class="recon-derandom-summary">${deps.escapeHtml(g.rule_summary || 'Shared probe fingerprint detected.')}</div>
                        </div>
                        <div class="recon-derandom-badges">
                            <span class="recon-mini-badge ${badge}">${deps.escapeHtml(g.confidence)}</span>
                            <span class="recon-badge recon-badge--dim">${g.total_macs} MACs</span>
                        </div>
                    </div>
                    <div class="recon-derandom-window">${deps.escapeHtml(timeWindow)}</div>
                    <div class="recon-derandom-sub">Shared fingerprint</div>
                    <div class="recon-derandom-ssids">${(g.ssid_fingerprint || []).map((s) => `<span class="recon-chip">${deps.escapeHtml(s)}</span>`).join(' ')}</div>
                    <div class="recon-derandom-sub">Known matches</div>
                    <div class="recon-derandom-known">${g.known_ssid_count ? (g.known_ssid_preview || []).map((s) => `<span class="recon-chip recon-chip--geo">${deps.escapeHtml(s)}</span>`).join(' ') : '<span class="recon-muted">No known network matches in the current Recon dataset.</span>'}</div>
                    <div class="recon-derandom-sub">Observed MACs</div>
                    <div class="recon-derandom-members">${memberRows}</div>
                </div>`;
            }
            h += '</div>';
            deWrap.innerHTML = h;
        } catch (_e) {
            deWrap.innerHTML = '<span class="recon-muted">Error loading data</span>';
        }
    }

    async function loadSigintGeocorrelation() {
        const geoWrap = document.getElementById('sigint-geocorr');
        if (!geoWrap) return;
        try {
            const gc = await API.getReconProbeGeocorrelation();
            const clients = (gc && gc.clients) || [];
            geoWrap.innerHTML = renderSigintGeocorrelationPanel(gc || {});
            if (clients.length) {
                bindSigintGeocorrelationActions(geoWrap, clients);
            }
        } catch (_e) {
            geoWrap.innerHTML = '<span class="recon-muted">Error loading data</span>';
        }
    }

    async function loadSigintExtensions() {
        await Promise.all([
            loadSigintDerandomization(),
            loadSigintGeocorrelation(),
        ]);
    }

    async function renderSigint(container) {
        const knownSsids = buildKnownReconSsidsFromState();
        const cachedView = tdcGet('sigint:view');
        if (cachedView?.available) {
            renderSigintData({ ...deps, loadSigintExtensions }, container, cachedView, knownSsids);
            loadSigintExtensions();
        }

        const [status, jobsData] = await Promise.all([
            API.getReconProbeIntelStatus(),
            API.listJobs().catch(() => []),
        ]);

        const probeJob = Array.isArray(jobsData)
            ? jobsData.find((j) => {
                const type = String(j?.type || '').toLowerCase();
                const st = String(j?.status || '').toLowerCase();
                return type === 'probe_intel_scan' && (st === 'starting' || st === 'running');
            })
            : null;
        const probeJobRunning = !!probeJob;
        const probeJobPct = Number(probeJob?.progress_data?.percentage || 0);
        const pcapCount = status?.pcap_count || 0;

        if (status?.cached && !status?.stale && status?.result && !probeJobRunning) {
            const data = status.result;
            if (data.available) {
                tdcSet('sigint:view', data);
                renderSigintData({ ...deps, loadSigintExtensions }, container, data, knownSsids);
                return;
            }
        }

        let html = `<div class="recon-lazy-panel">
            <div class="recon-lazy-panel-row">
            <div class="recon-lazy-panel-left">
            <div class="recon-lazy-header">
                <div class="recon-lazy-icon"><i class="fa-solid fa-tower-broadcast"></i></div>
                <div>
                    <div class="recon-lazy-title">SIGINT — Probe Request Analysis</div>
                    <div class="recon-lazy-subtitle">Correlate probed SSIDs, client behavior and unmatched targets from probe traffic. This workflow is separate from Deep Analysis / Threat Analysis.</div>
                </div>
            </div>
            <div class="recon-lazy-info">${pcapCount} PCAP file${pcapCount !== 1 ? 's' : ''} available for processing</div>`;

        if (status?.cached && status?.stale) {
            html += '<div class="recon-stale-badge"><i class="fa-solid fa-triangle-exclamation"></i> Cached data is stale — new artifacts detected</div>';
        }

        if (pcapCount === 0 && !probeJobRunning) {
            html += `</div></div>
            <div class="recon-empty-state recon-empty-state--inline">
                <i class="fa-solid fa-folder-open"></i>
                <div>
                    <strong>No PCAP files found</strong>
                    <span>Add captures first to unlock Probe Intelligence. This workflow is separate from Deep Analysis.</span>
                </div>
            </div></div>`;
            container.innerHTML = html;
            return;
        }

        html += '</div><div class="recon-lazy-actions recon-lazy-actions--vcenter">';

        if (probeJobRunning) {
            html += `<button class="recon-process-btn" id="sigint-process-btn" disabled>
                <i class="fa-solid fa-spinner fa-spin"></i> PROCESSING…
            </button>
            <div class="recon-job-progress"><div class="recon-job-bar" style="width:${probeJobPct}%"></div><span>${probeJobPct}%</span></div>`;
        } else {
            html += `<button class="recon-process-btn" id="sigint-process-btn">
                <i class="fa-solid fa-play"></i> PROCESS ${pcapCount} PCAPs
            </button>`;
        }

        if (status?.cached && status?.stale && status?.result) {
            html += `<button class="recon-show-cached-btn" id="sigint-show-cached-btn">
                <i class="fa-solid fa-database"></i> Show cached results
            </button>`;
        }

        html += '</div></div></div>';
        container.innerHTML = html;

        const showCachedBtn = document.getElementById('sigint-show-cached-btn');
        if (showCachedBtn) {
            showCachedBtn.addEventListener('click', () => {
                renderSigintData({ ...deps, loadSigintExtensions }, container, status.result, knownSsids);
            });
        }

        const processBtn = document.getElementById('sigint-process-btn');
        if (!processBtn || processBtn.disabled) return;
        processBtn.addEventListener('click', async () => {
            processBtn.disabled = true;
            processBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Starting…';
            try {
                const currentJobs = await API.listJobs().catch(() => []);
                const running = Array.isArray(currentJobs)
                    ? currentJobs.find((j) => {
                        const type = String(j?.type || '').toLowerCase();
                        const st = String(j?.status || '').toLowerCase();
                        return type === 'probe_intel_scan' && (st === 'starting' || st === 'running');
                    })
                    : null;

                if (running) {
                    const pct = Number(running?.progress_data?.percentage || 0);
                    container.innerHTML = `<div class="recon-lazy-panel">
                        <div class="recon-lazy-icon"><i class="fa-solid fa-spinner fa-spin"></i></div>
                        <div class="recon-lazy-title">Probe analysis already running</div>
                        <div class="recon-lazy-subtitle">Using current background job instead of creating a duplicate.</div>
                        <div class="recon-lazy-info">Job ID: ${escapeHtml(String(running.id || '').slice(0, 8))}</div>
                        <div class="recon-job-progress"><div class="recon-job-bar" style="width:${pct}%"></div><span>${pct}%</span></div>
                    </div>`;
                    return;
                }

                const res = await API.startReconProbeIntelScan();
                if (res?.job_id) {
                    addProcess(res.job_id, 'PROBE INTEL', `Scanning ${res.pcap_count} PCAPs`, 'STARTING');
                    container.innerHTML = `<div class="recon-lazy-panel">
                        <div class="recon-lazy-icon"><i class="fa-solid fa-spinner fa-spin"></i></div>
                        <div class="recon-lazy-title">Processing probe intelligence</div>
                        <div class="recon-lazy-subtitle">The Probe Intelligence scan is running in the background and will enrich this SIGINT tab when completed.</div>
                        <div class="recon-lazy-info">Check the Process Panel for progress.</div>
                        <div class="recon-lazy-info recon-lazy-hint">Results will appear here when you revisit this tab after the job completes.</div>
                    </div>`;
                    log('recon', `Probe intel scan started (${res.pcap_count} PCAPs)`, 'info');
                } else {
                    container.innerHTML = '<div class="recon-empty">No PCAPs to process.</div>';
                }
            } catch (e) {
                processBtn.disabled = false;
                processBtn.innerHTML = '<i class="fa-solid fa-play"></i> PROCESS';
                log('recon', `Failed to start probe scan: ${e.message}`, 'error');
            }
        });
    }

    return {
        renderSigint,
        renderSigintData: (container, data, knownSsids) => renderSigintData({ ...deps, loadSigintExtensions }, container, data, knownSsids),
    };
}
