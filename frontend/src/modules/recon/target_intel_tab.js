export function createTargetIntelRenderer(deps) {
    const {
        API,
        log,
        escapeHtml,
        addProcess,
        reconHintLabel,
        reconState,
        tdcGet,
        tdcSet,
        tdcClear,
        detailCacheSet,
        rememberReconRows,
        downloadFile,
        formatTime,
        selectTarget,
    } = deps;

    function renderThreatPanel(threats) {
        if (!threats || !threats.available || !threats.summary) return '';
        const s = threats.summary;
        const totalFrames = (s.total_deauth || 0) + (s.total_disassoc || 0);
        if (totalFrames === 0) return '';

        let html = `<div class="recon-threat-panel">
            <div class="recon-section-title">THREAT ANALYSIS</div>
            <div class="recon-kpi-row">
                <div class="recon-kpi"><span class="recon-kpi-val recon-val-red">${s.total_deauth || 0}</span><span class="recon-kpi-label">DEAUTH</span></div>
                <div class="recon-kpi"><span class="recon-kpi-val recon-val-orange">${s.total_disassoc || 0}</span><span class="recon-kpi-label">DISASSOC</span></div>
                <div class="recon-kpi"><span class="recon-kpi-val">${s.targeted_bssids || 0}</span><span class="recon-kpi-label">BSSIDs</span></div>
                <div class="recon-kpi"><span class="recon-kpi-val${s.deauth_flood_detected ? ' recon-val-red' : ''}">${s.deauth_flood_detected ? 'YES' : 'NO'}</span><span class="recon-kpi-label">FLOOD</span></div>
            </div>`;
        const rows = threats.threats_by_bssid || [];
        if (rows.length) {
            html += `<div class="recon-threat-table-wrap"><table class="recon-threat-table">
                <thead><tr><th>BSSID</th><th>DEAUTH</th><th>DISASSOC</th><th>SOURCES</th><th>REASON</th><th></th></tr></thead><tbody>`;
            for (const t of rows.slice(0, 15)) {
                const topReason = t.top_reasons && t.top_reasons[0] ? escapeHtml(t.top_reasons[0].text) : '—';
                const floodBadge = t.flood_indicator ? '<span class="recon-flag recon-flag--critical">FLOOD</span>' : '';
                html += `<tr>
                    <td class="recon-threat-mac">${escapeHtml(t.bssid)}</td>
                    <td>${t.deauth_count}</td>
                    <td>${t.disassoc_count}</td>
                    <td>${t.unique_sources}</td>
                    <td>${topReason}</td>
                    <td>${floodBadge}</td>
                </tr>`;
            }
            html += '</tbody></table></div>';
        }
        html += `<div class="recon-threat-meta">${s.pcaps_scanned} PCAPs scanned</div></div>`;
        return html;
    }

    function showRowTooltip(_event, row) {
        let tip = document.getElementById('recon-row-tooltip');
        if (tip) tip.remove();
        tip = document.createElement('div');
        tip.id = 'recon-row-tooltip';
        tip.className = 'recon-tooltip';
        tip.innerHTML = `<div><strong>${escapeHtml(row.dataset.tipEnc)}</strong> · ${escapeHtml(row.dataset.tipDevice)}</div>
            <div>Score: ${row.dataset.tipScore} · ${escapeHtml(row.dataset.tipReadiness.replace(/_/g, ' '))}</div>
            ${row.dataset.tipSources ? `<div class="recon-tooltip-sources">Sources: ${escapeHtml(row.dataset.tipSources)}</div>` : ''}`;
        document.body.appendChild(tip);
        const rect = row.getBoundingClientRect();
        tip.style.top = `${rect.top - tip.offsetHeight - 4}px`;
        tip.style.left = `${rect.left + rect.width / 2 - tip.offsetWidth / 2}px`;
    }

    function startDeepPoll(container) {
        if (reconState.deepPollTimer) clearInterval(reconState.deepPollTimer);
        reconState.deepPollTimer = setInterval(async () => {
            try {
                const jobs = await API.listJobs().catch(() => []);
                const job = Array.isArray(jobs)
                    ? jobs.find((j) => {
                        const t = String(j?.type || '').toLowerCase();
                        const s = String(j?.status || '').toLowerCase();
                        return t === 'deep_analysis_scan' && (s === 'starting' || s === 'running');
                    })
                    : null;
                if (!job) {
                    clearInterval(reconState.deepPollTimer);
                    reconState.deepPollTimer = null;
                    tdcClear('intel');
                    renderTargetIntel(container);
                    return;
                }
                const pct = Number(job?.progress_data?.percentage || 0);
                const bar = container.querySelector('.recon-job-bar');
                const span = container.querySelector('.recon-job-progress span');
                if (bar) bar.style.width = pct + '%';
                if (span) span.textContent = pct + '%';
            } catch (_) {
                /* silent */
            }
        }, 4000);
    }

    async function renderTargetIntel(container, { preloadedData = null, preloadedMeta = null } = {}) {
        if (reconState.deepPollTimer) {
            clearInterval(reconState.deepPollTimer);
            reconState.deepPollTimer = null;
        }
        const { col, dir } = reconState.intelSort;
        const { encryption, stage, severity } = reconState.intelFilter;
        const { offset, limit } = reconState.intelPage;

        const cacheKey = `intel:${col}:${dir}:${encryption}:${stage}:${severity}:${offset}:${limit}`;
        const cached = preloadedData ? { data: preloadedData } : tdcGet(cacheKey);
        let data = preloadedData;
        if (cached && !data) {
            ({ data } = cached);
        } else if (!data) {
            data = await API.getReconVulnerabilityMatrix({ sort_by: col, sort_dir: dir, encryption, stage, limit, offset });
            tdcSet(cacheKey, { data });
        }
        rememberReconRows(data?.rows);

        let deepStatus = preloadedMeta?.deepStatus || null;
        let jobsData = preloadedMeta?.jobsData || [];
        const metaPending = Boolean(cached && !preloadedMeta);
        if (!metaPending && !preloadedMeta) {
            [deepStatus, jobsData] = await Promise.all([
                API.getReconDeepAnalysisStatus().catch(() => null),
                API.listJobs().catch(() => []),
            ]);
        }

        const deepJob = Array.isArray(jobsData)
            ? jobsData.find((j) => {
                const type = String(j?.type || '').toLowerCase();
                const status = String(j?.status || '').toLowerCase();
                return type === 'deep_analysis_scan' && (status === 'starting' || status === 'running');
            })
            : null;
        const deepJobRunning = !!deepJob;
        const deepJobPct = Number(deepJob?.progress_data?.percentage || 0);
        if (!data || !data.rows) {
            container.innerHTML = '<div class="recon-empty">No data available.</div>';
            return;
        }

        if (metaPending) {
            const pendingCacheKey = cacheKey;
            Promise.all([
                API.getReconDeepAnalysisStatus().catch(() => null),
                API.listJobs().catch(() => []),
            ]).then(([nextDeepStatus, nextJobsData]) => {
                if (!container?.isConnected) return;
                const currentCacheKey = `intel:${reconState.intelSort.col}:${reconState.intelSort.dir}:${reconState.intelFilter.encryption}:${reconState.intelFilter.stage}:${reconState.intelFilter.severity}:${reconState.intelPage.offset}:${reconState.intelPage.limit}`;
                if (currentCacheKey !== pendingCacheKey) return;
                renderTargetIntel(container, {
                    preloadedData: data,
                    preloadedMeta: { deepStatus: nextDeepStatus, jobsData: nextJobsData },
                });
            }).catch(() => {
                /* ignore background threat-status refresh failures */
            });
        }

        const allRows = data.rows;
        const totalTargets = data.total;
        const avgScore = allRows.length ? Math.round(allRows.reduce((s, r) => s + (r.attack_score || 0), 0) / allRows.length) : 0;
        const withHash = allRows.filter((r) => r.has_pmkid || r.has_eapol_hash).length;
        const cracked = allRows.filter((r) => r.has_password).length;
        const critFlags = allRows.reduce((n, r) => n + (r.flags || []).filter((f) => f.severity === 'critical').length, 0);

        let html = `<div class="recon-kpi-row">
            <div class="recon-kpi"><span class="recon-kpi-val">${totalTargets}</span><span class="recon-kpi-label">TARGETS</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${avgScore}</span><span class="recon-kpi-label">${reconHintLabel('AVG SCORE', 'avg_score')}</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${withHash}</span><span class="recon-kpi-label">WITH HASH</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val recon-val-green">${cracked}</span><span class="recon-kpi-label">CRACKED</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val ${critFlags > 0 ? 'recon-val-red' : ''}">${critFlags}</span><span class="recon-kpi-label">CRITICAL FLAGS</span></div>
        </div>`;

        const hasCached = deepStatus?.cached && deepStatus?.result;
        const isStale = deepStatus?.stale;
        const pcapCount = deepStatus?.pcap_count || 0;

        if (metaPending) {
            html += `<div class="recon-lazy-panel recon-lazy-panel--inline" id="deep-analysis-lazy">
                <div class="recon-lazy-panel-row">
                    <div class="recon-lazy-panel-left">
                        <div class="recon-lazy-header">
                            <div class="recon-lazy-icon"><i class="fa-solid fa-spinner fa-spin"></i></div>
                            <div>
                                <div class="recon-lazy-title">THREAT ANALYSIS</div>
                                <div class="recon-lazy-subtitle">Refreshing cached threat-analysis state in the background.</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>`;
        } else if (hasCached && !isStale && !deepJobRunning) {
            html += renderThreatPanel(deepStatus.result);
        } else {
            html += `<div class="recon-lazy-panel recon-lazy-panel--inline" id="deep-analysis-lazy">
                <div class="recon-lazy-panel-row">
                <div class="recon-lazy-panel-left">
                <div class="recon-lazy-header">
                    <div class="recon-lazy-icon"><i class="fa-solid fa-satellite-dish"></i></div>
                    <div>
                        <div class="recon-lazy-title">THREAT ANALYSIS</div>
                        <div class="recon-lazy-subtitle">Inspect deauth, disassoc and flood activity extracted from PCAP artifacts.</div>
                    </div>
                </div>`;
            if (hasCached && isStale) {
                html += `<div class="recon-stale-badge"><i class="fa-solid fa-triangle-exclamation"></i> Cached data is stale — new artifacts detected</div>`;
            }
            if (deepJobRunning) {
                html += `<div class="recon-lazy-info">Background job in progress${deepJob?.id ? ` (ID ${escapeHtml(String(deepJob.id).slice(0, 8))})` : ''}.</div>
                    <div class="recon-job-progress"><div class="recon-job-bar" style="width:${deepJobPct}%"></div><span>${deepJobPct}%</span></div>`;
                if (hasCached) {
                    html += `<div class="recon-lazy-info recon-lazy-hint">Latest cached result is available and will refresh automatically when the scan completes.</div>`;
                }
                html += `</div><div class="recon-lazy-actions recon-lazy-actions--vcenter">`;
                if (hasCached) {
                    html += `<button class="recon-show-cached-btn recon-show-cached-btn--sm" id="deep-analysis-show-cached-btn">
                            <i class="fa-solid fa-database"></i> Show cached
                        </button>`;
                }
                html += `</div></div>`;
            } else if (pcapCount > 0) {
                html += `<div class="recon-lazy-info">${pcapCount} PCAPs available for threat analysis</div>
                </div>
                <div class="recon-lazy-actions recon-lazy-actions--vcenter">
                    <button class="recon-process-btn recon-process-btn--sm" id="deep-analysis-process-btn">
                        <i class="fa-solid fa-play"></i> ANALYZE THREATS
                    </button>`;
                if (hasCached && isStale) {
                    html += `<button class="recon-show-cached-btn recon-show-cached-btn--sm" id="deep-analysis-show-cached-btn">
                        <i class="fa-solid fa-database"></i> Show cached
                    </button>`;
                }
                html += `</div></div>`;
            } else {
                html += `</div></div>`;
                html += `<div class="recon-empty-state recon-empty-state--inline">
                    <i class="fa-solid fa-circle-info"></i>
                    <div>
                        <strong>No PCAPs for threat analysis</strong>
                        <span>Import or generate captures first to enable this stage.</span>
                    </div>
                </div>`;
            }
            html += `</div>`;
        }

        const sevFilter = reconState.intelFilter.severity;
        html += `<div class="recon-severity-filter">
            <span class="recon-severity-chip recon-flag--critical${sevFilter === 'critical' ? ' active' : ''}" data-severity="critical">CRITICAL</span>
            <span class="recon-severity-chip recon-flag--warning${sevFilter === 'warning' ? ' active' : ''}" data-severity="warning">WARNING</span>
            <span class="recon-severity-chip recon-flag--good${sevFilter === 'good' ? ' active' : ''}" data-severity="good">GOOD</span>
            <span class="recon-severity-chip recon-flag--info${sevFilter === 'info' ? ' active' : ''}" data-severity="info">INFO</span>
        </div>`;

        if (data.rows.length > 0) {
            const buckets = new Array(10).fill(0);
            for (const r of data.rows) {
                const idx = Math.min(Math.floor(r.attack_score / 10), 9);
                buckets[idx]++;
            }
            const maxB = Math.max(...buckets, 1);
            html += '<div class="recon-score-dist">';
            html += '<div class="recon-score-dist-title">SCORE DISTRIBUTION</div>';
            html += '<div class="recon-score-dist-chart">';
            for (let i = 0; i < 10; i++) {
                const pct = Math.round((buckets[i] / maxB) * 100);
                const cls = i >= 7 ? 'score-high' : i >= 4 ? 'score-mid' : 'score-low';
                html += `<div class="recon-score-dist-bar" title="${i * 10}-${i * 10 + 9}: ${buckets[i]}">
                    <div class="recon-score-dist-fill ${cls}" style="height:${pct}%"></div>
                    <span class="recon-score-dist-label">${i * 10}</span>
                </div>`;
            }
            html += '</div></div>';
        }

        html += `<div class="recon-intel-filters">
            <select class="recon-filter-select" id="intel-filter-enc">
                <option value="all"${encryption === 'all' ? ' selected' : ''}>All Encryption</option>
                <option value="WPA2"${encryption === 'WPA2' ? ' selected' : ''}>WPA2</option>
                <option value="WPA3"${encryption === 'WPA3' ? ' selected' : ''}>WPA3</option>
                <option value="WPA"${encryption === 'WPA' ? ' selected' : ''}>WPA</option>
                <option value="WEP"${encryption === 'WEP' ? ' selected' : ''}>WEP</option>
                <option value="OPN"${encryption === 'OPN' ? ' selected' : ''}>OPN</option>
            </select>
            <select class="recon-filter-select" id="intel-filter-stage">
                <option value="all"${stage === 'all' ? ' selected' : ''}>All Stages</option>
                <option value="discovered"${stage === 'discovered' ? ' selected' : ''}>Discovered</option>
                <option value="captured"${stage === 'captured' ? ' selected' : ''}>Captured</option>
                <option value="fingerprinted"${stage === 'fingerprinted' ? ' selected' : ''}>Fingerprinted</option>
                <option value="hash_ready"${stage === 'hash_ready' ? ' selected' : ''}>Hash Ready</option>
                <option value="under_attack"${stage === 'under_attack' ? ' selected' : ''}>Under Attack</option>
                <option value="cracked"${stage === 'cracked' ? ' selected' : ''}>Cracked</option>
            </select>
            <button class="recon-export-btn" id="intel-export-btn" title="Export CSV"><i class="fa-solid fa-download"></i> EXPORT</button>
        </div>`;

        const sortArrow = (c) => col === c ? (dir === 'asc' ? ' ▲' : ' ▼') : '';
        const threatMap = {};
        if (hasCached && deepStatus?.result?.threats_by_bssid) {
            for (const t of deepStatus.result.threats_by_bssid) {
                threatMap[t.bssid?.toLowerCase()] = t;
            }
        }

        html += `<div class="recon-vuln-table-wrap"><table class="recon-vuln-table">
            <thead><tr>
                <th class="recon-th-compare" title="Select to compare">⇔</th>
                <th class="recon-th-sortable" data-sort="ssid">SSID${sortArrow('ssid')}</th>
                <th class="recon-th-sortable" data-sort="encryption">ENC${sortArrow('encryption')}</th>
                <th class="recon-th-sortable" data-sort="stage">STAGE${sortArrow('stage')}</th>
                <th class="recon-th-sortable" data-sort="attack_score">SCORE${sortArrow('attack_score')}</th>
                <th>SEC</th>
                <th>FLAGS</th>
            </tr></thead><tbody>`;

        for (const row of data.rows) {
            const allFlags = [...(row.flags || [])];
            const threatInfo = threatMap[row.mac?.toLowerCase()];
            if (threatInfo) {
                const deauthCount = threatInfo.deauth_count || 0;
                allFlags.push({ severity: 'critical', label: `DEAUTH:${deauthCount}`, description: `Active deauth: ${deauthCount} frames` });
            }

            if (severity !== 'all' && !allFlags.some((f) => f.severity === severity)) continue;

            const maxVisible = 4;
            const visible = allFlags.slice(0, maxVisible);
            const overflow = allFlags.length - maxVisible;
            let flagsHtml = visible.map((f) => {
                const cls = `recon-flag recon-flag--${escapeHtml(f.severity)}`;
                return `<span class="${cls}" title="${escapeHtml(f.description)}">${escapeHtml(f.label)}</span>`;
            }).join('');
            if (overflow > 0) {
                const hiddenTitles = allFlags.slice(maxVisible).map((f) => f.label).join(', ');
                flagsHtml += ` <span class="recon-flag recon-flag--overflow" title="${escapeHtml(hiddenTitles)}">+${overflow}</span>`;
            }

            const scoreClass = row.attack_score >= 70 ? 'score-high' : row.attack_score >= 40 ? 'score-mid' : 'score-low';
            const isCompare = reconState.intelCompare.includes(row.mac);
            const compareIndex = isCompare ? reconState.intelCompare.indexOf(row.mac) + 1 : 0;
            const selectedChip = isCompare ? `<span class="recon-selected-chip">SELECTED ${compareIndex}</span>` : '';
            const rowClass = isCompare ? 'recon-vuln-row recon-vuln-row--selected' : 'recon-vuln-row';
            const srcBadge = (row.sources || []).map((s) => escapeHtml(s)).join(', ');

            html += `<tr class="${rowClass}" data-mac="${escapeHtml(row.mac)}"
                data-tip-enc="${escapeHtml(row.encryption)}" data-tip-device="${escapeHtml(row.device_type || 'unknown')}"
                data-tip-sources="${escapeHtml(srcBadge)}" data-tip-score="${row.attack_score}"
                data-tip-readiness="${escapeHtml(row.readiness_status || '')}">
                <td><input type="checkbox" class="recon-compare-check" data-mac="${escapeHtml(row.mac)}" ${isCompare ? 'checked' : ''} title="Compare"></td>
                <td class="recon-td-ssid">${escapeHtml(row.ssid || row.mac)} ${selectedChip}</td>
                <td>${escapeHtml(row.encryption)}</td>
                <td><span class="recon-stage-tag recon-stage-tag--${escapeHtml(row.stage)}">${escapeHtml(row.stage.replace(/_/g, ' '))}</span></td>
                <td><span class="recon-score ${scoreClass}">${row.attack_score}</span></td>
                <td class="recon-td-sec">${(row.akm && row.akm.length) ? escapeHtml(row.akm.slice(0, 2).join(', ')) : '—'}</td>
                <td>${flagsHtml}</td>
            </tr>`;
        }

        html += '</tbody></table></div>';

        const totalPages = Math.ceil(data.total / limit);
        const currentPage = Math.floor(offset / limit) + 1;
        const pageSizes = [25, 50, 100, 200];
        const pageSizeOptions = pageSizes.map((s) => `<option value="${s}"${s === limit ? ' selected' : ''}>${s}</option>`).join('');
        html += `<div class="recon-pagination-bar">
            <button class="recon-page-btn" id="intel-prev" ${offset === 0 ? 'disabled' : ''}>← Prev</button>
            <span class="recon-page-info">Page ${currentPage} of ${totalPages} (${data.total} total)</span>
            <button class="recon-page-btn" id="intel-next" ${offset + limit >= data.total ? 'disabled' : ''}>Next →</button>
            <select class="recon-page-size" id="intel-page-size" title="Rows per page">${pageSizeOptions}</select>
        </div>`;

        if (reconState.intelCompare.length === 1) {
            html += '<div class="recon-compare-hint">Select up to 3 more targets to compare in Target Details.</div>';
        } else if (reconState.intelCompare.length >= 2 && reconState.intelCompare.length < 4) {
            html += `<div class="recon-compare-hint">${reconState.intelCompare.length} selected. Comparison is shown in Target Details. (max 4)</div>`;
        } else if (reconState.intelCompare.length === 4) {
            html += '<div class="recon-compare-hint">4 targets selected — comparison is shown in Target Details.</div>';
        }

        container.innerHTML = html;

        container.querySelectorAll('.recon-vuln-row').forEach((row) => {
            row.addEventListener('click', (e) => {
                if (e.target.classList.contains('recon-compare-check')) return;
                const mac = row.dataset.mac;
                if (!reconState.intelCompare.includes(mac)) {
                    if (reconState.intelCompare.length >= 4) reconState.intelCompare.shift();
                    reconState.intelCompare.push(mac);
                }
                reconState.intelDetailMac = mac;
                renderTargetIntel(container);
                selectTarget(mac);
            });
            row.addEventListener('mouseenter', (e) => {
                showRowTooltip(e, row);
            });
            row.addEventListener('mouseleave', () => {
                const tip = document.getElementById('recon-row-tooltip');
                if (tip) tip.remove();
            });
        });

        container.querySelectorAll('.recon-compare-check').forEach((cb) => {
            cb.addEventListener('change', () => {
                const mac = cb.dataset.mac;
                if (cb.checked) {
                    if (!reconState.intelCompare.includes(mac)) {
                        if (reconState.intelCompare.length >= 4) reconState.intelCompare.shift();
                        reconState.intelCompare.push(mac);
                    }
                    reconState.intelDetailMac = mac;
                } else {
                    reconState.intelCompare = reconState.intelCompare.filter((m) => m !== mac);
                    if (reconState.intelDetailMac === mac) {
                        reconState.intelDetailMac = reconState.intelCompare[reconState.intelCompare.length - 1] || null;
                    }
                }
                renderTargetIntel(container);
                const nextMac = reconState.intelDetailMac || reconState.intelCompare[reconState.intelCompare.length - 1];
                if (nextMac) {
                    selectTarget(nextMac);
                } else {
                    const detailPanel = document.getElementById('recon-drawer-content') || document.getElementById('recon-right-content');
                    if (detailPanel) {
                        detailPanel.innerHTML = '<div class="recon-empty">Select one or two Intel rows to populate Target Details.</div>';
                    }
                    const drawer = document.getElementById('recon-drawer');
                    if (drawer) drawer.classList.add('recon-drawer--hidden');
                }
            });
        });

        container.querySelectorAll('.recon-th-sortable').forEach((th) => {
            th.style.cursor = 'pointer';
            th.addEventListener('click', () => {
                const c = th.dataset.sort;
                if (reconState.intelSort.col === c) {
                    reconState.intelSort.dir = reconState.intelSort.dir === 'asc' ? 'desc' : 'asc';
                } else {
                    reconState.intelSort.col = c;
                    reconState.intelSort.dir = 'desc';
                }
                reconState.intelPage.offset = 0;
                renderTargetIntel(container);
            });
        });

        const encFilter = container.querySelector('#intel-filter-enc');
        const stageFilter = container.querySelector('#intel-filter-stage');
        if (encFilter) {
            encFilter.addEventListener('change', () => {
                reconState.intelFilter.encryption = encFilter.value;
                reconState.intelPage.offset = 0;
                renderTargetIntel(container);
            });
        }
        if (stageFilter) {
            stageFilter.addEventListener('change', () => {
                reconState.intelFilter.stage = stageFilter.value;
                reconState.intelPage.offset = 0;
                renderTargetIntel(container);
            });
        }

        const prevBtn = container.querySelector('#intel-prev');
        const nextBtn = container.querySelector('#intel-next');
        if (prevBtn) {
            prevBtn.addEventListener('click', () => {
                reconState.intelPage.offset = Math.max(0, offset - limit);
                renderTargetIntel(container);
            });
        }
        if (nextBtn) {
            nextBtn.addEventListener('click', () => {
                reconState.intelPage.offset = offset + limit;
                renderTargetIntel(container);
            });
        }

        const pageSizeSelect = container.querySelector('#intel-page-size');
        if (pageSizeSelect) {
            pageSizeSelect.addEventListener('change', () => {
                reconState.intelPage.limit = parseInt(pageSizeSelect.value, 10);
                reconState.intelPage.offset = 0;
                renderTargetIntel(container);
            });
        }

        container.querySelectorAll('.recon-severity-chip').forEach((chip) => {
            chip.addEventListener('click', () => {
                const sev = chip.dataset.severity;
                reconState.intelFilter.severity = (reconState.intelFilter.severity === sev) ? 'all' : sev;
                reconState.intelPage.offset = 0;
                renderTargetIntel(container);
            });
        });

        const exportBtn = container.querySelector('#intel-export-btn');
        if (exportBtn) {
            exportBtn.addEventListener('click', async () => {
                try {
                    const allData = await API.getReconVulnerabilityMatrix({ limit: 10000 });
                    if (!allData || !allData.rows) return;
                    const csvLines = ['SSID,MAC,Encryption,Stage,Score,Readiness,Device,Sources,Flags'];
                    for (const r of allData.rows) {
                        const flags = (r.flags || []).map((f) => f.label).join('; ');
                        const sources = (r.sources || []).join('; ');
                        csvLines.push([r.ssid, r.mac, r.encryption, r.stage, r.attack_score, r.readiness_status, r.device_type, sources, flags].map((v) => `"${String(v || '').replace(/"/g, '""')}"`).join(','));
                    }
                    downloadFile('vuln_matrix.csv', csvLines.join('\n'), 'text/csv');
                } catch (e) {
                    log('recon', `Export failed: ${e.message}`, 'error');
                }
            });
        }

        const showCachedBtn = document.getElementById('deep-analysis-show-cached-btn');
        if (showCachedBtn) {
            showCachedBtn.addEventListener('click', () => {
                const lazyPanel = document.getElementById('deep-analysis-lazy');
                if (lazyPanel) {
                    lazyPanel.outerHTML = renderThreatPanel(deepStatus.result);
                }
            });
        }

        const processBtn = document.getElementById('deep-analysis-process-btn');
        if (processBtn) {
            processBtn.addEventListener('click', async () => {
                processBtn.disabled = true;
                processBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Starting…';
                try {
                    const currentJobs = await API.listJobs().catch(() => []);
                    const running = Array.isArray(currentJobs)
                        ? currentJobs.find((j) => {
                            const type = String(j?.type || '').toLowerCase();
                            const status = String(j?.status || '').toLowerCase();
                            return type === 'deep_analysis_scan' && (status === 'starting' || status === 'running');
                        })
                        : null;
                    if (running) {
                        const lazyPanel = document.getElementById('deep-analysis-lazy');
                        if (lazyPanel) {
                            const pct = Number(running?.progress_data?.percentage || 0);
                            lazyPanel.innerHTML = `<div class="recon-lazy-header">
                                    <div class="recon-lazy-icon"><i class="fa-solid fa-spinner fa-spin"></i></div>
                                    <div>
                                        <div class="recon-lazy-title">THREAT ANALYSIS ALREADY RUNNING</div>
                                        <div class="recon-lazy-subtitle">Using active job status instead of starting a duplicate scan.</div>
                                    </div>
                                </div>
                                <div class="recon-lazy-info">Job ID: ${escapeHtml(String(running.id || '').slice(0, 8))}</div>
                                <div class="recon-job-progress"><div class="recon-job-bar" style="width:${pct}%"></div><span>${pct}%</span></div>`;
                        }
                        startDeepPoll(container);
                        return;
                    }

                    const res = await API.startReconDeepAnalysisScan();
                    if (res?.job_id) {
                        addProcess(res.job_id, 'DEEP ANALYSIS', `Scanning ${res.pcap_count} PCAPs`, 'STARTING');
                        const lazyPanel = document.getElementById('deep-analysis-lazy');
                        if (lazyPanel) {
                            lazyPanel.innerHTML = `<div class="recon-lazy-header">
                                    <div class="recon-lazy-icon"><i class="fa-solid fa-spinner fa-spin"></i></div>
                                    <div>
                                        <div class="recon-lazy-title">THREAT ANALYSIS RUNNING</div>
                                        <div class="recon-lazy-subtitle">Deep analysis was queued in the background.</div>
                                    </div>
                                </div>
                                <div class="recon-lazy-info">Job ID: ${escapeHtml(String(res.job_id).slice(0, 8))}</div>
                                <div class="recon-job-progress"><div class="recon-job-bar" style="width:0%"></div><span>0%</span></div>`;
                        }
                        startDeepPoll(container);
                        log('recon', `Deep analysis scan started (${res.pcap_count} PCAPs)`, 'info');
                    }
                } catch (e) {
                    processBtn.disabled = false;
                    processBtn.innerHTML = '<i class="fa-solid fa-play"></i> ANALYZE THREATS';
                    log('recon', `Failed to start deep analysis: ${e.message}`, 'error');
                }
            });
        }

        if (deepJobRunning) startDeepPoll(container);
    }

    return {
        renderTargetIntel,
    };
}
