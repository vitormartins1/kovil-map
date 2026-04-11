const JOB_TYPE_META = {
    deep_analysis_scan: { label: 'Threat Analysis', origin: 'INTEL', icon: 'fa-satellite-dish', desc: 'Scanning PCAPs for deauth, disassoc & flood patterns' },
    probe_intel_scan: { label: 'Probe Intelligence', origin: 'SIGINT', icon: 'fa-satellite-dish', desc: 'Extracting probe-request intelligence from PCAPs' },
    cracking: { label: 'Password Cracking', origin: 'OPS', icon: 'fa-key', desc: null },
    aircrack: { label: 'Aircrack-ng Attack', origin: 'OPS', icon: 'fa-unlock', desc: null },
    hashcat: { label: 'Hashcat Attack', origin: 'OPS', icon: 'fa-microchip', desc: null },
    conversion_multi: { label: 'Format Conversion', origin: 'OPS', icon: 'fa-shuffle', desc: 'Converting capture files between formats' },
    fingerprint_scan: { label: 'Device Fingerprinting', origin: 'COMMS', icon: 'fa-fingerprint', desc: 'Scanning PCAPs for device signatures' },
    rawsniffer_ingest: { label: 'PCAP Ingest', origin: 'OPS', icon: 'fa-file-import', desc: 'Importing raw sniffer captures' },
};

export function createOperationsRenderer(deps) {
    const {
        STATE,
        saveLists,
        API,
        log,
        escapeHtml,
        openCrackingPanel,
        reconState,
        reconHintLabel,
        tdcGet,
        tdcSet,
        tdcClear,
        detailCacheSet,
        enableDynamicSectionCollapse,
        formatSize,
        formatRelativeTime,
        formatTime,
    } = deps;

    function renderOpsJobCard(job) {
        const pct = Number(job.progress_data?.percentage || 0);
        const meta = JOB_TYPE_META[job.type] || null;
        const label = meta?.label || (job.type || 'unknown').replace(/_/g, ' ').toUpperCase();
        const origin = meta?.origin || '';
        const icon = meta?.icon || 'fa-gear';
        const steps = job.progress_data || {};
        const stepInfo = steps.total_steps > 1 ? `Step ${steps.current_step || 0}/${steps.total_steps}` : '';
        const pcapCount = job.meta?.pcaps?.length;
        const desc = meta?.desc
            ? meta.desc + (pcapCount ? ` (${pcapCount} PCAPs)` : '')
            : (Array.isArray(job.command) ? job.command.join(' ') : String(job.command || '')).slice(0, 80);

        return `<div class="recon-job-card" data-ops-job="${escapeHtml(job.id)}">
            <div class="recon-job-header">
                <i class="fa-solid ${icon}" style="color:#2faad4;font-size:0.6rem"></i>
                <span class="recon-job-type">${escapeHtml(label)}</span>
                ${origin ? `<span class="recon-job-origin">${escapeHtml(origin)}</span>` : ''}
                <span class="recon-job-id">${escapeHtml(job.id || '').slice(0, 8)}</span>
            </div>
            <div class="recon-job-desc" title="${escapeHtml(desc)}">${escapeHtml(desc)}${stepInfo ? ` — ${escapeHtml(stepInfo)}` : ''}</div>
            <div class="recon-job-progress"><div class="recon-job-bar" style="width:${pct}%"></div><span>${pct}%</span></div>
            <button class="recon-job-cancel-btn" data-job-id="${escapeHtml(job.id)}"><i class="fa-solid fa-stop"></i> Cancel</button>
        </div>`;
    }

    function startOpsPoll(container) {
        if (reconState.opsPollTimer) clearInterval(reconState.opsPollTimer);
        reconState.opsPollTimer = setInterval(async () => {
            try {
                const jobs = await API.listJobs().catch(() => []);
                const active = Array.isArray(jobs)
                    ? jobs.filter((j) => j.status === 'running' || j.status === 'starting')
                    : [];
                if (active.length === 0) {
                    clearInterval(reconState.opsPollTimer);
                    reconState.opsPollTimer = null;
                    tdcClear('ops');
                    renderOperations(container);
                    return;
                }
                const wrap = container.querySelector('#ops-active-jobs');
                if (!wrap) return;
                for (const job of active) {
                    const card = wrap.querySelector(`[data-ops-job="${job.id}"]`);
                    if (card) {
                        const pct = Number(job.progress_data?.percentage || 0);
                        const bar = card.querySelector('.recon-job-bar');
                        const span = card.querySelector('.recon-job-progress span');
                        if (bar) bar.style.width = pct + '%';
                        if (span) span.textContent = pct + '%';
                        const steps = job.progress_data || {};
                        if (steps.total_steps > 1) {
                            const stepInfo = `Step ${steps.current_step || 0}/${steps.total_steps}`;
                            const descEl = card.querySelector('.recon-job-desc');
                            if (descEl) {
                                const base = descEl.textContent.split(' — ')[0];
                                descEl.textContent = `${base} — ${stepInfo}`;
                            }
                        }
                    } else {
                        wrap.insertAdjacentHTML('beforeend', renderOpsJobCard(job));
                    }
                }
            } catch (_) {
                /* silent */
            }
        }, 4000);
    }

    async function renderOperations(container) {
        if (reconState.opsPollTimer) {
            clearInterval(reconState.opsPollTimer);
            reconState.opsPollTimer = null;
        }
        const period = reconState.opsPeriod;
        const cacheKey = `ops:${period}`;
        let data;
        let jobsData;
        let pmkData;
        const cached = tdcGet(cacheKey);
        if (cached) {
            ({ data, jobsData, pmkData } = cached);
        } else {
            [data, jobsData, pmkData] = await Promise.all([
                API.getReconAttackEffectiveness({ period }),
                API.listJobs().catch(() => []),
                API.listPmkDatabases().catch(() => null),
            ]);
            tdcSet(cacheKey, { data, jobsData, pmkData });
        }
        if (period === 'all' && data) detailCacheSet('attack-history:all', data);
        if (!data) {
            container.innerHTML = '<div class="recon-empty">No attack data available.</div>';
            return;
        }

        let html = `<div class="recon-kpi-row">
            <div class="recon-kpi"><span class="recon-kpi-val">${data.total_attacks}</span><span class="recon-kpi-label">ATTACKS</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val recon-val-green">${data.total_cracked}</span><span class="recon-kpi-label">CRACKED</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${data.success_rate}%</span><span class="recon-kpi-label">${reconHintLabel('SUCCESS', 'success_rate')}</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${data.avg_crack_time_seconds != null ? formatTime(data.avg_crack_time_seconds) : '—'}</span><span class="recon-kpi-label">${reconHintLabel('AVG TIME', 'avg_time')}</span></div>
        </div>`;

        html += `<div class="recon-ops-filters">
            <select class="recon-filter-select" id="ops-period-filter">
                <option value="all"${period === 'all' ? ' selected' : ''}>All Time</option>
                <option value="24h"${period === '24h' ? ' selected' : ''}>Last 24h</option>
                <option value="7d"${period === '7d' ? ' selected' : ''}>Last 7 Days</option>
                <option value="30d"${period === '30d' ? ' selected' : ''}>Last 30 Days</option>
            </select>
        </div>`;

        const activeJobs = Array.isArray(jobsData)
            ? jobsData.filter((j) => j.status === 'running' || j.status === 'starting')
            : [];
        if (activeJobs.length > 0) {
            html += '<div class="recon-section-title">ACTIVE OPERATIONS</div>';
            html += '<div class="recon-active-jobs" id="ops-active-jobs">';
            for (const job of activeJobs) {
                html += renderOpsJobCard(job);
            }
            html += '</div>';
        }

        if (data.by_mode && data.by_mode.length) {
            html += '<div class="recon-section-title">ATTACK MODES</div>';
            html += '<div class="recon-bars">';
            const maxAttempts = Math.max(...data.by_mode.map((m) => m.attempts), 1);
            for (const m of data.by_mode) {
                const pct = Math.round((m.attempts / maxAttempts) * 100);
                const successPct = m.attempts ? Math.round((m.cracked / m.attempts) * 100) : 0;
                const avgTimeStr = m.avg_time != null ? `, avg ${formatTime(m.avg_time)}` : '';
                const tipText = `${m.mode.toUpperCase()}: ${m.attempts} attempts, ${m.cracked} cracked, ${m.exhausted || 0} exhausted, ${m.failed || 0} failed${avgTimeStr}`;
                html += `<div class="recon-bar-row" title="${escapeHtml(tipText)}">
                    <span class="recon-bar-label">${escapeHtml(m.mode.toUpperCase())}</span>
                    <div class="recon-bar-track">
                        <div class="recon-bar-fill" style="width:${pct}%"></div>
                        <div class="recon-bar-fill recon-bar-fill--success" style="width:${successPct}%"></div>
                    </div>
                    <span class="recon-bar-val">${m.attempts} / ${m.cracked}</span>
                </div>`;
            }
            html += '</div>';
        }

        const roi = data.wordlist_roi || [];
        if (roi.length) {
            html += `<div class="recon-section-title">${reconHintLabel('WORDLIST ROI', 'wordlist_roi')}</div>`;
            html += '<div class="recon-section-note">Compare which wordlists are worth reusing before launching another batch.</div>';
            html += '<div class="recon-roi-table-wrap"><table class="recon-roi-table">';
            html += '<thead><tr><th>WORDLIST</th><th>USES</th><th>CRACKS</th><th>RATE</th></tr></thead><tbody>';
            for (const w of roi.slice(0, 20)) {
                const rateClass = w.success_rate >= 50 ? 'score-high' : w.success_rate >= 20 ? 'score-mid' : 'score-low';
                html += `<tr>
                    <td>${escapeHtml(w.name)}</td>
                    <td>${w.uses}</td>
                    <td>${w.cracks}</td>
                    <td><span class="recon-score ${rateClass}">${w.success_rate}%</span></td>
                </tr>`;
            }
            html += '</tbody></table></div>';
        } else if (data.top_wordlists && data.top_wordlists.length) {
            html += '<div class="recon-section-title">TOP WORDLISTS</div><div class="recon-wordlist-list">';
            for (const wl of data.top_wordlists) {
                html += `<div class="recon-wordlist-row">
                    <span>${escapeHtml(wl.name)}</span>
                    <span class="recon-wordlist-stats"><span class="recon-badge">${wl.cracks}</span> cracks</span>
                </div>`;
            }
            html += '</div>';
        }

        const velocity = data.crack_velocity || [];
        html += `<div class="recon-section-title">${reconHintLabel('CRACK VELOCITY', 'crack_velocity')}</div>`;
        if (velocity.length > 0) {
            const dayMap = {};
            for (const ev of velocity) {
                if (!ev || !ev.ts) continue;
                const day = String(ev.ts).slice(0, 10);
                if (!day) continue;
                dayMap[day] = (dayMap[day] || 0) + 1;
            }
            const dayEntries = Object.entries(dayMap).sort((a, b) => a[0].localeCompare(b[0]));
            const chartDays = dayEntries.slice(-14);
            const maxDayCount = Math.max(...chartDays.map((d) => d[1]), 1);
            const peakDay = chartDays.reduce((best, item) => (item[1] > best[1] ? item : best), chartDays[0]);

            html += `<div class="recon-velocity-wrap">
                <div class="recon-velocity-chart">`;
            for (const [day, count] of chartDays) {
                const pct = Math.max(6, Math.round((count / maxDayCount) * 100));
                html += `<div class="recon-velocity-bar" title="${escapeHtml(day)}: ${count} cracks">
                    <div class="recon-velocity-track">
                        <div class="recon-velocity-fill" style="height:${pct}%"></div>
                    </div>
                    <span class="recon-velocity-count">${count}</span>
                    <span class="recon-velocity-label">${day.slice(5)}</span>
                </div>`;
            }
            html += `</div>
                <div class="recon-velocity-meta">
                    <div class="recon-kpi recon-kpi--mini"><span class="recon-kpi-val">${velocity.length}</span><span class="recon-kpi-label">CRACK EVENTS</span></div>
                    <div class="recon-kpi recon-kpi--mini"><span class="recon-kpi-val">${dayEntries.length}</span><span class="recon-kpi-label">ACTIVE DAYS</span></div>
                    <div class="recon-kpi recon-kpi--mini"><span class="recon-kpi-val">${peakDay ? peakDay[1] : 0}</span><span class="recon-kpi-label">PEAK / DAY</span></div>
                    <div class="recon-kpi recon-kpi--mini"><span class="recon-kpi-val">${chartDays.length}</span><span class="recon-kpi-label">DAYS SHOWN</span></div>
                </div>
            </div>`;
        } else {
            html += '<div class="recon-empty recon-empty-state--soft">No crack events in this period.</div>';
        }

        if (data.by_encryption && data.by_encryption.length) {
            html += '<div class="recon-section-title">BY ENCRYPTION</div>';
            const encRows = [...data.by_encryption].sort((a, b) => (b.targets || 0) - (a.targets || 0));
            const encTotal = encRows.reduce((sum, e) => sum + (Number(e.targets) || 0), 0);
            if (encTotal > 0) {
                const maxTargets = Math.max(...encRows.map((e) => Number(e.targets) || 0), 1);
                html += '<div class="recon-enc-breakdown-grid">';
                for (const e of encRows) {
                    const targets = Number(e.targets) || 0;
                    const cracked = Number(e.cracked) || 0;
                    const attempts = Number(e.attempts) || 0;
                    const sharePct = Math.round((targets / encTotal) * 100);
                    const successPct = targets > 0 ? Math.round((cracked / targets) * 100) : 0;
                    const densityPct = Math.max(6, Math.round((targets / maxTargets) * 100));
                    html += `<div class="recon-enc-breakdown-card">
                        <div class="recon-enc-breakdown-head">
                            <span class="recon-enc-breakdown-name">${escapeHtml(e.encryption || 'UNKNOWN')}</span>
                            <span class="recon-enc-breakdown-count">${targets} targets</span>
                        </div>
                        <div class="recon-enc-breakdown-metrics">
                            <span>${cracked} cracked</span>
                            <span>${attempts} attempts</span>
                        </div>
                        <div class="recon-enc-breakdown-row" title="Share of all targets: ${sharePct}%">
                            <span class="recon-enc-breakdown-label">Share</span>
                            <div class="recon-enc-breakdown-track"><div class="recon-enc-breakdown-fill" style="width:${densityPct}%"></div></div>
                            <span class="recon-enc-breakdown-val">${sharePct}%</span>
                        </div>
                        <div class="recon-enc-breakdown-row" title="Crack success for this encryption: ${successPct}%">
                            <span class="recon-enc-breakdown-label">Success</span>
                            <div class="recon-enc-breakdown-track recon-enc-breakdown-track--success"><div class="recon-enc-breakdown-fill recon-enc-breakdown-fill--success" style="width:${successPct}%"></div></div>
                            <span class="recon-enc-breakdown-val">${successPct}%</span>
                        </div>
                    </div>`;
                }
                html += '</div>';
            } else {
                html += '<div class="recon-empty recon-empty-state--soft">No encryption distribution available in this period.</div>';
            }
        }

        if (pmkData && Array.isArray(pmkData) && pmkData.length > 0) {
            html += '<div class="recon-section-title">PMK DATABASES</div>';
            html += '<div class="recon-pmk-grid">';
            for (const db of pmkData) {
                html += `<div class="recon-pmk-card">
                    <div class="recon-pmk-ssid">${escapeHtml(db.ssid || db.name || '?')}</div>
                    <div class="recon-pmk-meta">${db.entries || 0} entries · ${formatSize(db.size || 0)}</div>
                </div>`;
            }
            html += '</div>';
        }

        if (velocity.length > 0) {
            html += '<div class="recon-section-title">RECENT OPERATIONS</div>';
            html += '<div class="recon-recent-list">';
            for (const ev of velocity.slice(-15).reverse()) {
                const timeStr = ev.ts ? String(ev.ts).replace('T', ' ').slice(0, 19) : '';
                const rel = formatRelativeTime(ev.ts);
                const mode = String(ev.mode || 'unknown').toUpperCase();
                html += `<div class="recon-recent-item">
                    <div class="recon-recent-main">
                        <span class="recon-recent-target">${escapeHtml(ev.ssid || ev.mac)}</span>
                        <span class="recon-recent-mode">${escapeHtml(mode)}</span>
                    </div>
                    <div class="recon-recent-meta">
                        <span class="recon-recent-when">${escapeHtml(rel)}</span>
                        <span class="recon-recent-ts">${escapeHtml(timeStr)}</span>
                    </div>
                </div>`;
            }
            html += '</div>';
        }

        html += `<div class="recon-section-title">ATTACK PLANNER</div>
        <div class="recon-planner recon-panel-card">
            <div class="recon-planner-header">
                <div>
                    <div class="recon-planner-title">Build an execution plan before starting cracks</div>
                    <div class="recon-planner-copy">Paste target MACs, choose a strategy or leave auto-select enabled, and review which operations are executable versus skipped.</div>
                </div>
                <div class="recon-planner-badges">
                    <span class="recon-badge recon-badge--dim">Auto Select</span>
                    <span class="recon-badge recon-badge--dim">Dictionary</span>
                    <span class="recon-badge recon-badge--dim">PMK</span>
                </div>
            </div>
            <div class="recon-planner-form">
                <div class="recon-planner-targets-layout">
                    <label class="recon-field-group recon-planner-targets-editor">
                        <span class="recon-field-label">Targets</span>
                        <textarea id="planner-targets" class="recon-planner-textarea" placeholder="Paste MAC addresses (one per line or comma-separated)..." rows="8"></textarea>
                    </label>
                    <div class="recon-planner-target-picker">
                        <div class="recon-planner-target-picker-head">
                            <span class="recon-field-label">Possible Targets</span>
                            <span id="planner-target-picker-meta" class="recon-section-note">0 visible</span>
                        </div>
                        <div class="recon-planner-target-picker-filters">
                            <input id="planner-target-picker-filter" class="recon-search-input" type="text" placeholder="Filter by MAC, SSID, encryption...">
                            <select id="planner-target-picker-scope" class="recon-select recon-select--sm">
                                <option value="attackable">Attackable Only</option>
                                <option value="all">All Networks</option>
                            </select>
                        </div>
                        <div id="planner-target-picker-list" class="recon-planner-target-picker-list"></div>
                        <div class="recon-planner-target-picker-actions">
                            <button id="planner-target-add-selected" class="recon-btn recon-btn--sm" type="button"><i class="fa-solid fa-plus"></i> Add Selected</button>
                            <button id="planner-target-add-visible" class="recon-btn recon-btn--sm" type="button"><i class="fa-solid fa-layer-group"></i> Add Visible</button>
                        </div>
                    </div>
                </div>
                <div class="recon-planner-opts">
                    <label class="recon-field-group recon-field-group--compact">
                        <span class="recon-field-label">Strategy</span>
                        <select id="planner-strategy" class="recon-select">
                            <option value="auto">Auto-select</option>
                            <option value="dictionary">Dictionary</option>
                            <option value="bruteforce">Bruteforce</option>
                            <option value="pmk">PMK</option>
                        </select>
                    </label>
                    <label class="recon-field-group recon-field-group--compact recon-field-group--grow">
                        <span class="recon-field-label">Wordlist</span>
                        <select id="planner-wordlist" class="recon-select">
                            <option value="">Loading…</option>
                        </select>
                    </label>
                    <button id="planner-plan-btn" class="recon-btn recon-btn--primary"><i class="fa-solid fa-tasks"></i> Plan Attack</button>
                </div>
            </div>
            <div id="planner-results" class="recon-planner-results recon-empty-state recon-empty-state--soft">
                <i class="fa-solid fa-diagram-project"></i>
                <div>
                    <strong>No plan generated yet</strong>
                    <span>The planner will summarize executable and skipped operations here.</span>
                </div>
            </div>
        </div>`;

        container.innerHTML = html;

        enableDynamicSectionCollapse(container, {
            titleSelector: '.recon-section-title',
            stateSet: reconState.opsCollapsed,
            keyPrefix: 'ops',
            dataAttr: 'ops-section',
            rerender: () => { renderOperations(container); },
        });

        const atkTitle = container.querySelector('[data-ops-section="ops-attack-modes"]');
        const wlTitle = container.querySelector('[data-ops-section="ops-wordlist-roi"]')
            || container.querySelector('[data-ops-section="ops-top-wordlists"]');
        if (atkTitle && wlTitle) {
            const atkBlock = atkTitle.nextElementSibling;
            const wlBlock = wlTitle.nextElementSibling;
            const dualRow = document.createElement('div');
            dualRow.className = 'recon-ops-dual-row';
            const col1 = document.createElement('div');
            col1.className = 'recon-ops-dual-col';
            const col2 = document.createElement('div');
            col2.className = 'recon-ops-dual-col';
            atkTitle.parentElement.insertBefore(dualRow, atkTitle);
            col1.appendChild(atkTitle);
            if (atkBlock?.classList.contains('recon-report-block')) col1.appendChild(atkBlock);
            col2.appendChild(wlTitle);
            if (wlBlock?.classList.contains('recon-report-block')) col2.appendChild(wlBlock);
            dualRow.appendChild(col1);
            dualRow.appendChild(col2);
        }

        const plannerWlSelect = container.querySelector('#planner-wordlist');
        if (plannerWlSelect) {
            API.getCustomWordlists().then((wordlists) => {
                plannerWlSelect.innerHTML = '';
                const defOpt = document.createElement('option');
                defOpt.value = '';
                if (!wordlists || wordlists.length === 0) {
                    defOpt.textContent = 'No wordlists found';
                    plannerWlSelect.appendChild(defOpt);
                    plannerWlSelect.disabled = true;
                } else {
                    defOpt.textContent = '— auto —';
                    plannerWlSelect.appendChild(defOpt);
                    wordlists.forEach((wl) => {
                        const opt = document.createElement('option');
                        opt.value = wl.path;
                        opt.textContent = wl.type === 'directory'
                            ? `📁 ${wl.name.replace('[DIR] ', '')}${wl.size ? ` (${wl.size})` : ''}`
                            : `${wl.name}${wl.size ? ` (${wl.size})` : ''}`;
                        plannerWlSelect.appendChild(opt);
                    });
                }
            }).catch(() => {
                plannerWlSelect.innerHTML = '<option value="">Unavailable</option>';
                plannerWlSelect.disabled = true;
            });
        }

        const plannerTargetsInput = container.querySelector('#planner-targets');
        const pickerList = container.querySelector('#planner-target-picker-list');
        const pickerFilter = container.querySelector('#planner-target-picker-filter');
        const pickerScope = container.querySelector('#planner-target-picker-scope');
        const pickerMeta = container.querySelector('#planner-target-picker-meta');
        const addSelectedBtn = container.querySelector('#planner-target-add-selected');
        const addVisibleBtn = container.querySelector('#planner-target-add-visible');
        const selectedPickerTargets = new Set();
        let visiblePickerTargets = [];

        const normalizeMac = (value) => String(value || '').trim().toUpperCase();
        const isMac = (value) => /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(value);
        const parsePlannerTargets = () => {
            if (!plannerTargetsInput) return [];
            const tokens = String(plannerTargetsInput.value || '')
                .split(/[\n,]+/)
                .map((s) => normalizeMac(s))
                .filter((s) => isMac(s));
            return [...new Set(tokens)];
        };
        const writePlannerTargets = (macs) => {
            if (!plannerTargetsInput) return;
            plannerTargetsInput.value = [...new Set((macs || []).filter((m) => isMac(m)))].join('\n');
        };
        const mergeTargetsIntoPlanner = (macs) => {
            const current = parsePlannerTargets();
            const incoming = (macs || []).map((m) => normalizeMac(m)).filter((m) => isMac(m));
            writePlannerTargets([...current, ...incoming]);
        };
        const collectPickerCandidates = () => {
            const byMac = new Map();
            const allPositions = Object.values(STATE.allPositions || {});
            for (const pos of allPositions) {
                const mac = normalizeMac(pos?.mac);
                if (!isMac(mac)) continue;
                if (byMac.has(mac)) continue;
                const handshakeFiles = Array.isArray(pos?.handshake_files) ? pos.handshake_files : [];
                const hasHashArtifacts = handshakeFiles.some((f) => String(f || '').toLowerCase().endsWith('.22000'));
                const hasPcapArtifacts = handshakeFiles.some((f) => String(f || '').toLowerCase().endsWith('.pcap'));
                const hasRawHash = Number(pos?.raw_pmkid_count || 0) > 0 || Number(pos?.raw_eapol_count || 0) > 0;
                const cracked = !!pos?.pass;
                const attackable = !cracked && (hasHashArtifacts || hasPcapArtifacts || hasRawHash);
                byMac.set(mac, {
                    mac,
                    ssid: String(pos?.ssid || 'HIDDEN'),
                    encryption: String(pos?.encryption || 'UNKNOWN').toUpperCase(),
                    cracked,
                    attackable,
                });
            }
            return [...byMac.values()].sort((a, b) => {
                if (a.attackable !== b.attackable) return a.attackable ? -1 : 1;
                if (a.cracked !== b.cracked) return a.cracked ? 1 : -1;
                return a.ssid.localeCompare(b.ssid);
            });
        };

        const renderPlannerTargetPicker = () => {
            if (!pickerList) return;
            const scope = String(pickerScope?.value || 'attackable');
            const q = String(pickerFilter?.value || '').trim().toLowerCase();
            const inPlanner = new Set(parsePlannerTargets());
            const inTargetList = new Set((STATE.lists?.targets || []).map((m) => normalizeMac(m)));
            const candidates = collectPickerCandidates()
                .filter((row) => (scope === 'all' ? true : row.attackable))
                .filter((row) => (!q ? true : `${row.mac} ${row.ssid} ${row.encryption}`.toLowerCase().includes(q)));

            visiblePickerTargets = candidates.map((row) => row.mac).filter((mac) => !inPlanner.has(mac));

            for (const mac of [...selectedPickerTargets]) {
                if (!visiblePickerTargets.includes(mac)) selectedPickerTargets.delete(mac);
            }

            if (pickerMeta) {
                pickerMeta.textContent = `${visiblePickerTargets.length} visible${selectedPickerTargets.size ? ` | ${selectedPickerTargets.size} selected` : ''}`;
            }

            if (!candidates.length) {
                pickerList.innerHTML = '<div class="recon-empty recon-empty-state--soft">No matching targets.</div>';
                return;
            }

            pickerList.innerHTML = candidates.map((row) => {
                const isAlreadyInPlanner = inPlanner.has(row.mac);
                const isAlreadyInTargets = inTargetList.has(row.mac);
                const canAdd = !isAlreadyInPlanner;
                const checked = selectedPickerTargets.has(row.mac) && canAdd;
                return `<div class="recon-planner-target-item ${isAlreadyInPlanner ? 'recon-planner-target-item--locked' : ''}">
                    <label class="recon-planner-target-check">
                        <input type="checkbox" data-mac="${escapeHtml(row.mac)}" ${checked ? 'checked' : ''} ${canAdd ? '' : 'disabled'}>
                        <span></span>
                    </label>
                    <div class="recon-planner-target-main">
                        <div class="recon-planner-target-name">${escapeHtml(row.ssid)}</div>
                        <div class="recon-planner-target-meta">${escapeHtml(row.mac)} · ${escapeHtml(row.encryption)}</div>
                    </div>
                    <div class="recon-planner-target-right">
                        ${row.attackable ? '<span class="recon-mini-badge recon-mini-badge--pmkid">attackable</span>' : '<span class="recon-mini-badge">inspect</span>'}
                        ${isAlreadyInTargets ? '<span class="recon-mini-badge">targeted</span>' : ''}
                        <button class="recon-btn recon-btn--sm recon-planner-target-add" type="button" data-mac="${escapeHtml(row.mac)}" ${canAdd ? '' : 'disabled'}>${canAdd ? 'Add' : 'Added'}</button>
                    </div>
                </div>`;
            }).join('');
        };

        if (pickerFilter) pickerFilter.addEventListener('input', renderPlannerTargetPicker);
        if (pickerScope) pickerScope.addEventListener('change', renderPlannerTargetPicker);
        if (plannerTargetsInput) plannerTargetsInput.addEventListener('input', renderPlannerTargetPicker);
        if (pickerList) {
            pickerList.addEventListener('change', (e) => {
                const chk = e.target.closest('input[type="checkbox"][data-mac]');
                if (!chk) return;
                const mac = normalizeMac(chk.dataset.mac);
                if (!isMac(mac)) return;
                if (chk.checked) selectedPickerTargets.add(mac);
                else selectedPickerTargets.delete(mac);
                renderPlannerTargetPicker();
            });
            pickerList.addEventListener('click', (e) => {
                const addBtn = e.target.closest('.recon-planner-target-add[data-mac]');
                if (!addBtn) return;
                const mac = normalizeMac(addBtn.dataset.mac);
                if (!isMac(mac)) return;
                mergeTargetsIntoPlanner([mac]);
                selectedPickerTargets.delete(mac);
                renderPlannerTargetPicker();
            });
        }
        if (addSelectedBtn) {
            addSelectedBtn.addEventListener('click', () => {
                if (!selectedPickerTargets.size) return;
                mergeTargetsIntoPlanner([...selectedPickerTargets]);
                selectedPickerTargets.clear();
                renderPlannerTargetPicker();
            });
        }
        if (addVisibleBtn) {
            addVisibleBtn.addEventListener('click', () => {
                if (!visiblePickerTargets.length) return;
                mergeTargetsIntoPlanner(visiblePickerTargets);
                selectedPickerTargets.clear();
                renderPlannerTargetPicker();
            });
        }
        renderPlannerTargetPicker();

        const planBtn = container.querySelector('#planner-plan-btn');
        if (planBtn) {
            planBtn.addEventListener('click', async () => {
                const raw = container.querySelector('#planner-targets').value;
                const targets = raw.split(/[,\n]+/).map((s) => s.trim()).filter(Boolean);
                const out = container.querySelector('#planner-results');
                if (!targets.length) {
                    if (out) {
                        out.className = 'recon-planner-results recon-empty-state recon-empty-state--warning';
                        out.innerHTML = '<i class="fa-solid fa-circle-exclamation"></i><div><strong>Add at least one target MAC</strong><span>Use one MAC per line or separate multiple entries with commas.</span></div>';
                    }
                    return;
                }
                const strategy = container.querySelector('#planner-strategy').value;
                const wordlist = container.querySelector('#planner-wordlist').value || null;
                planBtn.disabled = true;
                planBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Planning…';
                try {
                    const plan = await API.createReconAttackPlan({ targets, strategy, wordlist });
                    if (out && plan) {
                        const executableOps = (plan.operations || []).filter((o) => !o.skip);
                        out.className = 'recon-planner-results';
                        let r = `<div class="recon-planner-summary">
                            <span class="recon-badge">${plan.executable} executable</span>
                            <span class="recon-badge recon-badge--dim">${plan.skipped} skipped</span>
                        </div>
                        <div class="recon-planner-next-step">
                            <i class="fa-solid fa-route"></i>
                            <span>Planner only builds recommendations. Use the actions below to continue execution.</span>
                        </div>
                        <div class="recon-planner-actions">
                            <button class="recon-btn recon-btn--sm" id="planner-add-executable-btn" ${executableOps.length ? '' : 'disabled'}>
                                <i class="fa-solid fa-bullseye"></i> Add Executable To Target List
                            </button>
                            <button class="recon-btn recon-btn--sm recon-btn--primary" id="planner-open-first-btn" ${executableOps.length ? '' : 'disabled'}>
                                <i class="fa-solid fa-up-right-from-square"></i> Open First In Cracking
                            </button>
                        </div>
                        <div class="recon-planner-ops">`;
                        for (const op of (plan.operations || [])) {
                            if (op.skip) {
                                r += `<div class="recon-planner-op recon-planner-op--skip"><span class="recon-planner-op-name">${escapeHtml(op.mac)}</span> <span class="recon-mini-badge">${escapeHtml(op.reason)}</span></div>`;
                            } else {
                                r += `<div class="recon-planner-op"><span class="recon-planner-op-name">${escapeHtml(op.ssid || op.mac)}</span> <span class="recon-mini-badge recon-mini-badge--pmkid">${escapeHtml(op.strategy)}</span> <span class="recon-mini-badge">${escapeHtml(op.mode)}</span> <button class="recon-btn recon-btn--sm recon-planner-open-cracking-btn" data-mac="${escapeHtml(op.mac)}" data-ssid="${escapeHtml(op.ssid || op.mac)}"><i class="fa-solid fa-up-right-from-square"></i> Open in Cracking</button></div>`;
                            }
                        }
                        r += '</div>';
                        out.innerHTML = r;

                        const addExecutableBtn = out.querySelector('#planner-add-executable-btn');
                        if (addExecutableBtn) {
                            addExecutableBtn.addEventListener('click', () => {
                                const existing = new Set((STATE.lists.targets || []).map((m) => String(m || '').toUpperCase()));
                                let added = 0;
                                executableOps.forEach((op) => {
                                    const mac = String(op?.mac || '').toUpperCase();
                                    if (!mac || existing.has(mac)) return;
                                    STATE.lists.targets.push(mac);
                                    existing.add(mac);
                                    added += 1;
                                });
                                if (added > 0) {
                                    saveLists();
                                    document.dispatchEvent(new CustomEvent('listsUpdated'));
                                    log('recon', `Added ${added} executable targets to Target List`, 'success');
                                } else {
                                    log('recon', 'All executable targets are already in Target List', 'info');
                                }
                            });
                        }

                        const openFirstBtn = out.querySelector('#planner-open-first-btn');
                        if (openFirstBtn) {
                            openFirstBtn.addEventListener('click', async () => {
                                const first = executableOps[0];
                                if (!first?.mac) return;
                                await openCrackingPanel(String(first.mac).toUpperCase(), String(first.ssid || first.mac));
                                log('recon', `Opened ${String(first.mac).toUpperCase()} in Crack in Operations`, 'info');
                            });
                        }

                        out.querySelectorAll('.recon-planner-open-cracking-btn').forEach((btn) => {
                            btn.addEventListener('click', async () => {
                                const targetMac = String(btn.dataset.mac || '').toUpperCase();
                                if (!targetMac) return;
                                const targetSsid = String(btn.dataset.ssid || targetMac);
                                await openCrackingPanel(targetMac, targetSsid);
                                log('recon', `Opened ${targetMac} in Crack in Operations`, 'info');
                            });
                        });
                    }
                } catch (e) {
                    log('recon', `Planner error: ${e.message}`);
                }
                planBtn.disabled = false;
                planBtn.innerHTML = '<i class="fa-solid fa-tasks"></i> Plan Attack';
            });
        }

        const periodSelect = container.querySelector('#ops-period-filter');
        if (periodSelect) {
            periodSelect.addEventListener('change', () => {
                reconState.opsPeriod = periodSelect.value;
                renderOperations(container);
            });
        }

        container.querySelectorAll('.recon-job-cancel-btn').forEach((btn) => {
            btn.addEventListener('click', async () => {
                btn.disabled = true;
                try {
                    await API.cancelJob(btn.dataset.jobId);
                } catch (_) {
                    /* ignore */
                }
                renderOperations(container);
            });
        });

        if (activeJobs.length > 0) startOpsPoll(container);
    }

    return {
        renderOperations,
    };
}
