export function createTargetDetailController(deps) {
    const {
        STATE,
        saveLists,
        API,
        log,
        escapeHtml,
        openCrackingPanel,
        setReconWorkspaceActive,
        normalizeReconSecurityLabel,
        detailCacheGet,
        detailCacheSet,
        tabCacheGet,
        getCachedReconRow,
        rememberReconRows,
        getActiveTab,
        tabsWithDrawer,
        reconState,
    } = deps;

    function syncSelectedHighlight() {
        const mac = STATE.reconUi?.selectedMac || '';
        const container = document.getElementById('recon-tab-content');
        if (!container) return;
        container.querySelectorAll('.recon-net-chip, .recon-rec-card').forEach((el) => {
            el.classList.toggle('recon-chip--selected', el.dataset.mac === mac);
        });
    }

    function getLocalReconTargetStub(mac) {
        const normalized = String(mac || '').trim().toUpperCase();
        const source = STATE.allPositions?.[normalized]
            || STATE.allPositions?.[normalized.toLowerCase()]
            || null;
        if (!source || typeof source !== 'object') return null;
        return {
            mac: normalized,
            ssid: source.ssid || normalized,
            encryption: normalizeReconSecurityLabel(source.encryption || source.security || 'UNKNOWN'),
            stage: 'discovered',
            attack_score: 0,
            readiness_status: 'loading',
            readiness_score: 0,
            device_type: source.device_type || 'unknown',
            sources: Array.isArray(source.sources) ? source.sources : [],
            lat: source.lat,
            lng: source.lng,
            has_handshake: Boolean(source.handshake),
            has_pmkid: false,
            has_eapol_hash: false,
            pmkid_count: 0,
            eapol_hash_count: 0,
            raw_eapol: Number(source.raw_eapol_count || 0),
            raw_beacon: Number(source.raw_beacon_count || 0),
            has_password: Boolean(source.pass),
            akm: [],
            flags: [],
        };
    }

    function renderReconTargetLoadingState(row, { compareCount = 0 } = {}) {
        const title = escapeHtml(row?.ssid || row?.mac || 'Loading target');
        const mac = escapeHtml(row?.mac || '—');
        const enc = escapeHtml(row?.encryption || 'Unknown');
        const device = escapeHtml(row?.device_type || 'unknown');
        const sources = Array.isArray(row?.sources) && row.sources.length
            ? row.sources.map((src) => escapeHtml(src)).join(', ')
            : 'Unknown sources';
        return `<div class="recon-target-detail recon-target-detail--loading">
            <div class="recon-target-ssid">${title}</div>
            <div class="recon-target-mac">${mac}</div>
            <div class="recon-target-meta">
                <span>${enc}</span>
                <span>${device}</span>
                <span>${sources}</span>
            </div>
            <div class="recon-loading-sm">${compareCount > 1 ? `Loading ${compareCount} target details…` : 'Loading target details…'}</div>
        </div>`;
    }

    async function hydrateReconTargetHistory(panel, mac) {
        if (!panel || !mac) return;
        const slot = panel.querySelector('#recon-target-history-slot');
        if (!slot) return;

        slot.innerHTML = '<div class="recon-loading-sm">Loading attack history…</div>';
        try {
            let historyData = detailCacheGet('attack-history:all') || tabCacheGet('ops:all')?.data || null;
            if (!historyData) {
                historyData = await API.getReconAttackEffectiveness();
                detailCacheSet('attack-history:all', historyData);
            }

            if (panel.dataset.reconDetailMac !== String(mac)) return;
            const history = (historyData?.crack_velocity || []).filter((ev) => ev.mac === mac);
            if (!history.length) {
                slot.remove();
                return;
            }

            slot.innerHTML = `<div class="recon-target-history"><div class="recon-section-title">Attack History</div>
                ${history.slice(-10).map((ev) => {
                    const d = ev.ts ? new Date(ev.ts).toLocaleString() : '—';
                    return `<div class="recon-history-row"><span>${d}</span><span>${escapeHtml(ev.mode || '')}</span><span>${escapeHtml(ev.ssid || '')}</span></div>`;
                }).join('')}
            </div>`;
        } catch (_) {
            if (panel.dataset.reconDetailMac === String(mac)) slot.remove();
        }
    }

    async function selectTarget(mac) {
        if (!mac) return;
        if (!STATE.reconUi) STATE.reconUi = {};
        STATE.reconUi.selectedMac = mac;
        syncSelectedHighlight();

        const activeTab = getActiveTab();
        const useDrawer = tabsWithDrawer.has(activeTab);
        const panel = useDrawer
            ? document.getElementById('recon-drawer-content')
            : document.getElementById('recon-right-content');
        if (!panel) return;

        if (useDrawer) {
            const drawer = document.getElementById('recon-drawer');
            if (drawer) {
                drawer.classList.remove('recon-drawer--hidden');
                drawer.classList.remove('recon-drawer--collapsed');
            }
        }

        try {
            const compareMacs = activeTab === 'target-intel'
                ? reconState.intelCompare.slice(0, 4).map((item) => String(item || '').trim().toUpperCase()).filter(Boolean)
                : [];
            const readTarget = (targetMac) => (
                detailCacheGet(`target:${String(targetMac || '').trim().toUpperCase()}`)
                || getCachedReconRow(targetMac)
                || getLocalReconTargetStub(targetMac)
            );

            let selectedPairRows = compareMacs
                .map((sel) => readTarget(sel))
                .filter(Boolean);
            let row = readTarget(mac);

            const missingDetails = Array.from(new Set([
                String(mac || '').trim().toUpperCase(),
                ...compareMacs,
            ].filter(Boolean))).filter((targetMac) => !detailCacheGet(`target:${targetMac}`));

            if (missingDetails.length > 0) {
                panel.innerHTML = renderReconTargetLoadingState(
                    row || selectedPairRows[0] || { mac: String(mac || '').trim().toUpperCase() },
                    { compareCount: Math.max(1, compareMacs.length) },
                );
                const detailResults = await Promise.all(
                    missingDetails.map(async (targetMac) => {
                        try {
                            const detail = await API.getReconTargetDetail({ mac: targetMac });
                            if (detail) {
                                detailCacheSet(`target:${targetMac}`, detail);
                                rememberReconRows([detail]);
                            }
                            return detail;
                        } catch (_) {
                            return null;
                        }
                    }),
                );
                detailResults.filter(Boolean).forEach((detail) => {
                    detailCacheSet(`target:${String(detail.mac || '').trim().toUpperCase()}`, detail);
                });
                selectedPairRows = compareMacs
                    .map((sel) => readTarget(sel))
                    .filter(Boolean);
                row = readTarget(mac);
            }

            if (activeTab === 'target-intel') {
                if (selectedPairRows.length >= 2) {
                    const focused = selectedPairRows.find((r) => r.mac === reconState.intelDetailMac);
                    row = focused || selectedPairRows[selectedPairRows.length - 1] || selectedPairRows[0];
                } else if (selectedPairRows.length === 1) {
                    row = selectedPairRows[0];
                }
            }

            if (!row) {
                panel.innerHTML = `<div class="recon-empty">Target ${escapeHtml(mac)} not found.</div>`;
                return;
            }

            const isInTargetList = STATE.lists.targets.includes(String(row.mac || '').toUpperCase());
            const compareGroup = activeTab === 'target-intel' ? selectedPairRows.slice(0, 4) : [];
            const showCompareInDetails = compareGroup.length >= 2;

            if (activeTab === 'target-intel' && showCompareInDetails) {
                panel.dataset.reconDetailMac = String(row?.mac || mac);
                const pairHeader = (r, index) => {
                    const sc = r.attack_score >= 70 ? 'score-high' : r.attack_score >= 40 ? 'score-mid' : 'score-low';
                    const inTargets = STATE.lists.targets.includes(String(r.mac || '').toUpperCase());
                    return `<div class="recon-pair-header">
                        <div class="recon-pair-net">
                            <span class="recon-selected-chip">SELECTED ${index}</span>
                            <span class="recon-pair-ssid">${escapeHtml(r.ssid || r.mac)}</span>
                            <span class="recon-pair-mac">${escapeHtml(r.mac)}</span>
                        </div>
                        <div class="recon-target-meta">
                            <span class="recon-stage-tag recon-stage-tag--${escapeHtml(r.stage)}">${escapeHtml(r.stage.replace(/_/g, ' '))}</span>
                            <span>${escapeHtml(r.encryption)}</span>
                            <span>${escapeHtml(r.device_type || 'unknown')}</span>
                        </div>
                        <div class="recon-target-score">
                            <div class="recon-gauge">
                                <div class="recon-gauge-fill ${sc}" style="width:${r.attack_score}%"></div>
                            </div>
                            <span class="recon-score ${sc}">${r.attack_score}/100</span>
                            <span class="recon-readiness">${escapeHtml(String(r.readiness_status || '').replace(/_/g, ' '))}</span>
                        </div>
                        <div class="recon-target-actions">
                            <button class="recon-btn recon-btn--sm ${inTargets ? 'recon-btn--done' : 'recon-btn--primary'} recon-detail-add-target-btn" data-mac="${escapeHtml(r.mac)}" ${inTargets ? 'disabled' : ''}>
                                <i class="fa-solid ${inTargets ? 'fa-check' : 'fa-crosshairs'}"></i>
                                ${inTargets ? 'In Target List' : 'Add To Target List'}
                            </button>
                            <button class="recon-btn recon-btn--sm recon-detail-open-ops-btn" data-mac="${escapeHtml(r.mac)}" data-ssid="${escapeHtml(r.ssid || r.mac)}">
                                <i class="fa-solid fa-bolt"></i>
                                Open in Cracking Operations
                            </button>
                        </div>
                    </div>`;
                };

                const yn = (has, count) => has ? `<span class="recon-val-green">YES${count ? ` (${count})` : ''}</span>` : 'NO';
                const coord = (r) => (r.lat != null && r.lng != null) ? `${r.lat.toFixed(4)}, ${r.lng.toFixed(4)}` : '—';

                let pairHtml = `<div class="recon-target-detail recon-target-pair-layout" data-compare-count="${compareGroup.length}">`;
                pairHtml += '<div class="recon-pair-cards-row">';
                compareGroup.forEach((r, i) => { pairHtml += pairHeader(r, i + 1); });
                pairHtml += '</div>';

                pairHtml += `<div class="recon-target-evidence">
                    <table class="recon-compare-table"><thead><tr>
                        <th></th>
                        ${compareGroup.map((r) => `<th>${escapeHtml(r.ssid || r.mac)}</th>`).join('')}
                    </tr></thead><tbody>
                        <tr><td>Stage</td>${compareGroup.map((r) => `<td>${escapeHtml(r.stage)}</td>`).join('')}</tr>
                        <tr><td>Encryption</td>${compareGroup.map((r) => `<td>${escapeHtml(r.encryption)}</td>`).join('')}</tr>
                        <tr><td>Attack Score</td>${compareGroup.map((r) => `<td>${r.attack_score}</td>`).join('')}</tr>
                        <tr><td>Readiness</td>${compareGroup.map((r) => `<td>${escapeHtml(String(r.readiness_status || '').replace(/_/g, ' '))} (${Number(r.readiness_score || 0)})</td>`).join('')}</tr>
                        <tr><td>Handshake</td>${compareGroup.map((r) => `<td>${yn(r.has_handshake)}</td>`).join('')}</tr>
                        <tr><td>PMKID</td>${compareGroup.map((r) => `<td>${yn(r.has_pmkid, r.pmkid_count)}</td>`).join('')}</tr>
                        <tr><td>EAPOL Hash</td>${compareGroup.map((r) => `<td>${yn(r.has_eapol_hash, r.eapol_hash_count)}</td>`).join('')}</tr>
                        <tr><td>Raw EAPOL</td>${compareGroup.map((r) => `<td>${r.raw_eapol ?? 0}</td>`).join('')}</tr>
                        <tr><td>Beacons</td>${compareGroup.map((r) => `<td>${r.raw_beacon ?? 0}</td>`).join('')}</tr>
                        <tr><td>Password</td>${compareGroup.map((r) => `<td>${r.has_password ? '<span class="recon-val-green">CRACKED</span>' : '—'}</td>`).join('')}</tr>
                        <tr><td>Coordinates</td>${compareGroup.map((r) => `<td>${coord(r)}</td>`).join('')}</tr>
                    </tbody></table>
                </div>`;

                const scores = compareGroup.map((r) => r.attack_score || 0);
                const bestScore = Math.max(...scores);
                const worstScore = Math.min(...scores);
                const preferred = compareGroup.reduce((best, r) => ((r.attack_score || 0) > (best.attack_score || 0) ? r : best), compareGroup[0]);
                pairHtml += `<div class="recon-kpi-row recon-kpi-row--compact">
                    <div class="recon-kpi"><span class="recon-kpi-val recon-val-green">${bestScore}</span><span class="recon-kpi-label">BEST SCORE</span></div>
                    <div class="recon-kpi"><span class="recon-kpi-val recon-val-red">${worstScore}</span><span class="recon-kpi-label">WORST SCORE</span></div>
                    <div class="recon-kpi"><span class="recon-kpi-val">${bestScore - worstScore}</span><span class="recon-kpi-label">SPREAD</span></div>
                    <div class="recon-kpi"><span class="recon-kpi-val recon-val-blue">${escapeHtml(preferred.ssid || preferred.mac)}</span><span class="recon-kpi-label">PRIORITY TARGET</span></div>
                </div>`;

                pairHtml += '</div>';
                panel.innerHTML = pairHtml;

                panel.querySelectorAll('.recon-detail-add-target-btn').forEach((btn) => {
                    btn.addEventListener('click', () => {
                        const targetMac = String(btn.dataset.mac || '').trim().toUpperCase();
                        if (!targetMac || STATE.lists.targets.includes(targetMac)) return;
                        STATE.lists.targets.push(targetMac);
                        saveLists();
                        document.dispatchEvent(new CustomEvent('listsUpdated'));
                        btn.disabled = true;
                        btn.classList.remove('recon-btn--primary');
                        btn.classList.add('recon-btn--done');
                        btn.innerHTML = '<i class="fa-solid fa-check"></i> In Target List';
                        log('recon', `Added ${targetMac} to Target List`, 'success');
                    });
                });

                panel.querySelectorAll('.recon-detail-open-ops-btn').forEach((btn) => {
                    btn.addEventListener('click', async () => {
                        try {
                            const targetMac = String(btn.dataset.mac || '').trim();
                            const targetSsid = String(btn.dataset.ssid || targetMac);
                            await openCrackingPanel(targetMac, targetSsid);
                            setReconWorkspaceActive(true);
                            log('recon', `Opened ${targetMac} in Crack in Operations`, 'info');
                        } catch (e) {
                            log('recon', `Failed opening Crack in Operations: ${e.message}`, 'error');
                        }
                    });
                });

                return;
            }

            let html = '<div class="recon-target-detail">';
            html += `<div class="recon-target-ssid">${escapeHtml(row.ssid || row.mac)}</div>`;
            html += `<div class="recon-target-mac">${escapeHtml(row.mac)}</div>`;
            html += `<div class="recon-target-meta">
                <span class="recon-stage-tag recon-stage-tag--${escapeHtml(row.stage)}">${escapeHtml(row.stage.replace(/_/g, ' '))}</span>
                <span>${escapeHtml(row.encryption || 'Unknown')}</span>
                <span>${escapeHtml(row.device_type || 'Unknown')}</span>
            </div>`;

            const scoreClass = row.attack_score >= 70 ? 'score-high' : row.attack_score >= 40 ? 'score-mid' : 'score-low';
            html += `<div class="recon-target-score">
                <div class="recon-gauge">
                    <div class="recon-gauge-fill ${scoreClass}" style="width:${row.attack_score}%"></div>
                </div>
                <span class="recon-score ${scoreClass}">${row.attack_score}/100</span>
                <span class="recon-readiness">${escapeHtml((row.readiness_status || '').replace(/_/g, ' '))}</span>
            </div>`;

            html += `<div class="recon-target-actions">
                <button class="recon-btn recon-btn--sm ${isInTargetList ? 'recon-btn--done' : 'recon-btn--primary'}" id="recon-detail-add-target" ${isInTargetList ? 'disabled' : ''}>
                    <i class="fa-solid ${isInTargetList ? 'fa-check' : 'fa-crosshairs'}"></i>
                    ${isInTargetList ? 'In Target List' : 'Add To Target List'}
                </button>
                <button class="recon-btn recon-btn--sm" id="recon-detail-open-ops">
                    <i class="fa-solid fa-bolt"></i>
                    Open in Cracking Operations
                </button>
            </div>`;

            html += '<div class="recon-target-grid">';
            html += `<div class="recon-target-cell"><span class="recon-target-cell-label">Readiness Score</span><span class="recon-target-cell-val">${row.readiness_score ?? '—'}</span></div>`;
            html += `<div class="recon-target-cell"><span class="recon-target-cell-label">Raw EAPOL</span><span class="recon-target-cell-val">${row.raw_eapol ?? 0}</span></div>`;
            html += `<div class="recon-target-cell"><span class="recon-target-cell-label">Raw Beacons</span><span class="recon-target-cell-val">${row.raw_beacon ?? 0}</span></div>`;
            html += `<div class="recon-target-cell"><span class="recon-target-cell-label">PMKID Lines</span><span class="recon-target-cell-val">${row.pmkid_count ?? 0}</span></div>`;
            html += `<div class="recon-target-cell"><span class="recon-target-cell-label">EAPOL Hash Lines</span><span class="recon-target-cell-val">${row.eapol_hash_count ?? 0}</span></div>`;
            html += `<div class="recon-target-cell"><span class="recon-target-cell-label">Coordinates</span><span class="recon-target-cell-val">${(row.lat != null && row.lng != null) ? `${row.lat.toFixed(5)}, ${row.lng.toFixed(5)}` : 'Not available'}</span></div>`;
            html += '</div>';

            html += '<div class="recon-target-evidence">';
            html += `<div class="recon-ev-row"><span>Handshake</span><span>${row.has_handshake ? 'YES' : 'NO'}</span></div>`;
            html += `<div class="recon-ev-row"><span>PMKID Hash</span><span>${row.has_pmkid ? `<span class="recon-val-red">YES (${row.pmkid_count || 0})</span>` : 'NO'}</span></div>`;
            html += `<div class="recon-ev-row"><span>EAPOL Hash</span><span>${row.has_eapol_hash ? `<span class="recon-val-blue">YES (${row.eapol_hash_count || 0})</span>` : 'NO'}</span></div>`;
            html += `<div class="recon-ev-row"><span>Password</span><span>${row.has_password ? '<span class="recon-val-green">CRACKED</span>' : '—'}</span></div>`;
            if (row.akm && row.akm.length) {
                html += `<div class="recon-ev-row"><span>AKM / SEC</span><span>${escapeHtml(row.akm.join(', '))}</span></div>`;
            }
            html += '</div>';

            if (row.flags && row.flags.length) {
                html += '<div class="recon-target-flags">';
                for (const f of row.flags) {
                    html += `<div class="recon-flag recon-flag--${escapeHtml(f.severity)}" title="${escapeHtml(f.description)}">${escapeHtml(f.label)}</div>`;
                }
                html += '</div>';
            }

            if (row.sources && row.sources.length) {
                html += `<div class="recon-target-sources">Sources: ${row.sources.map((s) => escapeHtml(s)).join(', ')}</div>`;
            }

            html += '<div id="recon-target-history-slot"></div>';
            html += '<div class="recon-target-recs"><div class="recon-section-title">Recommended Actions</div>';
            const recs = [];
            if (row.readiness_status === 'ready_pmkid') {
                recs.push({ icon: 'fa-bolt', text: 'PMKID captured — run hashcat -m 22000 for fast offline crack.' });
            }
            if (row.readiness_status === 'ready_eapol') {
                recs.push({ icon: 'fa-key', text: 'EAPOL handshake ready — use dictionary or brute-force attack.' });
            }
            if (row.has_pmkid && row.has_eapol_hash) {
                recs.push({ icon: 'fa-database', text: 'Both PMKID and EAPOL available — try PMK database attack for speed.' });
            }
            if (row.readiness_status === 'need_deauth') {
                recs.push({ icon: 'fa-wifi', text: 'Need deauth to capture handshake. Get closer to AP and retry.' });
            }
            if (row.readiness_status === 'initial_recon') {
                recs.push({ icon: 'fa-search', text: 'Initial recon only. Collect more data with active scanning.' });
            }
            if (row.encryption === 'WEP') {
                recs.push({ icon: 'fa-triangle-exclamation', text: 'WEP encryption — trivially crackable with aircrack-ng.' });
            }
            if (row.encryption === 'OPN' || row.encryption === 'OPEN') {
                recs.push({ icon: 'fa-door-open', text: 'Open network — no cracking needed.' });
            }
            if (row.has_password) {
                recs.push({ icon: 'fa-check-circle', text: 'Password already cracked. No further action needed.' });
            }
            if (!recs.length) {
                recs.push({ icon: 'fa-info-circle', text: 'Continue reconnaissance to identify attack vectors.' });
            }
            for (const r of recs) {
                html += `<div class="recon-rec-item"><i class="fa-solid ${r.icon}"></i> ${escapeHtml(r.text)}</div>`;
            }
            html += '</div>';
            html += '</div>';
            panel.innerHTML = html;
            panel.dataset.reconDetailMac = String(row.mac || mac);

            const addTargetBtn = panel.querySelector('#recon-detail-add-target');
            if (addTargetBtn && !isInTargetList) {
                addTargetBtn.addEventListener('click', () => {
                    const targetMac = String(row.mac || '').trim().toUpperCase();
                    if (!targetMac || STATE.lists.targets.includes(targetMac)) return;
                    STATE.lists.targets.push(targetMac);
                    saveLists();
                    document.dispatchEvent(new CustomEvent('listsUpdated'));
                    addTargetBtn.disabled = true;
                    addTargetBtn.classList.remove('recon-btn--primary');
                    addTargetBtn.classList.add('recon-btn--done');
                    addTargetBtn.innerHTML = '<i class="fa-solid fa-check"></i> In Target List';
                    log('recon', `Added ${targetMac} to Target List`, 'success');
                });
            }

            const openOpsBtn = panel.querySelector('#recon-detail-open-ops');
            if (openOpsBtn) {
                openOpsBtn.addEventListener('click', async () => {
                    try {
                        await openCrackingPanel(row.mac, row.ssid || row.mac);
                        setReconWorkspaceActive(true);
                        log('recon', `Opened ${row.mac} in Crack in Operations`, 'info');
                    } catch (e) {
                        log('recon', `Failed opening Crack in Operations: ${e.message}`, 'error');
                    }
                });
            }

            hydrateReconTargetHistory(panel, row.mac);
        } catch (e) {
            panel.innerHTML = `<div class="recon-error">${escapeHtml(e.message)}</div>`;
        }
    }

    return {
        syncSelectedHighlight,
        selectTarget,
    };
}
