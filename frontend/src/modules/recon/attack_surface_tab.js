export function createAttackSurfaceRenderer(deps) {
    const {
        API,
        escapeHtml,
        reconState,
        surfaceStagePreviewLimit,
        surfaceStagePageLimit,
        tdcGet,
        tdcSet,
        rememberReconRows,
        getCachedReconRow,
        detailCacheGet,
        downloadFile,
        showQuickAttackPopup,
        syncSelectedHighlight,
        enableDynamicSectionCollapse,
        selectTarget,
        reconHintLabel,
        getActiveTab,
        debounce,
    } = deps;

    async function loadKcSparklines() {
        const wrap = document.getElementById('recon-kc-sparklines');
        if (!wrap) return;
        try {
            const hist = await API.getReconKillChainHistory();
            const snaps = (hist && hist.snapshots) || [];
            if (snaps.length < 2) {
                wrap.innerHTML = '<span class="recon-spark-hint">Take snapshots to see trends</span>';
                return;
            }
            const stageNames = ['discovered', 'captured', 'fingerprinted', 'hash_ready', 'under_attack', 'cracked'];
            const stageColors = { discovered: '#7a8b92', captured: '#e0a528', fingerprinted: '#2e8bc0', hash_ready: '#9b59b6', under_attack: '#e74c3c', cracked: '#22c55e' };
            let html = '';
            for (const sn of stageNames) {
                const pts = snaps.map((s) => (s.counts && s.counts[sn]) || 0);
                const max = Math.max(1, ...pts);
                const w = 80;
                const h = 24;
                const step = w / Math.max(1, pts.length - 1);
                let path = '';
                pts.forEach((v, i) => {
                    const x = Math.round(i * step);
                    const y = Math.round(h - (v / max) * (h - 2));
                    path += (i === 0 ? `M${x},${y}` : ` L${x},${y}`);
                });
                const color = stageColors[sn] || '#7a8b92';
                html += `<div class="recon-spark-item" title="${sn.replace(/_/g, ' ')}">
                    <svg width="${w}" height="${h}" class="recon-spark-svg"><path d="${path}" stroke="${color}" fill="none" stroke-width="1.5"/></svg>
                    <span class="recon-spark-label">${sn.replace(/_/g, ' ').toUpperCase()}</span>
                </div>`;
            }
            wrap.innerHTML = html;
        } catch (_) {
            // silent
        }
    }

    function renderAttackSurfaceRecommendations(vulnData, { loading = false } = {}) {
        if (loading) {
            return `<div class="recon-section-title">RECOMMENDED TARGETS</div>
                <div class="recon-loading-sm">Loading recommended targets…</div>`;
        }
        const rows = (vulnData && vulnData.rows) || [];
        const recommended = rows
            .filter((r) => r.readiness_status !== 'cracked' && r.attack_score >= 40)
            .slice(0, 5);
        if (!recommended.length) return '';

        return `<div class="recon-section-title">RECOMMENDED TARGETS</div>
            <div class="recon-recommended">
                ${recommended.map((r) => {
                    const sc = r.attack_score >= 70 ? 'score-high' : r.attack_score >= 40 ? 'score-mid' : 'score-low';
                    return `<div class="recon-rec-card" data-mac="${escapeHtml(r.mac)}">
                        <div class="recon-rec-ssid">${escapeHtml(r.ssid || r.mac)}</div>
                        <div class="recon-rec-meta"><span class="recon-score ${sc}">${r.attack_score}</span> <span class="recon-stage-tag recon-stage-tag--${escapeHtml(r.stage)}">${escapeHtml(r.stage.replace(/_/g, ' '))}</span> ${escapeHtml(r.encryption)}</div>
                    </div>`;
                }).join('')}
            </div>`;
    }

    async function hydrateAttackSurfaceRecommendations(container) {
        const wrap = container?.querySelector?.('#recon-surface-recommended');
        if (!wrap) return;

        let vulnData = tdcGet('attack-surface:recommended');
        if (vulnData?.rows) {
            rememberReconRows(vulnData.rows);
            wrap.innerHTML = renderAttackSurfaceRecommendations(vulnData);
            return;
        }

        wrap.innerHTML = renderAttackSurfaceRecommendations(null, { loading: true });
        try {
            vulnData = await API.getReconVulnerabilityMatrix({ limit: 150, sort_by: 'attack_score', sort_dir: 'desc' });
            tdcSet('attack-surface:recommended', vulnData);
            rememberReconRows(vulnData?.rows);
            if (!container.isConnected) return;
            const liveWrap = container.querySelector('#recon-surface-recommended');
            if (liveWrap) liveWrap.innerHTML = renderAttackSurfaceRecommendations(vulnData);
            container.querySelectorAll('.recon-rec-card').forEach((card) => {
                card.addEventListener('click', () => selectTarget(card.dataset.mac));
            });
        } catch (_) {
            if (!container.isConnected) return;
            const liveWrap = container.querySelector('#recon-surface-recommended');
            if (liveWrap) liveWrap.innerHTML = '';
        }
    }

    function getAttackSurfaceStageCacheKey(stage, searchTerm = '') {
        return `attack-surface:stage:${String(stage || '').trim().toLowerCase()}:${String(searchTerm || '').trim().toLowerCase()}`;
    }

    function mergeReconChipNetworks(primary = [], secondary = []) {
        const merged = [];
        const seen = new Set();
        for (const entry of [...primary, ...secondary]) {
            const mac = String(entry?.mac || '').trim().toUpperCase();
            if (!mac || seen.has(mac)) continue;
            seen.add(mac);
            merged.push(entry);
        }
        return merged;
    }

    async function hydrateAttackSurfaceStage(container, stage, searchTerm = '', { append = false, offset = null, limit = surfaceStagePageLimit } = {}) {
        const cacheKey = getAttackSurfaceStageCacheKey(stage, searchTerm);
        const existing = tdcGet(cacheKey);
        if (!append && existing != null) return;
        if (append && existing && existing.has_more === false) return;
        if (reconState.surfaceStageLoading[cacheKey]) return;
        reconState.surfaceStageLoading[cacheKey] = true;
        try {
            const requestOffset = Number.isFinite(offset) ? Number(offset) : (append ? ((existing?.networks || []).length) : 0);
            const data = await API.getReconKillChainStage({
                stage,
                search: searchTerm,
                limit,
                offset: requestOffset,
            });
            if (data != null) {
                let nextData = data;
                if (append) {
                    const existingNetworks = Array.isArray(existing?.networks) ? existing.networks : [];
                    const mergedNetworks = mergeReconChipNetworks(existingNetworks, data?.networks || []);
                    nextData = {
                        ...data,
                        networks: mergedNetworks,
                        offset: 0,
                        limit: mergedNetworks.length,
                        has_more: requestOffset + (data?.networks || []).length < Number(data?.total || mergedNetworks.length),
                    };
                } else {
                    const pageNetworks = Array.isArray(data?.networks) ? data.networks : [];
                    nextData = {
                        ...data,
                        has_more: requestOffset + pageNetworks.length < Number(data?.total || pageNetworks.length),
                    };
                }
                tdcSet(cacheKey, nextData);
                rememberReconRows(nextData?.networks);
            }
        } finally {
            reconState.surfaceStageLoading[cacheKey] = false;
            if (container?.isConnected && getActiveTab() === 'attack-surface') {
                renderAttackSurface(container);
            }
        }
    }

    async function renderAttackSurface(container) {
        const cacheKey = 'attack-surface:summary';
        let summaryData = tdcGet(cacheKey);
        if (!summaryData) {
            container.innerHTML = '<div class="recon-loading">Loading attack surface…</div>';
            summaryData = await API.getReconKillChainSummary();
            tdcSet(cacheKey, summaryData);
        }
        if (!summaryData || !summaryData.stages) {
            container.innerHTML = '<div class="recon-empty">No data available.</div>';
            return;
        }
        const data = summaryData;
        rememberReconRows(data.stages.flatMap((stage) => (Array.isArray(stage?.preview_networks) ? stage.preview_networks : [])));

        const stageIcons = {
            discovered: 'fa-satellite-dish',
            captured: 'fa-handshake',
            fingerprinted: 'fa-fingerprint',
            hash_ready: 'fa-file-zipper',
            under_attack: 'fa-bolt',
            cracked: 'fa-unlock',
        };

        const stageColors = {
            discovered: '#7a8b92',
            captured: '#2faad4',
            fingerprinted: '#e6b422',
            hash_ready: '#e68a22',
            under_attack: '#e63946',
            cracked: '#22c55e',
        };

        const hi = data.hash_intel || {};
        const activeFilter = reconState.surfaceStageFilter;
        const searchTerm = reconState.surfaceSearch.toLowerCase();
        const stagesToHydrate = [];

        let html = `<div class="recon-kpi-row">
            <div class="recon-kpi"><span class="recon-kpi-val">${data.total}</span><span class="recon-kpi-label">TOTAL</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${hi.total_with_hash || 0}</span><span class="recon-kpi-label">WITH HASH</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val recon-val-red">${hi.total_pmkid || 0}</span><span class="recon-kpi-label">${reconHintLabel('PMKID', 'pmkid')}</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val recon-val-blue">${hi.total_eapol_hash || 0}</span><span class="recon-kpi-label">${reconHintLabel('EAPOL', 'eapol_hash')}</span></div>
        </div>`;

        const cachedRecommendations = tdcGet('attack-surface:recommended');
        html += `<div id="recon-surface-recommended">${renderAttackSurfaceRecommendations(cachedRecommendations, { loading: !cachedRecommendations })}</div>`;

        if (hi.total_with_hash > 0) {
            const pmkidOnly = hi.pmkid_only || 0;
            const eapolOnly = hi.eapol_only || 0;
            const both = hi.both || 0;
            const total = hi.total_with_hash;
            html += '<div class="recon-hash-intel">';
            html += '<div class="recon-section-title">HASH TYPE BREAKDOWN</div>';
            html += '<div class="recon-hash-bar">';
            if (pmkidOnly > 0) {
                const pct = Math.round((pmkidOnly / total) * 100);
                html += `<div class="recon-hash-seg recon-hash-seg--pmkid" style="width:${pct}%" title="PMKID only: ${pmkidOnly}"><span>${pmkidOnly}</span></div>`;
            }
            if (both > 0) {
                const pct = Math.round((both / total) * 100);
                html += `<div class="recon-hash-seg recon-hash-seg--both" style="width:${pct}%" title="PMKID + EAPOL: ${both}"><span>${both}</span></div>`;
            }
            if (eapolOnly > 0) {
                const pct = Math.round((eapolOnly / total) * 100);
                html += `<div class="recon-hash-seg recon-hash-seg--eapol" style="width:${pct}%" title="EAPOL only: ${eapolOnly}"><span>${eapolOnly}</span></div>`;
            }
            html += '</div>';
            html += '<div class="recon-hash-legend">';
            html += '<span class="recon-hash-legend-item"><span class="recon-dot recon-dot--pmkid"></span>PMKID only</span>';
            html += '<span class="recon-hash-legend-item"><span class="recon-dot recon-dot--both"></span>PMKID + EAPOL</span>';
            html += '<span class="recon-hash-legend-item"><span class="recon-dot recon-dot--eapol"></span>EAPOL only</span>';
            html += '</div></div>';
        }

        html += `<div class="recon-surface-search"><input type="text" class="recon-search-input" id="surface-search" placeholder="Search SSID / MAC…" value="${escapeHtml(reconState.surfaceSearch)}"></div>`;

        html += '<div class="recon-funnel">';
        const maxCount = Math.max(1, ...data.stages.map((s) => s.count));
        for (let i = 0; i < data.stages.length; i++) {
            const stage = data.stages[i];
            const icon = stageIcons[stage.stage] || 'fa-circle';
            const color = stageColors[stage.stage] || '#7a8b92';
            const widthPct = Math.max(12, Math.round((stage.count / maxCount) * 100));
            const isActive = activeFilter === stage.stage;
            const arrow = i < data.stages.length - 1 ? '<div class="recon-funnel-arrow"><i class="fa-solid fa-chevron-right"></i></div>' : '';
            html += `<div class="recon-funnel-step${isActive ? ' recon-funnel-step--active' : ''}" data-stage="${escapeHtml(stage.stage)}" style="--stage-color:${color}; --funnel-w:${widthPct}%">
                <div class="recon-funnel-bar"></div>
                <div class="recon-funnel-label">
                    <i class="fa-solid ${icon}"></i>
                    <span class="recon-funnel-name">${escapeHtml(stage.stage.replace(/_/g, ' ').toUpperCase())}</span>
                    <span class="recon-funnel-count">${stage.count}</span>
                </div>
            </div>${arrow}`;
        }
        html += '</div>';

        html += '<div id="recon-kc-sparklines" class="recon-sparklines-row"></div>';

        html += '<div class="recon-stage-details">';
        for (const stage of data.stages) {
            if (stage.count === 0) continue;
            if (activeFilter && stage.stage !== activeFilter) continue;
            const stageCacheKey = getAttackSurfaceStageCacheKey(stage.stage, searchTerm);
            const stageData = tdcGet(stageCacheKey);
            const loadingMembers = Boolean(reconState.surfaceStageLoading[stageCacheKey]);
            const stagePreview = (!searchTerm && Array.isArray(stage.preview_networks)) ? stage.preview_networks : [];
            const loadedStageNets = stageData && Array.isArray(stageData.networks) ? stageData.networks : [];
            const nets = searchTerm ? loadedStageNets : mergeReconChipNetworks(stagePreview, loadedStageNets);
            const filteredCount = searchTerm && stageData ? Number(stageData.total || nets.length || 0) : stage.count;
            const remainingCount = Math.max(0, filteredCount - nets.length);
            if (searchTerm && !stageData && !loadingMembers) {
                stagesToHydrate.push({ stage: stage.stage, append: false, offset: 0, limit: surfaceStagePageLimit });
            } else if (!searchTerm && !stagePreview.length && !stageData && !loadingMembers && stage.count > 0) {
                stagesToHydrate.push({ stage: stage.stage, append: false, offset: 0, limit: surfaceStagePreviewLimit });
            }

            html += `<div class="recon-stage-block" data-stage="${escapeHtml(stage.stage)}">
                <div class="recon-stage-header"><span>${escapeHtml(stage.stage.replace(/_/g, ' ').toUpperCase())}</span> <span class="recon-badge">${filteredCount}</span></div>
                <div class="recon-stage-nets">`;
            if (loadingMembers && !nets.length) {
                html += '<div class="recon-loading-sm">Loading stage targets…</div>';
            } else if (nets.length === 0) {
                html += `<div class="recon-loading-sm">${searchTerm ? 'No targets matched this search in the selected stage.' : 'No targets available in this stage.'}</div>`;
            } else {
                for (const n of nets) {
                    let badges = '';
                    if (n.has_pmkid) badges += '<span class="recon-mini-badge recon-mini-badge--pmkid" title="PMKID">P</span>';
                    if (n.has_eapol_hash) badges += '<span class="recon-mini-badge recon-mini-badge--eapol" title="EAPOL Hash">E</span>';
                    const isChecked = reconState.surfaceBulk.has(n.mac);
                    const checkbox = `<input type="checkbox" class="recon-bulk-check" data-mac="${escapeHtml(n.mac)}" ${isChecked ? 'checked' : ''}>`;
                    let attackBtn = '';
                    if (n.has_pmkid || n.has_eapol_hash || stage.stage === 'hash_ready') {
                        attackBtn = `<button class="recon-quick-attack-btn" data-mac="${escapeHtml(n.mac)}" data-ssid="${escapeHtml(n.ssid || '')}" title="Quick Attack"><i class="fa-solid fa-bolt"></i></button>`;
                    }
                    html += `<div class="recon-net-chip" data-mac="${escapeHtml(n.mac)}">
                        ${checkbox}
                        <span class="recon-net-ssid">${escapeHtml(n.ssid || n.mac)}</span>
                        ${badges}
                        <span class="recon-net-enc">${escapeHtml(n.encryption)}</span>
                        ${attackBtn}
                    </div>`;
                }
            }
            if (loadingMembers && nets.length) {
                html += '<div class="recon-loading-sm">Loading more targets…</div>';
            } else if (remainingCount > 0) {
                html += `<button class="recon-expand-btn" data-load-stage="${escapeHtml(stage.stage)}" data-load-offset="${nets.length}" data-load-search="${escapeHtml(searchTerm)}">Load more (${remainingCount} remaining)</button>`;
            }
            html += '</div></div>';
        }
        html += '</div>';

        if (reconState.surfaceBulk.size > 0) {
            html += `<div class="recon-bulk-toolbar">
                <span>${reconState.surfaceBulk.size} selected</span>
                <button class="recon-bulk-btn" id="bulk-export"><i class="fa-solid fa-download"></i> Export</button>
                <button class="recon-bulk-btn recon-bulk-btn--danger" id="bulk-clear"><i class="fa-solid fa-xmark"></i> Clear</button>
            </div>`;
        }

        container.innerHTML = html;

        enableDynamicSectionCollapse(container, {
            titleSelector: '.recon-section-title',
            stateSet: reconState.surfaceCollapsed,
            keyPrefix: 'surface',
            dataAttr: 'surface-section',
            rerender: () => { renderAttackSurface(container); },
        });

        container.querySelectorAll('.recon-net-chip').forEach((chip) => {
            chip.addEventListener('click', (e) => {
                if (e.target.closest('.recon-bulk-check') || e.target.closest('.recon-quick-attack-btn')) return;
                selectTarget(chip.dataset.mac);
            });
        });
        container.querySelectorAll('.recon-bulk-check').forEach((cb) => {
            cb.addEventListener('change', (e) => {
                e.stopPropagation();
                if (cb.checked) reconState.surfaceBulk.add(cb.dataset.mac);
                else reconState.surfaceBulk.delete(cb.dataset.mac);
                renderAttackSurface(container);
            });
        });
        const bulkClear = container.querySelector('#bulk-clear');
        if (bulkClear) bulkClear.addEventListener('click', () => {
            reconState.surfaceBulk.clear();
            renderAttackSurface(container);
        });
        const bulkExport = container.querySelector('#bulk-export');
        if (bulkExport) bulkExport.addEventListener('click', () => {
            const macs = [...reconState.surfaceBulk];
            const lines = ['MAC,SSID,Encryption,Stage'];
            macs.forEach((targetMac) => {
                const row = getCachedReconRow(targetMac) || detailCacheGet(`target:${String(targetMac || '').trim().toUpperCase()}`);
                if (!row) return;
                lines.push(`"${row.mac}","${row.ssid || ''}","${row.encryption || ''}","${row.stage || ''}"`);
            });
            downloadFile('selected_networks.csv', lines.join('\n'), 'text/csv');
        });
        container.querySelectorAll('.recon-quick-attack-btn').forEach((btn) => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                showQuickAttackPopup(btn, btn.dataset.mac, btn.dataset.ssid);
            });
        });
        container.querySelectorAll('.recon-rec-card').forEach((card) => {
            card.addEventListener('click', () => selectTarget(card.dataset.mac));
        });
        container.querySelectorAll('.recon-funnel-step').forEach((el) => {
            el.style.cursor = 'pointer';
            el.addEventListener('click', () => {
                const stage = el.dataset.stage;
                reconState.surfaceStageFilter = reconState.surfaceStageFilter === stage ? null : stage;
                renderAttackSurface(container);
            });
        });
        loadKcSparklines();
        const searchInput = container.querySelector('#surface-search');
        if (searchInput) {
            searchInput.addEventListener('input', debounce(() => {
                reconState.surfaceSearch = searchInput.value;
                renderAttackSurface(container);
            }, 200));
        }
        syncSelectedHighlight();
        hydrateAttackSurfaceRecommendations(container);
        container.querySelectorAll('.recon-expand-btn').forEach((btn) => {
            if (btn.dataset.loadStage) {
                btn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    hydrateAttackSurfaceStage(container, btn.dataset.loadStage, btn.dataset.loadSearch || '', {
                        append: true,
                        offset: Number(btn.dataset.loadOffset || 0),
                        limit: surfaceStagePageLimit,
                    });
                });
            }
        });
        stagesToHydrate.forEach((job) => {
            hydrateAttackSurfaceStage(container, job.stage, searchTerm, {
                append: job.append,
                offset: job.offset,
                limit: job.limit,
            });
        });
    }

    return {
        renderAttackSurface,
    };
}
