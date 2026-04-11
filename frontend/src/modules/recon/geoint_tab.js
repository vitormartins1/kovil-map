export function createGeointRenderer(deps) {
    const {
        API,
        escapeHtml,
        reconHintLabel,
        tdcGet,
        tdcSet,
        enableDynamicSectionCollapse,
        reconState,
    } = deps;

    async function renderGeoint(container) {
        const cacheKey = 'geoint';
        let data;
        const cached = tdcGet(cacheKey);
        if (cached) {
            data = cached;
        } else {
            data = await API.getReconTemporalIntel();
            if (data) tdcSet(cacheKey, data);
        }
        if (!data) {
            container.innerHTML = '<div class="recon-empty">No temporal data available.</div>';
            return;
        }

        const spanDays = (data.first_seen && data.last_seen)
            ? Math.max(1, Math.round((new Date(data.last_seen) - new Date(data.first_seen)) / 86400000))
            : 0;
        let html = `<div class="recon-kpi-row">
            <div class="recon-kpi"><span class="recon-kpi-val">${data.total_networks}</span><span class="recon-kpi-label">NETWORKS</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${data.freshness.active_24h}</span><span class="recon-kpi-label">ACTIVE 24H</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${data.freshness.active_7d}</span><span class="recon-kpi-label">ACTIVE 7D</span></div>
            <div class="recon-kpi"><span class="recon-kpi-val">${spanDays ? `${spanDays}d` : '—'}</span><span class="recon-kpi-label">SPAN</span></div>
        </div>`;

        const fresh = data.freshness;
        const freshTotal = (fresh.active_24h || 0) + (fresh.active_7d || 0) + (fresh.stale_30d || 0) + (fresh.ancient || 0);
        html += '<div class="recon-section-title">FRESHNESS</div>';

        if (freshTotal > 0) {
            html += '<div class="recon-freshness-stacked">';
            const segs = [
                { key: 'active_24h', label: '<24H', color: '#22c55e', count: fresh.active_24h || 0 },
                { key: 'active_7d', label: '<7D', color: '#2faad4', count: fresh.active_7d || 0 },
                { key: 'stale_30d', label: '<30D', color: '#e6b422', count: fresh.stale_30d || 0 },
                { key: 'ancient', label: '>30D', color: '#7a8b92', count: fresh.ancient || 0 },
            ];
            for (const seg of segs) {
                if (seg.count <= 0) continue;
                const pct = Math.round((seg.count / freshTotal) * 100);
                html += `<div class="recon-freshness-seg" style="width:${pct}%;background:${seg.color}" title="${seg.label}: ${seg.count} (${pct}%)"><span>${seg.count}</span></div>`;
            }
            html += '</div>';
        }

        html += '<div class="recon-freshness-grid">';
        const freshnessColors = { active_24h: '#22c55e', active_7d: '#2faad4', stale_30d: '#e6b422', ancient: '#7a8b92' };
        const freshnessLabels = { active_24h: '< 24H', active_7d: '< 7D', stale_30d: '< 30D', ancient: '> 30D' };
        for (const [key, count] of Object.entries(data.freshness)) {
            html += `<div class="recon-freshness-card" style="--fc:${freshnessColors[key] || '#7a8b92'}">
                <div class="recon-freshness-val">${count}</div>
                <div class="recon-freshness-label">${freshnessLabels[key] || key}</div>
            </div>`;
        }
        html += '</div>';

        if (data.hour_distribution && data.hour_distribution.length && data.day_distribution) {
            html += '<div class="recon-section-title">ACTIVITY HEATMAP</div>';
            html += '<div class="recon-section-note">Approximate weekly activity density using the temporal distribution currently available.</div>';
            html += '<div class="recon-heatmap-wrap">';
            const hourCounts = data.hour_distribution.map((h) => h.count);
            const dayLabels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
            const dayCounts = (data.day_distribution || []).map((d) => d.count);
            const maxCell = Math.max(...hourCounts, 1) * Math.max(...dayCounts, 1);

            html += '<div class="recon-heatmap">';
            html += '<div class="recon-heatmap-row"><div class="recon-heatmap-day-label"></div>';
            for (let h = 0; h < 24; h += 3) {
                html += `<div class="recon-heatmap-hour-label" style="flex:3">${h}h</div>`;
            }
            html += '</div>';

            for (let d = 0; d < 7; d++) {
                html += `<div class="recon-heatmap-row"><div class="recon-heatmap-day-label">${dayLabels[d]}</div>`;
                for (let h = 0; h < 24; h++) {
                    const val = (hourCounts[h] || 0) * (dayCounts[d] || 0);
                    const intensity = maxCell > 0 ? Math.min(val / maxCell, 1) : 0;
                    const alpha = Math.round(intensity * 0.9 * 100) / 100;
                    html += `<div class="recon-heatmap-cell" style="background:rgba(47,170,212,${alpha + 0.05})" title="${dayLabels[d]} ${h}:00"></div>`;
                }
                html += '</div>';
            }
            html += '</div></div>';
        }

        if (data.hour_distribution && data.hour_distribution.length) {
            const topHourSet = new Set((data.top_active_hours || []).map((h) => h.hour));
            html += '<div class="recon-section-title">HOUR DISTRIBUTION</div><div class="recon-hour-chart">';
            const maxH = Math.max(...data.hour_distribution.map((h) => h.count), 1);
            for (const h of data.hour_distribution) {
                const pct = Math.round((h.count / maxH) * 100);
                const pctOfTotal = data.total_networks > 0 ? Math.round((h.count / data.total_networks) * 100) : 0;
                const isPeak = topHourSet.has(h.hour);
                html += `<div class="recon-hour-bar${isPeak ? ' recon-hour-bar--peak' : ''}" title="${escapeHtml(h.hour)}: ${h.count} (${pctOfTotal}%)${isPeak ? ' ★ PEAK' : ''}">
                    <div class="recon-hour-fill" style="height:${pct}%${isPeak ? ';background:#e6b422' : ''}"></div>
                    <span class="recon-hour-label">${h.hour.replace(':00', '')}</span>
                    ${isPeak ? '<span class="recon-hour-peak-dot"></span>' : ''}
                </div>`;
            }
            html += '</div>';
        }

        const bySource = data.by_source || {};
        const sourceNames = Object.keys(bySource);
        let orderedSources = [];
        if (sourceNames.length > 0) {
            html += '<div class="recon-section-title">ACTIVITY BY SOURCE</div>';
            const srcColors = { pwnagotchi: '#e63946', wardrive: '#2faad4', bruce: '#22c55e', brucegotchi: '#22c55e', m5evil: '#e6b422', unknown: '#7a8b92' };
            const normSource = (value) => String(value || '').toLowerCase().replace(/[\s_-]+/g, '');
            const emptyHourDist = Array.from({ length: 24 }, (_, i) => ({ hour: `${String(i).padStart(2, '0')}:00`, count: 0 }));
            const mergeSourceInfo = (keys) => {
                const mergedHours = new Array(24).fill(0);
                let mergedTotal = 0;
                let mergedGps = 0;
                let mergedGpsOrigin = 0;
                for (const key of keys) {
                    const info = bySource[key] || {};
                    mergedTotal += Number(info.total || 0);
                    mergedGps += Number(info.gps_count || 0);
                    mergedGpsOrigin += Number(info.gps_origin_count || 0);
                    const hourDist = info.hour_distribution || [];
                    for (let i = 0; i < 24; i++) {
                        mergedHours[i] += Number(hourDist[i]?.count || 0);
                    }
                }
                return {
                    total: mergedTotal,
                    gps_count: mergedGps,
                    gps_origin_count: mergedGpsOrigin,
                    hour_distribution: mergedHours.map((count, i) => ({ hour: `${String(i).padStart(2, '0')}:00`, count })),
                };
            };
            const sourcePresets = [
                { id: 'pwnagotchi', label: 'PWNAGOTCHI HANDSHAKE', color: '#e63946', aliases: ['pwnagotchi', 'pwn', 'pwnagochi'] },
                { id: 'brucegotchi', label: 'BRUCEGOTCHI HANDSHAKE', color: '#22c55e', aliases: ['brucegotchi', 'bruce'] },
                { id: 'bruce_raw_sniffing', label: 'BRUCE RAW SNIFFING', color: '#2faad4', aliases: ['bruce_raw_sniffing', 'bruce_raw', 'bruceraw', 'bruce_rawsniffer', 'bruce_raw_sniffer'] },
                { id: 'm5evil', label: 'M5EVIL HANDSHAKE', color: '#e6b422', aliases: ['m5evil', 'm5 evil', 'm5evel'] },
                { id: 'm5evil_raw_sniffing', label: 'M5EVIL RAW SNIFFING', color: '#c678dd', aliases: ['m5evil_raw_sniffing', 'm5evil_raw', 'm5evilraw', 'm5evil_rawsniffer', 'm5evil_raw_sniffer', 'm5evel_raw_sniffing', 'm5evel_raw', 'm5evelraw'] },
                { id: 'm5evil_master_raw_sniffing', label: 'M5EVIL MASTER RAW SNIFFING', color: '#ff6b6b', aliases: ['m5evil_master_raw_sniffing', 'm5evil_master_sniffing', 'm5evil_master', 'm5evilmaster', 'm5evel_master_raw_sniffing', 'm5evel_master_sniffing', 'm5evel_master', 'm5evelmaster'] },
            ];

            const resolvedSources = new Set();
            orderedSources = [];
            for (const preset of sourcePresets) {
                const matchedKeys = sourceNames.filter((src) => preset.aliases.some((alias) => normSource(src) === normSource(alias)));
                if (matchedKeys.length > 0) {
                    orderedSources.push({
                        key: preset.id,
                        label: preset.label,
                        color: preset.color,
                        info: mergeSourceInfo(matchedKeys),
                    });
                    for (const mk of matchedKeys) resolvedSources.add(mk);
                } else {
                    orderedSources.push({
                        key: preset.id,
                        label: preset.label,
                        color: preset.color,
                        info: { total: 0, gps_count: 0, gps_origin_count: 0, hour_distribution: emptyHourDist.map((h) => ({ ...h })) },
                    });
                }
            }

            for (const src of sourceNames) {
                if (resolvedSources.has(src)) continue;
                orderedSources.push({
                    key: src,
                    label: src.toUpperCase(),
                    color: srcColors[src] || '#7a8b92',
                    info: bySource[src],
                });
            }

            html += '<div class="recon-source-split">';
            for (const entry of orderedSources) {
                const info = entry.info || { total: 0, hour_distribution: emptyHourDist };
                const color = entry.color || '#7a8b92';
                const label = entry.label || entry.key;
                html += `<div class="recon-source-block">
                    <div class="recon-source-header"><span class="recon-dot" style="background:${color}"></span> ${escapeHtml(label)} <span class="recon-badge">${info.total || 0}</span></div>
                    <div class="recon-source-mini-chart">`;
                const hourDistribution = info.hour_distribution || emptyHourDist;
                const maxH = Math.max(...hourDistribution.map((h) => h.count), 1);
                for (const h of hourDistribution) {
                    const pct = Math.round((h.count / maxH) * 100);
                    html += `<div class="recon-source-bar" style="height:${pct}%;background:${color}" title="${escapeHtml(h.hour)}: ${h.count}"></div>`;
                }
                html += '</div></div>';
            }
            html += '</div>';
        }

        {
            const totalGps = data.total_gps || 0;
            const totalWithout = data.total_networks - totalGps;
            const coveragePct = data.total_networks ? Math.round((totalGps / data.total_networks) * 100) : 0;
            const gpsOrigin = data.gps_origin || {};
            html += '<div class="recon-section-title">SPATIAL COVERAGE</div>';
            html += '<div class="recon-geo-coverage recon-panel-card">';
            html += `<div class="recon-coverage-grid recon-coverage-grid--wide">
                <div class="recon-coverage-item"><span class="recon-coverage-val">${totalGps}</span><span class="recon-coverage-label">${reconHintLabel('With GPS', 'with_gps')}</span></div>
                <div class="recon-coverage-item"><span class="recon-coverage-val">${Math.max(totalWithout, 0)}</span><span class="recon-coverage-label">${reconHintLabel('Without coordinates', 'without_coordinates')}</span></div>
                <div class="recon-coverage-item"><span class="recon-coverage-val">${coveragePct}%</span><span class="recon-coverage-label">${reconHintLabel('Coverage rate', 'coverage_rate')}</span></div>
            </div>`;
            const originEntries = Object.entries(gpsOrigin).filter(([, v]) => v > 0);
            if (originEntries.length > 0 && totalGps > 0) {
                html += '<div class="recon-section-note">GPS origin — which source provided the coordinates</div>';
                html += '<div class="recon-geo-origin-grid">';
                const originColors = {
                    pwnagotchi: '#e63946',
                    'wardrive:bruce': '#22c55e',
                    'wardrive:m5evil': '#e6b422',
                    'wardrive:uncategorized': '#7a8b92',
                    wardrive: '#2faad4',
                    unknown: '#7a8b92',
                };
                const originLabels = {
                    pwnagotchi: 'PWNAGOTCHI HANDSHAKE GPS',
                    'wardrive:bruce': 'WARDRIVE BRUCE',
                    'wardrive:m5evil': 'WARDRIVE M5EVIL',
                    'wardrive:uncategorized': 'WARDRIVE UNCATEGORIZED',
                    wardrive: 'WARDRIVE',
                    unknown: 'UNKNOWN',
                };
                for (const [src, count] of originEntries.sort((a, b) => b[1] - a[1])) {
                    const pct = Math.round((count / totalGps) * 100);
                    const color = originColors[src] || '#7a8b92';
                    const label = originLabels[src] || src.toUpperCase().replace(':', ' ');
                    html += `<div class="recon-geo-origin-row">
                        <div class="recon-geo-origin-label"><span class="recon-dot" style="background:${color}"></span>${escapeHtml(label)}</div>
                        <div class="recon-geo-origin-bar-wrap">
                            <div class="recon-geo-origin-bar" style="width:${pct}%;background:${color}"></div>
                        </div>
                        <div class="recon-geo-origin-val">${count} (${pct}%)</div>
                    </div>`;
                }
                html += '</div>';
            }
            if (orderedSources && orderedSources.length > 0) {
                html += '<div class="recon-section-note">GPS coverage by source</div>';
                html += '<div class="recon-geo-source-grid">';
                for (const entry of orderedSources) {
                    const srcTotal = (entry.info && entry.info.total) || 0;
                    const srcGps = (entry.info && entry.info.gps_count) || 0;
                    const srcOrigin = (entry.info && entry.info.gps_origin_count) || 0;
                    const srcPct = srcTotal > 0 ? Math.round((srcGps / srcTotal) * 100) : 0;
                    const color = entry.color || '#7a8b92';
                    html += `<div class="recon-geo-source-row">
                        <div class="recon-geo-source-label"><span class="recon-dot" style="background:${color}"></span>${escapeHtml(entry.label)}</div>
                        <div class="recon-geo-source-bar-wrap">
                            <div class="recon-geo-source-bar" style="width:${srcPct}%;background:${color}"></div>
                        </div>
                        <div class="recon-geo-source-val">${srcGps}/${srcTotal} (${srcPct}%)${srcOrigin > 0 ? ` · <span style="color:${color};font-weight:600">${srcOrigin} origin</span>` : ''}</div>
                    </div>`;
                }
                html += '</div>';
            }
            if (totalGps === 0) {
                html += `<div class="recon-empty-state recon-empty-state--soft">
                    <i class="fa-solid fa-location-dot"></i>
                    <div>
                        <strong>No geo-tagged networks available</strong>
                        <span>The main project map remains the right place for geographic exploration once coordinates are present.</span>
                    </div>
                </div>`;
            }
            html += '</div>';
        }

        const anomalies = data.anomalies || [];
        if (anomalies.length > 0) {
            html += '<div class="recon-section-title">ANOMALY ALERTS</div>';
            html += '<div class="recon-anomaly-list">';
            for (const a of anomalies) {
                const icon = a.type === 'spike' ? 'fa-arrow-trend-up' : 'fa-pause';
                const cls = a.type === 'spike' ? 'recon-anomaly--spike' : 'recon-anomaly--gap';
                html += `<div class="recon-anomaly-item ${cls}">
                    <i class="fa-solid ${icon}"></i>
                    <span>${escapeHtml(a.description)}</span>
                </div>`;
            }
            html += '</div>';
        }

        container.innerHTML = html;

        enableDynamicSectionCollapse(container, {
            titleSelector: '.recon-section-title',
            stateSet: reconState.geoCollapsed,
            keyPrefix: 'geo',
            dataAttr: 'geo-section',
            rerender: () => { renderGeoint(container); },
        });
    }

    return {
        renderGeoint,
    };
}
