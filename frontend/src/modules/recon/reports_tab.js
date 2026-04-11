export function createReportsRenderer(deps) {
    const {
        API,
        log,
        escapeHtml,
        reconState,
        reconHintLabel,
        tdcGet,
        tdcSet,
        renderReconFindingsPanel,
        downloadFile,
    } = deps;

    function reportSection(key, title, collapsed, contentFn) {
        const isCollapsed = collapsed.has(key);
        const arrow = isCollapsed ? '▸' : '▾';
        let html = `<div class="recon-section-toggle" data-section="${key}"><span class="recon-section-arrow">${arrow}</span> ${title}</div>`;
        html += `<div class="recon-report-block${isCollapsed ? ' recon-collapsed' : ''}">`;
        if (!isCollapsed) html += contentFn();
        html += '</div>';
        return html;
    }

    async function initReportHistory(container, renderReports) {
        const select = container.querySelector('#report-snapshot-select');
        const compareBtn = container.querySelector('#report-compare-btn');
        const snapBtn = container.querySelector('#report-snapshot-btn');
        const resultsDiv = container.querySelector('#report-compare-results');

        if (select) {
            try {
                const sl = await API.listReconReportSnapshots();
                const snaps = (sl && sl.snapshots) || [];
                for (const s of snaps.reverse()) {
                    const opt = document.createElement('option');
                    opt.value = s.id;
                    opt.textContent = s.id.replace(/_/g, ' ');
                    select.appendChild(opt);
                }
            } catch (_) {
                /* silent */
            }

            select.addEventListener('change', () => {
                if (compareBtn) compareBtn.disabled = !select.value;
            });
        }

        if (snapBtn) {
            snapBtn.addEventListener('click', async () => {
                snapBtn.disabled = true;
                try {
                    const res = await API.saveReconReportSnapshot();
                    if (res && res.snapshot_id && select) {
                        const opt = document.createElement('option');
                        opt.value = res.snapshot_id;
                        opt.textContent = res.snapshot_id.replace(/_/g, ' ');
                        select.prepend(opt);
                    }
                    log('recon', 'Report snapshot saved', 'info');
                } catch (e) {
                    log('recon', `Snapshot error: ${e.message}`, 'error');
                }
                snapBtn.disabled = false;
            });
        }

        if (compareBtn) {
            compareBtn.addEventListener('click', async () => {
                const snapId = select?.value;
                if (!snapId || !resultsDiv) return;
                compareBtn.disabled = true;
                try {
                    const delta = await API.compareReconReportSnapshot(snapId);
                    if (delta) {
                        let h = '<div class="recon-compare-grid">';
                        const metrics = ['total_networks', 'cracked', 'crack_rate_percent', 'crackable_remaining', 'with_handshake'];
                        const labels = { total_networks: 'Networks', cracked: 'Cracked', crack_rate_percent: 'Crack %', crackable_remaining: 'Crackable', with_handshake: 'Handshakes' };
                        for (const m of metrics) {
                            const d = delta[m] || {};
                            const cls = (d.delta || 0) > 0 ? 'recon-delta-up' : (d.delta || 0) < 0 ? 'recon-delta-down' : '';
                            const sign = (d.delta || 0) > 0 ? '+' : '';
                            h += `<div class="recon-compare-cell">
                                <div class="recon-compare-label">${labels[m] || m}</div>
                                <div class="recon-compare-vals">${d.old ?? '?'} → ${d.new ?? '?'}</div>
                                <div class="recon-compare-delta ${cls}">${sign}${d.delta ?? 0}</div>
                            </div>`;
                        }
                        h += '</div>';
                        resultsDiv.className = 'recon-compare-results';
                        resultsDiv.innerHTML = h;
                    }
                } catch (e) {
                    resultsDiv.className = 'recon-compare-results recon-empty-state recon-empty-state--warning';
                    resultsDiv.innerHTML = `<i class="fa-solid fa-circle-exclamation"></i><div><strong>Comparison failed</strong><span>${escapeHtml(e.message)}</span></div>`;
                }
                compareBtn.disabled = false;
            });
        }
    }

    async function renderReports(container) {
        const cacheKey = 'reports';
        let data;
        let healthData;
        const cached = tdcGet(cacheKey);
        if (cached) {
            ({ data, healthData } = cached);
        } else {
            [data, healthData] = await Promise.all([
                API.getReconAuditReport(),
                API.getDataHealthSummary().catch(() => null),
            ]);
            tdcSet(cacheKey, { data, healthData });
        }
        if (!data) {
            container.innerHTML = '<div class="recon-empty">Cannot generate report.</div>';
            return;
        }

        const f = data.findings;
        let html = '<div class="recon-report">';
        html += `<div class="recon-report-topbar">
            <div class="recon-report-intro recon-panel-card">
                <div>
                    <div class="recon-report-intro-title">Executive posture</div>
                    <div class="recon-report-intro-copy">Use this tab to summarize findings, compare historical snapshots and assess whether data collection quality is blocking the next phase.</div>
                </div>
                <span class="recon-badge recon-badge--dim">Audit</span>
            </div>
            <div class="recon-report-actions-panel recon-panel-card">
                <div class="recon-report-actions-title">Actions</div>
                <div class="recon-report-actions-btns">
                    <button class="recon-export-btn" id="report-export-md"><i class="fa-solid fa-file-lines"></i> EXPORT MD</button>
                    <button class="recon-export-btn" id="report-print"><i class="fa-solid fa-print"></i> PRINT</button>
                </div>
            </div>
        </div>`;

        const riskGrade = f.crack_rate_percent >= 60 ? 'A' : f.crack_rate_percent >= 40 ? 'B' : f.crack_rate_percent >= 20 ? 'C' : f.crack_rate_percent >= 10 ? 'D' : 'F';
        const gradeColor = { A: '#22c55e', B: '#2faad4', C: '#e6b422', D: '#e68a22', F: '#e63946' }[riskGrade] || '#7a8b92';
        html += '<div class="recon-report-pair">';
        html += `<div class="recon-report-pair-col">
            <div class="recon-section-toggle recon-section-toggle--static">SCORE</div>
            <div class="recon-exec-card">
            <div class="recon-exec-grade" style="--grade-color:${gradeColor}"><span>${riskGrade}</span></div>
            <div class="recon-exec-stats">
                <div class="recon-exec-big"><span class="recon-val-green">${f.cracked}</span> / ${f.total_networks}</div>
                <div class="recon-exec-label">CRACKED</div>
                <div class="recon-exec-rate">${f.crack_rate_percent}% success rate</div>
            </div>
            <div class="recon-exec-gauge">
                <div class="recon-gauge"><div class="recon-gauge-fill ${f.crack_rate_percent >= 60 ? 'score-high' : f.crack_rate_percent >= 30 ? 'score-mid' : 'score-low'}" style="width:${f.crack_rate_percent}%"></div></div>
            </div>
        </div></div>`;
        html += `<div class="recon-report-pair-col">
            <div class="recon-section-toggle recon-section-toggle--static">METHODOLOGY</div>
            <div class="recon-report-block">
                <div><strong>Tools:</strong> ${escapeHtml((data.methodology.tools || []).join(', ') || 'None')}</div>
                <div><strong>Sources:</strong> ${escapeHtml((data.methodology.sources || []).join(', ') || 'None')}</div>
                <div><strong>Networks Analyzed:</strong> ${data.methodology.total_networks_analyzed}</div>
            </div>
        </div>`;
        html += '</div>';

        const collapsed = reconState.reportCollapsed;
        html += reportSection('findings', 'FINDINGS', collapsed, () => renderReconFindingsPanel(f));

        const s = data.statistics;
        html += '<div class="recon-report-pair">';
        html += '<div class="recon-report-pair-col">';
        html += reportSection('statistics', 'STATISTICS', collapsed, () => {
            let inner = '';
            if (s.first_observation) inner += `<div class="recon-report-row"><span>First Observation</span><span>${escapeHtml(s.first_observation)}</span></div>`;
            if (s.last_observation) inner += `<div class="recon-report-row"><span>Last Observation</span><span>${escapeHtml(s.last_observation)}</span></div>`;
            if (s.observation_span_days != null) inner += `<div class="recon-report-row"><span>Span (days)</span><span>${s.observation_span_days}</span></div>`;
            return inner;
        });
        html += '</div>';
        if (data.risk_scoring && data.risk_scoring.length) {
            html += '<div class="recon-report-pair-col">';
            html += reportSection('risk-scoring', 'RISK SCORING', collapsed, () => {
                let inner = '<table class="recon-risk-table"><thead><tr><th>Encryption</th><th>Total</th><th>Cracked</th><th>Rate</th><th>Grade</th></tr></thead><tbody>';
                const gradeColors = { A: '#22c55e', B: '#2faad4', C: '#e6b422', D: '#e68a22', F: '#e63946', 'N/A': '#7a8b92' };
                for (const rs of data.risk_scoring) {
                    const gc = gradeColors[rs.grade] || '#7a8b92';
                    inner += `<tr>
                        <td>${escapeHtml(rs.encryption)}</td>
                        <td>${rs.total}</td>
                        <td>${rs.cracked}</td>
                        <td>${rs.crack_rate}%</td>
                        <td><span class="recon-grade-badge" style="background:${gc}">${escapeHtml(rs.grade)}</span></td>
                    </tr>`;
                }
                inner += '</tbody></table>';
                return inner;
            });
            html += '</div>';
        }
        html += '</div>';

        if (data.recommendations && data.recommendations.length) {
            html += reportSection('recommendations', 'RECOMMENDATIONS', collapsed, () => {
                let inner = '';
                const priColors = { high: '#e63946', medium: '#e68a22', low: '#2faad4' };
                for (const rec of data.recommendations) {
                    const color = priColors[rec.priority] || '#7a8b92';
                    inner += `<div class="recon-rec-row">
                        <span class="recon-rec-priority" style="background:${color}">${escapeHtml((rec.priority || '').toUpperCase())}</span>
                        <span class="recon-rec-action">${escapeHtml(rec.action)}</span>
                        <span class="recon-rec-desc">${escapeHtml(rec.description)} (${rec.count || 0})</span>
                    </div>`;
                }
                return inner;
            });
        }

        if (data.coverage) {
            html += reportSection('coverage', 'COVERAGE ANALYSIS', collapsed, () => {
                const c = data.coverage;
                let inner = '<div class="recon-coverage-grid">';
                const items = [
                    { label: 'Total', val: c.total },
                    { label: reconHintLabel('GPS', 'with_gps'), val: c.with_gps, pct: c.with_gps_pct },
                    { label: 'Fingerprint', val: c.with_fingerprint, pct: c.with_fingerprint_pct },
                    { label: 'Raw Data', val: c.with_raw_data, pct: c.with_raw_data_pct },
                    { label: 'Hash', val: c.with_hash, pct: c.with_hash_pct },
                    { label: reconHintLabel('Multi-Source', 'multi_source'), val: c.multi_source, pct: c.multi_source_pct },
                ];
                for (const it of items) {
                    inner += `<div class="recon-coverage-item">
                        <span class="recon-coverage-val">${it.val ?? '—'}</span>
                        <span class="recon-coverage-label">${it.label}</span>
                        ${it.pct != null ? `<div class="recon-gauge recon-gauge--mini"><div class="recon-gauge-fill score-mid" style="width:${it.pct}%"></div></div><span class="recon-coverage-pct">${it.pct}%</span>` : ''}
                    </div>`;
                }
                inner += '</div>';
                return inner;
            });
        }

        html += '<div class="recon-report-pair">';
        html += '<div class="recon-report-pair-col">';
        html += reportSection('checklist', 'COMPLIANCE CHECKLIST', collapsed, () => {
            if (!reconState.reportChecklist) {
                try {
                    reconState.reportChecklist = JSON.parse(localStorage.getItem('recon_checklist') || '{}');
                } catch (_) {
                    reconState.reportChecklist = {};
                }
            }
            const checks = [
                { id: 'auth', label: 'Authorization obtained before testing' },
                { id: 'scope', label: 'Scope of engagement documented' },
                { id: 'evidence', label: 'Evidence preserved for all findings' },
                { id: 'notification', label: 'Stakeholders notified of critical findings' },
                { id: 'remediation', label: 'Remediation plan created' },
                { id: 'data-handling', label: 'Captured data handled per policy' },
                { id: 'retesting', label: 'Re-testing scheduled after remediation' },
            ];
            let inner = '<div class="recon-checklist">';
            for (const ch of checks) {
                const checked = reconState.reportChecklist[ch.id] ? 'checked' : '';
                inner += `<label class="recon-checklist-item"><input type="checkbox" class="recon-checklist-check" data-check-id="${ch.id}" ${checked}> ${escapeHtml(ch.label)}</label>`;
            }
            inner += '</div>';
            return inner;
        });
        html += '</div>';
        if (healthData) {
            html += '<div class="recon-report-pair-col">';
            html += reportSection('data-health', 'DATA QUALITY', collapsed, () => {
                let inner = '';
                const h = healthData;
                const hs = h.handshakes || {};
                const ds = h.dataset || {};
                const br = h.bruce || {};
                const m5 = h.m5evil || {};
                const rs = h.rawsniffer || {};
                const numOrNull = (...values) => {
                    for (const value of values) {
                        const n = Number(value);
                        if (Number.isFinite(n)) return n;
                    }
                    return null;
                };

                const invalidDetails = numOrNull(h.invalid_details, hs.invalid_details);
                const missingDetails = numOrNull(
                    h.missing_details,
                    (Number(br.missing_details) || 0) + (Number(m5.missing_details) || 0),
                );
                const orphanedHandshakes = numOrNull(h.orphaned_handshakes, hs.handshake_without_details);
                const totalNetworks = numOrNull(h.total_networks, ds.total_networks);
                const networksWithGps = numOrNull(h.networks_with_gps, ds.with_gps);
                const networksWithoutGps = numOrNull(h.networks_without_gps, ds.no_gps);
                const totalHandshakes = numOrNull(h.total_handshakes, hs.pcap_files);
                const pendingRawFiles = numOrNull(h.pending_raw_files, rs.pending_files);

                inner += '<div class="recon-coverage-grid recon-coverage-grid--wide">';
                if (invalidDetails != null) inner += `<div class="recon-coverage-item"><span class="recon-coverage-val ${invalidDetails > 0 ? 'recon-val-red' : ''}">${invalidDetails}</span><span class="recon-coverage-label">${reconHintLabel('Invalid details', 'invalid_details')}</span></div>`;
                if (missingDetails != null) inner += `<div class="recon-coverage-item"><span class="recon-coverage-val ${missingDetails > 0 ? 'recon-val-orange' : ''}">${missingDetails}</span><span class="recon-coverage-label">${reconHintLabel('Missing details', 'missing_details')}</span></div>`;
                if (orphanedHandshakes != null) inner += `<div class="recon-coverage-item"><span class="recon-coverage-val ${orphanedHandshakes > 0 ? 'recon-val-orange' : ''}">${orphanedHandshakes}</span><span class="recon-coverage-label">${reconHintLabel('Orphaned handshakes', 'orphaned_handshakes')}</span></div>`;
                if (networksWithoutGps != null) inner += `<div class="recon-coverage-item"><span class="recon-coverage-val ${networksWithoutGps > 0 ? 'recon-val-orange' : ''}">${networksWithoutGps}</span><span class="recon-coverage-label">${reconHintLabel('Without GPS', 'without_gps')}</span></div>`;
                inner += '</div>';
                if (totalNetworks != null) inner += `<div class="recon-report-row"><span>Total Networks</span><span>${totalNetworks}</span></div>`;
                if (invalidDetails != null) inner += `<div class="recon-report-row"><span>${reconHintLabel('Invalid Details', 'invalid_details')}</span><span class="${invalidDetails > 0 ? 'recon-val-red' : ''}">${invalidDetails}</span></div>`;
                if (missingDetails != null) inner += `<div class="recon-report-row"><span>${reconHintLabel('Missing Details', 'missing_details')}</span><span class="${missingDetails > 0 ? 'recon-val-orange' : ''}">${missingDetails}</span></div>`;
                if (pendingRawFiles != null) inner += `<div class="recon-report-row"><span>${reconHintLabel('Pending RAW Files', 'pending_raw_files')}</span><span>${pendingRawFiles}</span></div>`;
                if (totalHandshakes != null) inner += `<div class="recon-report-row"><span>Total Handshakes</span><span>${totalHandshakes}</span></div>`;
                if (orphanedHandshakes != null) inner += `<div class="recon-report-row"><span>${reconHintLabel('Orphaned Handshakes', 'orphaned_handshakes')}</span><span class="${orphanedHandshakes > 0 ? 'recon-val-orange' : ''}">${orphanedHandshakes}</span></div>`;
                if (networksWithGps != null) inner += `<div class="recon-report-row"><span>Networks w/ GPS</span><span>${networksWithGps}</span></div>`;
                if (networksWithoutGps != null) inner += `<div class="recon-report-row"><span>${reconHintLabel('Networks w/o GPS', 'without_gps')}</span><span class="${networksWithoutGps > 0 ? 'recon-val-orange' : ''}">${networksWithoutGps}</span></div>`;
                if (!inner.trim()) inner = '<div class="recon-empty">No data quality metrics available yet.</div>';
                return inner;
            });
            html += '</div>';
        }
        html += '</div>';

        html += `<div class="recon-section-title">HISTORICAL COMPARISON</div>
        <div class="recon-history-panel recon-panel-card">
        <div class="recon-section-note">Save a snapshot before major imports or cracking campaigns, then compare deltas against the current dataset.</div>
        <div class="recon-history-controls">
            <button id="report-snapshot-btn" class="recon-btn recon-btn--sm"><i class="fa-solid fa-camera"></i> Take Snapshot</button>
            <select id="report-snapshot-select" class="recon-select recon-select--sm"><option value="">Compare with…</option></select>
            <button id="report-compare-btn" class="recon-btn recon-btn--sm" disabled><i class="fa-solid fa-code-compare"></i> Compare</button>
        </div>
        <div id="report-compare-results" class="recon-compare-results recon-empty-state recon-empty-state--soft"><i class="fa-solid fa-clock-rotate-left"></i><div><strong>No comparison loaded</strong><span>Select a snapshot to inspect growth, regressions and data drift.</span></div></div></div>`;

        html += `<div class="recon-report-footer">Generated: ${escapeHtml(data.generated_at)}</div>`;
        html += '</div>';
        container.innerHTML = html;

        initReportHistory(container, renderReports);

        container.querySelectorAll('.recon-section-toggle').forEach((btn) => {
            btn.addEventListener('click', () => {
                const key = btn.dataset.section;
                if (collapsed.has(key)) collapsed.delete(key);
                else collapsed.add(key);
                renderReports(container);
            });
        });

        const exportMd = container.querySelector('#report-export-md');
        if (exportMd) {
            exportMd.addEventListener('click', () => {
                let md = `# Audit Report\n\nGenerated: ${data.generated_at}\n\n`;
                md += `## Executive Summary\n- Grade: ${riskGrade}\n- Cracked: ${f.cracked} / ${f.total_networks} (${f.crack_rate_percent}%)\n\n`;
                md += `## Methodology\n- Tools: ${(data.methodology.tools || []).join(', ')}\n- Sources: ${(data.methodology.sources || []).join(', ')}\n- Networks Analyzed: ${data.methodology.total_networks_analyzed}\n\n`;
                md += '## Findings\n| Metric | Value |\n|--------|-------|\n';
                md += `| Total Networks | ${f.total_networks} |\n| Cracked | ${f.cracked} |\n| Crackable Remaining | ${f.crackable_remaining} |\n| With Handshake | ${f.with_handshake} |\n| EAPOL Evidence | ${f.with_eapol_evidence} |\n| Crack Rate | ${f.crack_rate_percent}% |\n\n`;
                if (f.encryption_distribution) {
                    md += '### Encryption Distribution\n';
                    for (const [enc, count] of Object.entries(f.encryption_distribution)) {
                        md += `- ${enc}: ${count}\n`;
                    }
                    md += '\n';
                }
                md += '## Statistics\n';
                if (s.first_observation) md += `- First Observation: ${s.first_observation}\n`;
                if (s.last_observation) md += `- Last Observation: ${s.last_observation}\n`;
                if (s.observation_span_days != null) md += `- Span: ${s.observation_span_days} days\n`;
                downloadFile('audit_report.md', md, 'text/markdown');
            });
        }

        const printBtn = container.querySelector('#report-print');
        if (printBtn) {
            printBtn.addEventListener('click', () => window.print());
        }

        container.querySelectorAll('.recon-checklist-check').forEach((cb) => {
            cb.addEventListener('change', () => {
                if (!reconState.reportChecklist) reconState.reportChecklist = {};
                reconState.reportChecklist[cb.dataset.checkId] = cb.checked;
                try {
                    localStorage.setItem('recon_checklist', JSON.stringify(reconState.reportChecklist));
                } catch (_) {
                    /* ignore storage failures */
                }
            });
        });
    }

    return {
        renderReports,
    };
}
