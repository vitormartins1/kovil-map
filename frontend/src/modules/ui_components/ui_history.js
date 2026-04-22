import { API } from '../api.js';
import { escapeHtml } from '../utils.js';

export async function renderHistoryPanel(filename, containerElement, options = {}) {
    containerElement.style.display = 'flex';
    containerElement.style.flexDirection = 'column';
    containerElement.style.alignItems = 'stretch';
    containerElement.style.gap = '8px';
    
    containerElement.innerHTML = `
        <div class="crack-artifact-summary">
            <div class="crack-artifact-summary-head">
                <div>
                    <div class="crack-artifact-summary-kicker">Attack history</div>
                    <div class="crack-artifact-summary-title">${escapeHtml(filename)}</div>
                </div>
                <div class="crack-artifact-summary-badges">
                    <span class="file-type-tag badge-history">TRY</span>
                </div>
            </div>
            <div class="crack-summary-note"><i class="fa-solid fa-spinner fa-spin"></i> Loading history...</div>
        </div>
    `;

    try {
        const content = await API.getFileContent(filename, options);
        let history;
        try {
            history = JSON.parse(content);
        } catch (e) {
            throw new Error("Invalid JSON content");
        }
        
        let historyHtml = `
            <div class="crack-artifact-summary">
                <div class="crack-artifact-summary-head">
                    <div>
                        <div class="crack-artifact-summary-kicker">Attack history</div>
                        <div class="crack-artifact-summary-title">${escapeHtml(filename)}</div>
                    </div>
                    <div class="crack-artifact-summary-badges">
                        <span class="file-type-tag badge-history">TRY</span>
                    </div>
                </div>
            </div>
            <div class="history-container">
        `;
        
        if (history.entries && history.entries.length > 0) {
            // Sort by start_time desc
            history.entries.sort((a, b) => new Date(b.start_time) - new Date(a.start_time));
            
            history.entries.forEach(entry => {
                const date = new Date(entry.start_time).toLocaleString();
                const statusClass = `status-${entry.status.toLowerCase()}`;
                const tagClass = `tag-${entry.status.toLowerCase()}`;
                
                let paramsHtml = '';
                if (entry.params) {
                    paramsHtml = '<div class="history-params">';
                    Object.entries(entry.params).forEach(([k, v]) => {
                        if (v !== null && v !== undefined && v !== "") {
                            paramsHtml += `<span>${escapeHtml(k)}: ${escapeHtml(String(v))}</span>`;
                        }
                    });
                    paramsHtml += '</div>';
                }
                
                let resultHtml = '';
                if (entry.result) {
                    resultHtml = `<div class="history-result">${escapeHtml(entry.result)}</div>`;
                }

                let metaHtml = '';
                if (entry.meta && entry.meta.length > 0) {
                    metaHtml = '<div class="history-meta-section">';
                    entry.meta.forEach(m => {
                        metaHtml += `<div class="meta-line">${escapeHtml(m)}</div>`;
                    });
                    metaHtml += '</div>';
                }

                let durationHtml = '';
                if (entry.duration) {
                    durationHtml = `<span class="history-duration"><i class="fa-solid fa-stopwatch"></i> ${escapeHtml(entry.duration)}</span>`;
                }

                historyHtml += `
                    <div class="history-entry ${statusClass}">
                        <div class="history-status-tag ${tagClass}">${escapeHtml(entry.status)}</div>
                        <div class="history-header">
                            <span class="tool-name">${escapeHtml(entry.tool)}</span>
                            <span class="history-date">${date}</span>
                            ${durationHtml}
                        </div>
                        ${paramsHtml}
                        <div class="history-details" title="Click to expand/collapse">${escapeHtml(entry.command)}</div>
                        ${metaHtml}
                        ${resultHtml}
                    </div>
                `;
            });
        } else {
            historyHtml += '<div class="details-footer-meta" style="padding:10px; text-align:center;">No history entries found.</div>';
        }
        
        historyHtml += '</div>';
        containerElement.innerHTML = historyHtml;
        
    } catch (e) {
        containerElement.innerHTML = `
            <div class="crack-artifact-summary">
                <div class="crack-artifact-summary-head">
                    <div>
                        <div class="crack-artifact-summary-kicker">Attack history</div>
                        <div class="crack-artifact-summary-title">${escapeHtml(filename)}</div>
                    </div>
                    <div class="crack-artifact-summary-badges">
                        <span class="file-type-tag badge-history">TRY</span>
                    </div>
                </div>
                <div class="crack-summary-warnings">
                    <div><i class="fa-solid fa-triangle-exclamation"></i> Failed to load history file: ${escapeHtml(e.message)}</div>
                </div>
            </div>
        `;
    }
}
