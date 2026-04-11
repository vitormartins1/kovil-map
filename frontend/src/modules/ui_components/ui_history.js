import { API } from '../api.js';
import { escapeHtml } from '../utils.js';

export async function renderHistoryPanel(filename, containerElement, options = {}) {
    containerElement.style.display = 'flex';
    containerElement.style.flexDirection = 'column';
    containerElement.style.alignItems = 'flex-start';
    containerElement.style.gap = '5px';
    
    containerElement.innerHTML = `
        <div style="display:flex; align-items:center; gap:10px; width:100%;">
            <i class="fa-solid fa-clock-rotate-left" style="color: var(--neon-cyan)"></i> 
            <span style="color: var(--neon-cyan); font-weight:bold;">ATTACK HISTORY</span>
        </div>
        <div style="width:100%; text-align:center; padding:10px; color:#666;">
            <i class="fa-solid fa-spinner fa-spin"></i> Loading history...
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
        
        let historyHtml = '<div class="history-container">';
        
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
            historyHtml += '<div style="padding:10px; color:#666; text-align:center;">No history entries found.</div>';
        }
        
        historyHtml += '</div>';
        containerElement.innerHTML = historyHtml;
        
    } catch (e) {
        containerElement.innerHTML = `
            <div style="color: var(--neon-red);"><i class="fa-solid fa-triangle-exclamation"></i> Failed to load history file: ${escapeHtml(e.message)}</div>
        `;
    }
}
