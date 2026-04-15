import { API } from '../api.js';
import { log, escapeHtml } from '../utils.js';
import { STATE, saveModes } from '../state.js';
import { updateTargetsList, updateNoGpsList } from './ui_lists.js';
import { updateMarkerStatusByMac } from '../map.js';
import { openCrackingPanel, updateCrackingPanelStatus, selectedFile } from './ui_cracking.js';
import { openBatchFromProcess } from '../ui.js';
import { Platform } from '../platform.js';

export let activeProcesses = {}; // Armazena processos ativos: { jobId: { type, details, percentage, status, extraInfo, indeterminate, mac } }

function notifyRightPanelsModeChanged() {
    document.dispatchEvent(new CustomEvent('rightPanelsModeChanged'));
}
const CRACKING_SYNC_DEBOUNCE_MS = 300;
const PROCESS_LIST_DEBOUNCE_MS = 400;
const PROCESS_PERCENT_THRESHOLD = 1;
let syncCrackingTimer = null;
let processListTimer = null;
const PERFORMANCE_DEBUG = false;
const PROCESS_STATUS_DEBUG = false;
const PROCESS_RENDER_THROTTLE_MS = 600;
let lastProcessRenderTs = 0;
const PROCESS_SUCCESS_STATUSES = new Set([
    'COMPLETED',
    'CRACKED',
    'SUCCESS',
    'UP TO DATE',
    'UP_TO_DATE',
    'PARTIAL',
    'SKIPPED',
]);
const PROCESS_FAILURE_STATUSES = new Set([
    'FAILED',
    'ERROR',
    'EXHAUSTED',
    'NO HANDSHAKE',
    'CANCELED',
]);
const PROCESS_WARNING_STATUSES = new Set([
    'AUTOTUNING',
    'BUILDING CACHE',
    'INIT KERNELS',
    'QUEUED',
]);
const PROCESS_FINISHED_STATUSES = new Set([
    ...PROCESS_SUCCESS_STATUSES,
    ...PROCESS_FAILURE_STATUSES,
]);

function normalizeProcessText(value) {
    if (value === null || value === undefined) return "";
    if (typeof value === "string") return value;
    if (Array.isArray(value)) {
        return value.map((item) => normalizeProcessText(item)).join(" ");
    }
    try {
        return JSON.stringify(value);
    } catch (_e) {
        return String(value);
    }
}

function normalizeProcessExtraInfo(value) {
    const raw = normalizeProcessText(value).trim();
    if (!raw) return "";
    return raw
        .split("|")
        .map((part) => part.trim())
        .filter(Boolean)
        .join(" | ");
}

export function getActiveHashcatJob() {
    const runningStatuses = ['RUNNING', 'AUTOTUNING', 'BUILDING CACHE', 'INIT KERNELS'];
    return Object.values(activeProcesses).find(proc =>
        proc.type && proc.type.includes("HASHCAT") && runningStatuses.includes(proc.status)
    ) || null;
}

export function addProcess(jobId, type, details, status = "STARTING", mac = null) {
    activeProcesses[jobId] = {
        type: normalizeProcessText(type || "PROCESS"),
        details: normalizeProcessText(details),
        percentage: 0,
        status: normalizeProcessText(status || "STARTING"),
        extraInfo: "",
        indeterminate: false,
        mac,
    };
    scheduleProcessListRender();
    updateTargetsList(); 
    scheduleCrackingSync();
    
    if (!STATE.modes.process) {
        document.getElementById('btn-process').click();
    }
    
    Platform.togglePowerSave(true);
}

export function updateProcess(jobId, percentage, status, extraInfo = "", indeterminate = false) {
    if (activeProcesses[jobId]) {
        const prev = activeProcesses[jobId];
        const prevStatus = (prev.status || '').trim().toUpperCase();
        const nextStatus = normalizeProcessText(status || '').trim().toUpperCase();
        const prevFinished = PROCESS_FINISHED_STATUSES.has(prevStatus);
        const nextFinished = PROCESS_FINISHED_STATUSES.has(nextStatus);

        // Sync progress events are emitted fire-and-forget, so a delayed RUNNING
        // update can arrive after the API response has already finalized a process.
        // Ignore those stale regressions to keep completed imports terminal in the UI.
        if (prevFinished && !nextFinished) {
            return;
        }

        const statusChanged = prevStatus !== nextStatus;
        const percentChanged = Math.abs((prev.percentage || 0) - (percentage || 0)) >= PROCESS_PERCENT_THRESHOLD;
        const normalizedExtraInfo = normalizeProcessExtraInfo(extraInfo);
        const extraChanged = (normalizedExtraInfo && normalizedExtraInfo !== prev.extraInfo);
        const shouldRender = statusChanged || percentChanged || extraChanged || (prev.indeterminate !== indeterminate);
        const shouldUpdateTargets = statusChanged;
        
        activeProcesses[jobId].percentage = percentage;
        activeProcesses[jobId].status = nextStatus || normalizeProcessText(status);
        activeProcesses[jobId].indeterminate = indeterminate;
        if (normalizedExtraInfo) {
            activeProcesses[jobId].extraInfo = normalizedExtraInfo;
        }
        if (PROCESS_STATUS_DEBUG) {
            const msg = statusChanged
                ? `[process] status change job=${jobId} ${prevStatus} -> ${nextStatus}`
                : `[process] update job=${jobId} status=${nextStatus} (no change)`;
            log(msg, 'info');
            console.log(msg);
        }

        if (shouldRender) scheduleProcessListRender();
        
        if (shouldUpdateTargets) {
            updateTargetsList();
        }
        if (statusChanged) {
            scheduleCrackingSync();
        }
        
        // Update Cracking Panel if open and relevant
        if (selectedFile && selectedFile.name === activeProcesses[jobId].details) {
            updateCrackingPanelStatus(activeProcesses[jobId]);
        }
    }
}

export function removeProcess(jobId) {
    if (activeProcesses[jobId]) {
        delete activeProcesses[jobId];
        scheduleProcessListRender();
        updateTargetsList(); 
        scheduleCrackingSync();
    }
}

export function clearFinishedProcesses() {
    const finishedIds = Object.entries(activeProcesses)
        .filter(([, proc]) => PROCESS_FINISHED_STATUSES.has(String(proc?.status || '').trim().toUpperCase()))
        .map(([jobId]) => jobId);

    if (finishedIds.length === 0) return 0;

    finishedIds.forEach((jobId) => {
        delete activeProcesses[jobId];
    });

    scheduleProcessListRender();
    updateTargetsList();
    scheduleCrackingSync();
    return finishedIds.length;
}

function scheduleCrackingSync() {
    if (syncCrackingTimer) clearTimeout(syncCrackingTimer);
    syncCrackingTimer = setTimeout(() => {
        syncCrackingTimer = null;
        syncActiveCrackingState();
    }, CRACKING_SYNC_DEBOUNCE_MS);
}

export async function cancelProcess(jobId) {
    try {
        log(`Canceling job ${jobId}...`, 'warn');
        await API.cancelJob(jobId);
        if (activeProcesses[jobId]) {
            activeProcesses[jobId].status = "CANCELED";
            activeProcesses[jobId].percentage = 0;
            activeProcesses[jobId].indeterminate = false;
            scheduleProcessListRender();
            scheduleCrackingSync();
        }
    } catch (e) {
        log(`Failed to cancel job: ${e.message}`, 'error');
    }
}

function scheduleProcessListRender() {
    const now = Date.now();
    const earliest = lastProcessRenderTs + PROCESS_RENDER_THROTTLE_MS;
    const delay = Math.max(PROCESS_LIST_DEBOUNCE_MS, earliest - now);
    if (processListTimer) return;
    processListTimer = setTimeout(() => {
        processListTimer = null;
        requestAnimationFrame(() => {
            lastProcessRenderTs = Date.now();
            renderProcessList();
        });
    }, delay);
}

export function renderProcessList() {
    const startTs = PERFORMANCE_DEBUG ? performance.now() : 0;
    const list = document.getElementById('process-list');

    if (Object.keys(activeProcesses).length === 0) {
        list.innerHTML = '<div style="padding: 20px; text-align: center; color: #666; font-style: italic;">NO ACTIVE PROCESSES</div>';
        return;
    }
    
    if (list.children.length === 1 && list.innerText.includes('NO ACTIVE PROCESSES')) {
        list.innerHTML = '';
    }

    Array.from(list.children).forEach(child => {
        const id = child.getAttribute('data-job-id');
        if (id && !activeProcesses[id]) {
            child.remove();
        }
    });

    Object.entries(activeProcesses).forEach(([jobId, proc]) => {
        let item = list.querySelector(`.process-item[data-job-id="${jobId}"]`);
        
        let barColor = 'var(--neon-cyan)';
        if (PROCESS_SUCCESS_STATUSES.has(proc.status)) barColor = 'var(--neon-green)';
        if (PROCESS_FAILURE_STATUSES.has(proc.status)) barColor = 'var(--neon-red)';
        if (PROCESS_WARNING_STATUSES.has(proc.status)) barColor = 'var(--neon-yellow)';

        const isFinished = PROCESS_FINISHED_STATUSES.has(proc.status);

        if (!item) {
            item = document.createElement('div');
            item.className = 'process-item';
            item.setAttribute('data-job-id', jobId);
            
            let actionBtnHtml = '';
            if (isFinished) {
                actionBtnHtml = `<i class="fa-solid fa-xmark process-remove" data-id="${jobId}" title="Remove Process"></i>`;
            } else if (proc.noCancel) {
                actionBtnHtml = '';
            } else {
                actionBtnHtml = `<i class="fa-solid fa-hand process-cancel" data-id="${jobId}" title="Cancel Process" style="color: var(--neon-yellow);"></i>`;
            }

            item.innerHTML = `
                <div class="process-info">
                    <div class="process-header">
                        <div class="process-name-wrapper">
                            <span class="process-type">${escapeHtml(proc.type)}</span>
                            <span class="process-details">${escapeHtml(proc.details)}</span>
                        </div>
                        <div class="process-status-container">
                            <span class="process-status" style="color: ${barColor}">${escapeHtml(proc.status)}</span>
                            ${actionBtnHtml}
                        </div>
                    </div>
                    <div class="progress-bar-container">
                        <div class="progress-bar" style="width: ${proc.percentage}%; background-color: ${barColor}"></div>
                        <div class="progress-text">${proc.percentage}% ${proc.extraInfo ? `| ${escapeHtml(proc.extraInfo)}` : ''}</div>
                    </div>
                </div>
            `;
            list.appendChild(item);
        } else {
            const statusEl = item.querySelector('.process-status');
            const statusContainer = item.querySelector('.process-status-container');
            const barEl = item.querySelector('.progress-bar');
            const textEl = item.querySelector('.progress-text');
            
            if (statusEl.innerText !== proc.status) statusEl.innerText = proc.status;
            if (statusEl.style.color !== barColor) statusEl.style.color = barColor;

            const existingRemoveBtn = item.querySelector('.process-remove');
            const existingCancelBtn = item.querySelector('.process-cancel');
            
            if (isFinished) {
                if (existingCancelBtn) existingCancelBtn.remove();
                if (!existingRemoveBtn) {
                    const btn = document.createElement('i');
                    btn.className = 'fa-solid fa-xmark process-remove';
                    btn.setAttribute('data-id', jobId);
                    btn.setAttribute('title', 'Remove Process');
                    statusContainer.appendChild(btn);
                }
            } else {
                if (existingRemoveBtn) existingRemoveBtn.remove();
                if (proc.noCancel) {
                    if (existingCancelBtn) existingCancelBtn.remove();
                } else {
                    if (!existingCancelBtn) {
                        const btn = document.createElement('i');
                        btn.className = 'fa-solid fa-hand process-cancel';
                        btn.setAttribute('data-id', jobId);
                        btn.setAttribute('title', 'Cancel Process');
                        btn.style.color = 'var(--neon-yellow)';
                        statusContainer.appendChild(btn);
                    }
                }
            }

            if (proc.indeterminate) {
                barEl.classList.add('indeterminate');
                barEl.style.width = '100%';
            } else {
                barEl.classList.remove('indeterminate');
                const widthStr = `${proc.percentage}%`;
                if (barEl.style.width !== widthStr) barEl.style.width = widthStr;
            }
            if (barEl.style.backgroundColor !== barColor) barEl.style.backgroundColor = barColor;

            let textStr = `${proc.percentage}% ${proc.extraInfo ? `| ${proc.extraInfo}` : ''}`;
            if (proc.indeterminate) {
                textStr = proc.extraInfo || "RUNNING...";
            }
            if (textEl.textContent !== textStr) textEl.textContent = textStr;
        }
    });

    if (PERFORMANCE_DEBUG) {
        const elapsed = performance.now() - startTs;
        console.log(`[perf] renderProcessList ${elapsed.toFixed(1)}ms`);
    }
}

export async function restoreActiveJobs() {
    try {
        const jobs = await API.listJobs();
        let batches = [];
        try {
            const batchList = await API.listMultiFiles();
            if (Array.isArray(batchList)) {
                batches = batchList;
            }
        } catch (e) {
            // ignore batch list errors for restore
        }
        const active = jobs.filter(j => 
            j.status === 'running' || 
            j.status === 'pending' || 
            j.status === 'queued' ||
            j.status === 'started'
        );

        if (active.length > 0) {
            log(`Restoring ${active.length} active jobs...`, 'info');
            
            active.forEach(job => {
                let details = "Unknown";
                let type = "PROCESS";
                let cmdStr = Array.isArray(job.command) ? job.command.join(' ') : job.command;

                if (job.type === 'cracking') {
                    type = "CRACKING (HASHCAT)";
                    const match = cmdStr.match(/[/\\]([^/\\]+\.22000)/);
                    if (match) details = match[1];
                } else if (job.type === 'conversion') {
                    type = "GENERATE HASH (22000)";
                    const match = cmdStr.match(/[/\\]([^/\\]+\.pcap)/);
                    if (match) details = match[1];
                } else if (job.type === 'conversion_multi') {
                    type = "MULTI CONVERSION";
                    const metaOutput = job.meta && job.meta.output_file ? job.meta.output_file : null;
                    let selectedBatch = metaOutput;
                    if (!selectedBatch && job.start_time && batches.length > 0) {
                        const jobTs = Date.parse(job.start_time);
                        if (!Number.isNaN(jobTs)) {
                            let bestDiff = Infinity;
                            batches.forEach(b => {
                                const batchTs = (b.modified || 0) * 1000;
                                const diff = Math.abs(batchTs - jobTs);
                                if (diff < bestDiff) {
                                    bestDiff = diff;
                                    selectedBatch = b.name;
                                }
                            });
                        }
                    }
                    if (!selectedBatch && batches.length > 0) {
                        selectedBatch = batches[0].name;
                    }
                    details = selectedBatch || "multi";
                } else if (job.type === 'sync_import') {
                    type = job.meta?.display_type || "SYNC";
                    details = job.meta?.display_details || details;
                } else if (job.type === 'fingerprint_multi') {
                    type = "BRUCE PCAP IMPORT";
                    const count = job.meta?.files_to_process?.length || job.progress_data?.total_steps || '';
                    details = count ? `Import ${count} files` : "Bruce";
                } else if (job.type === 'rawsniffer_multi') {
                    type = "RAW SNIFFER";
                    const count = job.meta?.files_to_process?.length || job.progress_data?.total_steps || '';
                    details = count ? `Process ${count} files` : "Bruce RAW";
                } else if (job.type === 'raw_prepare_all') {
                    type = "RAW SNIFFER PREPARE ALL";
                    const count = job.progress_data?.total_steps || 0;
                    const mac = job.meta?.bssid || "";
                    details = mac
                        ? (count ? `${mac} (${count} files)` : mac)
                        : (count ? `Process ${count} files` : "RAW context");
                } else if (job.type === 'aircrack') {
                    type = "AIRCRACK-NG";
                    const match = cmdStr.match(/[/\\]([^/\\]+\.pcap)/);
                    if (match) details = match[1];
                } else if (job.meta?.display_type || job.meta?.display_details) {
                    type = job.meta?.display_type || type;
                    details = job.meta?.display_details || details;
                }

                const mac = extractMacFromDetails(details);
                addProcess(job.id, type, details, job.status.toUpperCase(), mac);
                if (job.meta?.no_cancel && activeProcesses[job.id]) {
                    activeProcesses[job.id].noCancel = true;
                }
                if (job.progress_data) {
                    updateProcess(
                        job.id,
                        job.progress_data.percentage || 0,
                        job.progress_data.stage || (job.status || '').toUpperCase(),
                        job.progress_data.extra || '',
                        false
                    );
                }
            });
            
            if (!STATE.modes.process) {
                document.getElementById('btn-process').click();
            }
        }
    } catch (e) {
        console.error("Failed to restore jobs:", e);
    }
}

export function syncActiveCrackingState() {
    const startTs = PERFORMANCE_DEBUG ? performance.now() : 0;
    const runningStatuses = ['RUNNING', 'QUEUED', 'STARTING', 'AUTOTUNING', 'BUILDING CACHE', 'INIT KERNELS'];

    const nextByMac = {};
    Object.values(activeProcesses).forEach(proc => {
        if ((proc.type.includes("HASHCAT") || proc.type.includes("AIRCRACK") || proc.type.includes("22000")) && runningStatuses.includes(proc.status)) {
            let mac = proc.mac || null;
            if (!mac && proc.details) {
                mac = extractMacFromDetails(proc.details);
            }
            if (mac) {
                nextByMac[mac] = { status: proc.status, type: proc.type };
            }
        }
    });

    const changedMacs = diffCrackingMacs(STATE.crackingByMac, nextByMac);
    const wasCrackingActive = STATE.isCrackingActive;
    STATE.crackingByMac = nextByMac;
    STATE.activeCrackingStatus = nextByMac;
    STATE.isCrackingActive = Object.keys(nextByMac).length > 0;

    if (changedMacs.length > 0) {
        changedMacs.forEach(mac => updateMarkerStatusByMac(mac));
    }

    if (wasCrackingActive !== STATE.isCrackingActive) {
        document.dispatchEvent(new CustomEvent(STATE.isCrackingActive ? 'crackingActive' : 'crackingIdle'));
    }

    if (PERFORMANCE_DEBUG) {
        const elapsed = performance.now() - startTs;
        console.log(`[perf] syncActiveCrackingState ${elapsed.toFixed(1)}ms`);
    }
}

function extractMacFromDetails(details) {
    if (!details || typeof details !== 'string') return null;
    const macWithColons = details.match(/([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})/);
    if (macWithColons) return macWithColons[1].toUpperCase();
    const macCleanMatch = details.match(/([0-9A-Fa-f]{12})/);
    if (macCleanMatch) {
        return macCleanMatch[1].match(/.{1,2}/g).join(':').toUpperCase();
    }
    const parts = details.split('.');
    const nameWithoutExt = parts.slice(0, -1).join('.') || details;
    const nameParts = nameWithoutExt.split('_');
    if (nameParts.length >= 2) {
        const macClean = nameParts[nameParts.length - 1];
        if (macClean.length === 12) {
            return macClean.match(/.{1,2}/g).join(':').toUpperCase();
        }
    }
    return null;
}

function buildCrackingByMac(activeCracking) {
    const map = {};
    Object.entries(activeCracking).forEach(([details, statusObj]) => {
        const mac = extractMacFromDetails(details);
        if (!mac) return;
        const status = typeof statusObj === 'object' ? statusObj.status : statusObj;
        const type = typeof statusObj === 'object' ? statusObj.type : null;
        map[mac] = { status, type };
    });
    return map;
}

function diffCrackingMacs(prevMap, nextMap) {
    const changed = new Set();
    const prevKeys = Object.keys(prevMap || {});
    const nextKeys = Object.keys(nextMap || {});
    prevKeys.forEach(mac => {
        if (!nextMap[mac]) changed.add(mac);
        else if (prevMap[mac].status !== nextMap[mac].status || prevMap[mac].type !== nextMap[mac].type) {
            changed.add(mac);
        }
    });
    nextKeys.forEach(mac => {
        if (!prevMap[mac]) changed.add(mac);
    });
    return Array.from(changed);
}

export function setupProcessListeners() {
    document.getElementById('btn-process').addEventListener('click', function() {
        STATE.modes.process = !STATE.modes.process;
        this.classList.toggle('active');
        const processPanel = document.getElementById('process-panel');
        processPanel.style.display = STATE.modes.process ? 'flex' : 'none';
        saveModes();
        notifyRightPanelsModeChanged();
        
        if (STATE.modes.process && Object.keys(activeProcesses).length === 0) {
            renderProcessList();
        }
    });

    document.querySelector('#process-panel .close-panel').addEventListener('click', () => {
        STATE.modes.process = false;
        document.getElementById('process-panel').style.display = 'none';
        document.getElementById('btn-process').classList.remove('active');
        saveModes();
        notifyRightPanelsModeChanged();
    });

    const processClearBtn = document.getElementById('btn-process-clear');
    if (processClearBtn) {
        processClearBtn.addEventListener('click', () => {
            clearFinishedProcesses();
        });
    }

    document.getElementById('process-list').addEventListener('click', (e) => {
        if (e.target.classList.contains('process-remove')) {
            const id = e.target.getAttribute('data-id');
            removeProcess(id);
        } else if (e.target.classList.contains('process-cancel')) {
            const id = e.target.getAttribute('data-id');
            cancelProcess(id);
        } else {
            const item = e.target.closest('.process-item');
            if (item) {
                const jobId = item.getAttribute('data-job-id');
                const proc = activeProcesses[jobId];
                if (proc && proc.details) {
                    const filename = proc.details;
                    let macClean = "";
                    const parts = filename.split('.');
                    const nameWithoutExt = parts.slice(0, -1).join('.'); 
                    const nameParts = nameWithoutExt.split('_');
                    
                    if (nameParts.length >= 2) {
                        macClean = nameParts[nameParts.length - 1];
                    }
                    
                    let targetPos = null;
                    if (macClean.length === 12) {
                        const macFormatted = macClean.match(/.{1,2}/g).join(':').toUpperCase();
                        targetPos = STATE.allPositions[macFormatted];
                    }
                    
                    if (!targetPos) {
                        targetPos = Object.values(STATE.allPositions).find(p => {
                            const pMacClean = p.mac.replace(/:/g, '').toLowerCase();
                            return filename.toLowerCase().includes(pMacClean);
                        });
                    }

                    const isBatchProcess = proc.type === "MULTI CONVERSION" || (filename && filename.toLowerCase().startsWith('batch_'));
                    if (isBatchProcess) {
                        openBatchFromProcess(filename);
                        return;
                    }

                    if (targetPos) {
                        openCrackingPanel(targetPos.mac, targetPos.ssid, filename);
                    } else {
                        let ssid = "UNKNOWN";
                        if (nameParts.length >= 2) {
                             ssid = nameParts.slice(0, -1).join('_');
                        }
                        if (macClean.length === 12) {
                             const macFormatted = macClean.match(/.{1,2}/g).join(':').toUpperCase();
                             openCrackingPanel(macFormatted, ssid, filename);
                        }
                    }
                }
            }
        }
    });
}

export function handleJobCompletionSideEffects(job) {
    // Lógica para atualizar lista de arquivos No-GPS quando conversores terminam
    const jobType = activeProcesses[job.id].type; // Usa tipo local mapeado
    const details = activeProcesses[job.id].details;

    if (jobType.includes("GENERATE HASH")) {
        if (details) {
            let newFile = "";
            if (jobType.includes("22000")) newFile = details.replace(/\.pcap$/i, '.22000');
            
            // Tenta achar a rede e adicionar o arquivo na lista localmente para feedback instantâneo
            // (O reloadData via WS vai acontecer, mas isso é visualmente mais rápido)
            const parts = details.split('.');
            const nameWithoutExt = parts.slice(0, -1).join('.');
            const nameParts = nameWithoutExt.split('_');
            let macClean = "";
            if (nameParts.length >= 2) macClean = nameParts[nameParts.length - 1];
            
            let targetPos = null;
            if (macClean.length === 12) {
                const macFormatted = macClean.match(/.{1,2}/g).join(':').toUpperCase();
                targetPos = STATE.allPositions[macFormatted];
            }
            
            if (targetPos) {
                if (!targetPos.handshake_files) targetPos.handshake_files = [];
                if (!targetPos.handshake_files.includes(newFile)) {
                    targetPos.handshake_files.push(newFile);
                    updateNoGpsList();
                }
            }
        }
    }
    
    // Se o painel de cracking estiver aberto para este arquivo, atualiza a UI
    if (selectedFile && selectedFile.name === details) {
        const mac = document.getElementById('crack-mac').innerText;
        const ssid = document.getElementById('crack-ssid').innerText;
        openCrackingPanel(mac, ssid, details);
    }
}
