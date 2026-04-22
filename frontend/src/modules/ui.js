import { STATE, saveLists, saveModes } from './state.js';
import { API } from './api.js';
import { Socket } from './socket.js';
import { renderMarkers, calculateZones, calculateToConquerZones, calculateDiscoveredZones, calculateIntelligenceZones, clearDetailsCache, clearAnalyticsHeatmapLayer, clearAnalyticsHotspotsLayer } from './map.js';
import { log, bootLog } from './utils.js';
import { Platform } from './platform.js';
import {
    STARTUP_PROGRESS,
    buildCrackingTitle,
    resetAppTitle,
    setAppTitle,
    setBootStepState,
    setBootVisualState,
} from './ui_shell.js';

const ENABLE_MOCK_NETWORKS = false;

// Importando módulos refatorados
import { uiConfig, applyClientConfig, openSettings, closeSettings, renderDemoDataStatus, saveSettings } from './ui_components/ui_settings.js';
import { updateTargetsList, updateFavsList, updateZonesList, updateToConquerZonesList, updateDiscoveredZonesList, updateIntelligenceZonesList, updateNoGpsList, updateMultiList, updateMultiFilesList, updateMultiContentsList } from './ui_components/ui_lists.js';
import { activeProcesses, addProcess, updateProcess, restoreActiveJobs, renderProcessList, setupProcessListeners, handleJobCompletionSideEffects, getActiveHashcatJob } from './ui_components/ui_processes.js';
import { openMultiCrackingPanel, setupCrackingListeners, clearHistory } from './ui_components/ui_cracking.js';
import { setupRawListeners, refreshRawFiles } from './ui_raw.js';
import { clearReconRuntimeCache, primeReconCacheManifest, setupReconListeners, refreshReconPanel, setReconWorkspaceActive } from './ui_recon.js';
import { setupMultiListeners, handleMultiCreate, handleMultiClear, refreshMultiFiles, loadMultiContents } from './ui_multi.js';
import { deactivateWardriveMode, markWardriveDirty, prewarmWardriveWorkspace, refreshWardriveIfActive, setupWardriveListeners } from './ui_wardrive.js';
import { setupGlobalHints } from './ui_components/ui_hints.js';

function updateFilterClearButtonVisibility(value) {
    const clearButton = document.getElementById('btn-filter-clear');
    if (!clearButton) return;
    const hasValue = Boolean(String(value || '').trim());
    clearButton.hidden = !hasValue;
    clearButton.setAttribute('aria-hidden', hasValue ? 'false' : 'true');
}

function applyMainSearchFilter(value, { render = false } = {}) {
    const normalized = String(value || '').toLowerCase();
    STATE.filters.search = normalized;
    updateFilterClearButtonVisibility(normalized);

    if (render) {
        renderMarkers(STATE.allPositions, true);
        calculateZones(STATE.allPositions);
        calculateToConquerZones(STATE.allPositions);
        calculateDiscoveredZones(STATE.allPositions);
        if (STATE.modes.intelligence) calculateIntelligenceZones();
    }

    if (STATE.modes.noGps) updateNoGpsList();
    if (STATE.modes.multi) updateMultiList();
}

function setupNoGpsFilterListeners() {
    const searchInput = document.getElementById('no-gps-filter-search');
    const deviceSelect = document.getElementById('no-gps-filter-device');
    const statusSelect = document.getElementById('no-gps-filter-status');
    const visibilitySelect = document.getElementById('no-gps-filter-visibility');
    const artifactSelect = document.getElementById('no-gps-filter-artifact');
    const resetButton = document.getElementById('btn-no-gps-filter-reset');

    if (!STATE.noGpsUi || typeof STATE.noGpsUi !== 'object') {
        STATE.noGpsUi = {
            search: '',
            device: 'all',
            status: 'all',
            visibility: 'all',
            artifact: 'all'
        };
    }

    const syncAndRender = () => {
        if (searchInput) STATE.noGpsUi.search = String(searchInput.value || '').trim().toLowerCase();
        if (deviceSelect) STATE.noGpsUi.device = deviceSelect.value || 'all';
        if (statusSelect) STATE.noGpsUi.status = statusSelect.value || 'all';
        if (visibilitySelect) STATE.noGpsUi.visibility = visibilitySelect.value || 'all';
        if (artifactSelect) STATE.noGpsUi.artifact = artifactSelect.value || 'all';
        updateNoGpsList();
    };

    if (searchInput) {
        searchInput.value = STATE.noGpsUi.search || '';
        searchInput.addEventListener('input', syncAndRender);
    }
    if (deviceSelect) {
        deviceSelect.value = STATE.noGpsUi.device || 'all';
        deviceSelect.addEventListener('change', syncAndRender);
    }
    if (statusSelect) {
        statusSelect.value = STATE.noGpsUi.status || 'all';
        statusSelect.addEventListener('change', syncAndRender);
    }
    if (visibilitySelect) {
        visibilitySelect.value = STATE.noGpsUi.visibility || 'all';
        visibilitySelect.addEventListener('change', syncAndRender);
    }
    if (artifactSelect) {
        artifactSelect.value = STATE.noGpsUi.artifact || 'all';
        artifactSelect.addEventListener('change', syncAndRender);
    }

    if (resetButton) {
        resetButton.addEventListener('click', () => {
            STATE.noGpsUi = {
                search: '',
                device: 'all',
                status: 'all',
                visibility: 'all',
                artifact: 'all'
            };
            if (searchInput) searchInput.value = '';
            if (deviceSelect) deviceSelect.value = 'all';
            if (statusSelect) statusSelect.value = 'all';
            if (visibilitySelect) visibilitySelect.value = 'all';
            if (artifactSelect) artifactSelect.value = 'all';
            updateNoGpsList();
        });
    }
}

export function initUI() {
    setBootVisualState({
        statusText: 'Initializing...',
        pillText: 'Boot',
        tone: 'boot',
        progress: STARTUP_PROGRESS.init,
        progressLabel: 'Starting startup pipeline',
        subtitle: 'Preparing backend services, telemetry caches and the map workspace.',
        tip: 'The app checks the backend first, then loads discovered networks and finally renders the main cockpit.',
    });
    setBootStepState('backend', 'active', 'Waiting for local API');
    setBootStepState('dataset', null, 'Network inventory not loaded yet');
    setBootStepState('workspace', null, 'Waiting to render cockpit');

    setupEventListeners();
    setupWindowControls(); 
    checkBackendStatus();

    // WarDrive should never auto-boot as an active workspace.
    STATE.modes.wardrive = false;
    localStorage.setItem('pwn_mode_wardrive', JSON.stringify(false));
    
    // Inicializa WebSocket
    Socket.connect();
    setupSocketListeners();

    restoreActiveJobs(); 
    
    // Restore panel states
    if (STATE.modes.zones) {
        document.getElementById('btn-zones').classList.add('active');
        document.getElementById('zones-panel').style.display = 'flex';
    }
    if (STATE.modes.toConquer) {
        document.getElementById('btn-to-conquer').classList.add('active');
    }
    if (STATE.modes.conquered) {
        document.getElementById('btn-conquered').classList.add('active');
    }
    if (STATE.modes.discovered) {
        document.getElementById('btn-discovered').classList.add('active');
    }
    if (STATE.modes.intelligence) {
        document.getElementById('btn-intelligence').classList.add('active');
    }
    if (STATE.modes.targets) {
        document.getElementById('btn-targets').classList.add('active');
        document.getElementById('targets-panel').style.display = 'flex';
    }
    if (STATE.modes.favs) {
        document.getElementById('btn-favs').classList.add('active');
        document.getElementById('favorites-panel').style.display = 'flex';
    }
    // Restore Right Panels
    if (STATE.modes.cracking) {
        document.getElementById('btn-toggle-cracking').classList.add('active');
        document.getElementById('cracking-panel').style.display = 'flex';
    }
    if (STATE.modes.process) {
        document.getElementById('btn-process').classList.add('active');
        document.getElementById('process-panel').style.display = 'flex';
        if (Object.keys(activeProcesses).length === 0) {
            renderProcessList();
        }
    }
    if (STATE.modes.logs) {
        document.getElementById('btn-logs').classList.add('active');
        document.getElementById('log-panel').style.display = 'block';
    } else {
        document.getElementById('btn-logs').classList.remove('active');
        document.getElementById('log-panel').style.display = 'none';
    }
    syncRightPanelsLayout();
    syncLeftPanelsLayout();
    setReconWorkspaceActive(false);

    // Restore No-GPS panel state
    const analyticsPanel = document.getElementById('analytics-panel');
    const btnAnalyticsView = document.getElementById('btn-analytics-view');
    if (STATE.modes.noGps) {
        document.getElementById('btn-no-gps-view').classList.add('active');
        document.getElementById('btn-map-view').classList.remove('active');
        document.getElementById('no-gps-panel').style.display = 'flex';
        document.getElementById('multi-panel').style.display = 'none';
        const rawPanel = document.getElementById('raw-panel');
        if (rawPanel) rawPanel.style.display = 'none';
        document.getElementById('btn-multi-view').classList.remove('active');
        const btnRaw = document.getElementById('btn-raw-view');
        if (btnRaw) btnRaw.classList.remove('active');
        if (btnAnalyticsView) btnAnalyticsView.classList.remove('active');
        if (analyticsPanel) analyticsPanel.style.display = 'none';
        setReconWorkspaceActive(false);
    } else {
        document.getElementById('btn-map-view').classList.add('active');
        document.getElementById('btn-no-gps-view').classList.remove('active');
        document.getElementById('no-gps-panel').style.display = 'none';
        if (btnAnalyticsView) btnAnalyticsView.classList.remove('active');
        if (analyticsPanel) analyticsPanel.style.display = 'none';
        setReconWorkspaceActive(false);
    }
    if (STATE.modes.multi) {
        document.getElementById('btn-multi-view').classList.add('active');
        document.getElementById('btn-map-view').classList.remove('active');
        const btnRaw = document.getElementById('btn-raw-view');
        if (btnRaw) btnRaw.classList.remove('active');
        if (btnAnalyticsView) btnAnalyticsView.classList.remove('active');
        document.getElementById('no-gps-panel').style.display = 'none';
        document.getElementById('multi-panel').style.display = 'flex';
        const rawPanel = document.getElementById('raw-panel');
        if (rawPanel) rawPanel.style.display = 'none';
        if (analyticsPanel) analyticsPanel.style.display = 'none';
        setReconWorkspaceActive(false);
    }
    if (STATE.modes.raw) {
        const btnRaw = document.getElementById('btn-raw-view');
        if (btnRaw) btnRaw.classList.add('active');
        document.getElementById('btn-map-view').classList.remove('active');
        document.getElementById('btn-no-gps-view').classList.remove('active');
        document.getElementById('btn-multi-view').classList.remove('active');
        if (btnAnalyticsView) btnAnalyticsView.classList.remove('active');
        document.getElementById('no-gps-panel').style.display = 'none';
        document.getElementById('multi-panel').style.display = 'none';
        const rawPanel = document.getElementById('raw-panel');
        if (rawPanel) rawPanel.style.display = 'flex';
        if (analyticsPanel) analyticsPanel.style.display = 'none';
        setReconWorkspaceActive(false);
        refreshRawFiles();
    }
    if (STATE.modes.analytics) {
        if (btnAnalyticsView) btnAnalyticsView.classList.add('active');
        document.getElementById('btn-map-view').classList.remove('active');
        document.getElementById('btn-no-gps-view').classList.remove('active');
        document.getElementById('btn-multi-view').classList.remove('active');
        const btnRaw = document.getElementById('btn-raw-view');
        if (btnRaw) btnRaw.classList.remove('active');
        document.getElementById('no-gps-panel').style.display = 'none';
        document.getElementById('multi-panel').style.display = 'none';
        const rawPanel = document.getElementById('raw-panel');
        if (rawPanel) rawPanel.style.display = 'none';
        if (analyticsPanel) analyticsPanel.style.display = 'none';
        setReconWorkspaceActive(true);
        refreshReconPanel();
    }

    // Load initial config
    API.getConfig().then(config => {
        applyClientConfig(config);
        resetAppTitle();
        
    }).catch(e => console.error("Failed to load config", e));

    syncTopBarsHeight();
    setupTopBarsHeightSync();
}

function syncLeftPanelsLayout() {
    const panelsContainer = document.querySelector('.panels-container');
    if (!panelsContainer) return;

    const openCount = [
        !!STATE?.modes?.zones,
        !!STATE?.modes?.targets,
        !!STATE?.modes?.favs,
    ].filter(Boolean).length;

    panelsContainer.classList.remove(
        'left-panels--count-0',
        'left-panels--count-1',
        'left-panels--count-2',
        'left-panels--count-3'
    );
    panelsContainer.classList.add(`left-panels--count-${openCount}`);
}

function syncTopBarsHeight() {
    const left = document.querySelector('.controls-row');
    const right = document.querySelector('.stats-container-wrapper');
    if (!left || !right) return;
    left.style.height = 'auto';
    right.style.height = 'auto';
    const leftHeight = left.offsetHeight;
    const rightHeight = right.offsetHeight;
    const targetHeight = Math.max(leftHeight, rightHeight);
    if (targetHeight > 0) {
        left.style.height = `${targetHeight}px`;
        right.style.height = `${targetHeight}px`;
    }
}

function setupTopBarsHeightSync() {
    let resizeTimer = null;
    window.addEventListener('resize', () => {
        if (resizeTimer) clearTimeout(resizeTimer);
        resizeTimer = setTimeout(() => {
            resizeTimer = null;
            syncTopBarsHeight();
        }, 150);
    });
}

function syncRightPanelsLayout() {
    const rightPanelsContainer = document.querySelector('.right-panels-container');
    if (!rightPanelsContainer) return;

    const hasCracking = !!STATE?.modes?.cracking;
    const hasProcess = !!STATE?.modes?.process;
    const hasLogs = !!STATE?.modes?.logs;

    rightPanelsContainer.classList.toggle('right-panels--has-cracking', hasCracking);
    rightPanelsContainer.classList.toggle('right-panels--has-process', hasProcess);
    rightPanelsContainer.classList.toggle('right-panels--has-logs', hasLogs);

    rightPanelsContainer.classList.toggle('right-panels--only-cracking', hasCracking && !hasProcess && !hasLogs);
    rightPanelsContainer.classList.toggle('right-panels--only-process', hasProcess && !hasCracking && !hasLogs);
    rightPanelsContainer.classList.toggle('right-panels--only-logs', hasLogs && !hasCracking && !hasProcess);
}

function snapshotDemoUiState() {
    return {
        lists: {
            targets: Array.isArray(STATE.lists?.targets) ? [...STATE.lists.targets] : [],
            favs: Array.isArray(STATE.lists?.favs) ? [...STATE.lists.favs] : [],
        },
        modes: {
            zones: !!STATE.modes?.zones,
            conquered: !!STATE.modes?.conquered,
            toConquer: !!STATE.modes?.toConquer,
            discovered: !!STATE.modes?.discovered,
            intelligence: !!STATE.modes?.intelligence,
            targets: !!STATE.modes?.targets,
            favs: !!STATE.modes?.favs,
            process: !!STATE.modes?.process,
            logs: !!STATE.modes?.logs,
        },
    };
}

function applyPersistedPanelModes() {
    const setActive = (buttonId, active) => {
        const button = document.getElementById(buttonId);
        if (button) button.classList.toggle('active', !!active);
    };
    const setDisplay = (panelId, active, displayValue = 'flex') => {
        const panel = document.getElementById(panelId);
        if (panel) panel.style.display = active ? displayValue : 'none';
    };

    setActive('btn-zones', STATE.modes.zones);
    setActive('btn-conquered', STATE.modes.conquered);
    setActive('btn-to-conquer', STATE.modes.toConquer);
    setActive('btn-discovered', STATE.modes.discovered);
    setActive('btn-intelligence', STATE.modes.intelligence);
    setActive('btn-targets', STATE.modes.targets);
    setActive('btn-favs', STATE.modes.favs);
    setDisplay('zones-panel', STATE.modes.zones);
    setDisplay('targets-panel', STATE.modes.targets);
    setDisplay('favorites-panel', STATE.modes.favs);

    setActive('btn-toggle-cracking', STATE.modes.cracking);
    setActive('btn-process', STATE.modes.process);
    setActive('btn-logs', STATE.modes.logs);
    setDisplay('cracking-panel', STATE.modes.cracking);
    setDisplay('process-panel', STATE.modes.process);
    setDisplay('log-panel', STATE.modes.logs, 'block');

    if (STATE.modes.process && Object.keys(activeProcesses).length === 0) {
        renderProcessList();
    }

    syncLeftPanelsLayout();
    syncRightPanelsLayout();
}

function applyDemoUiState(seed = null) {
    if (!seed || typeof seed !== 'object') return;

    const nextTargets = seed?.lists?.targets;
    const nextFavs = seed?.lists?.favs;
    if (Array.isArray(nextTargets)) {
        STATE.lists.targets = nextTargets.map((item) => String(item || '').trim()).filter(Boolean);
    }
    if (Array.isArray(nextFavs)) {
        STATE.lists.favs = nextFavs.map((item) => String(item || '').trim()).filter(Boolean);
    }
    saveLists();
    document.dispatchEvent(new Event('listsUpdated'));

    const modes = seed?.modes;
    if (modes && typeof modes === 'object') {
        const modeMap = {
            zones: 'zones',
            conquered: 'conquered',
            toConquer: 'toConquer',
            discovered: 'discovered',
            intelligence: 'intelligence',
            targets: 'targets',
            favs: 'favs',
            cracking: 'cracking',
            process: 'process',
            logs: 'logs',
        };
        Object.entries(modeMap).forEach(([sourceKey, stateKey]) => {
            if (Object.prototype.hasOwnProperty.call(modes, sourceKey)) {
                STATE.modes[stateKey] = !!modes[sourceKey];
            }
        });
        saveModes();
        applyPersistedPanelModes();
    }
}

function setPrimaryWorkspaceMode(mode, { clearAnalyticsLayers = true } = {}) {
    const isNoGps = mode === 'noGps';
    const isMulti = mode === 'multi';
    const isRaw = mode === 'raw';
    const isAnalytics = mode === 'analytics';

    STATE.modes.noGps = isNoGps;
    STATE.modes.multi = isMulti;
    STATE.modes.raw = isRaw;
    STATE.modes.analytics = isAnalytics;

    const btnMap = document.getElementById('btn-map-view');
    const btnNoGps = document.getElementById('btn-no-gps-view');
    const btnMulti = document.getElementById('btn-multi-view');
    const btnRaw = document.getElementById('btn-raw-view');
    const btnAnalytics = document.getElementById('btn-analytics-view');

    if (btnMap) btnMap.classList.toggle('active', !isNoGps && !isMulti && !isRaw && !isAnalytics);
    if (btnNoGps) btnNoGps.classList.toggle('active', isNoGps);
    if (btnMulti) btnMulti.classList.toggle('active', isMulti);
    if (btnRaw) btnRaw.classList.toggle('active', isRaw);
    if (btnAnalytics) btnAnalytics.classList.toggle('active', isAnalytics);

    const noGpsPanel = document.getElementById('no-gps-panel');
    const multiPanel = document.getElementById('multi-panel');
    const rawPanel = document.getElementById('raw-panel');

    if (noGpsPanel) noGpsPanel.style.display = isNoGps ? 'flex' : 'none';
    if (multiPanel) multiPanel.style.display = isMulti ? 'flex' : 'none';
    if (rawPanel) rawPanel.style.display = isRaw ? 'flex' : 'none';

    setReconWorkspaceActive(isAnalytics);

    if (clearAnalyticsLayers && !isAnalytics) {
        clearAnalyticsHeatmapLayer();
        clearAnalyticsHotspotsLayer();
    }
}

const LOAD_DEBOUNCE_MS = 800;
const LOAD_IDLE_RECHECK_MS = 1500;
let loadDataTimer = null;
let hasLoadedMapOnce = false;

function buildJobProgressExtraInfo({ speed, eta, extra } = {}) {
    const parts = [];
    const speedText = String(speed || '').trim();
    const etaText = String(eta || '').trim();
    const extraText = String(extra || '').trim();

    if (speedText) parts.push(speedText);
    if (etaText) parts.push(`ETA: ${etaText}`);
    if (extraText) parts.push(extraText);

    return parts.join(' | ');
}

function scheduleLoadData() {
    if (loadDataTimer) clearTimeout(loadDataTimer);
    loadDataTimer = setTimeout(() => {
        loadDataTimer = null;
        if (STATE.isCrackingActive && hasLoadedMapOnce) {
            loadDataTimer = setTimeout(() => scheduleLoadData(), LOAD_IDLE_RECHECK_MS);
            return;
        }
        loadData();
    }, LOAD_DEBOUNCE_MS);
}

export const __testUiHelpers = {
    updateFilterClearButtonVisibility,
    applyMainSearchFilter,
    snapshotDemoUiState,
    applyDemoUiState,
    buildCrackingTitle,
    buildJobProgressExtraInfo,
    syncRightPanelsLayout,
    setAppTitle,
    resetAppTitle,
};

function setupSocketListeners() {
    // Atualização de dados do mapa (Sync ou Cracking Success)
    Socket.on('data_update', (payload) => {
        if (payload === 'map_data') {
            log("Data update received from server.", "info");
            scheduleLoadData();
        }
    });

    // Progresso de Jobs (Hashcat, Aircrack, etc)
    Socket.on('job_progress', (payload) => {
        const { job_id, data } = payload;
        // Update parent job if present
        if (activeProcesses[job_id]) {
            const { percentage, speed, eta, stage, extra } = data;
            const extraInfo = buildJobProgressExtraInfo({ speed, eta, extra });
            const isIndeterminate = (stage === 'RUNNING' && (!percentage || percentage === 100) && !eta);
            updateProcess(job_id, percentage || 0, stage, extraInfo, isIndeterminate);

            // Update titlebar for Hashcat
            const proc = activeProcesses[job_id];
            const isHashcat = proc?.type?.includes("HASHCAT");
            const shouldUpdateTitle = isHashcat && (stage === 'RUNNING' || (percentage && percentage > 0));
            if (shouldUpdateTitle) {
                setAppTitle(buildCrackingTitle(percentage || 0, extra || ""));
            }
            if (stage === 'RUNNING' || stage === 'CRACKING') {
                Platform.setProgressBar((percentage || 0) / 100, isIndeterminate ? 'indeterminate' : 'normal');
            }
        }

        // Multi-job itemized progress is ignored for child entries; backend provides
        // current filename in `extra` which we surface on the parent job.
    });

    // Atualização de Estado de Job (Started, Queued)
    Socket.on('job_update', (job) => {
        // Atualiza se já existe
        if (activeProcesses[job.id]) {
            updateProcess(job.id, job.progress_data.percentage, job.status.toUpperCase());
            return;
        }

        // Se não existe, adiciona ao painel (ex: trabalho iniciado no servidor)
        try {
            const details = job.progress_data?.extra || job.meta?.output_file || job.command || job.type || 'process';
            const isFingerprintMulti = job.type === 'fingerprint_multi';
            const isSyncImport = job.type === 'sync_import';
            const isRawsnifferMulti = job.type === 'rawsniffer_multi';
            const isRawPrepareAll = job.type === 'raw_prepare_all';
            const isProbeIntelScan = job.type === 'probe_intel_scan';
            const isDeepAnalysisScan = job.type === 'deep_analysis_scan';
            if (isProbeIntelScan || isDeepAnalysisScan) {
                const count = job.meta?.pcaps?.length || job.progress_data?.total_steps || '';
                const niceType = isProbeIntelScan ? 'PROBE INTEL' : 'DEEP ANALYSIS';
                const niceDetails = count
                    ? `Scanning ${count} PCAPs`
                    : (job.progress_data?.extra || details);
                addProcess(
                    job.id,
                    niceType,
                    niceDetails,
                    job.status ? job.status.toUpperCase() : 'STARTING'
                );
                if (job.progress_data) {
                    updateProcess(job.id, job.progress_data.percentage || 0, job.progress_data.stage || (job.status || '').toUpperCase(), job.progress_data.extra || niceDetails, false);
                }
            } else if (isSyncImport) {
                const niceType = job.meta?.display_type || 'SYNC';
                const niceDetails = job.meta?.display_details || details;
                addProcess(
                    job.id,
                    niceType,
                    niceDetails,
                    job.status ? job.status.toUpperCase() : 'STARTING'
                );
                if (activeProcesses[job.id] && job.meta?.no_cancel) {
                    activeProcesses[job.id].noCancel = true;
                }
                if (job.progress_data) {
                    updateProcess(
                        job.id,
                        job.progress_data.percentage || 0,
                        job.progress_data.stage || (job.status || '').toUpperCase(),
                        job.progress_data.extra || "",
                        false
                    );
                }
            } else if (isFingerprintMulti || isRawsnifferMulti || isRawPrepareAll) {
                const count = job.meta?.files_to_process?.length || job.progress_data?.total_steps || '';
                let niceType = 'BRUCE PCAP IMPORT';
                let niceDetails = count
                    ? `Import ${count} files`
                    : (job.progress_data?.extra || details);
                let mac = null;
                if (isRawsnifferMulti) {
                    niceType = 'RAW SNIFFER';
                    niceDetails = count
                        ? `Process ${count} files`
                        : (job.progress_data?.extra || details);
                } else if (isRawPrepareAll) {
                    niceType = 'RAW SNIFFER PREPARE ALL';
                    mac = job.meta?.bssid || null;
                    niceDetails = mac
                        ? (count ? `${mac} (${count} files)` : mac)
                        : (count ? `Process ${count} files` : (job.progress_data?.extra || details));
                }
                if (mac) {
                    addProcess(
                        job.id,
                        niceType,
                        niceDetails,
                        job.status ? job.status.toUpperCase() : 'STARTING',
                        mac
                    );
                } else {
                    addProcess(
                        job.id,
                        niceType,
                        niceDetails,
                        job.status ? job.status.toUpperCase() : 'STARTING'
                    );
                }
                // Sincroniza estado inicial
                if (job.progress_data) {
                    updateProcess(job.id, job.progress_data.percentage || 0, job.progress_data.stage || (job.status || '').toUpperCase(), job.progress_data.extra || niceDetails, false);
                }
            } else {
                const type = (job.meta?.display_type || job.type || 'GENERIC').toString().toUpperCase();
                const niceDetails = job.meta?.display_details || details;
                addProcess(job.id, type, niceDetails, job.status ? job.status.toUpperCase() : 'STARTING');
                if (activeProcesses[job.id] && job.meta?.no_cancel) {
                    activeProcesses[job.id].noCancel = true;
                }
                if (job.progress_data) {
                    updateProcess(job.id, job.progress_data.percentage || 0, job.progress_data.stage || (job.status || '').toUpperCase(), job.progress_data.extra || "", false);
                }
            }
        } catch (e) {
            console.error('Failed to add job from job_update:', e);
        }
    });

    // Job Completo (Success/Failed/Canceled)
    Socket.on('job_complete', (job) => {
        if (activeProcesses[job.id]) {
            const status = job.status.toUpperCase();
            const stage = job.progress_data?.stage?.toUpperCase();

            if (job.type === 'aircrack') {
                if (stage === 'EXHAUSTED') {
                    updateProcess(job.id, 100, "EXHAUSTED", "Password not found");
                    log(`Job ${job.type} finished: Password not found.`, 'warn');
                } else if (stage === 'CRACKED') {
                    updateProcess(job.id, 100, "CRACKED");
                    log(`Job ${job.type} finished: Password found.`, 'success');
                    handleJobCompletionSideEffects(job);
                } else {
                    updateProcess(job.id, 100, status);
                    log(`Job ${job.type} ${status.toLowerCase()}.`, status === 'CANCELED' ? 'warn' : 'error');
                }
            } else if (status === 'SUCCESS') {
                // Verifica se foi exhausted (Hashcat retorna success mas stage EXHAUSTED)
                if (job.progress_data.stage === 'EXHAUSTED') {
                    updateProcess(job.id, 100, "EXHAUSTED", "Password not found");
                    log(`Job ${job.type} finished: Password not found.`, 'warn');
                } else {
                    updateProcess(job.id, 100, "COMPLETED");
                    log(`Job ${job.type} finished successfully.`, 'success');

                    // Auto-update file list logic (moved from monitorJob)
                    handleJobCompletionSideEffects(job);
                }
            } else {
                updateProcess(job.id, 100, status);
                log(`Job ${job.type} ${status.toLowerCase()}.`, status === 'CANCELED' ? 'warn' : 'error');
            }

            Platform.setProgressBar(-1);
            Platform.togglePowerSave(false);
        }

        // Reset titlebar quando não houver hashcat ativo
        if (!getActiveHashcatJob()) {
            resetAppTitle();
        }

        if (job.type === 'conversion_multi') {
            refreshMultiFiles();
        }
        if (job.type === 'rawsniffer_multi') {
            refreshRawFiles();
        }
        if (job.type === 'raw_prepare_all') {
            const summary = job.meta?.raw_prepare_summary || {};
            const processed = Number(summary.processed ?? job.progress_data?.processed ?? 0);
            const succeeded = Number(summary.succeeded ?? job.progress_data?.succeeded ?? 0);
            const failed = Number(summary.failed ?? job.progress_data?.failed ?? 0);
            const canonicalHash = summary.canonical_hash || job.progress_data?.canonical_hash || null;
            let completionStatus = String(summary.status || '').toLowerCase();
            if (!completionStatus) {
                if (String(job.progress_data?.stage || '').toUpperCase() === 'PARTIAL') {
                    completionStatus = 'success_partial';
                } else if (String(job.progress_data?.stage || '').toUpperCase() === 'UP TO DATE') {
                    completionStatus = 'up_to_date';
                } else {
                    completionStatus = String(job.status || '').toLowerCase();
                }
            }
            const detailMac = String(job.meta?.bssid || '').trim().toUpperCase();
            const summaryText = `${succeeded}/${processed} source files processed${failed > 0 ? ` (${failed} failed)` : ''}`;
            document.dispatchEvent(new CustomEvent('rawPrepareAllComplete', {
                detail: {
                    mac: detailMac,
                    status: completionStatus,
                    canonical_hash: canonicalHash,
                    summary: summaryText,
                },
            }));
        }
        // If fingerprint multi-job finished, propagate per-file results
        if (job.type === 'fingerprint_multi' && job.progress_data && Array.isArray(job.progress_data.items)) {
            try {
                job.progress_data.items.forEach(item => {
                    const childId = `${job.id}::${item.file}`;
                    const status = (item.status || '').toUpperCase();
                    const extraInfo = item.details_count ? `${item.details_count} details` : (item.reason || "");
                    if (activeProcesses[childId]) {
                        const pct = (status === 'SUCCESS' || status === 'SKIPPED') ? 100 : 0;
                        updateProcess(childId, pct, status || job.status.toUpperCase(), extraInfo, false);
                    }
                });
            } catch (e) {
                console.error('Failed to finalize fingerprint child entries:', e);
            }
        }
    });
}

function setupWindowControls() {
    document.getElementById('btn-min').addEventListener('click', () => Platform.minimizeWindow());
    document.getElementById('btn-max').addEventListener('click', () => Platform.maximizeWindow());
    document.getElementById('btn-close').addEventListener('click', () => Platform.closeWindow());
}

function setupEventListeners() {
    document.addEventListener('rightPanelsModeChanged', syncRightPanelsLayout);
    setupGlobalHints();
    setupWardriveListeners();

    document.getElementById('btn-sync').addEventListener('click', syncData);

    document.getElementById('btn-intelligence').addEventListener('click', function() {
        STATE.modes.intelligence = !STATE.modes.intelligence;
        this.classList.toggle('active');
        calculateIntelligenceZones();
        saveModes();
    });

    document.getElementById('btn-heat').addEventListener('click', function() {
        STATE.modes.heat = !STATE.modes.heat;
        this.classList.toggle('active');
        renderMarkers(STATE.allPositions, false);
    });

    document.getElementById('btn-zones').addEventListener('click', function() {
        STATE.modes.zones = !STATE.modes.zones;
        this.classList.toggle('active');
        const panel = document.getElementById('zones-panel');
        panel.style.display = STATE.modes.zones ? 'flex' : 'none';
        syncLeftPanelsLayout();
        saveModes();
    });

    document.getElementById('btn-conquered').addEventListener('click', function() {
        STATE.modes.conquered = !STATE.modes.conquered;
        this.classList.toggle('active');
        calculateZones(STATE.allPositions);
        saveModes();
    });

    document.getElementById('btn-to-conquer').addEventListener('click', function() {
        STATE.modes.toConquer = !STATE.modes.toConquer;
        this.classList.toggle('active');
        calculateToConquerZones(STATE.allPositions);
        saveModes();
    });

    document.getElementById('btn-discovered').addEventListener('click', function() {
        STATE.modes.discovered = !STATE.modes.discovered;
        this.classList.toggle('active');
        calculateDiscoveredZones(STATE.allPositions);
        saveModes();
    });

    document.getElementById('btn-targets').addEventListener('click', function() {
        STATE.modes.targets = !STATE.modes.targets;
        this.classList.toggle('active');
        document.getElementById('targets-panel').style.display = STATE.modes.targets ? 'flex' : 'none';
        syncLeftPanelsLayout();
        saveModes();
    });

    document.getElementById('btn-favs').addEventListener('click', function() {
        STATE.modes.favs = !STATE.modes.favs;
        this.classList.toggle('active');
        document.getElementById('favorites-panel').style.display = STATE.modes.favs ? 'flex' : 'none';
        syncLeftPanelsLayout();
        saveModes();
    });

    document.getElementById('btn-map-view').addEventListener('click', function() {
        deactivateWardriveMode();
        setPrimaryWorkspaceMode('map');
    });

    document.getElementById('btn-no-gps-view').addEventListener('click', function() {
        deactivateWardriveMode();
        setPrimaryWorkspaceMode('noGps');
        updateNoGpsList();
    });

    document.getElementById('btn-multi-view').addEventListener('click', function() {
        deactivateWardriveMode();
        setPrimaryWorkspaceMode('multi');
        updateMultiList();
        refreshMultiFiles();
    });

    const btnRawView = document.getElementById('btn-raw-view');
    if (btnRawView) {
        btnRawView.addEventListener('click', function() {
            deactivateWardriveMode();
            setPrimaryWorkspaceMode('raw');
            refreshRawFiles();
        });
    }

    const btnAnalyticsView = document.getElementById('btn-analytics-view');
    if (btnAnalyticsView) {
        btnAnalyticsView.addEventListener('click', function() {
            deactivateWardriveMode();
            setPrimaryWorkspaceMode('analytics', { clearAnalyticsLayers: false });
            refreshReconPanel();
        });
    }

    document.addEventListener('exitAnalyticsView', () => {
        if (!STATE.modes.analytics) return;
        setPrimaryWorkspaceMode('map');
    });

    document.getElementById('btn-logs').addEventListener('click', function() {
        STATE.modes.logs = !STATE.modes.logs;
        this.classList.toggle('active');
        document.getElementById('log-panel').style.display = STATE.modes.logs ? 'block' : 'none';
        saveModes();
        syncRightPanelsLayout();
    });

    setupProcessListeners();
    setupCrackingListeners();

    document.getElementById('btn-settings').addEventListener('click', openSettings);
    document.getElementById('btn-close-settings').addEventListener('click', closeSettings);
    document.getElementById('btn-cancel-settings').addEventListener('click', closeSettings);
    document.getElementById('btn-save-settings').addEventListener('click', saveSettings);
    const btnClearHistory = document.getElementById('btn-clear-history');
    if (btnClearHistory) {
        btnClearHistory.addEventListener('click', clearHistory);
    }
    const btnClearDetails = document.getElementById('btn-clear-details');
    if (btnClearDetails) {
        btnClearDetails.addEventListener('click', async () => {
            if (!window.confirm('Delete all .details files from handshakes?')) return;
            try {
                const out = await API.clearDetailsFiles();
                const deleted = Number(out?.deleted_count || 0);
                const failed = Number(out?.failed_count || 0);
                clearDetailsCache();
                clearReconRuntimeCache();
                scheduleLoadData();
                if (STATE.modes.raw) refreshRawFiles();
                if (STATE.modes.analytics) refreshReconPanel();
                log(`Details cleanup complete: deleted ${deleted}${failed ? ` | failed ${failed}` : ''}.`, failed ? 'warn' : 'success');
            } catch (e) {
                log(`Failed to clear details: ${e.message}`, 'error');
            }
        });
    }
    const btnClearCache = document.getElementById('btn-clear-cache');
    if (btnClearCache) {
        btnClearCache.addEventListener('click', async () => {
            if (!window.confirm('Clear cached metadata and runtime caches?')) return;
            try {
                const out = await API.clearCache();
                const rawDeleted = Number(out?.raw_metadata_deleted_count || 0);
                const rawFailed = Number(out?.raw_metadata_failed_count || 0);
                clearDetailsCache();
                clearReconRuntimeCache();
                scheduleLoadData();
                if (STATE.modes.raw) refreshRawFiles();
                if (STATE.modes.analytics) refreshReconPanel();
                log(
                    `Cache cleanup complete: raw metadata deleted ${rawDeleted}${rawFailed ? ` | failed ${rawFailed}` : ''}.`,
                    rawFailed ? 'warn' : 'success'
                );
            } catch (e) {
                log(`Failed to clear cache: ${e.message}`, 'error');
            }
        });
    }
    const btnInstallDemoData = document.getElementById('btn-install-demo-data');
    if (btnInstallDemoData) {
        btnInstallDemoData.addEventListener('click', async () => {
            if (!window.confirm('Install the showcase demo data pack and temporarily replace the current runtime dataset?')) return;
            try {
                const out = await API.installDemoData({
                    profile_id: 'showcase-core-v5',
                    frontend_state: snapshotDemoUiState(),
                });
                applyDemoUiState(out?.ui_seed || null);
                renderDemoDataStatus({
                    active: true,
                    active_profile_label: out?.label || out?.profile_id || 'showcase-core-v5',
                    active_profile_id: out?.profile_id || 'showcase-core-v5',
                    summary: out?.summary || {},
                    snapshot_available: true,
                });
                log(`Demo data install started: ${out?.label || out?.profile_id || 'showcase-core-v5'}.`, 'success');
            } catch (e) {
                log(`Failed to install demo data: ${e.message}`, 'error');
            }
        });
    }
    const btnRemoveDemoData = document.getElementById('btn-remove-demo-data');
    if (btnRemoveDemoData) {
        btnRemoveDemoData.addEventListener('click', async () => {
            if (!window.confirm('Remove the active demo data pack and restore the previous runtime dataset if a snapshot exists?')) return;
            try {
                const out = await API.removeDemoData();
                applyDemoUiState(out?.ui_restore || null);
                renderDemoDataStatus({
                    active: false,
                    snapshot_available: false,
                    summary: null,
                });
                log(`Demo data removal started${out?.restore_mode ? ` (${out.restore_mode}).` : '.'}`, 'success');
            } catch (e) {
                log(`Failed to remove demo data: ${e.message}`, 'error');
            }
        });
    }
    document.getElementById('btn-quick-settings').addEventListener('click', openSettings);
    const settingsModal = document.getElementById('settings-modal');
    if (settingsModal) {
        if (!settingsModal.dataset.overlayCloseBound) {
            settingsModal.addEventListener('click', (event) => {
                if (event.target === settingsModal) {
                    closeSettings();
                }
            });
            settingsModal.dataset.overlayCloseBound = '1';
        }
    }
    if (!document.documentElement.dataset.settingsEscCloseBound) {
        document.addEventListener('keydown', (event) => {
            if (event.key !== 'Escape') return;
            const modal = document.getElementById('settings-modal');
            if (!modal || modal.style.display === 'none') return;
            closeSettings();
        });
        document.documentElement.dataset.settingsEscCloseBound = '1';
    }

    setupMultiListeners();
    setupRawListeners();
    setupReconListeners();
    setupNoGpsFilterListeners();

    const filterInput = document.getElementById('filter-input');
    const filterClearButton = document.getElementById('btn-filter-clear');
    if (filterInput) {
        updateFilterClearButtonVisibility(filterInput.value);
        filterInput.addEventListener('input', (e) => {
            applyMainSearchFilter(e.target.value, { render: false });
        });
        filterInput.addEventListener('keyup', (e) => {
            if (e.key !== 'Enter') return;
            applyMainSearchFilter(e.target.value, { render: true });
        });
    }
    if (filterInput && filterClearButton) {
        filterClearButton.addEventListener('click', () => {
            filterInput.value = '';
            applyMainSearchFilter('', { render: true });
            filterInput.focus();
        });
    }

    document.addEventListener('statsUpdated', (e) => updateStatsUI(e.detail));
    document.addEventListener('listsUpdated', () => {
        updateTargetsList();
        updateFavsList();
    });
    document.addEventListener('zonesUpdated', (e) => updateZonesList(e.detail));
    document.addEventListener('toConquerZonesUpdated', (e) => updateToConquerZonesList(e.detail));
    document.addEventListener('discoveredZonesUpdated', (e) => updateDiscoveredZonesList(e.detail));
    document.addEventListener('intelligenceZonesUpdated', (e) => updateIntelligenceZonesList(e.detail));
    document.addEventListener('crackingIdle', () => scheduleLoadData());
}

async function checkBackendStatus() {
    try {
        setBootStepState('backend', 'active', 'Checking backend health endpoint');
        const status = await API.getStatus();
        
        if (status.status === 'ready') {
            setBootVisualState({
                statusText: status.message,
                pillText: 'Backend ready',
                tone: 'ready',
                progress: STARTUP_PROGRESS.backendReady,
                progressLabel: 'Backend online, loading network dataset',
                subtitle: 'Core services responded successfully. Pulling the latest discovered network inventory now.',
                tip: 'If the overlay stays here for long, the dataset fetch is usually the next thing to inspect.',
            });
            setBootStepState('backend', 'done', 'API responded successfully');
            setBootStepState('dataset', 'active', 'Waiting for dataset fetch');
            bootLog("Backend ready. Loading map data...");
            scheduleLoadData(); 
        } else {
            setBootVisualState({
                statusText: status.message,
                pillText: 'Backend busy',
                tone: 'busy',
                progress: STARTUP_PROGRESS.backendBusy,
                progressLabel: 'Waiting for backend readiness',
                subtitle: 'The backend is still warming up. The app will keep polling automatically until it is ready.',
                tip: 'No action is needed here unless the same status persists for too long.',
            });
            setBootStepState('backend', 'active', `Busy: ${status.message}`);
            bootLog(`Backend busy: ${status.message}`);
            setTimeout(checkBackendStatus, 1000); 
        }
    } catch (e) {
        setBootVisualState({
            statusText: 'Connecting...',
            pillText: 'Retrying',
            tone: 'error',
            progress: STARTUP_PROGRESS.connecting,
            progressLabel: 'Waiting for backend connection',
            subtitle: 'The UI is online, but the local backend has not responded yet. Automatic retries are still running.',
            tip: 'This usually resolves once the backend process finishes booting or becomes reachable again.',
        });
        setBootStepState('backend', 'error', 'Backend did not respond');
        bootLog("Waiting for backend connection...");
        setTimeout(checkBackendStatus, 2000);
    }
}

async function loadData() {
    try {
        setBootVisualState({
            statusText: 'Loading data...',
            pillText: 'Syncing',
            tone: 'busy',
            progress: STARTUP_PROGRESS.loadingData,
            progressLabel: 'Fetching discovered networks',
            subtitle: 'The backend is ready. Building the live network inventory and preparing overlays.',
            tip: 'After the dataset loads, the cockpit renders markers, panels and any saved workspace state.',
        });
        setBootStepState('dataset', 'active', 'Fetching map dataset');
        const data = await API.getMapData();
        const mergedData = ENABLE_MOCK_NETWORKS ? addMockNetworks(data) : data;
        
        const loadingScreen = document.getElementById('loading');
        hasLoadedMapOnce = true;
        
        STATE.retryCount = 0;

        const currentHash = JSON.stringify(mergedData);
        if (currentHash === STATE.lastDataHash) {
            setBootVisualState({
                statusText: 'Up to date',
                pillText: 'Ready',
                tone: 'ready',
                progress: STARTUP_PROGRESS.online,
                progressLabel: 'Dataset already current',
                subtitle: 'No new changes were detected in the network dataset.',
                tip: 'The overlay will disappear as soon as the cockpit is confirmed ready.',
            });
            setBootStepState('dataset', 'done', 'No dataset changes detected');
            setBootStepState('workspace', 'done', 'Existing workspace already current');
            if (loadingScreen) loadingScreen.style.display = 'none';
            return;
        }

        clearDetailsCache();
        STATE.lastDataHash = currentHash;
        STATE.allPositions = mergedData;
        markWardriveDirty();
        void primeReconCacheManifest({ force: true });

        setBootVisualState({
            statusText: 'Rendering workspace...',
            pillText: 'Finalizing',
            tone: 'busy',
            progress: STARTUP_PROGRESS.renderingWorkspace,
            progressLabel: 'Rendering cockpit and overlays',
            subtitle: 'Dataset loaded. Applying markers, spatial overlays and any active workspace panels.',
            tip: 'This last step prepares the interactive view and restores the current workspace state.',
        });
        setBootStepState('dataset', 'done', `${Object.keys(mergedData).length} network${Object.keys(mergedData).length !== 1 ? 's' : ''} loaded`);
        setBootStepState('workspace', 'active', 'Rendering map and HUD');
        
        renderMarkers(mergedData, false);
        calculateZones(mergedData);
        if (STATE.modes.toConquer) calculateToConquerZones(mergedData);
        if (STATE.modes.discovered) calculateDiscoveredZones(mergedData);
        if (STATE.modes.intelligence) calculateIntelligenceZones();
        updateTargetsList();
        updateFavsList();
        updateNoGpsList(); 
        if (STATE.modes.multi) {
            updateMultiList();
        }
        if (STATE.modes.analytics) {
            refreshReconPanel();
        }
        if (STATE.modes.wardrive) {
            refreshWardriveIfActive(true);
        } else {
            void prewarmWardriveWorkspace();
        }
        
        if(STATE.isFirstLoad) {
            log(`System Online. Loaded ${Object.keys(mergedData).length} networks.`, "success");
            STATE.isFirstLoad = false;
        }

        setBootVisualState({
            statusText: 'Online',
            pillText: 'Ready',
            tone: 'ready',
            progress: STARTUP_PROGRESS.online,
            progressLabel: `Loaded ${Object.keys(mergedData).length} discovered networks`,
            subtitle: 'The cockpit is ready. Hiding startup overlay and handing control to the live workspace.',
            tip: 'Startup completed successfully.',
        });
        setBootStepState('workspace', 'done', 'Cockpit rendered successfully');
        if (loadingScreen) loadingScreen.style.display = 'none';
    } catch (err) {
        console.error(err);
        STATE.retryCount++;
        const delay = Math.min(STATE.retryCount * 2000, 10000);
        setBootVisualState({
            statusText: 'Retry scheduled',
            pillText: 'Retrying',
            tone: 'error',
            progress: STARTUP_PROGRESS.retry,
            progressLabel: `Data load failed, retrying in ${delay / 1000}s`,
            subtitle: 'The backend responded, but the dataset fetch failed. Automatic retries remain active.',
            tip: 'If this keeps happening, check the backend logs or dataset source files.',
        });
        setBootStepState('dataset', 'error', `Fetch failed, retry in ${delay / 1000}s`);
        bootLog(`Data load failed. Retrying in ${delay/1000}s...`);
        setTimeout(loadData, delay);
    }
}

function addMockNetworks(data) {
    const merged = { ...data };
    const now = Date.now() / 1000;

    // Engenho de Dentro (RJ) vicinity
    const baseLat = -22.9038;
    const baseLng = -43.2950;

    // Estádio Nilton Santos (Engenhão) vicinity
    const estadioLat = -22.8939;
    const estadioLng = -43.2925;

    const randAcc = () => 25 + Math.floor(Math.random() * 78); // 10-44m

    const mocks = [
        // Pwned
        { mac: "AA:ED:00:00:00:01", ssid: "ED-ZONE-ALPHA", lat: baseLat + 0.0012, lng: baseLng - 0.0011, acc: randAcc(), pass: "mock-pass-01" },
        { mac: "AA:ED:00:00:00:02", ssid: "ED-ZONE-BETA", lat: baseLat + 0.0018, lng: baseLng + 0.0004, acc: randAcc(), pass: "mock-pass-02" },
        { mac: "AA:ED:00:00:00:03", ssid: "ED-ZONE-GAMMA", lat: baseLat + 0.0007, lng: baseLng + 0.0013, acc: randAcc(), pass: "mock-pass-03" },
        { mac: "AA:ED:00:00:00:04", ssid: "ED-ZONE-DELTA", lat: baseLat - 0.0009, lng: baseLng + 0.0009, acc: randAcc(), pass: "mock-pass-04" },
        { mac: "AA:ED:00:00:00:05", ssid: "ED-ZONE-EPS", lat: baseLat - 0.0014, lng: baseLng - 0.0006, acc: randAcc(), pass: "mock-pass-05" },
        { mac: "AA:ED:00:00:00:06", ssid: "ED-ZONE-ZETA", lat: baseLat + 0.0022, lng: baseLng - 0.0002, acc: randAcc(), pass: "mock-pass-06" },
        { mac: "AA:ED:00:00:00:07", ssid: "ED-ZONE-ETA", lat: baseLat - 0.0019, lng: baseLng + 0.0017, acc: randAcc(), pass: "mock-pass-07" },
        { mac: "AA:ED:00:00:00:08", ssid: "ED-ZONE-THETA", lat: baseLat + 0.0003, lng: baseLng - 0.0018, acc: randAcc(), pass: "mock-pass-08" },
        { mac: "AA:ED:00:00:00:09", ssid: "ED-ZONE-IOTA", lat: baseLat - 0.0002, lng: baseLng + 0.0021, acc: randAcc(), pass: "mock-pass-09" },
        { mac: "AA:ED:00:00:00:0A", ssid: "ED-ZONE-KAPPA", lat: baseLat + 0.0010, lng: baseLng + 0.0022, acc: randAcc(), pass: "mock-pass-10" },
        { mac: "AA:ED:00:00:00:0B", ssid: "ED-ZONE-LAMBDA", lat: baseLat - 0.0023, lng: baseLng - 0.0004, acc: randAcc(), pass: "mock-pass-11" },
        { mac: "AA:ED:00:00:00:0C", ssid: "ED-ZONE-MU", lat: baseLat + 0.0016, lng: baseLng - 0.0020, acc: randAcc(), pass: "mock-pass-12" },
        { mac: "AA:ED:00:00:00:0D", ssid: "ED-ZONE-NU", lat: baseLat + 0.0026, lng: baseLng + 0.0009, acc: randAcc(), pass: "mock-pass-13" },
        { mac: "AA:ED:00:00:00:0E", ssid: "ED-ZONE-XI", lat: baseLat - 0.0027, lng: baseLng + 0.0011, acc: randAcc(), pass: "mock-pass-14" },
        { mac: "AA:ED:00:00:00:0F", ssid: "ED-ZONE-OMIC", lat: baseLat + 0.0009, lng: baseLng - 0.0026, acc: randAcc(), pass: "mock-pass-15" },
        { mac: "AA:ED:00:00:00:10", ssid: "ED-ZONE-PI", lat: baseLat - 0.0012, lng: baseLng + 0.0028, acc: randAcc(), pass: "mock-pass-16" },
        { mac: "AA:ED:00:00:00:11", ssid: "ED-ZONE-RHO", lat: baseLat + 0.0030, lng: baseLng - 0.0014, acc: randAcc(), pass: "mock-pass-17" },
        { mac: "AA:ED:00:00:00:12", ssid: "ED-ZONE-SIGMA", lat: baseLat - 0.0034, lng: baseLng + 0.0029, acc: randAcc(), pass: "mock-pass-18" },
        { mac: "AA:ED:00:00:00:13", ssid: "ED-ZONE-TAU", lat: baseLat + 0.0041, lng: baseLng + 0.0006, acc: randAcc(), pass: "mock-pass-19" },
        { mac: "AA:ED:00:00:00:14", ssid: "ED-ZONE-UPS", lat: baseLat - 0.0040, lng: baseLng - 0.0016, acc: randAcc(), pass: "mock-pass-20" },
        { mac: "AA:ED:00:00:00:15", ssid: "ED-ZONE-PHI", lat: baseLat + 0.0027, lng: baseLng + 0.0036, acc: randAcc(), pass: "mock-pass-21" },
        { mac: "AA:ED:00:00:00:16", ssid: "ED-ZONE-CHI", lat: baseLat - 0.0029, lng: baseLng - 0.0031, acc: randAcc(), pass: "mock-pass-22" },
        { mac: "AA:ED:00:00:00:17", ssid: "ED-ZONE-PSI", lat: baseLat + 0.0043, lng: baseLng - 0.0027, acc: randAcc(), pass: "mock-pass-23" },
        { mac: "AA:ED:00:00:00:18", ssid: "ED-ZONE-OMEGA", lat: baseLat - 0.0042, lng: baseLng + 0.0014, acc: randAcc(), pass: "mock-pass-24" },

        // Locked
        { mac: "AA:ED:00:00:00:21", ssid: "ED-LOCK-ALFA", lat: baseLat + 0.0014, lng: baseLng + 0.0010, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:22", ssid: "ED-LOCK-BRAVO", lat: baseLat + 0.0021, lng: baseLng - 0.0008, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:23", ssid: "ED-LOCK-CHARLIE", lat: baseLat - 0.0008, lng: baseLng - 0.0019, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:24", ssid: "ED-LOCK-DELTA", lat: baseLat - 0.0017, lng: baseLng + 0.0019, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:25", ssid: "ED-LOCK-ECHO", lat: baseLat + 0.0005, lng: baseLng + 0.0026, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:26", ssid: "ED-LOCK-FOXTROT", lat: baseLat - 0.0022, lng: baseLng - 0.0012, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:27", ssid: "ED-LOCK-GOLF", lat: baseLat + 0.0029, lng: baseLng + 0.0017, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:28", ssid: "ED-LOCK-HOTEL", lat: baseLat - 0.0010, lng: baseLng + 0.0023, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:29", ssid: "ED-LOCK-INDIA", lat: baseLat + 0.0019, lng: baseLng - 0.0024, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:2A", ssid: "ED-LOCK-JULIET", lat: baseLat - 0.0026, lng: baseLng + 0.0002, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:2B", ssid: "ED-LOCK-KILO", lat: baseLat + 0.0002, lng: baseLng - 0.0028, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:2C", ssid: "ED-LOCK-LIMA", lat: baseLat + 0.0032, lng: baseLng - 0.0005, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:2D", ssid: "ED-LOCK-MIKE", lat: baseLat - 0.0036, lng: baseLng + 0.0034, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:2E", ssid: "ED-LOCK-NOV", lat: baseLat + 0.0046, lng: baseLng + 0.0019, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:2F", ssid: "ED-LOCK-OSCAR", lat: baseLat - 0.0044, lng: baseLng - 0.0024, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:30", ssid: "ED-LOCK-PAPA", lat: baseLat + 0.0039, lng: baseLng - 0.0032, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:31", ssid: "ED-LOCK-QUEBEC", lat: baseLat - 0.0031, lng: baseLng + 0.0040, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:32", ssid: "ED-LOCK-ROMEO", lat: baseLat + 0.0024, lng: baseLng - 0.0041, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:33", ssid: "ED-LOCK-SIERRA", lat: baseLat + 0.0008, lng: baseLng + 0.0043, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:34", ssid: "ED-LOCK-TANGO", lat: baseLat - 0.0006, lng: baseLng - 0.0044, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:ED:00:00:00:35", ssid: "ED-LOCK-UNIF", lat: baseLat + 0.0048, lng: baseLng - 0.0010, acc: randAcc(), encryption: "WPA2" },

        // Pwned (Estadio cluster)
        { mac: "AA:NS:00:00:00:01", ssid: "NS-ZONE-ALPHA", lat: estadioLat + 0.0011, lng: estadioLng - 0.0010, acc: randAcc(), pass: "mock-pass-25" },
        { mac: "AA:NS:00:00:00:02", ssid: "NS-ZONE-BETA", lat: estadioLat + 0.0018, lng: estadioLng + 0.0006, acc: randAcc(), pass: "mock-pass-26" },
        { mac: "AA:NS:00:00:00:03", ssid: "NS-ZONE-GAMMA", lat: estadioLat + 0.0004, lng: estadioLng + 0.0015, acc: randAcc(), pass: "mock-pass-27" },
        { mac: "AA:NS:00:00:00:04", ssid: "NS-ZONE-DELTA", lat: estadioLat - 0.0009, lng: estadioLng + 0.0008, acc: randAcc(), pass: "mock-pass-28" },
        { mac: "AA:NS:00:00:00:05", ssid: "NS-ZONE-EPS", lat: estadioLat - 0.0015, lng: estadioLng - 0.0007, acc: randAcc(), pass: "mock-pass-29" },
        { mac: "AA:NS:00:00:00:06", ssid: "NS-ZONE-ZETA", lat: estadioLat + 0.0023, lng: estadioLng - 0.0002, acc: randAcc(), pass: "mock-pass-30" },
        { mac: "AA:NS:00:00:00:07", ssid: "NS-ZONE-ETA", lat: estadioLat - 0.0020, lng: estadioLng + 0.0019, acc: randAcc(), pass: "mock-pass-31" },
        { mac: "AA:NS:00:00:00:08", ssid: "NS-ZONE-THETA", lat: estadioLat + 0.0002, lng: estadioLng - 0.0019, acc: randAcc(), pass: "mock-pass-32" },
        { mac: "AA:NS:00:00:00:09", ssid: "NS-ZONE-IOTA", lat: estadioLat - 0.0001, lng: estadioLng + 0.0022, acc: randAcc(), pass: "mock-pass-33" },
        { mac: "AA:NS:00:00:00:0A", ssid: "NS-ZONE-KAPPA", lat: estadioLat + 0.0012, lng: estadioLng + 0.0023, acc: randAcc(), pass: "mock-pass-34" },
        { mac: "AA:NS:00:00:00:0B", ssid: "NS-ZONE-LAMBDA", lat: estadioLat - 0.0024, lng: estadioLng - 0.0003, acc: randAcc(), pass: "mock-pass-35" },
        { mac: "AA:NS:00:00:00:0C", ssid: "NS-ZONE-MU", lat: estadioLat + 0.0017, lng: estadioLng - 0.0021, acc: randAcc(), pass: "mock-pass-36" },

        // Locked (Estadio cluster)
        { mac: "AA:NS:00:00:00:21", ssid: "NS-LOCK-ALFA", lat: estadioLat + 0.0015, lng: estadioLng + 0.0011, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:NS:00:00:00:22", ssid: "NS-LOCK-BRAVO", lat: estadioLat + 0.0022, lng: estadioLng - 0.0009, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:NS:00:00:00:23", ssid: "NS-LOCK-CHARLIE", lat: estadioLat - 0.0007, lng: estadioLng - 0.0020, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:NS:00:00:00:24", ssid: "NS-LOCK-DELTA", lat: estadioLat - 0.0016, lng: estadioLng + 0.0020, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:NS:00:00:00:25", ssid: "NS-LOCK-ECHO", lat: estadioLat + 0.0006, lng: estadioLng + 0.0027, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:NS:00:00:00:26", ssid: "NS-LOCK-FOXTROT", lat: estadioLat - 0.0021, lng: estadioLng - 0.0013, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:NS:00:00:00:27", ssid: "NS-LOCK-GOLF", lat: estadioLat + 0.0028, lng: estadioLng + 0.0018, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:NS:00:00:00:28", ssid: "NS-LOCK-HOTEL", lat: estadioLat - 0.0011, lng: estadioLng + 0.0024, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:NS:00:00:00:29", ssid: "NS-LOCK-INDIA", lat: estadioLat + 0.0020, lng: estadioLng - 0.0025, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:NS:00:00:00:2A", ssid: "NS-LOCK-JULIET", lat: estadioLat - 0.0025, lng: estadioLng + 0.0003, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:NS:00:00:00:2B", ssid: "NS-LOCK-KILO", lat: estadioLat + 0.0003, lng: estadioLng - 0.0029, acc: randAcc(), encryption: "WPA2" },
        { mac: "AA:NS:00:00:00:2C", ssid: "NS-LOCK-LIMA", lat: estadioLat + 0.0033, lng: estadioLng - 0.0004, acc: randAcc(), encryption: "WPA2" }
    ];

    const denseLat = baseLat + 0.0006;
    const denseLng = baseLng + 0.0006;
    const denseMocks = [
        { mac: "AA:ED:00:00:00:80", ssid: "ED-DENSE-01", lat: denseLat + 0.0000, lng: denseLng + 0.0000, acc: randAcc(), pass: "mock-pass-80" },
        { mac: "AA:ED:00:00:00:81", ssid: "ED-DENSE-02", lat: denseLat + 0.0002, lng: denseLng - 0.0001, acc: randAcc(), pass: "mock-pass-81" },
        { mac: "AA:ED:00:00:00:82", ssid: "ED-DENSE-03", lat: denseLat - 0.0002, lng: denseLng + 0.0001, acc: randAcc(), pass: "mock-pass-82" },
        { mac: "AA:ED:00:00:00:83", ssid: "ED-DENSE-04", lat: denseLat + 0.0001, lng: denseLng + 0.0002, acc: randAcc(), pass: "mock-pass-83" },
        { mac: "AA:ED:00:00:00:84", ssid: "ED-DENSE-05", lat: denseLat - 0.0001, lng: denseLng - 0.0002, acc: randAcc(), pass: "mock-pass-84" },
        { mac: "AA:ED:00:00:00:85", ssid: "ED-DENSE-06", lat: denseLat + 0.0003, lng: denseLng + 0.0000, acc: randAcc(), pass: "mock-pass-85" },
        { mac: "AA:ED:00:00:00:86", ssid: "ED-DENSE-07", lat: denseLat + 0.0000, lng: denseLng + 0.0003, acc: randAcc(), pass: "mock-pass-86" },
        { mac: "AA:ED:00:00:00:87", ssid: "ED-DENSE-08", lat: denseLat - 0.0003, lng: denseLng + 0.0000, acc: randAcc(), pass: "mock-pass-87" },
        { mac: "AA:ED:00:00:00:88", ssid: "ED-DENSE-09", lat: denseLat + 0.0000, lng: denseLng - 0.0003, acc: randAcc(), pass: "mock-pass-88" },
        { mac: "AA:ED:00:00:00:89", ssid: "ED-DENSE-10", lat: denseLat + 0.0004, lng: denseLng - 0.0001, acc: randAcc(), pass: "mock-pass-89" },
        { mac: "AA:ED:00:00:00:8A", ssid: "ED-DENSE-11", lat: denseLat - 0.0004, lng: denseLng + 0.0001, acc: randAcc(), pass: "mock-pass-90" },
        { mac: "AA:ED:00:00:00:8B", ssid: "ED-DENSE-12", lat: denseLat + 0.0001, lng: denseLng - 0.0004, acc: randAcc(), pass: "mock-pass-91" },
        { mac: "AA:ED:00:00:00:8C", ssid: "ED-DENSE-13", lat: denseLat - 0.0001, lng: denseLng + 0.0004, acc: randAcc(), pass: "mock-pass-92" },
        { mac: "AA:ED:00:00:00:8D", ssid: "ED-DENSE-14", lat: denseLat + 0.0005, lng: denseLng + 0.0002, acc: randAcc(), pass: "mock-pass-93" },
        { mac: "AA:ED:00:00:00:8E", ssid: "ED-DENSE-15", lat: denseLat - 0.0005, lng: denseLng - 0.0002, acc: randAcc(), pass: "mock-pass-94" },
        { mac: "AA:ED:00:00:00:8F", ssid: "ED-DENSE-16", lat: denseLat + 0.0002, lng: denseLng + 0.0005, acc: randAcc(), pass: "mock-pass-95" },
        { mac: "AA:ED:00:00:00:90", ssid: "ED-DENSE-17", lat: denseLat - 0.0002, lng: denseLng - 0.0005, acc: randAcc(), pass: "mock-pass-96" },
        { mac: "AA:ED:00:00:00:91", ssid: "ED-DENSE-18", lat: denseLat + 0.0006, lng: denseLng + 0.0000, acc: randAcc(), pass: "mock-pass-97" }
    ];

    const pwnedLat = baseLat + 0.0011;
    const pwnedLng = baseLng - 0.0009;
    const pwnedMocks = [
        { mac: "AA:ED:00:00:02:01", ssid: "ED-PWNED-01", lat: pwnedLat + 0.0000, lng: pwnedLng + 0.0000, acc: randAcc(), pass: "mock-pass-201" },
        { mac: "AA:ED:00:00:02:02", ssid: "ED-PWNED-02", lat: pwnedLat + 0.0002, lng: pwnedLng - 0.0001, acc: randAcc(), pass: "mock-pass-202" },
        { mac: "AA:ED:00:00:02:03", ssid: "ED-PWNED-03", lat: pwnedLat - 0.0002, lng: pwnedLng + 0.0001, acc: randAcc(), pass: "mock-pass-203" },
        { mac: "AA:ED:00:00:02:04", ssid: "ED-PWNED-04", lat: pwnedLat + 0.0001, lng: pwnedLng + 0.0002, acc: randAcc(), pass: "mock-pass-204" },
        { mac: "AA:ED:00:00:02:05", ssid: "ED-PWNED-05", lat: pwnedLat - 0.0001, lng: pwnedLng - 0.0002, acc: randAcc(), pass: "mock-pass-205" },
        { mac: "AA:ED:00:00:02:06", ssid: "ED-PWNED-06", lat: pwnedLat + 0.0003, lng: pwnedLng + 0.0000, acc: randAcc(), pass: "mock-pass-206" },
        { mac: "AA:ED:00:00:02:07", ssid: "ED-PWNED-07", lat: pwnedLat + 0.0000, lng: pwnedLng + 0.0003, acc: randAcc(), pass: "mock-pass-207" },
        { mac: "AA:ED:00:00:02:08", ssid: "ED-PWNED-08", lat: pwnedLat - 0.0003, lng: pwnedLng + 0.0000, acc: randAcc(), pass: "mock-pass-208" },
        { mac: "AA:ED:00:00:02:09", ssid: "ED-PWNED-09", lat: pwnedLat + 0.0000, lng: pwnedLng - 0.0003, acc: randAcc(), pass: "mock-pass-209" },
        { mac: "AA:ED:00:00:02:0A", ssid: "ED-PWNED-10", lat: pwnedLat + 0.0004, lng: pwnedLng - 0.0001, acc: randAcc(), pass: "mock-pass-210" }
    ];

    const allMocks = mocks.concat(denseMocks, pwnedMocks);

    allMocks.forEach((m, idx) => {
        if (merged[m.mac]) return;
        merged[m.mac] = {
            mac: m.mac,
            ssid: m.ssid,
            lat: m.lat,
            lng: m.lng,
            acc: m.acc,
            ts_last: now - (idx * 300),
            type: "ap",
            encryption: m.encryption || "WPA2",
            pass: m.pass || null,
            handshake: true,
            handshake_files: []
        };
    });

    return merged;
}

function parseMacFromFilename(filename) {
    const clean = (filename || '').toLowerCase();
    const match = clean.match(/([0-9a-f]{12})/);
    if (match) {
        return match[1].match(/.{1,2}/g).join(':').toUpperCase();
    }
    return null;
}

export async function openBatchFromProcess(batchFilename) {
    deactivateWardriveMode();
    STATE.modes.multi = true;
    STATE.modes.noGps = false;
    STATE.modes.raw = false;
    STATE.modes.analytics = false;
    document.getElementById('btn-multi-view').classList.add('active');
    document.getElementById('btn-map-view').classList.remove('active');
    document.getElementById('btn-no-gps-view').classList.remove('active');
    const btnRaw = document.getElementById('btn-raw-view');
    if (btnRaw) btnRaw.classList.remove('active');
    const btnAnalytics = document.getElementById('btn-analytics-view');
    if (btnAnalytics) btnAnalytics.classList.remove('active');
    document.getElementById('multi-panel').style.display = 'flex';
    document.getElementById('no-gps-panel').style.display = 'none';
    const rawPanel = document.getElementById('raw-panel');
    if (rawPanel) rawPanel.style.display = 'none';
    const analyticsPanel = document.getElementById('analytics-panel');
    if (analyticsPanel) analyticsPanel.style.display = 'none';
    setReconWorkspaceActive(false);
    clearAnalyticsHeatmapLayer();
    clearAnalyticsHotspotsLayer();

    await refreshMultiFiles();
    let target = batchFilename;
    if (!target || !target.toLowerCase().startsWith('batch_')) {
        target = (STATE.multiFiles && STATE.multiFiles.length > 0) ? STATE.multiFiles[0].name : null;
    }
    if (!target) {
        updateMultiFilesList();
        updateMultiContentsList();
        return;
    }
    STATE.multiSelectedFile = target;
    updateMultiFilesList();
    await loadMultiContents(target);
    updateMultiContentsList();
    await openMultiCrackingPanel(target);
}

function logSyncSuccess(data) {
    log(data.message, 'success');
    const details = data.details || {};
    const handshakes = details.handshakes || [];
    const wardrive = details.wardrive || null;
    const pwnRemote = details.pwnagotchi_remote_sync || {};
    const m5Remote = details.m5evil_remote_sync || {};
    const bruceRemote = details.bruce_remote_sync || {};
    const wardriveFiles = Number.isFinite(wardrive?.files_count) ? wardrive.files_count : 0;
    const wardriveNetworks = Number.isFinite(wardrive?.networks_count) ? wardrive.networks_count : 0;

    if (handshakes.length > 0) {
        log(`Downloaded: ${handshakes.length} files`, 'success');
        // loadData will be triggered by WS event
    }
    if (pwnRemote.status === 'success' || pwnRemote.status === 'partial') {
        const pwnDownloaded = Number(pwnRemote.downloaded_handshakes || 0);
        const pwnTotal = Number(pwnRemote.handshake_files_to_download || pwnDownloaded || 0);
        const pwnFailed = Number(pwnRemote.handshake_files_failed || 0);
        const pwnSuffix = pwnFailed > 0 ? ` | ${pwnFailed} failed` : '';
        log(
            pwnTotal > 0
                ? `Pwnagotchi SSH sync${pwnRemote.status === 'partial' ? ' (partial)' : ''}: ${pwnDownloaded}/${pwnTotal} sync file(s)${pwnSuffix}`
                : 'Pwnagotchi SSH sync: no new sync files',
            pwnRemote.status === 'partial' ? 'warn' : 'success'
        );
    }
    if (m5Remote.status === 'success' || m5Remote.status === 'partial') {
        log(
            `M5Evil Admin WebUI sync${m5Remote.status === 'partial' ? ' (partial)' : ''}: ${Number(m5Remote.downloaded_handshakes || 0)} handshake file(s) | ${Number(m5Remote.downloaded_wardrive_csvs || 0)} Wardrive CSV file(s)`,
            m5Remote.status === 'partial' ? 'warn' : 'success'
        );
    }
    if (bruceRemote.status === 'success' || bruceRemote.status === 'partial') {
        log(
            `Bruce WebUI sync${bruceRemote.status === 'partial' ? ' (partial)' : ''}: ${Number(bruceRemote.downloaded_handshakes || 0)} handshake file(s) | ${Number(bruceRemote.downloaded_rawsniffer_pcaps || 0)} RAW sniffer file(s)`,
            bruceRemote.status === 'partial' ? 'warn' : 'success'
        );
    }
    if (wardrive && wardriveFiles > 0) {
        log(`Wardrive: ${wardriveFiles} files | ${wardriveNetworks} networks`, 'success');
    }
    if (handshakes.length === 0 && wardriveFiles === 0) {
        log("No new data found.", "info");
    }
    if (details.errors && details.errors.length > 0) {
        details.errors.forEach(err => log(err, 'error'));
    }
}

function buildHostKeyTrustPrompt(syncResult) {
    const details = syncResult?.details || {};
    const hostKey = details.host_key || {};
    const host = hostKey.host || details.host || "unknown-host";
    const port = hostKey.port || details.port || 22;
    const keyType = hostKey.key_type || "unknown";
    const fingerprint = hostKey.fingerprint_sha256 || hostKey.fingerprint_md5 || "Unavailable";
    const expected = details.expected_host_key || {};
    const expectedFingerprint = expected.fingerprint_sha256 || expected.fingerprint_md5;
    const isMismatch = syncResult.code === 'ssh_host_key_mismatch';

    const lines = [
        isMismatch
            ? `SSH host key changed for ${host}:${port}.`
            : `Trust SSH host key for ${host}:${port}?`,
        "",
        `Type: ${keyType}`,
        `Fingerprint: ${fingerprint}`,
    ];

    if (expectedFingerprint) {
        lines.push(`Previously trusted: ${expectedFingerprint}`);
    }

    lines.push("");
    lines.push(
        isMismatch
            ? "Replace trusted key and continue sync?"
            : "Trust this key and continue sync?"
    );
    return lines.join("\n");
}

function createM5SyncProcessIds() {
    const base = `sync::m5evil::${Date.now()}`;
    return {
        handshakes: `${base}::handshakes`,
        rawsniffer: `${base}::rawsniffer`,
        mastersniffer: `${base}::mastersniffer`,
        wardrive: `${base}::wardrive`,
    };
}

function createPwnagotchiSyncProcessId() {
    return `sync::pwnagotchi::${Date.now()}::handshakes`;
}

function createBruceSyncProcessIds() {
    const base = `sync::bruce::${Date.now()}`;
    return {
        handshakes: `${base}::handshakes`,
        rawsniffer: `${base}::rawsniffer`,
        wardrive: `${base}::wardrive`,
    };
}

function startPwnagotchiSyncProcess(config = {}) {
    if (!config || !config.pwn_sync_enabled) return null;
    const processId = createPwnagotchiSyncProcessId();
    addProcess(processId, 'SYNC', 'Pwnagotchi handshakes', 'STARTING');
    if (activeProcesses[processId]) {
        activeProcesses[processId].noCancel = true;
    }
    updateProcess(
        processId,
        15,
        'RUNNING',
        'Importing handshake captures and GPS sidecars from Pwnagotchi SSH',
        true
    );
    return processId;
}

function startM5SyncProcesses(config = {}) {
    if (!config || !config.m5_sync_enabled) return null;
    const processIds = createM5SyncProcessIds();
    addProcess(processIds.handshakes, 'SYNC', 'M5Evil handshakes', 'STARTING');
    if (activeProcesses[processIds.handshakes]) {
        activeProcesses[processIds.handshakes].noCancel = true;
    }
    updateProcess(
        processIds.handshakes,
        15,
        'RUNNING',
        'Importing handshake captures from Admin WebUI',
        true
    );

    addProcess(processIds.rawsniffer, 'SYNC', 'M5Evil raw sniffer', 'STARTING');
    if (activeProcesses[processIds.rawsniffer]) {
        activeProcesses[processIds.rawsniffer].noCancel = true;
    }
    updateProcess(
        processIds.rawsniffer,
        0,
        'QUEUED',
        'Queued behind M5Evil handshakes',
        false
    );

    addProcess(processIds.mastersniffer, 'SYNC', 'M5Evil master sniffer', 'STARTING');
    if (activeProcesses[processIds.mastersniffer]) {
        activeProcesses[processIds.mastersniffer].noCancel = true;
    }
    updateProcess(
        processIds.mastersniffer,
        0,
        'QUEUED',
        'Queued behind M5Evil RAW sniffer',
        false
    );

    addProcess(processIds.wardrive, 'SYNC', 'M5Evil Wardrive CSVs', 'STARTING');
    if (activeProcesses[processIds.wardrive]) {
        activeProcesses[processIds.wardrive].noCancel = true;
    }
    updateProcess(
        processIds.wardrive,
        0,
        'QUEUED',
        'Queued behind M5Evil Master Sniffer',
        false
    );
    return processIds;
}

function startBruceSyncProcesses(config = {}) {
    if (!config || !config.bruce_sync_enabled) return null;
    const processIds = createBruceSyncProcessIds();

    addProcess(processIds.handshakes, 'SYNC', 'Bruce handshakes', 'STARTING');
    if (activeProcesses[processIds.handshakes]) {
        activeProcesses[processIds.handshakes].noCancel = true;
    }
    updateProcess(
        processIds.handshakes,
        15,
        'RUNNING',
        'Importing handshake captures from Bruce WebUI',
        true
    );

    addProcess(processIds.rawsniffer, 'SYNC', 'Bruce raw sniffer', 'STARTING');
    if (activeProcesses[processIds.rawsniffer]) {
        activeProcesses[processIds.rawsniffer].noCancel = true;
    }
    updateProcess(
        processIds.rawsniffer,
        0,
        'QUEUED',
        'Queued behind Bruce handshakes',
        false
    );

    addProcess(processIds.wardrive, 'SYNC', 'Bruce Wardrive CSVs', 'STARTING');
    if (activeProcesses[processIds.wardrive]) {
        activeProcesses[processIds.wardrive].noCancel = true;
    }
    updateProcess(
        processIds.wardrive,
        0,
        'QUEUED',
        'Queued behind Bruce RAW sniffer',
        false
    );

    return processIds;
}

function buildSyncForceConfig(config = {}) {
    return {
        pwnagotchi: !!(config.pwn_force_sync ?? config.force_sync ?? false),
        m5evil: !!(config.m5_force_sync ?? false),
        bruce: !!(config.bruce_force_sync ?? false),
    };
}

function buildSyncRunConfig(config = {}) {
    return {
        pwnagotchiEnabled: !!(config.pwn_sync_enabled ?? true),
        m5evilEnabled: !!(config.m5_sync_enabled ?? false),
        bruceEnabled: !!(config.bruce_sync_enabled ?? false),
    };
}

function buildM5ProcessResult({
    downloaded = 0,
    total = 0,
    failed = 0,
    skippedMessage = 'No new files',
}) {
    if (total <= 0) {
        return {
            status: 'UP TO DATE',
            message: skippedMessage,
        };
    }
    if (failed > 0) {
        return {
            status: 'PARTIAL',
            message: `${downloaded}/${total} | ${failed} failed`,
        };
    }
    return {
        status: 'COMPLETED',
        message: `${downloaded}/${total}`,
    };
}

function finalizeM5SyncProcesses(processIds, syncResult) {
    if (!processIds) return;
    const details = syncResult?.details || {};
    const stage = details.m5evil_remote_sync || details.sync_stages?.m5evil_remote_sync || {};
    const status = String(stage.status || '').trim().toLowerCase();
    const handshakeCount = Number(stage.downloaded_handshakes || 0);
    const rawsnifferCount = Number(stage.downloaded_rawsniffer_pcaps || 0);
    const mastersnifferCount = Number(stage.downloaded_mastersniffer_pcaps || 0);
    const wardriveCount = Number(stage.downloaded_wardrive_csvs || 0);
    const handshakeTotal = Number(stage.handshake_files_to_download || handshakeCount || 0);
    const rawsnifferTotal = Number(stage.rawsniffer_files_to_download || rawsnifferCount || 0);
    const mastersnifferTotal = Number(stage.mastersniffer_files_to_download || mastersnifferCount || 0);
    const wardriveTotal = Number(stage.wardrive_files_to_download || wardriveCount || 0);
    const handshakeFailed = Number(stage.handshake_files_failed || 0);
    const rawsnifferFailed = Number(stage.rawsniffer_files_failed || 0);
    const mastersnifferFailed = Number(stage.mastersniffer_files_failed || 0);
    const wardriveFailed = Number(stage.wardrive_files_failed || 0);
    const message = stage.message || syncResult?.message || 'M5Evil sync finished';
    const blockingTarget = String(details.target || '').trim().toLowerCase();

    if (status === 'success' || status === 'partial') {
        const handshakeResult = buildM5ProcessResult({
            downloaded: handshakeCount,
            total: handshakeTotal,
            failed: handshakeFailed,
            skippedMessage: 'No new files',
        });
        const rawsnifferResult = buildM5ProcessResult({
            downloaded: rawsnifferCount,
            total: rawsnifferTotal,
            failed: rawsnifferFailed,
            skippedMessage: 'No new files',
        });
        const mastersnifferResult = buildM5ProcessResult({
            downloaded: mastersnifferCount,
            total: mastersnifferTotal,
            failed: mastersnifferFailed,
            skippedMessage: 'No new files',
        });
        const wardriveResult = buildM5ProcessResult({
            downloaded: wardriveCount,
            total: wardriveTotal,
            failed: wardriveFailed,
            skippedMessage: 'No new files',
        });
        updateProcess(
            processIds.handshakes,
            100,
            handshakeResult.status,
            handshakeResult.message,
            false
        );
        updateProcess(
            processIds.rawsniffer,
            100,
            rawsnifferResult.status,
            rawsnifferResult.message,
            false
        );
        updateProcess(
            processIds.mastersniffer,
            100,
            mastersnifferResult.status,
            mastersnifferResult.message,
            false
        );
        updateProcess(
            processIds.wardrive,
            100,
            wardriveResult.status,
            wardriveResult.message,
            false
        );
        return;
    }

    if (status === 'skipped') {
        updateProcess(processIds.handshakes, 100, 'UP TO DATE', 'M5Evil sync skipped', false);
        updateProcess(processIds.rawsniffer, 100, 'UP TO DATE', 'M5Evil sync skipped', false);
        updateProcess(processIds.mastersniffer, 100, 'UP TO DATE', 'M5Evil sync skipped', false);
        updateProcess(processIds.wardrive, 100, 'UP TO DATE', 'M5Evil sync skipped', false);
        return;
    }

    const blockedBeforeM5 = (
        (syncResult?.code === 'ssh_host_key_not_trusted' || syncResult?.code === 'ssh_host_key_mismatch')
        && blockingTarget
        && blockingTarget !== 'm5evil'
    );
    const errorInfo = blockedBeforeM5
        ? 'Blocked before M5Evil Admin WebUI stage'
        : message;
    updateProcess(processIds.handshakes, 100, 'ERROR', errorInfo, false);
    updateProcess(processIds.rawsniffer, 100, 'ERROR', errorInfo, false);
    updateProcess(processIds.mastersniffer, 100, 'ERROR', errorInfo, false);
    updateProcess(processIds.wardrive, 100, 'ERROR', errorInfo, false);
}

function finalizeBruceSyncProcesses(processIds, syncResult) {
    if (!processIds) return;
    const details = syncResult?.details || {};
    const stage = details.bruce_remote_sync || details.sync_stages?.bruce_remote_sync || {};
    const status = String(stage.status || '').trim().toLowerCase();
    const handshakeCount = Number(stage.downloaded_handshakes || 0);
    const rawsnifferCount = Number(stage.downloaded_rawsniffer_pcaps || 0);
    const wardriveCount = Number(stage.downloaded_wardrive_csvs || 0);
    const handshakeTotal = Number(stage.handshake_files_to_download || handshakeCount || 0);
    const rawsnifferTotal = Number(stage.rawsniffer_files_to_download || rawsnifferCount || 0);
    const wardriveTotal = Number(stage.wardrive_files_to_download || wardriveCount || 0);
    const handshakeFailed = Number(stage.handshake_files_failed || 0);
    const rawsnifferFailed = Number(stage.rawsniffer_files_failed || 0);
    const wardriveFailed = Number(stage.wardrive_files_failed || 0);
    const message = stage.message || syncResult?.message || 'Bruce WebUI sync finished';
    const blockingTarget = String(details.target || '').trim().toLowerCase();

    if (status === 'success' || status === 'partial') {
        const handshakeResult = buildM5ProcessResult({
            downloaded: handshakeCount,
            total: handshakeTotal,
            failed: handshakeFailed,
            skippedMessage: 'No new files',
        });
        const rawsnifferResult = buildM5ProcessResult({
            downloaded: rawsnifferCount,
            total: rawsnifferTotal,
            failed: rawsnifferFailed,
            skippedMessage: 'No new files',
        });
        const wardriveResult = buildM5ProcessResult({
            downloaded: wardriveCount,
            total: wardriveTotal,
            failed: wardriveFailed,
            skippedMessage: 'No new files',
        });

        updateProcess(processIds.handshakes, 100, handshakeResult.status, handshakeResult.message, false);
        updateProcess(processIds.rawsniffer, 100, rawsnifferResult.status, rawsnifferResult.message, false);
        updateProcess(processIds.wardrive, 100, wardriveResult.status, wardriveResult.message, false);
        return;
    }

    if (status === 'skipped') {
        updateProcess(processIds.handshakes, 100, 'UP TO DATE', 'Bruce sync skipped', false);
        updateProcess(processIds.rawsniffer, 100, 'UP TO DATE', 'Bruce sync skipped', false);
        updateProcess(processIds.wardrive, 100, 'UP TO DATE', 'Bruce sync skipped', false);
        return;
    }

    const blockedBeforeBruce = (
        (syncResult?.code === 'ssh_host_key_not_trusted' || syncResult?.code === 'ssh_host_key_mismatch')
        && blockingTarget
        && blockingTarget !== 'bruce'
    );
    const errorInfo = blockedBeforeBruce
        ? 'Blocked before Bruce WebUI stage'
        : message;
    updateProcess(processIds.handshakes, 100, 'ERROR', errorInfo, false);
    updateProcess(processIds.rawsniffer, 100, 'ERROR', errorInfo, false);
    updateProcess(processIds.wardrive, 100, 'ERROR', errorInfo, false);
}

function finalizePwnagotchiSyncProcess(processId, syncResult) {
    if (!processId) return;
    const details = syncResult?.details || {};
    const stage = details.pwnagotchi_remote_sync || details.sync_stages?.pwnagotchi_remote_sync || {};
    const status = String(stage.status || '').trim().toLowerCase();
    const downloaded = Number(stage.downloaded_handshakes || 0);
    const total = Number(stage.handshake_files_to_download || downloaded || 0);
    const failed = Number(stage.handshake_files_failed || 0);
    const message = stage.message || syncResult?.message || 'Pwnagotchi sync finished';
    const blockingTarget = String(details.target || '').trim().toLowerCase();

    if (status === 'success' || status === 'partial') {
        const result = buildM5ProcessResult({
            downloaded,
            total,
            failed,
            skippedMessage: 'No new files',
        });
        updateProcess(processId, 100, result.status, result.message, false);
        return;
    }

    if (status === 'skipped') {
        updateProcess(processId, 100, 'UP TO DATE', 'Pwnagotchi sync skipped', false);
        return;
    }

    const blockedBeforePwnagotchi = (
        (syncResult?.code === 'ssh_host_key_not_trusted' || syncResult?.code === 'ssh_host_key_mismatch')
        && blockingTarget
        && blockingTarget !== 'pwnagotchi'
    );
    const errorInfo = blockedBeforePwnagotchi
        ? 'Blocked before Pwnagotchi SSH stage'
        : message;
    updateProcess(processId, 100, 'ERROR', errorInfo, false);
}

async function handleSyncHostKeyTrust(syncResult, force, syncConfig = null, pwnProcessId = null, processIds = null, bruceProcessIds = null) {
    const code = syncResult?.code;
    if (code !== 'ssh_host_key_not_trusted' && code !== 'ssh_host_key_mismatch') {
        return false;
    }

    const details = syncResult?.details || {};
    const hostKey = details.host_key || {};
    const host = hostKey.host || details.host || null;
    const port = hostKey.port || details.port || null;
    const replace = code === 'ssh_host_key_mismatch';
    const target = String(details.target || '').trim() || null;

    if (!window.confirm(buildHostKeyTrustPrompt(syncResult))) {
        log("Sync canceled: host key was not trusted.", "info");
        return true;
    }

    try {
        const trust = await API.trustHostKey(host, port, replace, target);
        if (trust.status !== 'success') {
            log(`Host key trust failed: ${trust.message}`, 'error');
            return true;
        }

        log(trust.message || "SSH host key trusted.", "success");

        const retry = await API.sync(force, processIds ? {
            pwnagotchiHandshakesProcessId: pwnProcessId,
            m5HandshakesProcessId: processIds.handshakes,
            m5RawsnifferProcessId: processIds.rawsniffer,
            m5MastersnifferProcessId: processIds.mastersniffer,
            m5WardriveProcessId: processIds.wardrive,
            bruceHandshakesProcessId: bruceProcessIds?.handshakes,
            bruceRawsnifferProcessId: bruceProcessIds?.rawsniffer,
            bruceWardriveProcessId: bruceProcessIds?.wardrive,
        } : (bruceProcessIds ? {
            pwnagotchiHandshakesProcessId: pwnProcessId,
            bruceHandshakesProcessId: bruceProcessIds.handshakes,
            bruceRawsnifferProcessId: bruceProcessIds.rawsniffer,
            bruceWardriveProcessId: bruceProcessIds.wardrive,
        } : (pwnProcessId ? {
            pwnagotchiHandshakesProcessId: pwnProcessId,
        } : null)), buildSyncForceConfig(syncConfig || {}));
        finalizePwnagotchiSyncProcess(pwnProcessId, retry);
        finalizeM5SyncProcesses(processIds, retry);
        finalizeBruceSyncProcesses(bruceProcessIds, retry);
        if (retry.status === 'success') {
            logSyncSuccess(retry);
        } else {
            log(`Sync Error: ${retry.message}`, 'error');
        }
    } catch (e) {
        log(`Host key trust failed: ${e.message}`, 'error');
    }
    return true;
}

async function syncData() {
    const btn = document.getElementById('btn-sync');
    btn.classList.add('active'); 
    log("Initiating Sync Protocol...", "warn");
    let pwnSyncProcessId = null;
    let m5SyncProcessIds = null;
    let bruceSyncProcessIds = null;
    
    try {
        const config = await API.getConfig();
        const force = config.force_sync || false;
        pwnSyncProcessId = startPwnagotchiSyncProcess(config);
        m5SyncProcessIds = startM5SyncProcesses(config);
        bruceSyncProcessIds = startBruceSyncProcesses(config);
        const syncForceConfig = buildSyncForceConfig(config);
        const syncRunConfig = buildSyncRunConfig(config);

        if (syncForceConfig.pwnagotchi) {
            log("Pwnagotchi FORCE SYNC enabled: downloading all matching files.", "warn");
        }
        if (syncForceConfig.m5evil) {
            log("M5Evil FORCE SYNC enabled: downloading all matching files.", "warn");
        }
        if (syncForceConfig.bruce) {
            log("Bruce FORCE SYNC enabled: downloading all matching files.", "warn");
        }
        if (!syncRunConfig.pwnagotchiEnabled && !syncRunConfig.m5evilEnabled && !syncRunConfig.bruceEnabled) {
            log("All remote sync targets are disabled.", "warn");
        }

        const data = await API.sync(force, m5SyncProcessIds ? {
            pwnagotchiHandshakesProcessId: pwnSyncProcessId,
            m5HandshakesProcessId: m5SyncProcessIds.handshakes,
            m5RawsnifferProcessId: m5SyncProcessIds.rawsniffer,
            m5MastersnifferProcessId: m5SyncProcessIds.mastersniffer,
            m5WardriveProcessId: m5SyncProcessIds.wardrive,
            bruceHandshakesProcessId: bruceSyncProcessIds?.handshakes,
            bruceRawsnifferProcessId: bruceSyncProcessIds?.rawsniffer,
            bruceWardriveProcessId: bruceSyncProcessIds?.wardrive,
        } : (bruceSyncProcessIds ? {
            pwnagotchiHandshakesProcessId: pwnSyncProcessId,
            bruceHandshakesProcessId: bruceSyncProcessIds.handshakes,
            bruceRawsnifferProcessId: bruceSyncProcessIds.rawsniffer,
            bruceWardriveProcessId: bruceSyncProcessIds.wardrive,
        } : (pwnSyncProcessId ? {
            pwnagotchiHandshakesProcessId: pwnSyncProcessId,
        } : null)), syncForceConfig);
        finalizePwnagotchiSyncProcess(pwnSyncProcessId, data);
        finalizeM5SyncProcesses(m5SyncProcessIds, data);
        finalizeBruceSyncProcesses(bruceSyncProcessIds, data);

        const details = data.details || {};
        const bruce = details.bruce || {};
        const m5evil = details.m5evil || {};
        const bruceToProcess = Number(bruce.handshakes_to_process || 0);
        const bruceHiddenRefresh = Number(bruce.handshakes_hidden_refresh || 0);
        const bruceMissingDetails = Number(bruce.handshakes_missing_details || 0);
        const bruceInvalidDetails = Number(bruce.handshakes_invalid_details || 0);
        const bruceBreakdown = `hidden ${bruceHiddenRefresh} | missing ${bruceMissingDetails} | invalid ${bruceInvalidDetails}`;
        const m5evilToProcess = Number(m5evil.handshakes_to_process || 0);
        const m5evilHiddenRefresh = Number(m5evil.handshakes_hidden_refresh || 0);
        const m5evilMissingDetails = Number(m5evil.handshakes_missing_details || 0);
        const m5evilInvalidDetails = Number(m5evil.handshakes_invalid_details || 0);
        const m5evilBreakdown = `hidden ${m5evilHiddenRefresh} | missing ${m5evilMissingDetails} | invalid ${m5evilInvalidDetails}`;
        const syncWasSuccessful = data.status === 'success';
        const syncStages = details.sync_stages || {};
        const syncMetrics = details.metrics || {};

        const remoteStage = syncStages.remote_sync || {};
        if (remoteStage.status) {
            const remoteMsg = remoteStage.message ? ` (${remoteStage.message})` : '';
            log(
                `Sync stage remote: ${remoteStage.status}${remoteMsg}`,
                remoteStage.status === 'success' ? 'info' : 'warn'
            );
        }
        const pwnRemoteStage = syncStages.pwnagotchi_remote_sync || {};
        if (pwnRemoteStage.status && pwnRemoteStage.status !== 'skipped') {
            const pwnRemoteMsg = pwnRemoteStage.message ? ` (${pwnRemoteStage.message})` : '';
            log(
                `Sync stage Pwnagotchi remote: ${pwnRemoteStage.status}${pwnRemoteMsg}`,
                pwnRemoteStage.status === 'success' ? 'info' : 'warn'
            );
        }
        const m5RemoteStage = syncStages.m5evil_remote_sync || {};
        if (m5RemoteStage.status && m5RemoteStage.status !== 'skipped') {
            const m5RemoteMsg = m5RemoteStage.message ? ` (${m5RemoteStage.message})` : '';
            log(
                `Sync stage M5Evil Admin WebUI: ${m5RemoteStage.status}${m5RemoteMsg}`,
                m5RemoteStage.status === 'success' ? 'info' : 'warn'
            );
            log(
                `M5Evil remote import counts: HS ${Number(m5RemoteStage.downloaded_handshakes || 0)}/${Number(m5RemoteStage.handshake_files_to_download || 0)} | RAW ${Number(m5RemoteStage.downloaded_rawsniffer_pcaps || 0)}/${Number(m5RemoteStage.rawsniffer_files_to_download || 0)} | MASTER ${Number(m5RemoteStage.downloaded_mastersniffer_pcaps || 0)}/${Number(m5RemoteStage.mastersniffer_files_to_download || 0)} | WDR ${Number(m5RemoteStage.downloaded_wardrive_csvs || 0)}/${Number(m5RemoteStage.wardrive_files_to_download || 0)}`,
                'info'
            );
        }
        const bruceRemoteStage = syncStages.bruce_remote_sync || {};
        if (bruceRemoteStage.status && bruceRemoteStage.status !== 'skipped') {
            const bruceRemoteMsg = bruceRemoteStage.message ? ` (${bruceRemoteStage.message})` : '';
            log(
                `Sync stage Bruce WebUI: ${bruceRemoteStage.status}${bruceRemoteMsg}`,
                bruceRemoteStage.status === 'success' ? 'info' : 'warn'
            );
            log(
                `Bruce remote import counts: HS ${Number(bruceRemoteStage.downloaded_handshakes || 0)}/${Number(bruceRemoteStage.handshake_files_to_download || 0)} | RAW ${Number(bruceRemoteStage.downloaded_rawsniffer_pcaps || 0)}/${Number(bruceRemoteStage.rawsniffer_files_to_download || 0)} | WDR ${Number(bruceRemoteStage.downloaded_wardrive_csvs || 0)}/${Number(bruceRemoteStage.wardrive_files_to_download || 0)}`,
                'info'
            );
        }
        if (typeof syncMetrics.remote_sync_ms === 'number') {
            const fpPlanMs = Number(syncMetrics.fingerprint_plan_ms || 0).toFixed(0);
            const fpQueueMs = Number(syncMetrics.fingerprint_queue_ms || 0).toFixed(0);
            const rawQueueMs = Number(syncMetrics.rawsniffer_queue_ms || 0).toFixed(0);
            const bruceMs = Number(syncMetrics.bruce_remote_sync_ms || 0).toFixed(0);
            log(
                `Sync timings: remote ${Number(syncMetrics.remote_sync_ms).toFixed(0)}ms | bruce ${bruceMs}ms | fp plan ${fpPlanMs}ms | fp queue ${fpQueueMs}ms | raw queue ${rawQueueMs}ms`,
                'info'
            );
        }

        const handleFingerprintFamily = (jobId, label, filesToProcess, breakdown, familyDetails) => {
            if (jobId) {
                addProcess(
                    jobId,
                    "FINGERPRINT",
                    `${label} (${filesToProcess} files)`,
                    "STARTING"
                );
                if (syncWasSuccessful) {
                    log(`Processing ${filesToProcess} ${label} fingerprints in background (${breakdown}).`, 'info');
                } else {
                    log(
                        `Sync failed (${data.message || data.status}), but processing ${filesToProcess} ${label} fingerprints locally (${breakdown}).`,
                        'warn'
                    );
                }
                return;
            }

            if (filesToProcess > 0) {
                log(
                    `${label} fingerprint planned ${filesToProcess} files (${breakdown}), but no background job id was returned.`,
                    'warn'
                );
            } else if (syncWasSuccessful && familyDetails.handshakes_seen !== undefined) {
                log(`${label} handshakes up to date: no hidden/missing/invalid files to reprocess.`, 'info');
            }
        };

        handleFingerprintFamily(
            bruce.fingerprint_job_id,
            'Bruce',
            bruceToProcess,
            bruceBreakdown,
            bruce
        );
        handleFingerprintFamily(
            m5evil.fingerprint_job_id,
            'M5Evil',
            m5evilToProcess,
            m5evilBreakdown,
            m5evil
        );

        const rawsniffer = details.rawsniffer || {};
        if (rawsniffer.job_id) {
            addProcess(
                rawsniffer.job_id,
                "RAW SNIFFER",
                `RAW unified (${rawsniffer.files_to_process || 0} files)`,
                "STARTING"
            );
            if (syncWasSuccessful) {
                log(
                    `Processing ${rawsniffer.files_to_process || 0} RAW PCAP files in background...`,
                    'info'
                );
            } else {
                log(
                    `Sync failed (${data.message || data.status}), but RAW processing started locally for ${rawsniffer.files_to_process || 0} files.`,
                    'warn'
                );
            }
        }
        
        if (data.status === 'success') {
            logSyncSuccess(data);
        } else if (!(await handleSyncHostKeyTrust(data, force, config, pwnSyncProcessId, m5SyncProcessIds, bruceSyncProcessIds))) {
            log(`Sync Error: ${data.message}`, 'error');
        } else {
            // handled by host key trust flow
        }
    } catch (e) {
        if (pwnSyncProcessId) {
            updateProcess(pwnSyncProcessId, 100, 'ERROR', e.message || 'Sync failed', false);
        }
        if (m5SyncProcessIds) {
            updateProcess(m5SyncProcessIds.handshakes, 100, 'ERROR', e.message || 'Sync failed', false);
            updateProcess(m5SyncProcessIds.rawsniffer, 100, 'ERROR', e.message || 'Sync failed', false);
            updateProcess(m5SyncProcessIds.mastersniffer, 100, 'ERROR', e.message || 'Sync failed', false);
            updateProcess(m5SyncProcessIds.wardrive, 100, 'ERROR', e.message || 'Sync failed', false);
        }
        if (bruceSyncProcessIds) {
            updateProcess(bruceSyncProcessIds.handshakes, 100, 'ERROR', e.message || 'Sync failed', false);
            updateProcess(bruceSyncProcessIds.rawsniffer, 100, 'ERROR', e.message || 'Sync failed', false);
            updateProcess(bruceSyncProcessIds.wardrive, 100, 'ERROR', e.message || 'Sync failed', false);
        }
        log(`Sync Failed: ${e.message}`, 'error');
    } finally {
        setTimeout(() => btn.classList.remove('active'), 1000);
    }
}

function updateStatsUI(stats) {
    const total = (stats.total || 0) + (stats.noGpsTotal || 0);
    const cracked = (stats.cracked || 0) + (stats.noGpsCracked || 0);
    const wardriveCount = stats.wardrive || 0;
    const openCount = stats.open || 0;
    const noGpsLocked = Math.max(0, stats.noGpsLocked || 0);
    const locked = (stats.locked || 0) + noGpsLocked;

    document.getElementById('count-total').innerText = total;
    document.getElementById('count-cracked').innerText = cracked;
    const openEl = document.getElementById('count-open');
    if (openEl) openEl.innerText = openCount;
    const wardriveEl = document.getElementById('count-wardrive');
    if (wardriveEl) wardriveEl.innerText = wardriveCount;
    document.getElementById('count-locked').innerText = locked;
}

// Test-only exports for deterministic coverage on utility paths.
export const __test = {
    addMockNetworks,
    parseMacFromFilename,
    checkBackendStatus,
    loadData,
    syncData,
    applyMainSearchFilter,
    handleMultiCreate,
    handleMultiClear,
    refreshMultiFiles,
    loadMultiContents
};
