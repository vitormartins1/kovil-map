import { STATE } from './state.js';
import { API } from './api.js';
import { log } from './utils.js';
import { addProcess } from './ui_components/ui_processes.js';
import { openMultiCrackingPanel } from './ui_components/ui_cracking.js';
import { updateMultiList, updateMultiFilesList, updateMultiContentsList } from './ui_components/ui_lists.js';

export function getMultiUiState() {
    if (!STATE.multiUi || typeof STATE.multiUi !== 'object') {
        STATE.multiUi = {
            search: "",
            status: "all",
            location: "all",
            source: "all",
            artifact: "all",
        };
    }
    const defaults = {
        search: "",
        status: "all",
        location: "all",
        source: "all",
        artifact: "all",
    };
    Object.keys(defaults).forEach((key) => {
        if (STATE.multiUi[key] === undefined || STATE.multiUi[key] === null) {
            STATE.multiUi[key] = defaults[key];
        }
    });

    if (STATE.multiFilter === 'locked' || STATE.multiFilter === 'all') {
        STATE.multiUi.status = STATE.multiFilter;
    } else {
        STATE.multiFilter = STATE.multiUi.status;
    }

    return STATE.multiUi;
}

function setMultiSelection(mac, isSelected) {
    if (isSelected) {
        if (!STATE.multiSelection.includes(mac)) STATE.multiSelection.push(mac);
    } else {
        STATE.multiSelection = STATE.multiSelection.filter(m => m !== mac);
    }
    updateMultiList();
}

export async function refreshMultiFiles() {
    try {
        const files = await API.listMultiFiles();
        STATE.multiFiles = files || [];
        updateMultiFilesList();
    } catch (e) {
        console.error("Failed to load multi files", e);
    }
}

export async function loadMultiContents(filename) {
    try {
        const res = await API.getMultiFileContent(filename);
        STATE.multiFileContents[filename] = res.items || [];
    } catch (e) {
        STATE.multiFileContents[filename] = [];
    }
}

export async function handleMultiCreate() {
    if (!STATE.multiSelection.length) {
        log("Select at least one network to create a multi file.", "warn");
        return;
    }

    const filenames = [];
    const captureIds = [];
    STATE.multiSelection.forEach(mac => {
        const pos = STATE.allPositions[mac];
        if (!pos) return;
        const preferredCaptureId = String(pos.preferred_handshake_capture_id || '').trim();
        if (preferredCaptureId) {
            captureIds.push(preferredCaptureId);
            return;
        }
        const pcap = (pos.handshake_files || []).find(f => f.endsWith('.pcap'));
        if (pcap) filenames.push(pcap);
    });

    if (!filenames.length && !captureIds.length) {
        log("No PCAP files found for selected networks.", "error");
        return;
    }

    try {
        const res = await API.convertMultiPcaps(filenames, captureIds);
        if (res.status === 'started') {
            addProcess(res.job_id, "MULTI CONVERSION", res.output_file || "multi", "STARTING");
            log(`Multi conversion started (${filenames.length + captureIds.length} files).`, 'info');
            refreshMultiFiles();
            STATE.multiSelection = [];
            STATE.multiLastClickedMac = null;
            STATE.multiItemStatus = {};
            updateMultiList();
        } else {
            log(`Multi conversion failed to start: ${res.message}`, 'error');
        }
    } catch (e) {
        log(`Multi conversion error: ${e.message}`, 'error');
    }
}

export function handleMultiClear() {
    STATE.multiSelection = [];
    STATE.multiItemStatus = {};
    updateMultiList();
}

export function setupMultiListeners() {
    const multiList = document.getElementById('multi-all-list');
    if (multiList) {
        multiList.addEventListener('change', (e) => {
            if (!e.target.classList.contains('multi-select-chk')) return;
            const mac = e.target.getAttribute('data-mac');
            if (!mac) return;
            setMultiSelection(mac, e.target.checked);
            STATE.multiLastClickedMac = mac;
        });

        multiList.addEventListener('click', (e) => {
            if (e.target.classList.contains('multi-select-chk')) return;
            const row = e.target.closest('.list-item');
            if (!row) return;
            const chk = row.querySelector('.multi-select-chk');
            if (!chk || chk.disabled) return;
            const mac = chk.getAttribute('data-mac');
            if (!mac) return;
            const isShift = e.shiftKey;
            if (isShift && STATE.multiLastClickedMac) {
                const allChecks = Array.from(multiList.querySelectorAll('.multi-select-chk'))
                    .filter(el => !el.disabled);
                const anchorIdx = allChecks.findIndex(el => el.getAttribute('data-mac') === STATE.multiLastClickedMac);
                const currentIdx = allChecks.findIndex(el => el.getAttribute('data-mac') === mac);
                if (anchorIdx !== -1 && currentIdx !== -1) {
                    const [start, end] = anchorIdx < currentIdx ? [anchorIdx, currentIdx] : [currentIdx, anchorIdx];
                    for (let i = start; i <= end; i++) {
                        allChecks[i].checked = true;
                        const rangeMac = allChecks[i].getAttribute('data-mac');
                        if (rangeMac) {
                            if (!STATE.multiSelection.includes(rangeMac)) STATE.multiSelection.push(rangeMac);
                        }
                    }
                    updateMultiList();
                } else {
                    chk.checked = !chk.checked;
                    setMultiSelection(mac, chk.checked);
                }
            } else {
                chk.checked = !chk.checked;
                setMultiSelection(mac, chk.checked);
            }
            STATE.multiLastClickedMac = mac;
        });
    }

    const multiFilesList = document.getElementById('multi-files-list');
    if (multiFilesList) {
        multiFilesList.addEventListener('click', async (e) => {
            const deleteBtn = e.target.closest('.multi-delete');
            if (deleteBtn) {
                const name = deleteBtn.getAttribute('data-name');
                if (!name) return;
                try {
                    const res = await API.deleteMultiFile(name);
                    if (res && res.deleted) {
                        if (STATE.multiSelectedFile === name) {
                            STATE.multiSelectedFile = null;
                            updateMultiContentsList();
                        }
                        refreshMultiFiles();
                        log(`Multi file deleted: ${name}`, 'success');
                    } else {
                        log(`Failed to delete multi file: ${res.message}`, 'error');
                    }
                } catch (err) {
                    log(`Delete error: ${err.message}`, 'error');
                }
                return;
            }

            const item = e.target.closest('.list-item');
            if (!item) return;
            const name = item.getAttribute('data-name');
            if (!name) return;
            STATE.multiSelectedFile = name;
            updateMultiFilesList();
            await loadMultiContents(name);
            updateMultiContentsList();
            await openMultiCrackingPanel(name);
        });
    }

    const btnMultiCreate = document.getElementById('btn-multi-create');
    if (btnMultiCreate) {
        btnMultiCreate.addEventListener('click', handleMultiCreate);
    }
    const btnMultiClear = document.getElementById('btn-multi-clear');
    if (btnMultiClear) {
        btnMultiClear.addEventListener('click', handleMultiClear);
    }

    const btnMultiFilterAll = document.getElementById('btn-multi-filter-all');
    const btnMultiFilterLocked = document.getElementById('btn-multi-filter-locked');
    if (btnMultiFilterAll && btnMultiFilterLocked) {
        btnMultiFilterAll.addEventListener('click', () => {
            STATE.multiFilter = 'all';
            const multiUi = getMultiUiState();
            multiUi.status = 'all';
            btnMultiFilterAll.classList.add('active');
            btnMultiFilterLocked.classList.remove('active');
            updateMultiList();
        });
        btnMultiFilterLocked.addEventListener('click', () => {
            STATE.multiFilter = 'locked';
            const multiUi = getMultiUiState();
            multiUi.status = 'locked';
            btnMultiFilterLocked.classList.add('active');
            btnMultiFilterAll.classList.remove('active');
            updateMultiList();
        });
    }

    const multiFilterSearch = document.getElementById('multi-filter-search');
    if (multiFilterSearch) {
        multiFilterSearch.addEventListener('input', () => {
            const multiUi = getMultiUiState();
            multiUi.search = (multiFilterSearch.value || '').trim().toLowerCase();
            updateMultiList();
        });
    }

    const multiFilterLocation = document.getElementById('multi-filter-location');
    if (multiFilterLocation) {
        multiFilterLocation.addEventListener('change', () => {
            const multiUi = getMultiUiState();
            multiUi.location = multiFilterLocation.value || 'all';
            updateMultiList();
        });
    }

    const multiFilterSource = document.getElementById('multi-filter-source');
    if (multiFilterSource) {
        multiFilterSource.addEventListener('change', () => {
            const multiUi = getMultiUiState();
            multiUi.source = multiFilterSource.value || 'all';
            updateMultiList();
        });
    }

    const multiFilterArtifact = document.getElementById('multi-filter-artifact');
    if (multiFilterArtifact) {
        multiFilterArtifact.addEventListener('change', () => {
            const multiUi = getMultiUiState();
            multiUi.artifact = multiFilterArtifact.value || 'all';
            updateMultiList();
        });
    }

    const multiUi = getMultiUiState();
    if (multiFilterSearch) multiFilterSearch.value = multiUi.search || "";
    if (multiFilterLocation) multiFilterLocation.value = multiUi.location || 'all';
    if (multiFilterSource) multiFilterSource.value = multiUi.source || 'all';
    if (multiFilterArtifact) multiFilterArtifact.value = multiUi.artifact || 'all';
    if (btnMultiFilterAll && btnMultiFilterLocked) {
        if ((multiUi.status || 'all') === 'locked') {
            btnMultiFilterLocked.classList.add('active');
            btnMultiFilterAll.classList.remove('active');
        } else {
            btnMultiFilterAll.classList.add('active');
            btnMultiFilterLocked.classList.remove('active');
        }
    }
}
