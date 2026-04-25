import { API } from '../api.js';
import { log, escapeHtml } from '../utils.js';
import {
    getModePanelLabel,
    getModeRunLabel,
    isSlowCandidatesCompatible,
    modeRequiresAssociationHints,
    modeRequiresMaskProfile,
    modeRequiresSecondWordlist,
    modeRequiresWordlist
} from '../attack_modes.js';
import { STATE, saveModes } from '../state.js';
import { updateNoGpsList } from './ui_lists.js';
import { activeProcesses, addProcess, updateProcess } from './ui_processes.js';
import { renderHistoryPanel } from './ui_history.js';

export let selectedFile = null;
let incrementSlider = null;
let currentFiles = [];
let currentHandshakeSet = null;
let insightsRenderToken = 0;
let currentBatchContext = null;
let currentBatchManifestItems = [];
let currentRawContext = null;
let rawPrepareAllRunningMac = null;
let crackingAccordionMode = 'multi';
let crackingAttackPanelMode = 'multi';

function notifyRightPanelsModeChanged() {
    document.dispatchEvent(new CustomEvent('rightPanelsModeChanged'));
}

function normalizeCrackingAccordionMode(value) {
    const normalized = String(value || 'multi').trim().toLowerCase();
    return normalized === 'single' ? 'single' : 'multi';
}

function normalizeCrackingAttackPanelMode(value) {
    const normalized = String(value || 'multi').trim().toLowerCase();
    return normalized === 'single' ? 'single' : 'multi';
}

function escapeMaybe(value, fallback = '—') {
    if (value === null || value === undefined || value === '') return fallback;
    return escapeHtml(String(value));
}

function isAssociationMode(mode) {
    return mode === 'association' || mode === 'association_hint_first' || mode === 'association_hint_rule';
}

function isRawHashFilename(name) {
    return /^raw_.*\.22000$/i.test(String(name || '').trim());
}

function isRawHashCompanionFilename(name) {
    return /^raw_.*\.(details|try|cracked)$/i.test(String(name || '').trim());
}

function getFileStem(name) {
    const filename = String(name || '');
    const idx = filename.lastIndexOf('.');
    return idx > 0 ? filename.slice(0, idx) : filename;
}

function filterFilesForRawHashScope(files, selectedFilename) {
    const selectedName = String(selectedFilename || '').trim();
    if (!selectedName) return files;

    const selectedStem = getFileStem(selectedName);
    const scoped = (Array.isArray(files) ? files : []).filter((file) => {
        const name = String(file?.name || '');
        return name === selectedName || name.startsWith(`${selectedStem}.`);
    });
    if (scoped.length > 0) return scoped;

    const selectedFromAll = (Array.isArray(files) ? files : []).find(
        (file) => String(file?.name || '') === selectedName
    );
    if (selectedFromAll) return [selectedFromAll];

    return [
        {
            name: selectedName,
            type: '22000',
            size: 0,
            modified: Date.now() / 1000,
        },
    ];
}

function isValidMac(value) {
    return /^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$/i.test(String(value || '').trim());
}

function normalizeRawContextPayload(payload) {
    const source = payload && typeof payload === 'object' ? payload : {};
    const filesRaw = Array.isArray(source.files) ? source.files : [];
    const files = filesRaw
        .filter((item) => item && typeof item === 'object')
        .map((item) => ({
            artifact_type: 'pcap',
            raw_item_id: String(item.raw_item_id || '').trim(),
            source: String(item.source || '').trim() || 'brucegotchi',
            device_label: String(item.device_label || '').trim() || 'Brucegotchi',
            source_path_role: String(item.source_path_role || '').trim() || 'rawsniffer',
            filename: String(item.filename || item.source_file || '').trim(),
            source_file: String(item.source_file || '').trim(),
            bssid: String(item.bssid || '').trim() || null,
            ssid: String(item.ssid || '').trim(),
            channel: Number.isFinite(Number(item.channel)) ? Number(item.channel) : null,
            frequency_mhz: Number.isFinite(Number(item.frequency_mhz)) ? Number(item.frequency_mhz) : null,
            beacon_count: Number(item.beacon_count || 0) || 0,
            eapol_count: Number(item.eapol_count || 0) || 0,
            processed_at: item.processed_at || null,
            warnings: Array.isArray(item.warnings) ? item.warnings : [],
            details_present: Boolean(item.details_present),
            details_filename: String(item.details_filename || '').trim() || null,
            details_size: Number(item.details_size || 0) || 0,
            details_modified: Number(item.details_modified || 0) || 0,
            analysis_present: Boolean(item.analysis_present),
            analysis_summary: item.analysis_summary && typeof item.analysis_summary === 'object'
                ? item.analysis_summary
                : null,
        }))
        .filter((item) => !!item.source_file);

    const hashFilesRaw = Array.isArray(source.hash_files) ? source.hash_files : [];
    const hashFiles = hashFilesRaw
        .filter((item) => item && typeof item === 'object')
        .map((item) => ({
            artifact_type: '22000',
            raw_item_id: String(item.raw_item_id || '').trim(),
            source: String(item.source || '').trim() || 'brucegotchi',
            device_label: String(item.device_label || '').trim() || 'Brucegotchi',
            source_path_role: String(item.source_path_role || '').trim() || 'rawsniffer',
            filename: String(item.filename || '').trim(),
            bssid: String(item.bssid || '').trim() || null,
            valid_hash_lines: Number(item.valid_hash_lines || 0) || 0,
            matched_lines: Number(item.matched_lines || 0) || 0,
            source_raw_file: String(item.source_raw_file || '').trim(),
            modified: Number.isFinite(Number(item.modified)) ? Number(item.modified) : null,
            size: Number(item.size || 0) || 0,
            matched_ssid: String(item.matched_ssid || '').trim() || null,
            primary_ssid: String(item.primary_ssid || '').trim() || null,
            details_present: Boolean(item.details_present),
            details_filename: String(item.details_filename || '').trim() || null,
            details_size: Number(item.details_size || 0) || 0,
            details_modified: Number(item.details_modified || 0) || 0,
            analysis_present: Boolean(item.analysis_present),
            analysis_summary: item.analysis_summary && typeof item.analysis_summary === 'object'
                ? item.analysis_summary
                : null,
        }))
        .filter((item) => !!item.filename);

    return {
        present: Boolean(source.present) || files.length > 0 || hashFiles.length > 0,
        bssid: source.bssid || null,
        files_count: files.length,
        hash_files_count: hashFiles.length,
        files,
        hash_files: hashFiles,
        aggregate: source.aggregate && typeof source.aggregate === 'object' ? source.aggregate : {},
    };
}

function getRawItemUiKey(item) {
    const artifactType = String(item?.artifact_type || '').trim().toLowerCase() || 'raw';
    const rawItemId = String(item?.raw_item_id || '').trim();
    const name = String(item?.filename || item?.source_file || '').trim();
    return `raw::${artifactType}::${rawItemId || name}`;
}

function getRawSubtypeLabel(sourcePathRole) {
    const normalized = String(sourcePathRole || '').trim().toLowerCase();
    if (normalized === 'master_sniffer') return 'MASTER SNIFFER';
    if (normalized === 'rawsniffer') return 'RAWSNIFFER';
    return '';
}

function toRawSelectableFile(item) {
    const artifactType = String(item?.artifact_type || '').trim().toLowerCase();
    return {
        name: String(item?.filename || item?.source_file || '').trim(),
        size: Number(item?.size || 0) || 0,
        modified: Number(item?.modified || 0) || 0,
        type: artifactType === '22000' ? 'raw_22000' : 'raw_pcap',
        source: String(item?.source || '').trim() || null,
        device_label: String(item?.device_label || '').trim() || null,
        source_path_role: String(item?.source_path_role || '').trim() || null,
        raw_item_id: String(item?.raw_item_id || '').trim() || null,
        raw_artifact_type: artifactType || 'pcap',
        raw_context_item: item,
        ui_key: getRawItemUiKey(item),
    };
}

function toRawDetailsSelectableFile(item) {
    const detailsName = String(item?.details_filename || '').trim();
    if (!detailsName) return null;
    const sourceName = String(item?.filename || item?.source_file || '').trim();
    const detailsDisplayName = sourceName
        ? `${getFileStem(sourceName)}.details`
        : detailsName;
    const metaParts = [];
    if (Number(item?.details_size || 0) > 0) {
        metaParts.push(`${(Number(item.details_size || 0) / 1024).toFixed(1)} KB`);
    }
    if (String(item?.bssid || '').trim()) {
        metaParts.push(String(item.bssid).trim());
    } else if (sourceName) {
        metaParts.push(`from ${sourceName}`);
    }
    return {
        name: detailsName,
        display_name: detailsDisplayName,
        meta_text: metaParts.join(' | '),
        size: Number(item?.details_size || 0) || 0,
        modified: Number(item?.details_modified || 0) || 0,
        type: 'details',
        source: null,
        device_label: null,
        source_path_role: 'rawsniffer_details',
        raw_item_id: String(item?.raw_item_id || '').trim() || null,
        raw_artifact_type: 'details',
        raw_context_item: item,
        ui_key: `raw::details::${String(item?.raw_item_id || detailsName).trim()}`,
    };
}

function getRawSelectableFilesForContext(context) {
    const normalized = normalizeRawContextPayload(context);
    const items = [
        ...(Array.isArray(normalized.files) ? normalized.files : []),
        ...(Array.isArray(normalized.hash_files) ? normalized.hash_files : []),
    ];
    const selectables = [];
    items.forEach((item) => {
        selectables.push(toRawSelectableFile(item));
        if (String(item?.artifact_type || '').trim().toLowerCase() === 'pcap' && item?.details_present && item?.details_filename) {
            const detailsFile = toRawDetailsSelectableFile(item);
            if (detailsFile) selectables.push(detailsFile);
        }
    });
    return selectables.filter(Boolean);
}

function isRawCanonicalFile(file) {
    const name = String(file?.name || '').trim().toLowerCase();
    if (!name) return false;
    if (String(file?.capture_id || '').trim()) return false;
    if (!name.includes('__wdrs__')) return false;
    if (name.includes('__wdrs__raw_')) return false;
    if (name.endsWith('.wdrs.json')) return false;
    return true;
}

function getRawCanonicalFiles(files = currentFiles) {
    return (Array.isArray(files) ? files : []).filter((file) => isRawCanonicalFile(file));
}

function getRawHashCompanionFiles(rawHashName, files = currentFiles) {
    const hashName = String(rawHashName || '').trim();
    if (!isRawHashFilename(hashName)) return [];

    const stem = getFileStem(hashName);
    const companionTypeOrder = { details: 0, try: 1, cracked: 2 };
    return (Array.isArray(files) ? files : [])
        .filter((file) => {
            const name = String(file?.name || '').trim();
            if (!name || name === hashName) return false;
            if (!name.startsWith(`${stem}.`)) return false;
            if (!isRawHashCompanionFilename(name)) return false;
            return true;
        })
        .map((file) => {
            const normalized = normalizeHandshakeFileRecord(file);
            return {
                ...normalized,
                source: null,
                device_label: null,
                ui_key: `raw-companion::${normalized.name}`,
            };
        })
        .sort((left, right) => {
            const leftType = String(left?.type || '').trim().toLowerCase();
            const rightType = String(right?.type || '').trim().toLowerCase();
            const leftOrder = companionTypeOrder[leftType] ?? 9;
            const rightOrder = companionTypeOrder[rightType] ?? 9;
            if (leftOrder !== rightOrder) return leftOrder - rightOrder;
            return String(left?.name || '').localeCompare(String(right?.name || ''), undefined, {
                numeric: true,
                sensitivity: 'base',
            });
        });
}

function getRawContextSummaryText(context, overrideText = null) {
    if (overrideText) return overrideText;
    const hashFilesCount = Number(context?.hash_files_count || 0);
    const filesCount = Number(context?.files_count || 0);
    const hashFiles = Array.isArray(context?.hash_files) ? context.hash_files : [];
    const totalHashLines = hashFiles.reduce((sum, item) => sum + Number(item?.valid_hash_lines || 0), 0);
    const aggregate = context?.aggregate && typeof context.aggregate === 'object' ? context.aggregate : {};
    if (hashFilesCount > 0) {
        const eapolTotal = Number(aggregate.eapol_count_total || 0);
        return `${hashFilesCount} RAW hash(es) linked · ${totalHashLines} valid lines · EAPOL ${eapolTotal}`;
    }
    if (filesCount > 0) {
        return `No RAW hashes linked yet · ${filesCount} RAW capture(s) available for BUILD CANONICAL FROM ALL`;
    }
    return 'No RAW context linked to this BSSID';
}

function formatRawProcessedAt(value) {
    if (!value) return 'Processed: unknown';
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return `Processed: ${escapeHtml(String(value))}`;
    return `Processed: ${parsed.toLocaleString()}`;
}

function renderRawContextSummary(context, overrideText = null) {
    const summary = document.getElementById('crack-raw-context-summary');
    if (!summary) return;
    summary.textContent = getRawContextSummaryText(context, overrideText);
}

function resolveCanonicalHashFromResult(result) {
    if (!result || typeof result !== 'object') return null;
    if (result.canonical_hash) return String(result.canonical_hash);
    if (result.artifacts && result.artifacts.hash_file) return String(result.artifacts.hash_file);
    return null;
}

function setRawPrepareAllButtonState({ running = false } = {}) {
    const button = document.getElementById('crack-raw-prepare-all-btn');
    if (!button) return;
    button.disabled = running;
    button.innerHTML = running
        ? '<i class="fa-solid fa-spinner fa-spin"></i> RUNNING'
        : 'BUILD CANONICAL FROM ALL';
}

function renderRawContextSection(rawContext) {
    const context = normalizeRawContextPayload(rawContext);
    currentRawContext = context;
    return context;
}

function renderRawContextLoading() {
    currentRawContext = {
        present: false,
        loading: true,
        files_count: 0,
        hash_files_count: 0,
        files: [],
        hash_files: [],
        aggregate: {},
    };
}

async function handleRawAutoPrepare(button) {
    const rawTarget = button && typeof button === 'object' && button.raw_item_id
        ? button
        : selectedFile;
    if (!rawTarget || rawTarget.type !== 'raw_pcap') return;

    const sourceFile = String(rawTarget.name || rawTarget.source_file || '').trim();
    const rawItemId = String(rawTarget.raw_item_id || '').trim();
    if (!sourceFile && !rawItemId) return;

    const mac = document.getElementById('crack-mac')?.innerText || '';
    const ssid = document.getElementById('crack-ssid')?.innerText || '';
    if (!mac) return;

    const buildButton = document.getElementById('btn-convert-hash');
    const originalHtml = buildButton?.innerHTML;
    if (buildButton) {
        buildButton.disabled = true;
        buildButton.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> BUILDING...';
    }
    const processId = `raw-prepare-item-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const sourceLabel = sourceFile || rawItemId;
    const processDetails = `${mac} · ${sourceLabel}`;
    addProcess(
        processId,
        'RAW SNIFFER BUILD CANONICAL',
        processDetails,
        'STARTING',
        mac
    );
    try {
        const result = await API.prepareHandshakeRaw(mac, {
            source_file: sourceFile,
            raw_item_id: rawItemId || null,
            force: false,
        });
        const resultStatus = String(result?.status || '').toLowerCase();
        if (resultStatus === 'success') {
            updateProcess(processId, 100, 'COMPLETED', result?.canonical_hash || sourceFile, false);
        } else if (resultStatus === 'success_partial') {
            updateProcess(processId, 100, 'PARTIAL', result?.message || sourceFile, false);
        } else if (resultStatus === 'up_to_date') {
            updateProcess(processId, 100, 'UP TO DATE', result?.canonical_hash || sourceFile, false);
        } else {
            updateProcess(processId, 100, 'ERROR', result?.message || 'RAW prepare failed', false);
        }

        const selectedName = resolveCanonicalHashFromResult(result);
        await openCrackingPanel(mac, ssid, selectedName);
        if (result?.message) {
            log(result.message, result.status === 'success_partial' ? 'warning' : 'success');
        }
    } catch (e) {
        updateProcess(processId, 100, 'ERROR', e.message || 'RAW prepare failed', false);
        log(`RAW auto-prepare failed: ${e.message}`, 'error');
    } finally {
        if (buildButton) {
            buildButton.disabled = false;
            buildButton.innerHTML = originalHtml || '<i class="fa-solid fa-layer-group"></i> BUILD CANONICAL';
        }
    }
}

async function handleRawAutoPrepareAll(button) {
    if (!button) return;
    const mac = document.getElementById('crack-mac')?.innerText || '';
    const ssid = document.getElementById('crack-ssid')?.innerText || '';
    if (!isValidMac(mac)) return;

    setRawPrepareAllButtonState({ running: true });
    renderRawContextSummary(currentRawContext, 'Building canonical hash from linked RAW items...');

    try {
        const result = await API.prepareHandshakeRawAll(mac, { force: false });
        rawPrepareAllRunningMac = mac.toUpperCase();
        const totalFiles = Number(
            result?.total_files
            || currentRawContext?.hash_files_count
            || currentRawContext?.files_count
            || 0
        );
        const details = totalFiles > 0
            ? `${mac} (${totalFiles} source files)`
            : mac;
        if (result?.job_id) {
            addProcess(
                result.job_id,
                'RAW SNIFFER PREPARE ALL',
                details,
                'STARTING',
                mac
            );
        }
        renderRawContextSummary(
            currentRawContext,
            totalFiles > 0
                ? `Running canonical prepare across ${totalFiles} source file(s)...`
                : 'Running canonical build...'
        );
        log(`RAW prepare-all started for ${ssid || mac}`, 'info');
    } catch (e) {
        rawPrepareAllRunningMac = null;
        setRawPrepareAllButtonState({ running: false });
        renderRawContextSummary(currentRawContext);
        log(`RAW prepare-all failed to start: ${e.message}`, 'error');
    }
}

async function handleBuildCombinedCandidate(button) {
    const mac = document.getElementById('crack-mac')?.innerText || '';
    const ssid = document.getElementById('crack-ssid')?.innerText || '';
    if (!isValidMac(mac)) return;
    const captureIds = Array.isArray(currentHandshakeSet?.captures)
        ? currentHandshakeSet.captures.map((capture) => String(capture.capture_id || '').trim()).filter(Boolean)
        : [];
    if (captureIds.length < 2) {
        log('Need at least two capture candidates to build a combined candidate.', 'warning');
        return;
    }

    const processId = `combined-build-${Date.now()}`;
    const processDetails = ssid && ssid !== 'HIDDEN'
        ? `${ssid} (${captureIds.length} captures)`
        : `${mac} (${captureIds.length} captures)`;

    const originalLabel = button?.textContent || 'BUILD COMBINED CANDIDATE';
    if (button) {
        button.disabled = true;
        button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> BUILDING...';
    }
    addProcess(
        processId,
        'BUILD COMBINED CANDIDATE',
        processDetails,
        'STARTING',
        mac
    );
    if (activeProcesses[processId]) {
        activeProcesses[processId].noCancel = true;
    }
    updateProcess(
        processId,
        5,
        'RUNNING',
        `${captureIds.length} capture(s) selected`,
        true
    );
    try {
        const result = await API.buildCombinedCapture(mac, captureIds);
        if (result?.status !== 'success') {
            throw new Error(result?.message || 'Failed to build combined candidate');
        }
        updateProcess(
            processId,
            100,
            'COMPLETED',
            result?.output_file || `deduped ${Number(result?.deduped_hash_count || 0)} line(s)`,
            false
        );
        log(`Combined candidate built for ${ssid || mac}`, 'success');
        await openCrackingPanel(mac, ssid, result.output_file, {
            combinedBuildId: result.build_id,
        });
    } catch (e) {
        updateProcess(
            processId,
            100,
            'ERROR',
            e.message || 'Combined candidate build failed',
            false
        );
        log(`Combined candidate build failed: ${e.message}`, 'error');
    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = originalLabel;
        }
    }
}

function normalizeMacAddress(value) {
    const cleaned = String(value || '').replace(/[^0-9A-Fa-f]/g, '').toUpperCase();
    if (cleaned.length !== 12) return null;
    return cleaned.match(/.{1,2}/g).join(':');
}

function isVisibleBatchSsid(ssid) {
    const text = String(ssid || '').trim();
    if (!text) return false;
    const upper = text.toUpperCase();
    if (upper === 'HS' || upper === 'HIDDEN') return false;
    if (upper.startsWith('HS_') || upper.startsWith('HIDDEN_')) return false;
    return true;
}

function resolveBatchContext(items) {
    if (!Array.isArray(items) || !items.length) return null;
    let best = null;

    items.forEach((item) => {
        if (!item || typeof item !== 'object') return;
        const mac = normalizeMacAddress(item.mac || item.bssid || item.mac_address);
        if (!mac) return;

        const ssid = String(item.ssid || '').trim();
        const status = String(item.status || '').trim().toUpperCase();
        const hasVisibleSsid = isVisibleBatchSsid(ssid);
        let score = 0;
        if (status === 'OK') score += 4;
        if (hasVisibleSsid) score += 3;
        if (String(item.reason || '').toUpperCase() === 'HANDSHAKE OK') score += 1;

        const candidate = { mac, ssid, hasVisibleSsid, score };
        if (!best || candidate.score > best.score) {
            best = candidate;
        }
    });

    if (!best) return null;
    return {
        mac: best.mac,
        ssid: best.ssid,
        hasVisibleSsid: best.hasVisibleSsid,
    };
}

function normalizeBatchManifestItems(items) {
    if (!Array.isArray(items)) return [];
    return items.filter((item) => item && typeof item === 'object');
}

function summarizeBatchManifest(items) {
    const normalizedItems = normalizeBatchManifestItems(items);
    const summary = {
        total: normalizedItems.length,
        ok: 0,
        eapolMissing: 0,
        invalid: 0,
        cracked: 0,
        failed: 0,
    };

    normalizedItems.forEach((item) => {
        const status = String(item?.status || '').trim().toUpperCase();
        const reason = String(item?.reason || '').trim().toUpperCase();
        const isCracked = Boolean(item?.cracked || item?.pass)
            || status === 'CRACKED'
            || reason.includes('CRACKED');
        if (isCracked) {
            summary.cracked += 1;
        }
        const handshakeOk = status === 'OK' || reason === 'HANDSHAKE OK';
        if (handshakeOk) {
            summary.ok += 1;
            return;
        }

        if (reason.includes('EAPOL MISSING')) {
            summary.eapolMissing += 1;
        }
        if (reason.includes('INVALID')) {
            summary.invalid += 1;
        }
        if (status === 'FAILED' || status === 'ERROR' || reason.includes('MISSING') || reason.includes('INVALID') || reason.includes('EMPTY')) {
            summary.failed += 1;
        }
    });

    return summary;
}

function renderBatchSelectionSummary(filename) {
    const summaryNode = document.getElementById('crack-handshake-set-summary');
    if (!summaryNode) return;

    const selectedFilename = String(filename || '').trim();
    if (!selectedFilename || !selectedFilename.toLowerCase().endsWith('.22000')) {
        summaryNode.style.display = 'none';
        summaryNode.innerHTML = '';
        return;
    }

    const manifestSummary = summarizeBatchManifest(currentBatchManifestItems);
    const metaBits = [
        `${manifestSummary.total} item(s)`,
        `${manifestSummary.ok} handshake OK`,
        `${manifestSummary.eapolMissing} EAPOL missing`,
        `${manifestSummary.invalid} invalid`,
        `${manifestSummary.cracked} cracked`,
    ];

    summaryNode.style.display = 'flex';
    summaryNode.innerHTML = `
        <div class="crack-set-summary-main">
            <div class="crack-set-summary-title">HANDSHAKE SET</div>
            <div class="crack-set-summary-meta">
                ${metaBits.map((bit) => `<span>${escapeHtml(String(bit))}</span>`).join('')}
            </div>
        </div>
        <div class="crack-set-summary-side">
            <div class="crack-set-summary-sources">
                ${renderSemanticBadge(`OK ${manifestSummary.ok}`, 'source-badge badge-role-artifact-cracked')}
                ${renderSemanticBadge(`EAPOL MISS ${manifestSummary.eapolMissing}`, 'source-badge badge-role-state-raw')}
                ${renderSemanticBadge(`INVALID ${manifestSummary.invalid}`, 'source-badge badge-role-state-legacy')}
                ${renderSemanticBadge(`CRACKED ${manifestSummary.cracked}`, 'source-badge badge-role-state-combined')}
            </div>
        </div>
    `;
}

function getFileUiKey(file) {
    const name = String(file?.name || '');
    const combinedBuildId = String(file?.combined_build_id || '').trim();
    if (combinedBuildId) return `combined::${combinedBuildId}::${name}`;
    const captureId = String(file?.capture_id || 'legacy');
    return `${captureId}::${name}`;
}

function normalizeHandshakeSetPayload(payload) {
    const source = payload && typeof payload === 'object' ? payload : {};
    const capturesRaw = Array.isArray(source.captures) ? source.captures : [];
    const captures = capturesRaw
        .filter((capture) => capture && typeof capture === 'object')
        .map((capture) => ({
            capture_id: String(capture.capture_id || '').trim(),
            source: String(capture.source || '').trim(),
            device_label: String(capture.device_label || '').trim(),
            source_filename: String(capture.source_filename || '').trim(),
            source_path_role: String(capture.source_path_role || '').trim(),
            ssid: String(capture.ssid || '').trim(),
            resolved_ssid: String(capture.resolved_ssid || '').trim(),
            quality: capture.quality && typeof capture.quality === 'object'
                ? {
                    score: Number(capture.quality.score || 0) || 0,
                    tier: String(capture.quality.tier || 'low').trim() || 'low',
                    reasons: Array.isArray(capture.quality.reasons) ? capture.quality.reasons : [],
                    valid_hash_lines: Number(capture.quality.valid_hash_lines || 0) || 0,
                    details_richness: Number(capture.quality.details_richness || 0) || 0,
                }
                : {
                    score: 0,
                    tier: 'low',
                    reasons: [],
                    valid_hash_lines: 0,
                    details_richness: 0,
                },
            is_preferred: Boolean(capture.is_preferred),
            legacy_shared_artifacts: Boolean(capture.legacy_shared_artifacts),
        }))
        .filter((capture) => !!capture.capture_id);

    return {
        handshake_set_id: String(source.handshake_set_id || '').trim(),
        mac: String(source.mac || '').trim(),
        resolved_ssid: String(source.resolved_ssid || '').trim(),
        sources: Array.isArray(source.sources) ? source.sources : [],
        preferred_capture_id: String(source.preferred_capture_id || '').trim(),
        artifact_summary: source.artifact_summary && typeof source.artifact_summary === 'object'
            ? source.artifact_summary
            : {},
        combined_candidates: Array.isArray(source.combined_candidates)
            ? source.combined_candidates
                .filter((item) => item && typeof item === 'object')
                .map((item) => ({
                    name: String(item.name || '').trim() || 'combined.22000',
                    size: Number(item.size || 0) || 0,
                    modified: Number(item.modified || 0) || 0,
                    type: String(item.type || '22000').trim().toLowerCase() || '22000',
                    combined_build_id: String(item.combined_build_id || item.build_id || '').trim() || null,
                    artifact_scope: 'combined',
                    source: 'combined',
                    device_label: 'Combined',
                    included_capture_ids: Array.isArray(item.included_capture_ids) ? item.included_capture_ids : [],
                    included_captures: Array.isArray(item.included_captures)
                        ? item.included_captures
                            .filter((capture) => capture && typeof capture === 'object')
                            .map((capture) => ({
                                capture_id: String(capture.capture_id || '').trim() || null,
                                source: String(capture.source || '').trim() || null,
                                device_label: String(capture.device_label || '').trim() || null,
                                source_filename: String(capture.source_filename || '').trim() || null,
                                source_kind: String(capture.source_kind || '').trim() || null,
                                valid_hash_lines: Number(capture.valid_hash_lines || 0) || 0,
                            }))
                        : [],
                    included_capture_count: Number(item.included_capture_count || 0) || 0,
                    deduped_hash_count: Number(item.deduped_hash_count || 0) || 0,
                    cracked_present: Boolean(item.cracked_present),
                    history_present: Boolean(item.history_present),
                }))
            : [],
        captures,
    };
}

function normalizeHandshakeFileRecord(file) {
    const source = file && typeof file === 'object' ? file : {};
    const name = String(source.name || '').trim();
    return {
        name,
        size: Number(source.size || 0) || 0,
        modified: Number(source.modified || 0) || 0,
        type: String(source.type || '').trim().toLowerCase() || 'file',
        capture_id: String(source.capture_id || '').trim() || null,
        source: String(source.source || '').trim() || null,
        device_label: String(source.device_label || '').trim() || null,
        source_path_role: String(source.source_path_role || '').trim() || null,
        legacy_shared: Boolean(source.legacy_shared),
        is_preferred: Boolean(source.is_preferred),
        artifact_scope: String(source.artifact_scope || '').trim() || (source.capture_id ? 'capture' : 'shared_legacy'),
        artifact_owner_capture_id: String(source.artifact_owner_capture_id || '').trim() || null,
        combined_build_id: String(source.combined_build_id || '').trim() || null,
        ui_key: getFileUiKey(source),
    };
}

function getCaptureById(captureId) {
    const normalizedId = String(captureId || '').trim();
    if (!normalizedId) return null;
    const captures = Array.isArray(currentHandshakeSet?.captures) ? currentHandshakeSet.captures : [];
    return captures.find((capture) => capture.capture_id === normalizedId) || null;
}

function getCombinedCandidateByBuildId(buildId) {
    const normalizedId = String(buildId || '').trim();
    if (!normalizedId) return null;
    const candidates = Array.isArray(currentHandshakeSet?.combined_candidates)
        ? currentHandshakeSet.combined_candidates
        : [];
    return candidates.find((candidate) => String(candidate?.combined_build_id || '').trim() === normalizedId) || null;
}

function getCaptureFiles(captureId, files = currentFiles) {
    const normalizedId = String(captureId || '').trim();
    return (Array.isArray(files) ? files : []).filter(
        (file) => String(file?.capture_id || '').trim() === normalizedId
    );
}

function getCapturePreferredFile(captureId, files = currentFiles) {
    const captureFiles = getCaptureFiles(captureId, files);
    if (!captureFiles.length) return null;
    const byType = (type) => captureFiles.find((file) => file.type === type);
    return byType('22000')
        || byType('pcap')
        || byType('details')
        || byType('cracked')
        || captureFiles[0];
}

function getStandaloneFiles(files = currentFiles) {
    return (Array.isArray(files) ? files : []).filter(
        (file) => !String(file?.capture_id || '').trim()
    );
}

function getCaptureTierLabel(tier) {
    const normalized = String(tier || '').trim().toLowerCase();
    if (normalized === 'high') return 'HIGH';
    if (normalized === 'medium') return 'MEDIUM';
    return 'LOW';
}

function getCaptureTierClass(tier) {
    const normalized = String(tier || '').trim().toLowerCase();
    if (normalized === 'high') return 'capture-tier-high';
    if (normalized === 'medium') return 'capture-tier-medium';
    return 'capture-tier-low';
}

function getSourceBadgeClass(source) {
    const normalized = String(source || '').trim().toLowerCase();
    if (!normalized) return 'source-badge';
    return `source-badge source-${normalized}`;
}

function renderSemanticBadge(label, className) {
    return `<span class="${className}">${escapeHtml(String(label || ''))}</span>`;
}

function renderSectionDivider(label) {
    return `
        <div class="capture-section-divider" role="separator" aria-label="${escapeHtml(String(label || ''))}">
            <span class="capture-section-divider-line"></span>
            <span class="capture-section-divider-label">${escapeHtml(String(label || ''))}</span>
            <span class="capture-section-divider-line"></span>
        </div>
    `;
}

function appendDerivedArtifactsDivider(list) {
    const divider = document.createElement('div');
    divider.innerHTML = renderSectionDivider('DERIVED ARTIFACTS');
    list.appendChild(divider.firstElementChild);
}

function updateActiveCaptureGroups(selectedElement) {
    document
        .querySelectorAll('#crack-file-list .capture-group, #crack-file-list .capture-group-header')
        .forEach((node) => node.classList.remove('capture-group-active', 'capture-group-header-active'));
    if (!selectedElement) return;
    let current = selectedElement.closest('.capture-group');
    while (current) {
        current.classList.add('capture-group-active');
        const header = current.querySelector(':scope > .capture-group-header');
        if (header) header.classList.add('capture-group-header-active');
        current = current.parentElement ? current.parentElement.closest('.capture-group') : null;
    }
}

function syncAccordionState(group, expanded) {
    if (!group) return;
    const body = group.querySelector(':scope > .capture-group-body');
    const header = group.querySelector(':scope > .capture-group-header');
    const arrow = header?.querySelector('.capture-group-arrow');
    if (body) body.hidden = !expanded;
    if (arrow) arrow.classList.toggle('capture-group-arrow-open', !!expanded);
}

function collapseSiblingAccordions(group) {
    if (crackingAccordionMode !== 'single' || !group?.parentElement) return;
    Array.from(group.parentElement.children).forEach((sibling) => {
        if (sibling === group) return;
        if (!sibling.classList?.contains('capture-group')) return;
        syncAccordionState(sibling, false);
    });
}

function autoSelectGroupFile(file, itemByKey) {
    if (!file) return;
    const targetItem = itemByKey?.get?.(file.ui_key);
    if (targetItem) selectFile(file, targetItem);
}

function getFileVisuals(file) {
    let icon = 'fa-file';
    let typeTag = 'FILE';
    let badgeClass = 'badge-default';
    const type = String(file?.type || '').toLowerCase();
    const name = String(file?.name || '');

    if (type === 'pcap') {
        icon = 'fa-handshake';
        typeTag = 'PCAP';
        badgeClass = 'badge-pcap';
    } else if (type === 'raw_pcap') {
        icon = 'fa-handshake';
        typeTag = 'RAW PCAP';
        badgeClass = 'badge-pcap';
    } else if (type === 'raw_22000') {
        icon = 'fa-hashtag';
        typeTag = 'RAW 22000';
        badgeClass = 'badge-hash';
    } else if (type === 'details' || name.endsWith('.details')) {
        icon = 'fa-magnifying-glass-chart';
        typeTag = 'DETAILS';
        badgeClass = 'badge-details';
    } else if (type === '22000') {
        icon = 'fa-hashtag';
        typeTag = '22000';
        badgeClass = 'badge-hash';
    } else if (type === 'batch') {
        icon = 'fa-layer-group';
        typeTag = 'BATCH';
        badgeClass = 'badge-hash';
    } else if (type === 'cracked' || name.endsWith('.cracked')) {
        icon = 'fa-key';
        typeTag = 'CRACKED';
        badgeClass = 'badge-cracked';
    } else if (name.endsWith('.gps.json') || name.endsWith('.geo.json')) {
        icon = 'fa-location-dot';
        typeTag = 'GPS';
        badgeClass = 'badge-gps';
    } else if (type === 'try') {
        icon = 'fa-clock-rotate-left';
        typeTag = 'HISTORY';
        badgeClass = 'badge-history';
    }

    return { icon, typeTag, badgeClass };
}

function buildSelectedFileSourceBadge(file) {
    if (!file) return '';
    if (isRawCanonicalFile(file)) {
        return renderSemanticBadge('WDRS', 'source-badge badge-role-state-wdrs selected-file-source');
    }
    if (String(file.type || '').toLowerCase() === 'raw_22000') {
        return renderSemanticBadge('RAW HASH', 'source-badge badge-role-state-raw selected-file-source');
    }
    if (file.source) {
        return renderSemanticBadge(file.device_label || file.source, `${getSourceBadgeClass(file.source)} selected-file-source`);
    }
    return '';
}

function renderHandshakeSetSummary(handshakeSet) {
    const summary = document.getElementById('crack-handshake-set-summary');
    if (!summary) return;

    const captures = Array.isArray(handshakeSet?.captures) ? handshakeSet.captures : [];
    if (!captures.length) {
        summary.style.display = 'none';
        summary.innerHTML = '';
        return;
    }

    const artifactSummary = handshakeSet?.artifact_summary && typeof handshakeSet.artifact_summary === 'object'
        ? handshakeSet.artifact_summary
        : {};
    const rawItemsCount = Number(currentRawContext?.files_count || 0) + Number(currentRawContext?.hash_files_count || 0);
    const combinedBuildCount = Array.isArray(handshakeSet?.combined_candidates)
        ? handshakeSet.combined_candidates.length
        : Number(artifactSummary.combined || 0);
    const sourceBadges = [
        ...(Array.isArray(handshakeSet?.sources) ? handshakeSet.sources : []).map(
            (source) => renderSemanticBadge(String(source || ''), getSourceBadgeClass(source))
        ),
        ...(rawItemsCount > 0 ? [renderSemanticBadge('RAW SNIFFER', 'source-badge badge-role-state-raw')] : []),
        ...(combinedBuildCount > 0 ? [renderSemanticBadge('COMBINED', 'source-badge badge-role-state-combined')] : []),
        ...(Number(artifactSummary.cracked || 0) > 0 ? [renderSemanticBadge('CRACKED', 'source-badge badge-role-artifact-cracked')] : []),
    ].join('');
    const metaBits = [
        `${captures.length} capture(s)`,
        `${Number(artifactSummary.hash_22000 || 0)} hash file(s)`,
        `${Number(artifactSummary.details || 0)} details`,
        `${Number(artifactSummary.cracked || 0)} cracked`,
    ];
    if (rawItemsCount > 0) {
        metaBits.push(`${rawItemsCount} RAW item(s)`);
    }
    if (combinedBuildCount > 0) {
        metaBits.push(`${combinedBuildCount} combined build(s)`);
    }
    summary.style.display = 'flex';
    summary.innerHTML = `
        <div class="crack-set-summary-main">
            <div class="crack-set-summary-title">HANDSHAKE SET</div>
            <div class="crack-set-summary-meta">
                ${metaBits.map((bit) => `<span>${escapeHtml(bit)}</span>`).join('')}
            </div>
        </div>
        <div class="crack-set-summary-side">
            <div class="crack-set-summary-sources">${sourceBadges}</div>
        </div>
    `;
}

function renderRawHashScopeSummary(fileToSelectName, files, rawContext) {
    const summary = document.getElementById('crack-handshake-set-summary');
    if (!summary) return;

    const allFiles = Array.isArray(files) ? files : [];
    const targetName = String(fileToSelectName || '').trim();
    const selectedHashFile = allFiles.find((file) => String(file?.name || '').trim() === targetName)
        || allFiles.find((file) => isRawHashFilename(file?.name));
    const selectedHashName = String(selectedHashFile?.name || targetName || '').trim();
    const selectedStem = getFileStem(selectedHashName);

    const context = normalizeRawContextPayload(rawContext);
    const hashItems = Array.isArray(context?.hash_files) ? context.hash_files : [];
    const selectedHashItem = hashItems.find((item) => String(item?.filename || '').trim() === selectedHashName)
        || hashItems.find((item) => getFileStem(String(item?.filename || '').trim()) === selectedStem)
        || null;

    const rawFiles = Array.isArray(context?.files) ? context.files : [];
    const sourceRawFile = String(selectedHashItem?.source_raw_file || '').trim();
    const sourceRawItem = rawFiles.find((item) => String(item?.filename || item?.source_file || '').trim() === sourceRawFile) || null;

    const validHashLines = Number(selectedHashItem?.valid_hash_lines || 0) || 0;
    const matchedLines = Number(selectedHashItem?.matched_lines || 0) || 0;
    const invalidHashLines = Math.max(matchedLines - validHashLines, 0);
    const eapolObserved = Number(sourceRawItem?.eapol_count || context?.aggregate?.eapol_count_total || 0) || 0;
    const eapolMissing = Math.max(eapolObserved - validHashLines, 0);

    const relatedArtifacts = allFiles.filter((file) => {
        const name = String(file?.name || '').trim();
        if (!name || !selectedStem || name === selectedHashName) return false;
        return name.startsWith(`${selectedStem}.`);
    });

    summary.style.display = 'flex';
    summary.innerHTML = `
        <div class="crack-set-summary-main">
            <div class="crack-set-summary-title">HANDSHAKE SET</div>
            <div class="crack-set-summary-meta">
                <span>${escapeHtml(selectedHashName || 'RAW hash')}</span>
                <span>valid ${validHashLines}</span>
                <span>matched ${matchedLines}</span>
                <span>EAPOL missing ${eapolMissing}</span>
                <span>invalid ${invalidHashLines}</span>
                <span>${relatedArtifacts.length} related file(s)</span>
            </div>
        </div>
        <div class="crack-set-summary-side">
            <div class="crack-set-summary-sources">
                ${renderSemanticBadge('RAW SNIFFER', 'source-badge badge-role-state-raw')}
                ${renderSemanticBadge('RAW HASH', 'source-badge badge-role-state-raw')}
                ${renderSemanticBadge('FLAT VIEW', 'source-badge badge-role-state-combined')}
            </div>
        </div>
    `;
}

function renderFileRow(file, itemByKey, options = {}) {
    const showSourceBadge = options.showSourceBadge !== false;
    const { icon, typeTag, badgeClass } = getFileVisuals(file);
    const displayName = String(file?.display_name || file?.name || '').trim();
    const actualName = String(file?.name || '').trim();
    const item = document.createElement('div');
    item.className = 'file-item';
    item.dataset.fileKey = file.ui_key;
    item.dataset.captureId = file.capture_id || '';

    const size = `${(Number(file.size || 0) / 1024).toFixed(1)} KB`;
    const date = file.modified ? new Date(file.modified * 1000).toLocaleDateString() : 'n/a';
    const metaText = String(file?.meta_text || '').trim() || `${size} | ${date}`;
    const isCanonical = isRawCanonicalFile(file);
    const sourceBadge = !showSourceBadge
        ? ''
        : (isCanonical
        ? renderSemanticBadge('WDRS', 'source-badge badge-role-state-wdrs')
        : (file.combined_build_id
            ? renderSemanticBadge('COMBINED', 'source-badge badge-role-state-combined')
        : (file.source
            ? renderSemanticBadge(file.device_label || file.source, getSourceBadgeClass(file.source))
            : '')));
    const legacyBadge = file.legacy_shared && !isCanonical
        ? renderSemanticBadge('SHARED', 'legacy-badge crack-legacy-badge-inline badge-role-state-shared')
        : '';
    const combinedMetaText = file.combined_build_id
        ? `captures ${Number(file.included_capture_count || 0)} | deduped ${Number(file.deduped_hash_count || 0)}`
        : '';
    const combinedMeta = file.combined_build_id
        ? `<span class="file-meta file-meta-combined" title="${escapeHtml(combinedMetaText)}">${escapeHtml(combinedMetaText)}</span>`
        : '';

    item.innerHTML = `
        <div class="file-name-wrapper">
            <i class="fa-solid ${icon}"></i>
            <span class="file-name-text" title="${escapeHtml(actualName || displayName)}">${escapeHtml(displayName || actualName)}</span>
        </div>
        <div class="file-meta-wrapper">
            <span class="file-meta" title="${escapeHtml(metaText)}">${escapeHtml(metaText)}</span>
            ${combinedMeta}
            ${sourceBadge}
            ${legacyBadge}
            <span class="file-type-tag ${badgeClass}">${typeTag}</span>
        </div>
    `;
    item.onclick = () => selectFile(file, item);
    itemByKey.set(file.ui_key, item);
    return item;
}

function renderRawHashScopedList(list, files, fileToSelectName = null) {
    const itemByKey = new Map();
    const scopedFiles = (Array.isArray(files) ? files : []).slice().sort((a, b) => {
        const orderByType = { '22000': 0, details: 1, try: 2, cracked: 3, pcap: 4 };
        const leftType = String(a?.type || '').toLowerCase();
        const rightType = String(b?.type || '').toLowerCase();
        const leftOrder = orderByType[leftType] ?? 9;
        const rightOrder = orderByType[rightType] ?? 9;
        if (leftOrder !== rightOrder) return leftOrder - rightOrder;
        return String(a?.name || '').localeCompare(String(b?.name || ''), undefined, {
            numeric: true,
            sensitivity: 'base',
        });
    });

    list.innerHTML = '';
    list.classList.add('crack-file-list-flat');
    let selectedKey = null;
    scopedFiles.forEach((file) => {
        const normalizedName = String(file?.name || '').trim();
        const normalizedType = String(file?.type || '').toLowerCase();
        const scopedType = (
            normalizedType === '22000' && isRawHashFilename(normalizedName)
        )
            ? 'raw_22000'
            : file.type;
        const row = renderFileRow(
            {
                ...file,
                type: scopedType,
                source: null,
                device_label: null,
            },
            itemByKey,
            { showSourceBadge: false }
        );
        list.appendChild(row);
        if (!selectedKey && String(fileToSelectName || '').trim() === String(file?.name || '').trim()) {
            selectedKey = file.ui_key;
        }
    });

    if (!selectedKey && scopedFiles.length) {
        const preferred = scopedFiles.find((file) => String(file?.type || '').toLowerCase() === '22000') || scopedFiles[0];
        selectedKey = preferred?.ui_key || null;
    }

    // Persist normalized scoped types so downstream actions/labels can use RAW HASH semantics.
    scopedFiles.forEach((file) => {
        const normalizedName = String(file?.name || '').trim();
        if (String(file?.type || '').toLowerCase() === '22000' && isRawHashFilename(normalizedName)) {
            file.type = 'raw_22000';
        }
    });

    return { itemByKey, selectedKey };
}

function renderHandshakeSetList(list, handshakeSet, files, fileToSelectName = null, contextOptions = null) {
    const itemByKey = new Map();
    const captureIdSet = new Set(
        (Array.isArray(handshakeSet?.captures) ? handshakeSet.captures : []).map(
            (capture) => capture.capture_id
        )
    );
    let preferredFile = null;
    let preferredKey = null;

    list.innerHTML = '';
    list.classList.remove('crack-file-list-flat');

    (Array.isArray(handshakeSet?.captures) ? handshakeSet.captures : []).forEach((capture) => {
        const captureFiles = getCaptureFiles(capture.capture_id, files);
        const group = document.createElement('div');
        group.className = 'capture-group capture-group-card capture-group-source-root';
        const header = document.createElement('button');
        header.type = 'button';
        header.className = 'capture-group-header';
        if (capture.capture_id === handshakeSet.preferred_capture_id) {
            header.classList.add('capture-group-header-preferred');
        }
        const defaultFile = getCapturePreferredFile(capture.capture_id, files);
        const quality = capture.quality || {};
        const summaryBits = [];
        if (captureFiles.some((file) => file.type === '22000')) summaryBits.push('22000');
        if (captureFiles.some((file) => file.type === 'pcap')) summaryBits.push('PCAP');
        if (captureFiles.some((file) => file.type === 'details')) summaryBits.push('DETAILS');
        if (captureFiles.some((file) => file.type === 'cracked')) summaryBits.push('CRACKED');
        const expanded = capture.capture_id === handshakeSet.preferred_capture_id
            || captureFiles.some((file) => file.name === fileToSelectName);

        header.innerHTML = `
            <div class="capture-group-main">
                <div class="capture-group-title-row">
                    <div class="capture-group-name">${escapeHtml(capture.source_filename || capture.resolved_ssid || capture.ssid || 'capture')}</div>
                    <div class="capture-group-badges">
                        <span class="${getSourceBadgeClass(capture.source)}">${escapeHtml(capture.device_label || capture.source || 'Capture')}</span>
                        <span class="capture-quality-badge ${getCaptureTierClass(quality.tier)}">${getCaptureTierLabel(quality.tier)}</span>
                    </div>
                </div>
                <div class="capture-group-meta">
                    <span>Score ${escapeHtml(String(quality.score ?? 0))}</span>
                    <span>${captureFiles.length} file(s)</span>
                    ${summaryBits.length ? `<span>${escapeHtml(summaryBits.join(' · '))}</span>` : ''}
                </div>
            </div>
            <i class="fa-solid fa-chevron-down capture-group-arrow ${expanded ? 'capture-group-arrow-open' : ''}"></i>
        `;

        const body = document.createElement('div');
        body.className = 'capture-group-body';
        body.hidden = !expanded;

        captureFiles
            .sort((a, b) => {
                const typeOrder = { '22000': 0, pcap: 1, details: 2, cracked: 3, try: 4 };
                const orderA = typeOrder[a.type] ?? 9;
                const orderB = typeOrder[b.type] ?? 9;
                if (orderA !== orderB) return orderA - orderB;
                return String(a.name || '').localeCompare(String(b.name || ''), undefined, { numeric: true, sensitivity: 'base' });
            })
            .forEach((file) => {
                body.appendChild(renderFileRow(file, itemByKey, { showSourceBadge: false }));
                if (!preferredFile && capture.capture_id === handshakeSet.preferred_capture_id && defaultFile && file.ui_key === defaultFile.ui_key) {
                    preferredFile = file;
                }
                if (!preferredKey && fileToSelectName && file.name === fileToSelectName) {
                    preferredKey = file.ui_key;
                }
            });

        header.addEventListener('click', () => {
            const nextHidden = !body.hidden;
            if (!nextHidden) {
                collapseSiblingAccordions(group);
            }
            body.hidden = nextHidden;
            const arrow = header.querySelector('.capture-group-arrow');
            if (arrow) {
                arrow.classList.toggle('capture-group-arrow-open', !nextHidden);
            }
            if (!nextHidden && defaultFile) {
                const targetItem = itemByKey.get(defaultFile.ui_key);
                if (targetItem) selectFile(defaultFile, targetItem);
            }
        });

        group.appendChild(header);
        group.appendChild(body);
        list.appendChild(group);
    });

    const rawCanonicalFiles = currentRawContext?.present ? getRawCanonicalFiles(files) : [];
    const rawCanonicalKeys = new Set(rawCanonicalFiles.map((file) => file.ui_key));

    // Legacy/shared flat artifacts are intentionally hidden from the main
    // operator flow. Capture-scoped files now live inside their source groups.
    const standaloneFiles = [];
    const willRenderRaw = Boolean(currentRawContext?.present);
    const willRenderCombined = Array.isArray(handshakeSet?.captures) && (
        handshakeSet.captures.length >= 2
        || (Array.isArray(handshakeSet?.combined_candidates) && handshakeSet.combined_candidates.length)
    );
    const willRenderStandalone = standaloneFiles.length > 0;
    if (captureIdSet.size > 0 && (willRenderRaw || willRenderCombined || willRenderStandalone)) {
        appendDerivedArtifactsDivider(list);
    }

    const rawRendered = appendRawContextAccordion(
        list,
        currentRawContext,
        itemByKey,
        fileToSelectName,
        contextOptions,
        rawCanonicalFiles
    );
    if (!preferredKey && rawRendered?.selectedKey) {
        preferredKey = rawRendered.selectedKey;
    }

    const combinedRendered = appendCombinedCandidatesAccordion(
        list,
        handshakeSet,
        itemByKey,
        fileToSelectName,
        contextOptions,
    );
    if (!preferredKey && combinedRendered?.selectedKey) {
        preferredKey = combinedRendered.selectedKey;
    }

    return {
        itemByKey,
        selectedKey: preferredKey || preferredFile?.ui_key || null,
    };
}

function renderRawContextRow(item, itemByKey) {
    const selectable = toRawSelectableFile(item);
    const fileRow = document.createElement('div');
    fileRow.className = 'file-item';
    fileRow.dataset.fileKey = selectable.ui_key;
    fileRow.dataset.rawItemId = selectable.raw_item_id || '';

    const { icon, typeTag, badgeClass } = getFileVisuals(selectable);
    const metaBits = [];
    if (selectable.type === 'raw_pcap') {
        if (Number(item.eapol_count || 0) > 0) metaBits.push(`EAPOL ${Number(item.eapol_count || 0)}`);
        if (Number(item.beacon_count || 0) > 0) metaBits.push(`Beacons ${Number(item.beacon_count || 0)}`);
        if (Number.isFinite(Number(item.channel))) metaBits.push(`CH ${Number(item.channel)}`);
    } else {
        if (Number(item.valid_hash_lines || 0) > 0) metaBits.push(`${Number(item.valid_hash_lines || 0)} valid line(s)`);
        if (item.source_raw_file) metaBits.push(`from ${String(item.source_raw_file)}`);
    }
    const metaText = metaBits.join(' | ');

    fileRow.innerHTML = `
        <div class="file-name-wrapper">
            <i class="fa-solid ${icon}"></i>
            <span class="file-name-text" title="${escapeHtml(selectable.name)}">${escapeHtml(selectable.name)}</span>
        </div>
        <div class="file-meta-wrapper">
            ${metaText ? `<span class="file-meta" title="${escapeHtml(metaText)}">${escapeHtml(metaText)}</span>` : ''}
            <span class="file-type-tag ${badgeClass}">${typeTag}</span>
        </div>
    `;
    fileRow.onclick = () => selectFile(selectable, fileRow);
    itemByKey.set(selectable.ui_key, fileRow);
    return fileRow;
}

function appendRawContextAccordion(
    list,
    rawContext,
    itemByKey,
    fileToSelectName = null,
    contextOptions = null,
    canonicalFiles = []
) {
    const context = normalizeRawContextPayload(rawContext);
    if (!context.present) {
        return { selectedKey: null };
    }

    const panelMac = String(document.getElementById('crack-mac')?.innerText || '').trim().toUpperCase();
    const isRunningForCurrentMac = Boolean(rawPrepareAllRunningMac && panelMac && panelMac === rawPrepareAllRunningMac);
    const groupEntries = [...context.files, ...context.hash_files].reduce((acc, item) => {
        const source = String(item?.source || '').trim().toLowerCase() || 'brucegotchi';
        if (!acc.has(source)) {
            acc.set(source, {
                source,
                label: String(item?.device_label || source),
                items: [],
            });
        }
        acc.get(source).items.push(item);
        return acc;
    }, new Map());

    const preferredSources = ['brucegotchi', 'm5evil'];
    const grouped = [...groupEntries.values()].sort((left, right) => {
        const leftIndex = preferredSources.indexOf(left.source);
        const rightIndex = preferredSources.indexOf(right.source);
        const a = leftIndex === -1 ? preferredSources.length : leftIndex;
        const b = rightIndex === -1 ? preferredSources.length : rightIndex;
        if (a !== b) return a - b;
        return String(left.label || '').localeCompare(String(right.label || ''), undefined, {
            sensitivity: 'base',
            numeric: true,
        });
    });

    const topLevel = document.createElement('div');
    topLevel.className = 'capture-group capture-group-card capture-group-derived-root capture-group-raw-root';
    const expanded = grouped.some((group) =>
        group.items.some((item) => {
            const targetName = String(fileToSelectName || '').trim();
            const targetRawId = String(contextOptions?.rawItemId || '').trim();
            if (targetRawId && String(item.raw_item_id || '').trim() === targetRawId) return true;
            if (!targetName) return false;
            return [item.filename, item.source_file, item.details_filename]
                .map((value) => String(value || '').trim())
                .filter(Boolean)
                .includes(targetName);
        })
    ) || canonicalFiles.some((file) => String(file?.name || '').trim() === String(fileToSelectName || '').trim());

    const header = document.createElement('button');
    header.type = 'button';
    header.className = 'capture-group-header capture-group-header-raw';
    header.innerHTML = `
            <div class="capture-group-main">
                <div class="capture-group-title-row">
                    <div class="capture-group-name">RAW Sniffer</div>
                    <div class="capture-group-badges">
                        ${renderSemanticBadge('RAWSNIFFER', 'capture-quality-badge badge-role-state-raw')}
                    </div>
                </div>
            <div class="capture-group-meta">
                <span>${Number(context.files_count || 0)} PCAP(s)</span>
                <span>${Number(context.hash_files_count || 0)} hash file(s)</span>
                <span>${escapeHtml(getRawContextSummaryText(context))}</span>
            </div>
        </div>
        <i class="fa-solid fa-chevron-down capture-group-arrow ${expanded ? 'capture-group-arrow-open' : ''}"></i>
    `;

    const body = document.createElement('div');
    body.className = 'capture-group-body crack-raw-context-body';
    if (grouped.length || canonicalFiles.length) {
        body.classList.add('crack-raw-context-body-tree');
    }
    body.hidden = !expanded;

    const toolbar = document.createElement('div');
    toolbar.className = 'crack-raw-context-toolbar';
    const summary = document.createElement('div');
    summary.className = 'crack-raw-context-summary';
    summary.textContent = getRawContextSummaryText(context);
    toolbar.appendChild(summary);
    const prepareAll = document.createElement('button');
    prepareAll.type = 'button';
    prepareAll.className = 'crack-raw-prepare-all-btn';
    prepareAll.dataset.action = 'raw-auto-prepare-all';
    prepareAll.disabled = isRunningForCurrentMac;
    prepareAll.innerHTML = isRunningForCurrentMac
        ? '<i class="fa-solid fa-spinner fa-spin"></i> RUNNING'
        : 'BUILD CANONICAL FROM ALL';
    toolbar.appendChild(prepareAll);
    body.appendChild(toolbar);

    let firstChildBody = null;
    let firstChildHeader = null;
    let firstChildDefaultFile = null;

    grouped.forEach((group) => {
        const nested = document.createElement('div');
        nested.className = 'capture-group capture-group-raw-device capture-group-raw-child';
        const nestedExpanded = expanded && group.items.some((item) => {
            const targetName = String(fileToSelectName || '').trim();
            const targetRawId = String(contextOptions?.rawItemId || '').trim();
            if (targetRawId && String(item.raw_item_id || '').trim() === targetRawId) return true;
            if (!targetName) return false;
            return [item.filename, item.source_file, item.details_filename]
                .map((value) => String(value || '').trim())
                .filter(Boolean)
                .includes(targetName);
        });
        const nestedHeader = document.createElement('button');
        nestedHeader.type = 'button';
        nestedHeader.className = 'capture-group-header capture-group-header-raw-device';
        nestedHeader.innerHTML = `
            <div class="capture-group-main">
                <div class="capture-group-title-row">
                    <div class="capture-group-name">${escapeHtml(group.label)}</div>
                    <div class="capture-group-badges">
                        <span class="${getSourceBadgeClass(group.source)}">${escapeHtml(group.label)}</span>
                    </div>
                </div>
                <div class="capture-group-meta">
                    <span>${group.items.length} item(s)</span>
                </div>
            </div>
            <i class="fa-solid fa-chevron-down capture-group-arrow ${nestedExpanded ? 'capture-group-arrow-open' : ''}"></i>
        `;
        const nestedBody = document.createElement('div');
        nestedBody.className = 'capture-group-body';
        nestedBody.hidden = !nestedExpanded;

        const sortedItems = [...group.items].sort((left, right) => {
            const typeWeight = (item) => String(item?.artifact_type || '').trim() === 'pcap' ? 0 : 1;
            const weightDiff = typeWeight(left) - typeWeight(right);
            if (weightDiff !== 0) return weightDiff;
            return String(left?.filename || left?.source_file || '').localeCompare(
                String(right?.filename || right?.source_file || ''),
                undefined,
                { numeric: true, sensitivity: 'base' }
            );
        });

        let nestedDefaultFile = null;
        sortedItems.forEach((item) => {
            const row = renderRawContextRow(item, itemByKey);
            nestedBody.appendChild(row);
            if (!nestedDefaultFile) {
                nestedDefaultFile = toRawSelectableFile(item);
            }
            if (String(item?.artifact_type || '').trim().toLowerCase() === 'pcap' && item?.details_present && item?.details_filename) {
                const detailsSelectable = toRawDetailsSelectableFile(item);
                if (detailsSelectable) {
                    const detailsRow = renderFileRow(detailsSelectable, itemByKey);
                    detailsRow.classList.add('raw-context-details-row');
                    nestedBody.appendChild(detailsRow);
                }
            }
            if (String(item?.artifact_type || '').trim().toLowerCase() === '22000') {
                const companionFiles = getRawHashCompanionFiles(item?.filename, currentFiles);
                companionFiles.forEach((companion) => {
                    const companionRow = renderFileRow(companion, itemByKey, { showSourceBadge: false });
                    companionRow.classList.add('raw-context-details-row');
                    nestedBody.appendChild(companionRow);
                });
            }
        });

        if (!firstChildBody && nestedDefaultFile) {
            firstChildBody = nestedBody;
            firstChildHeader = nestedHeader;
            firstChildDefaultFile = nestedDefaultFile;
        }

        nestedHeader.addEventListener('click', () => {
            const nextHidden = !nestedBody.hidden;
            if (!nextHidden) {
                collapseSiblingAccordions(nested);
            }
            nestedBody.hidden = nextHidden;
            const arrow = nestedHeader.querySelector('.capture-group-arrow');
            if (arrow) arrow.classList.toggle('capture-group-arrow-open', !nextHidden);
            if (!nextHidden) {
                autoSelectGroupFile(nestedDefaultFile, itemByKey);
            }
        });

        nested.appendChild(nestedHeader);
        nested.appendChild(nestedBody);
        body.appendChild(nested);
    });

    if (canonicalFiles.length) {
        const canonical = document.createElement('div');
        canonical.className = 'capture-group capture-group-raw-device capture-group-raw-child';
        const canonicalExpanded = expanded && canonicalFiles.some(
            (file) => String(file?.name || '').trim() === String(fileToSelectName || '').trim()
        );
        const canonicalHeader = document.createElement('button');
        canonicalHeader.type = 'button';
        canonicalHeader.className = 'capture-group-header capture-group-header-raw-device';
        canonicalHeader.innerHTML = `
            <div class="capture-group-main">
                <div class="capture-group-title-row">
                    <div class="capture-group-name">Canonical (WDRS)</div>
                    <div class="capture-group-badges">
                        ${renderSemanticBadge('WDRS', 'capture-quality-badge badge-role-state-wdrs')}
                    </div>
                </div>
                <div class="capture-group-meta">
                    <span>${canonicalFiles.length} file(s)</span>
                </div>
            </div>
            <i class="fa-solid fa-chevron-down capture-group-arrow ${canonicalExpanded ? 'capture-group-arrow-open' : ''}"></i>
        `;
        const canonicalBody = document.createElement('div');
        canonicalBody.className = 'capture-group-body';
        canonicalBody.hidden = !canonicalExpanded;

        canonicalFiles
            .slice()
            .sort((a, b) => String(a.name || '').localeCompare(String(b.name || ''), undefined, { numeric: true, sensitivity: 'base' }))
            .forEach((file) => {
                canonicalBody.appendChild(renderFileRow(file, itemByKey));
            });

        if (!firstChildBody && canonicalFiles[0]) {
            firstChildBody = canonicalBody;
            firstChildHeader = canonicalHeader;
            firstChildDefaultFile = canonicalFiles[0];
        }

        canonicalHeader.addEventListener('click', () => {
            const nextHidden = !canonicalBody.hidden;
            if (!nextHidden) {
                collapseSiblingAccordions(canonical);
            }
            canonicalBody.hidden = nextHidden;
            const arrow = canonicalHeader.querySelector('.capture-group-arrow');
            if (arrow) arrow.classList.toggle('capture-group-arrow-open', !nextHidden);
            if (!nextHidden) {
                autoSelectGroupFile(canonicalFiles[0] || null, itemByKey);
            }
        });

        canonical.appendChild(canonicalHeader);
        canonical.appendChild(canonicalBody);
        body.appendChild(canonical);
    }

    if (!grouped.length) {
        const empty = document.createElement('div');
        empty.className = 'crack-raw-empty';
        empty.textContent = 'No RAW items linked to this network yet.';
        body.appendChild(empty);
    }

    header.addEventListener('click', () => {
        const nextHidden = !body.hidden;
        if (!nextHidden) {
            collapseSiblingAccordions(topLevel);
        }
        body.hidden = nextHidden;
        const arrow = header.querySelector('.capture-group-arrow');
        if (arrow) arrow.classList.toggle('capture-group-arrow-open', !nextHidden);
        if (!nextHidden && firstChildBody && firstChildBody.hidden) {
            firstChildBody.hidden = false;
            const childArrow = firstChildHeader?.querySelector('.capture-group-arrow');
            if (childArrow) childArrow.classList.add('capture-group-arrow-open');
            autoSelectGroupFile(firstChildDefaultFile, itemByKey);
        }
    });

    topLevel.appendChild(header);
    topLevel.appendChild(body);
    list.appendChild(topLevel);

    let selectedKey = null;
    for (const group of grouped) {
        for (const item of group.items) {
            const targetName = String(fileToSelectName || '').trim();
            const targetRawId = String(contextOptions?.rawItemId || '').trim();
            const detailsSelectable = toRawDetailsSelectableFile(item);
            if (targetName && detailsSelectable && detailsSelectable.name === targetName) {
                selectedKey = detailsSelectable.ui_key;
                break;
            }
            const selectable = toRawSelectableFile(item);
            if (targetRawId && selectable.raw_item_id === targetRawId) {
                selectedKey = selectable.ui_key;
                break;
            }
            if (
                targetName
                && [item.filename, item.source_file, item.details_filename]
                    .map((value) => String(value || '').trim())
                    .filter(Boolean)
                    .includes(targetName)
            ) {
                selectedKey = selectable.ui_key;
                break;
            }
            if (targetName && String(item?.artifact_type || '').trim().toLowerCase() === '22000') {
                const companionMatch = getRawHashCompanionFiles(item?.filename, currentFiles)
                    .find((companion) => String(companion?.name || '').trim() === targetName);
                if (companionMatch) {
                    selectedKey = companionMatch.ui_key;
                    break;
                }
            }
        }
        if (selectedKey) break;
    }

    if (!selectedKey) {
        const targetName = String(fileToSelectName || '').trim();
        const canonicalMatch = canonicalFiles.find(
            (file) => String(file?.name || '').trim() === targetName
        );
        if (canonicalMatch) {
            selectedKey = canonicalMatch.ui_key;
        }
    }

    return { selectedKey };
}

function appendCombinedCandidatesAccordion(list, handshakeSet, itemByKey, fileToSelectName = null, contextOptions = null) {
    const captures = Array.isArray(handshakeSet?.captures) ? handshakeSet.captures : [];
    const combinedCandidates = Array.isArray(handshakeSet?.combined_candidates)
        ? handshakeSet.combined_candidates
        : [];
    const sortedCombinedCandidates = combinedCandidates
        .slice()
        .sort((a, b) => Number(b.modified || 0) - Number(a.modified || 0));
    if (captures.length < 2 && !combinedCandidates.length) {
        return { selectedKey: null };
    }

    const topLevel = document.createElement('div');
    topLevel.className = 'capture-group capture-group-card capture-group-derived-root capture-group-combined-root';
    const targetBuildId = String(contextOptions?.combinedBuildId || '').trim();
    const expanded = combinedCandidates.some((file) => {
        if (targetBuildId && String(file?.combined_build_id || '').trim() === targetBuildId) return true;
        return String(file?.name || '').trim() === String(fileToSelectName || '').trim();
    });
    const header = document.createElement('button');
    header.type = 'button';
    header.className = 'capture-group-header capture-group-header-legacy';
    header.innerHTML = `
        <div class="capture-group-main">
            <div class="capture-group-title-row">
                <div class="capture-group-name">COMBINED CANDIDATES</div>
                <div class="capture-group-badges">
                    ${renderSemanticBadge('COMBINED', 'capture-quality-badge badge-role-state-combined')}
                </div>
            </div>
            <div class="capture-group-meta">
                <span>${combinedCandidates.length} build(s)</span>
                <span>${captures.length} capture(s) eligible</span>
            </div>
        </div>
        <i class="fa-solid fa-chevron-down capture-group-arrow ${expanded ? 'capture-group-arrow-open' : ''}"></i>
    `;

    const body = document.createElement('div');
    body.className = 'capture-group-body crack-raw-context-body';
    body.hidden = !expanded;

    const toolbar = document.createElement('div');
    toolbar.className = 'crack-raw-context-toolbar';
    const summary = document.createElement('div');
    summary.className = 'crack-raw-context-summary';
    summary.textContent = combinedCandidates.length
        ? 'Manual combined 22000 builds for this BSSID'
        : 'Build a deduplicated 22000 from all capture-specific candidates for this BSSID';
    toolbar.appendChild(summary);
    const buildButton = document.createElement('button');
    buildButton.type = 'button';
    buildButton.className = 'crack-raw-prepare-all-btn';
    buildButton.textContent = 'BUILD COMBINED CANDIDATE';
    buildButton.disabled = captures.length < 2;
    buildButton.addEventListener('click', async (event) => {
        event.preventDefault();
        event.stopPropagation();
        await handleBuildCombinedCandidate(buildButton);
    });
    toolbar.appendChild(buildButton);
    body.appendChild(toolbar);

    if (!combinedCandidates.length) {
        const empty = document.createElement('div');
        empty.className = 'crack-raw-empty';
        empty.textContent = 'No combined candidates built yet.';
        body.appendChild(empty);
    } else {
        sortedCombinedCandidates
            .forEach((file) => {
                const selectable = {
                    ...file,
                    ui_key: getFileUiKey(file),
                };
                body.appendChild(renderFileRow(selectable, itemByKey));
            });
    }

    header.addEventListener('click', () => {
        const nextHidden = !body.hidden;
        if (!nextHidden) {
            collapseSiblingAccordions(topLevel);
        }
        body.hidden = nextHidden;
        const arrow = header.querySelector('.capture-group-arrow');
        if (arrow) arrow.classList.toggle('capture-group-arrow-open', !nextHidden);
        if (!nextHidden && combinedCandidates.length) {
            const firstCandidate = {
                ...sortedCombinedCandidates[0],
                ui_key: getFileUiKey(sortedCombinedCandidates[0]),
            };
            autoSelectGroupFile(firstCandidate, itemByKey);
        }
    });

    topLevel.appendChild(header);
    topLevel.appendChild(body);
    list.appendChild(topLevel);

    const selected = combinedCandidates.find((file) => {
        if (targetBuildId && String(file?.combined_build_id || '').trim() === targetBuildId) return true;
        return String(file?.name || '').trim() === String(fileToSelectName || '').trim();
    });
    return { selectedKey: selected ? getFileUiKey(selected) : null };
}

function getBatchRecommendationRequest(filename) {
    const query = { filename };
    let sourceLabel = filename;
    if (currentBatchContext?.mac) {
        query.mac = currentBatchContext.mac;
    }
    if (currentBatchContext?.hasVisibleSsid) {
        sourceLabel = `${currentBatchContext.ssid} · ${filename}`;
    } else if (currentBatchContext?.mac) {
        sourceLabel = `${filename} · partial context`;
    }
    return { query, sourceLabel };
}

function haversineMeters(lat1, lng1, lat2, lng2) {
    const toRad = (value) => (value * Math.PI) / 180;
    const earthRadius = 6371000;
    const dLat = toRad(lat2 - lat1);
    const dLng = toRad(lng2 - lng1);
    const a = Math.sin(dLat / 2) ** 2
        + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLng / 2) ** 2;
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return earthRadius * c;
}

function getAreaContextForMac(mac) {
    const normalizedMac = String(mac || '').trim().toUpperCase();
    if (!isValidMac(normalizedMac)) return null;

    const pos = STATE.allPositions?.[normalizedMac];
    if (!pos) return null;

    const lat = Number(pos.lat);
    const lng = Number(pos.lng);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;

    const analyticsUi = STATE.analyticsUi || {};
    const hotspots = Array.isArray(analyticsUi.hotspots) ? analyticsUi.hotspots : [];
    if (!hotspots.length) return null;

    let best = null;
    hotspots.forEach((hotspot) => {
        const centerLat = Number(hotspot.center_lat);
        const centerLng = Number(hotspot.center_lng);
        const radius = Number(hotspot.radius_m || 0);
        if (!Number.isFinite(centerLat) || !Number.isFinite(centerLng) || radius <= 0) return;
        const distance = haversineMeters(lat, lng, centerLat, centerLng);
        if (distance > radius) return;
        if (!best || Number(hotspot.score || 0) > Number(best.score || 0)) {
            best = hotspot;
        }
    });

    if (!best) return null;
    const dominantChannel = Array.isArray(best.top_channels) && best.top_channels.length
        ? best.top_channels[0]
        : null;
    return {
        hotspotId: best.id,
        score: Number(best.score || 0),
        nearbyLocked: Number(best.locked_count || 0),
        dominantChannel,
    };
}

function getAssociationPreviewTarget() {
    if (!selectedFile) return null;
    if (selectedFile.type !== '22000' && selectedFile.type !== 'batch' && selectedFile.type !== 'raw_22000') return null;
    return selectedFile.name;
}

function removeAssociationPreviewCard() {
    const card = document.getElementById('association-preview-card');
    if (card && card.parentNode) {
        card.parentNode.removeChild(card);
    }
}

function renderAssociationPreviewCard(payload, isError = false) {
    if (isError) {
        return `
            <div id="association-preview-card" class="crack-insights-card">
                <div class="crack-insights-title">ASSOCIATION PREVIEW</div>
                <div class="crack-insights-error"><i class="fa-solid fa-triangle-exclamation"></i> ${escapeMaybe(payload)}</div>
            </div>
        `;
    }

    const sample = Array.isArray(payload?.sample_candidates) ? payload.sample_candidates : [];
    const warnings = Array.isArray(payload?.warnings) ? payload.warnings : [];
    const sources = payload?.sources || {};
    const seedCounts = sources.seed_counts || {};
    const transforms = Array.isArray(sources.transformations) ? sources.transformations : [];

    return `
        <div id="association-preview-card" class="crack-insights-card">
            <div class="crack-insights-title">ASSOCIATION PREVIEW</div>
            <div class="crack-insights-grid">
                <div>Mode</div><div>${escapeMaybe(payload?.mode)}</div>
                <div>Candidates</div><div><b>${escapeMaybe(payload?.candidate_count, '0')}</b>${payload?.capped ? ` (capped @ ${escapeMaybe(payload?.cap, '0')})` : ''}</div>
                <div>Seeds</div><div>ssid ${escapeMaybe(sources?.ssid_count, '0')} | hints ${escapeMaybe(sources?.hint_count, '0')}</div>
                <div>Usage</div><div>ssid ${escapeMaybe(seedCounts?.ssid, '0')} | hint ${escapeMaybe(seedCounts?.hint, '0')} | fallback ${escapeMaybe(seedCounts?.fallback_hint, '0')} | ssid_fb ${escapeMaybe(seedCounts?.ssid_fallback, '0')}</div>
            </div>
            ${transforms.length ? `
                <div class="crack-insights-subtitle">Transforms</div>
                <div class="crack-insights-muted">${transforms.map((t) => escapeHtml(t)).join(', ')}</div>
            ` : ''}
            ${sample.length ? `
                <div class="crack-insights-subtitle">Top Candidates</div>
                <ul class="crack-insights-list">${sample.map((c) => `<li>${escapeHtml(c)}</li>`).join('')}</ul>
            ` : ''}
            ${warnings.length ? `
                <div class="crack-insights-subtitle">Warnings</div>
                <ul class="crack-insights-list">${warnings.map((w) => `<li>${escapeHtml(String(w))}</li>`).join('')}</ul>
            ` : ''}
        </div>
    `;
}

function getContextSeverity(attackScore = {}, recommendation = {}) {
    const score = Number(attackScore.score ?? 0);
    const priority = String(attackScore.priority || '').toLowerCase();
    const action = String(recommendation.action || '').toLowerCase();

    if (action === 'skip') {
        return { level: 'low', label: 'LOW', className: 'insights-context-low' };
    }
    if (action === 'prepare') {
        return { level: 'medium', label: 'MEDIUM', className: 'insights-context-medium' };
    }
    if (priority === 'high' || score >= 70) {
        return { level: 'high', label: 'HIGH', className: 'insights-context-high' };
    }
    if (priority === 'medium' || score >= 45) {
        return { level: 'medium', label: 'MEDIUM', className: 'insights-context-medium' };
    }
    return { level: 'low', label: 'LOW', className: 'insights-context-low' };
}

function formatAttemptTimestamp(value) {
    if (!value) return 'time n/a';
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return escapeHtml(String(value));
    return escapeHtml(parsed.toLocaleString());
}

function getAttemptOutcomeStyle(outcome) {
    const normalized = String(outcome || 'other').toLowerCase();
    if (normalized === 'cracked') {
        return { label: 'CRACKED', className: 'attempt-outcome-cracked' };
    }
    if (normalized === 'exhausted') {
        return { label: 'EXHAUSTED', className: 'attempt-outcome-exhausted' };
    }
    if (normalized === 'fatal') {
        return { label: 'FATAL', className: 'attempt-outcome-fatal' };
    }
    if (normalized === 'running') {
        return { label: 'RUNNING', className: 'attempt-outcome-running' };
    }
    return { label: normalized.toUpperCase() || 'OTHER', className: 'attempt-outcome-other' };
}

function getReadableMode(mode) {
    const raw = String(mode || '').trim();
    if (!raw) return 'unknown';
    return raw.replace(/_/g, ' ');
}

function renderAttemptParams(params = {}) {
    const paramEntries = Object.entries(params).filter(([, value]) => value !== null && value !== undefined && value !== '');
    if (!paramEntries.length) {
        return '<span class="attempt-param-empty">no params</span>';
    }
    return paramEntries.map(([key, value]) => {
        const displayValue = typeof value === 'boolean' ? (value ? 'on' : 'off') : String(value);
        return `<span class="attempt-param-chip">${escapeHtml(key)}:${escapeHtml(displayValue)}</span>`;
    }).join('');
}

function renderAttemptMemorySection(attemptFeedback) {
    const feedback = attemptFeedback && typeof attemptFeedback === 'object' ? attemptFeedback : null;
    const totals = feedback?.totals && typeof feedback.totals === 'object' ? feedback.totals : {};
    const byMode = Array.isArray(feedback?.by_mode) ? feedback.by_mode : [];
    const recent = Array.isArray(feedback?.recent) ? feedback.recent : [];
    const tip = String(feedback?.tip || '').trim();
    const attempts = Number(totals.attempts || 0);

    if (!attempts) {
        return `
            <div class="crack-insights-card">
                <div class="crack-insights-title">ATTACK MEMORY</div>
                <div class="crack-insights-muted">No prior hashcat attempts.</div>
            </div>
        `;
    }

    const summaryChips = [
        `attempts ${escapeMaybe(totals.attempts, '0')}`,
        `modes ${escapeMaybe(totals.distinct_modes, '0')}`,
        `exhausted ${escapeMaybe(totals.exhausted, '0')}`,
        `fatal ${escapeMaybe(totals.fatal, '0')}`,
    ].map((label) => `<span class="crack-insights-summary-chip">${label}</span>`).join('');

    const modeSummary = byMode
        .slice(0, 4)
        .map((item) => `${escapeHtml(getReadableMode(item?.mode))} (${escapeMaybe(item?.attempts, '0')})`)
        .join(' | ');

    const recentHtml = recent.map((item) => {
        const outcome = getAttemptOutcomeStyle(item?.outcome);
        return `
            <li class="attempt-memory-item">
                <div class="attempt-memory-head">
                    <span class="attempt-memory-time">${formatAttemptTimestamp(item?.started_at)}</span>
                    <span class="attempt-memory-mode">${escapeHtml(getReadableMode(item?.mode))}</span>
                    <span class="attempt-memory-outcome ${outcome.className}">${outcome.label}</span>
                </div>
                <div class="attempt-memory-params">${renderAttemptParams(item?.params || {})}</div>
            </li>
        `;
    }).join('');

    return `
        <div class="crack-insights-card">
            <div class="crack-insights-title">ATTACK MEMORY</div>
            <div class="crack-insights-summary-row">${summaryChips}</div>
            ${modeSummary ? `<div class="crack-insights-muted">${modeSummary}</div>` : ''}
            ${recent.length ? `<ul class="attempt-memory-list">${recentHtml}</ul>` : '<div class="crack-insights-muted">No recent attempts.</div>'}
            ${tip ? `<div class="crack-insights-tip">${escapeHtml(tip)}</div>` : ''}
        </div>
    `;
}

function renderCrackingInsightsView(recommendation, sourceLabel = '', areaContext = null) {
    if (!recommendation) {
        return `
            <div class="crack-insights-card">
                <div class="crack-insights-title">ATTACK INSIGHTS</div>
                <div class="crack-insights-muted">No recommendation data available.</div>
            </div>
        `;
    }

    const attackScore = recommendation.attack_score || {};
    const score = Number(attackScore.score ?? 0);
    const priority = escapeMaybe(attackScore.priority || 'low');
    const scoreReasons = Array.isArray(attackScore.score_reasons) ? attackScore.score_reasons : [];
    const recommendationReasons = Array.isArray(recommendation.reasons) ? recommendation.reasons : [];
    const candidateModes = Array.isArray(recommendation.candidate_modes) ? recommendation.candidate_modes : [];
    const hints = Array.isArray(recommendation.suggested_hints) ? recommendation.suggested_hints : [];
    const contextSeverity = getContextSeverity(attackScore, recommendation);
    const readiness = recommendation.handshake_readiness || {};
    const readinessSignals = readiness.signals || {};
    const readinessEnrichment = readiness.enrichment || {};
    const attemptMemorySection = renderAttemptMemorySection(recommendation.attempt_feedback);

    const scoreReasonsHtml = scoreReasons.map((reason) => {
        const delta = Number(reason?.delta || 0);
        const deltaPrefix = delta >= 0 ? `+${delta}` : `${delta}`;
        return `<li><span class="insights-score-delta">${escapeHtml(deltaPrefix)}</span> ${escapeMaybe(reason?.reason)}</li>`;
    }).join('');
    const recommendationReasonsHtml = recommendationReasons.map((reason) => `<li>${escapeMaybe(reason)}</li>`).join('');
    const readinessStatus = escapeMaybe(readiness.status || 'unknown');
    const readinessReason = escapeMaybe(readiness.reason || 'No readiness diagnostics.');
    const pendingEnrichment = Array.isArray(readinessEnrichment.pending_hash_files)
        ? readinessEnrichment.pending_hash_files
        : [];
    const readyEnrichment = Array.isArray(readinessEnrichment.existing_hash_files)
        ? readinessEnrichment.existing_hash_files
        : [];
    const readinessSection = readiness.status ? `
        <div class="crack-insights-subtitle">Handshake Readiness</div>
        <div class="crack-insights-grid">
            <div>Status</div><div><b>${readinessStatus}</b> (${escapeMaybe(readiness.score, '0')}/100)</div>
            <div>Signals</div><div>hash ${escapeMaybe(readinessSignals.valid_hash_lines, '0')} | eapol ${escapeMaybe(readinessSignals.raw_eapol_total, '0')} | beacon ${escapeMaybe(readinessSignals.raw_beacon_total, '0')}</div>
            <div>RAW files</div><div>${escapeMaybe(readinessSignals.raw_files_count, '0')}</div>
            <div>Enrichment</div><div>ready ${readyEnrichment.length} | pending ${pendingEnrichment.length}</div>
        </div>
        <div class="crack-insights-muted">${readinessReason}</div>
        ${pendingEnrichment.length ? `
            <div class="crack-insights-subtitle">Pending .22000</div>
            <ul class="crack-insights-list">${pendingEnrichment.slice(0, 6).map((name) => `<li>${escapeHtml(String(name))}</li>`).join('')}${pendingEnrichment.length > 6 ? '<li>...</li>' : ''}</ul>
        ` : ''}
    ` : '';

    const areaContextSection = areaContext
        ? `
            <div class="crack-insights-subtitle">Area Context</div>
            <div class="crack-insights-grid">
                <div>Zone</div><div>${escapeMaybe(areaContext.hotspotId)}</div>
                <div>Score</div><div>${escapeMaybe(areaContext.score, '0')}</div>
                <div>Dominant CH</div><div>${escapeMaybe(areaContext.dominantChannel)}</div>
                <div>Nearby locked</div><div>${escapeMaybe(areaContext.nearbyLocked, '0')}</div>
            </div>
        `
        : '';

    return `
        <div class="crack-insights-card">
            <div class="crack-insights-title">
                ATTACK INSIGHTS ${sourceLabel ? `<span class="crack-insights-source">${escapeHtml(sourceLabel)}</span>` : ''}
            </div>
            <div class="crack-insights-grid">
                <div>Score</div><div><b>${escapeHtml(String(score))}</b> / 100 (${priority})</div>
                <div>Context</div><div><span class="insights-context-badge ${contextSeverity.className}">${contextSeverity.label}</span></div>
                <div>Action</div><div>${escapeMaybe(recommendation.action)}</div>
                <div>Mode</div><div>${escapeMaybe(recommendation.recommended_mode)}</div>
                <div>Candidates</div><div>${candidateModes.length ? candidateModes.map((mode) => escapeHtml(mode)).join(', ') : '—'}</div>
            </div>

            ${hints.length ? `
                <div class="crack-insights-subtitle">Suggested Hints</div>
                <div class="crack-insights-muted">${hints.map((hint) => escapeHtml(hint)).join(' | ')}</div>
            ` : ''}

            ${recommendationReasonsHtml ? `
                <div class="crack-insights-subtitle">Recommendation Reasons</div>
                <ul class="crack-insights-list">${recommendationReasonsHtml}</ul>
            ` : ''}

            ${scoreReasonsHtml ? `
                <div class="crack-insights-subtitle">Score Breakdown</div>
                <ul class="crack-insights-list">${scoreReasonsHtml}</ul>
            ` : ''}

            ${readinessSection}
            ${areaContextSection}
        </div>
        ${attemptMemorySection}
    `;
}

function formatCombinedSourceKind(value) {
    const normalized = String(value || '').trim();
    if (normalized === 'existing_hash') return 'existing 22000';
    if (normalized === 'converted_from_pcap') return 'converted from PCAP';
    return normalized ? normalized.replace(/_/g, ' ') : 'capture candidate';
}

function resolveCombinedCandidateSources(file) {
    const candidate = getCombinedCandidateByBuildId(file?.combined_build_id || null);
    const explicit = Array.isArray(candidate?.included_captures) ? candidate.included_captures : [];
    if (explicit.length) return explicit;

    const captureIds = Array.isArray(file?.included_capture_ids) ? file.included_capture_ids : [];
    return captureIds
        .map((captureId) => {
            const capture = getCaptureById(captureId);
            if (!capture) return null;
            return {
                capture_id: capture.capture_id,
                source: capture.source,
                device_label: capture.device_label,
                source_filename: capture.source_filename,
                source_kind: null,
                valid_hash_lines: Number(capture?.quality?.valid_hash_lines || 0) || 0,
            };
        })
        .filter(Boolean);
}

function renderCombinedOriginSection(file) {
    if (!file?.combined_build_id) return '';

    const sourceRows = resolveCombinedCandidateSources(file);
    const captureCount = Number(file.included_capture_count || sourceRows.length || 0) || 0;
    const dedupedCount = Number(file.deduped_hash_count || 0) || 0;
    const summaryChips = [
        `${captureCount} capture(s) included`,
        `${dedupedCount} deduped hash line(s)`,
    ].map((label) => `<span class="crack-insights-summary-chip">${escapeHtml(label)}</span>`).join('');

    const rowsHtml = sourceRows.length
        ? `
            <ul class="attempt-memory-list">
                ${sourceRows.map((item) => `
                    <li class="attempt-memory-item">
                        <div class="attempt-memory-head">
                            <span class="attempt-memory-mode">${escapeHtml(item.device_label || item.source || item.capture_id || 'Capture')}</span>
                            ${item.capture_id ? `<span class="attempt-memory-time">${escapeHtml(item.capture_id)}</span>` : ''}
                        </div>
                        <div class="attempt-memory-params">
                            ${[
                                item.source_filename ? `file:${item.source_filename}` : null,
                                item.source_kind ? `origin:${formatCombinedSourceKind(item.source_kind)}` : null,
                                item.valid_hash_lines > 0 ? `valid_hashes:${item.valid_hash_lines}` : null,
                            ]
                                .filter(Boolean)
                                .map((chip) => `<span class="attempt-param-chip">${escapeHtml(chip)}</span>`)
                                .join('')}
                        </div>
                    </li>
                `).join('')}
            </ul>
        `
        : '<div class="crack-insights-muted">No source capture metadata available for this combined build.</div>';

    return `
        <div class="crack-insights-card">
            <div class="crack-insights-title">COMBINED ORIGIN</div>
            <div class="crack-insights-summary-row">${summaryChips}</div>
            ${rowsHtml}
        </div>
    `;
}

async function loadAttackRecommendation(query, fileFeedback, sourceLabel = '') {
    const requestToken = ++insightsRenderToken;
    fileFeedback.innerHTML = `
        <div class="crack-insights-card">
            <div class="crack-insights-title">ATTACK INSIGHTS</div>
            <div class="crack-insights-muted"><i class="fa-solid fa-spinner fa-spin"></i> Loading recommendation...</div>
        </div>
    `;

    try {
        const recommendation = await API.getAttackRecommendation(query);
        if (requestToken !== insightsRenderToken) return;
        const currentMac = (document.getElementById('crack-mac')?.innerText || '').trim();
        const areaContext = getAreaContextForMac(currentMac);
        fileFeedback.innerHTML = renderCrackingInsightsView(recommendation, sourceLabel, areaContext);
        if (selectedFile?.combined_build_id) {
            fileFeedback.insertAdjacentHTML('beforeend', renderCombinedOriginSection(selectedFile));
        }
    } catch (e) {
        if (requestToken !== insightsRenderToken) return;
        fileFeedback.innerHTML = `
            <div class="crack-insights-card">
                <div class="crack-insights-title">ATTACK INSIGHTS</div>
                <div class="crack-insights-error"><i class="fa-solid fa-triangle-exclamation"></i> Failed to load recommendation: ${escapeMaybe(e.message)}</div>
            </div>
        `;
        if (selectedFile?.combined_build_id) {
            fileFeedback.insertAdjacentHTML('beforeend', renderCombinedOriginSection(selectedFile));
        }
    }
}

async function runAssociationPreview() {
    const target = getAssociationPreviewTarget();
    if (!target) {
        log("Select a .22000 or batch file to preview association candidates.", "error");
        return;
    }

    const mode = document.getElementById('custom-mode-select')?.value;
    if (!isAssociationMode(mode)) {
        log("Association preview is available only for association modes.", "error");
        return;
    }

    const button = document.getElementById('btn-association-preview');
    const feedback = document.getElementById('crack-file-feedback');
    if (!feedback) return;

    if (button) {
        button.disabled = true;
        button.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> PREVIEWING...';
    }

    removeAssociationPreviewCard();
    feedback.insertAdjacentHTML(
        'beforeend',
        `
            <div id="association-preview-card" class="crack-insights-card">
                <div class="crack-insights-title">ASSOCIATION PREVIEW</div>
                <div class="crack-insights-muted"><i class="fa-solid fa-spinner fa-spin"></i> Building candidates...</div>
            </div>
        `
    );

    try {
        const associationHint = document.getElementById('crack-association-hint-input')?.value?.trim() || null;
        const associationHints = document.getElementById('crack-association-hints-input')?.value || null;
        const preview = await API.previewAssociationCandidates(
            target,
            mode,
            associationHint,
            associationHints,
            selectedFile?.capture_id || null,
            selectedFile?.combined_build_id || null,
            document.getElementById('crack-mac')?.innerText || null,
        );
        removeAssociationPreviewCard();
        feedback.insertAdjacentHTML('beforeend', renderAssociationPreviewCard(preview));
    } catch (e) {
        removeAssociationPreviewCard();
        feedback.insertAdjacentHTML('beforeend', renderAssociationPreviewCard(`Failed to preview candidates: ${e.message}`, true));
    } finally {
        if (button) {
            button.disabled = false;
            button.innerHTML = '<i class="fa-solid fa-list-check"></i> PREVIEW CANDIDATES';
        }
    }
}

// Helper para calcular tamanho real da máscara (conta ?a como 1 char)
function getMaskLength(mask) {
    if (!mask) return 0;
    // Substitui tokens como ?a, ?d, ?1 por um placeholder único para contar corretamente
    const simplified = mask.replace(/\?./g, '#');
    return simplified.length;
}

// Helper function to update mask text
const updateMaskFromSlider = (maxVal) => {
    const max = Math.round(maxVal);
    const maskInput = document.getElementById('crack-mask-input');
    const modeSelect = document.getElementById('custom-mode-select');
    
    if (modeSelect && maskInput) {
        const mode = modeSelect.value;
        let char = '?a'; // Default
        if (mode === 'digits') char = '?d';
        
        maskInput.value = char.repeat(max);
    }
};

export async function openCrackingPanel(mac, ssid, fileToSelectName = null, contextOptions = null) {
    if (STATE.modes.analytics) {
        document.dispatchEvent(new CustomEvent('exitAnalyticsView'));
    }
    const panel = document.getElementById('cracking-panel');
    panel.style.display = 'flex';
    document.getElementById('btn-toggle-cracking').classList.add('active'); 
    
    if (!STATE.modes.cracking) {
        STATE.modes.cracking = true;
        saveModes();
    }
    notifyRightPanelsModeChanged();
    
    document.getElementById('crack-ssid').innerText = ssid || 'HIDDEN';
    document.getElementById('crack-mac').innerText = mac;
    currentBatchContext = null;
    currentHandshakeSet = null;
    
    const list = document.getElementById('crack-file-list');
    list.classList.remove('crack-file-list-flat');
    list.innerHTML = '<div style="padding:10px; color:#666;">Loading files...</div>';
    renderHandshakeSetSummary(null);
    renderRawContextSection({ present: false });
    renderRawContextLoading();
    
    if (!fileToSelectName) {
        document.getElementById('crack-actions').style.display = 'none';
        selectedFile = null;
    }

    // --- INJECT AUTO-MASK TOGGLE ---
    const maskInputContainer = document.querySelector('#crack-mask-row > div');
    if (maskInputContainer && !document.getElementById('auto-mask-chk')) {
        // Criar container para o checkbox
        const chkContainer = document.createElement('div');
        chkContainer.style.display = 'flex';
        chkContainer.style.alignItems = 'center';
        chkContainer.style.marginLeft = '5px';
        chkContainer.title = "Auto-generate mask based on slider";
        
        const chk = document.createElement('input');
        chk.type = 'checkbox';
        chk.id = 'auto-mask-chk';
        chk.checked = true; // Default ON
        chk.style.width = '16px';
        chk.style.height = '16px';
        chk.style.accentColor = 'var(--theme-color)';
        
        const lbl = document.createElement('label');
        lbl.htmlFor = 'auto-mask-chk';
        lbl.innerText = 'AUTO';
        lbl.style.fontSize = '0.7em';
        lbl.style.marginLeft = '4px';
        lbl.style.color = 'var(--theme-color)';
        lbl.style.fontWeight = 'bold';
        lbl.style.cursor = 'pointer';

        chkContainer.appendChild(chk);
        chkContainer.appendChild(lbl);
        
        // Inserir antes do botão de ajuda
        const helpBtn = document.getElementById('mask-help-btn');
        maskInputContainer.insertBefore(chkContainer, helpBtn);

        // Event Listener para o Checkbox
        chk.addEventListener('change', (e) => {
            const maskInput = document.getElementById('crack-mask-input');
            const isAuto = e.target.checked;
            
            if (isAuto) {
                maskInput.readOnly = true;
                maskInput.style.opacity = '0.7';
                maskInput.style.cursor = 'not-allowed';
                // Force update from slider immediately
                if (incrementSlider) {
                    const values = incrementSlider.get();
                    updateMaskFromSlider(values[1]); 
                }
            } else {
                maskInput.readOnly = false;
                maskInput.style.opacity = '1';
                maskInput.style.cursor = 'text';
                maskInput.focus();
                
                // Sync slider to current text length immediately
                if (incrementSlider) {
                    const len = getMaskLength(maskInput.value);
                    if (len > 0) {
                        const currentMin = parseInt(incrementSlider.get()[0]);
                        incrementSlider.set([currentMin, len]);
                    }
                }
            }
        });

        // Event Listener para o Input de Texto (Modo Manual)
        const maskInput = document.getElementById('crack-mask-input');
        maskInput.addEventListener('input', (e) => {
            const isAuto = document.getElementById('auto-mask-chk').checked;
            if (!isAuto && incrementSlider) {
                const len = getMaskLength(e.target.value);
                // Se o tamanho for válido, atualiza o slider MAX para refletir o tamanho do texto
                if (len > 0) {
                    // Mantém o Min onde está (ou reduz se for maior que o novo Max)
                    let currentMin = parseInt(incrementSlider.get()[0]);
                    if (currentMin > len) currentMin = len;
                    
                    // Atualiza o slider sem disparar o evento 'set' (se possível) ou lidamos com isso no 'update'
                    incrementSlider.set([currentMin, len]);
                }
            }
        });
        
        // Inicializa estado visual
        const maskInp = document.getElementById('crack-mask-input');
        maskInp.readOnly = true;
        maskInp.style.opacity = '0.7';
    }

    // Initialize Slider if not already done
    if (!incrementSlider) {
        const sliderEl = document.getElementById('increment-slider');
        if (sliderEl && window.noUiSlider) {
            incrementSlider = noUiSlider.create(sliderEl, {
                start: [1, 8], // Start safer
                connect: true,
                range: {
                    'min': 1,
                    'max': 20
                },
                step: 1,
                tooltips: [true, true],
                format: {
                    to: function (value) {
                        return Math.round(value);
                    },
                    from: function (value) {
                        return Number(value);
                    }
                }
            });

            incrementSlider.on('update', function (values, handle) {
                const min = Math.round(values[0]);
                const max = Math.round(values[1]);
                document.getElementById('inc-val-min').innerText = min;
                document.getElementById('inc-val-max').innerText = max;

                const isAuto = document.getElementById('auto-mask-chk')?.checked;
                
                if (isAuto) {
                    // Modo Auto: Slider manda no Texto
                    updateMaskFromSlider(max);
                } 
                // Modo Manual: Slider NÃO toca no texto. Apenas atualiza os labels visuais (acima).
            });
        }
    }

    await loadCrackingDefaults();

    await loadCrackingDefaults();
    await loadCrackingResources();

    try {
        const isRawHashScoped = (
            contextOptions?.scope === 'raw_hash'
            && !!fileToSelectName
            && isRawHashFilename(fileToSelectName)
        );

        const [handshakeSetResponse, filesResponse, rawContextResponse] = await Promise.all([
            API.getHandshakeSet(mac).catch(() => null),
            API.getHandshakeFiles(mac),
            API.getHandshakeRawContext(mac).catch((err) => {
                log(`RAW context unavailable for ${mac}: ${err.message}`, 'warning');
                return { present: false };
            }),
        ]);

        currentHandshakeSet = normalizeHandshakeSetPayload(handshakeSetResponse);
        let files = Array.isArray(filesResponse) ? filesResponse.map(normalizeHandshakeFileRecord) : [];
        files = files || [];
        if (isRawHashScoped) {
            files = filterFilesForRawHashScope(files, fileToSelectName);
            files = files.map(normalizeHandshakeFileRecord);
        }
        renderRawContextSection(rawContextResponse);
        currentFiles = files;
        list.innerHTML = '';
        if (isRawHashScoped) {
            renderRawHashScopeSummary(fileToSelectName, files, currentRawContext);
        } else {
            renderHandshakeSetSummary(currentHandshakeSet);
        }

        if (isRawHashScoped) {
            const rendered = renderRawHashScopedList(list, files, fileToSelectName);
            const targetItem = rendered.selectedKey ? rendered.itemByKey.get(rendered.selectedKey) : null;
            const targetFile = rendered.selectedKey
                ? files.find((file) => file.ui_key === rendered.selectedKey)
                : null;
            if (targetItem && targetFile) {
                await selectFile(targetFile, targetItem);
            }
            return;
        }

        const hasCombinedCandidates = Array.isArray(currentHandshakeSet?.combined_candidates)
            && currentHandshakeSet.combined_candidates.length > 0;
        
        if (files.length === 0 && !hasCombinedCandidates) {
            const hasRawContext = currentRawContext?.present;
            list.innerHTML = hasRawContext
                ? '<div style="padding:10px; color:#8cb7c2;">No crackable files found locally. RAW/Wardrive data is present, but no valid WPA handshake (EAPOL) is linked yet. Use BUILD CANONICAL FROM ALL in RAW Sniffer after capturing a valid handshake.</div>'
                : '<div style="padding:10px; color:#666;">No files found locally. Try Sync.</div>';
            if (hasRawContext) {
                const rawItemByKey = new Map();
                const rawRendered = appendRawContextAccordion(
                    list,
                    currentRawContext,
                    rawItemByKey,
                    fileToSelectName,
                    contextOptions
                );
                if (rawRendered?.selectedKey && rawItemByKey.has(rawRendered.selectedKey)) {
                    const targetItem = rawItemByKey.get(rawRendered.selectedKey);
                    const targetFile = getRawSelectableFilesForContext(currentRawContext)
                        .find((item) => item.ui_key === rawRendered.selectedKey);
                    if (targetItem && targetFile) {
                        await selectFile(targetFile, targetItem);
                    }
                }
            }
            return;
        }

        let selectedKey = null;
        let itemByKey = new Map();

        if (currentHandshakeSet?.captures?.length || hasCombinedCandidates) {
            const rendered = renderHandshakeSetList(
                list,
                currentHandshakeSet,
                files,
                fileToSelectName,
                contextOptions
            );
            itemByKey = rendered.itemByKey;
            selectedKey = rendered.selectedKey;
        } else {
            const rawCanonicalFiles = currentRawContext?.present ? getRawCanonicalFiles(files) : [];
            const rawCanonicalKeys = new Set(rawCanonicalFiles.map((file) => file.ui_key));
            const sortedFiles = [...files]
                .filter((file) => !rawCanonicalKeys.has(file.ui_key))
                .sort((a, b) => {
                    const nameA = (a?.name || '').toLowerCase();
                    const nameB = (b?.name || '').toLowerCase();
                    return nameA.localeCompare(nameB, undefined, { numeric: true, sensitivity: 'base' });
                });

            sortedFiles.forEach((file) => {
                const item = renderFileRow(file, itemByKey);
                list.appendChild(item);
                if (fileToSelectName && file.name === fileToSelectName && !selectedKey) {
                    selectedKey = file.ui_key;
                }
            });
            if (!selectedKey && sortedFiles.length) {
                const defaultFile = sortedFiles.find((file) => file.type === '22000')
                    || sortedFiles.find((file) => file.type === 'pcap')
                    || sortedFiles[0];
                selectedKey = defaultFile?.ui_key || null;
            }

            const rawRendered = appendRawContextAccordion(
                list,
                currentRawContext,
                itemByKey,
                fileToSelectName,
                contextOptions,
                rawCanonicalFiles
            );
            if (!selectedKey && rawRendered?.selectedKey) {
                selectedKey = rawRendered.selectedKey;
            }
        }

        if (selectedKey && itemByKey.has(selectedKey)) {
            const targetItem = itemByKey.get(selectedKey);
            const targetFile = files.find((file) => file.ui_key === selectedKey)
                || (Array.isArray(currentHandshakeSet?.combined_candidates)
                    ? currentHandshakeSet.combined_candidates.find(
                        (item) => getFileUiKey(item) === selectedKey
                    )
                    : null)
                || getRawSelectableFilesForContext(currentRawContext)
                    .find((item) => item.ui_key === selectedKey);
            if (targetItem && targetFile) {
                await selectFile(targetFile, targetItem);
            }
        }
    } catch (e) {
        renderHandshakeSetSummary(null);
        renderRawContextSection({ present: false });
        list.innerHTML = '<div style="padding:10px; color:red;">Error loading files.</div>';
        log(`Error loading files for ${mac}: ${e.message}`, 'error');
    }
}

export async function openMultiCrackingPanel(filename) {
    if (STATE.modes.analytics) {
        document.dispatchEvent(new CustomEvent('exitAnalyticsView'));
    }
    const panel = document.getElementById('cracking-panel');
    panel.style.display = 'flex';
    document.getElementById('btn-toggle-cracking').classList.add('active');

    if (!STATE.modes.cracking) {
        STATE.modes.cracking = true;
        saveModes();
    }
    notifyRightPanelsModeChanged();

    await loadCrackingResources();

    document.getElementById('crack-ssid').innerText = 'BATCH';
    document.getElementById('crack-mac').innerText = filename;

    const list = document.getElementById('crack-file-list');
    list.classList.remove('crack-file-list-flat');
    list.innerHTML = '<div style="padding:10px; color:#666;">Loading files...</div>';
    renderHandshakeSetSummary(null);

    let files = [];
    currentBatchContext = null;
    currentBatchManifestItems = [];
    try {
        const manifest = await API.getMultiFileContent(filename);
        currentBatchManifestItems = normalizeBatchManifestItems(manifest?.items || []);
        currentBatchContext = resolveBatchContext(manifest?.items || []);
    } catch (_e) {
        currentBatchContext = null;
        currentBatchManifestItems = [];
    }
    try {
        files = await API.getBatchFiles(filename);
    } catch (e) {
        files = [{ name: filename, type: 'batch', size: 0, modified: Date.now() / 1000 }];
    }

        const sortedFiles = [...files].sort((a, b) => {
            const nameA = (a?.name || '').toLowerCase();
            const nameB = (b?.name || '').toLowerCase();
            return nameA.localeCompare(nameB, undefined, { numeric: true, sensitivity: 'base' });
        });

        list.innerHTML = '';
        list.classList.add('crack-file-list-flat');
        const itemByName = new Map();
        const normalizedFiles = sortedFiles.map((file) => {
            const name = String(file?.name || '').trim();
            let type = String(file?.type || '').trim().toLowerCase() || 'file';
            if (name.endsWith('.22000') || type === 'batch') {
                type = 'batch';
            } else if (type === 'try' || name.endsWith('.try')) {
                type = 'try';
            } else if (type === 'cracked' || name.endsWith('.cracked')) {
                type = 'cracked';
            }
            return normalizeHandshakeFileRecord({
                ...file,
                name,
                type,
            });
        });
        normalizedFiles.forEach((file) => {
            const item = renderFileRow(file, itemByName, { showSourceBadge: false });
            list.appendChild(item);
            itemByName.set(file.name, item);
        });

    const preferredFile = normalizedFiles.find(f => f.name === filename)
        || normalizedFiles.find(f => f.type === 'batch')
        || normalizedFiles[0];
    if (preferredFile) {
        const targetItem = itemByName.get(preferredFile.name) || list.querySelector('.file-item');
        if (targetItem) {
            selectFile(preferredFile, targetItem);
            // Re-apply defaults to ensure batch uses configured flags
            await loadCrackingDefaults();
        }
    }
}

async function loadCrackingResources() {
    try {
        const [wordlists, rules, masks, devices] = await Promise.all([
            API.getCustomWordlists(),
            API.getHashcatRules(),
            API.getHashcatMasks(),
            API.getHashcatDevices()
        ]);
        
        const selectAircrack = document.getElementById('wordlist-select');
        const selectCustom = document.getElementById('crack-wordlist-select');
        const selectCustom2 = document.getElementById('crack-wordlist-2-select');
        const selectRule = document.getElementById('crack-rule-select');
        const selectRule2 = document.getElementById('crack-rule-2-select');
        const selectMaskProfile = document.getElementById('crack-mask-profile-select');
        const selectDevice = document.getElementById('crack-device-select');
        
        selectAircrack.innerHTML = '';
        selectCustom.innerHTML = '';
        selectCustom2.innerHTML = '';
        selectRule.innerHTML = '';
        selectRule2.innerHTML = '';
        selectMaskProfile.innerHTML = '';
        selectDevice.innerHTML = '';
        
        // Populate Devices
        const autoOpt = document.createElement('option');
        autoOpt.value = "all";
        autoOpt.innerText = "Auto / All";
        selectDevice.appendChild(autoOpt);
        
        if (devices && devices.length > 0) {
            devices.forEach(d => {
                const opt = document.createElement('option');
                opt.value = d.id;
                opt.innerText = `Device #${d.id}: ${d.name} (${d.type} - ${d.backend})`;
                selectDevice.appendChild(opt);
            });
        }
        applyDeviceDefaultSelection();
        
        // Always show device row
        const deviceRow = document.getElementById('crack-device-row');
        if (deviceRow) deviceRow.style.display = 'flex';

        // Populate Rules
        if (rules.length === 0) {
            const fillFallbackRule = (select) => {
                const opt = document.createElement('option');
                opt.value = "default";
                opt.innerText = "Best64 (Default)";
                select.appendChild(opt);
            };
            fillFallbackRule(selectRule);
            fillFallbackRule(selectRule2);
        } else {
            rules.forEach(r => {
                const opt = document.createElement('option');
                opt.value = r.path;
                opt.innerText = r.name;
                selectRule.appendChild(opt);

                const opt2 = document.createElement('option');
                opt2.value = r.path;
                opt2.innerText = r.name;
                selectRule2.appendChild(opt2);
            });
        }

        // Default selection focused on passphrase workflow when available.
        const selectRuleByName = (select, name) => {
            for (const option of select.options) {
                if (option.text.toLowerCase() === name.toLowerCase()) {
                    select.value = option.value;
                    return true;
                }
            }
            return false;
        };
        const hasRule1 = selectRuleByName(selectRule, 'passphrase-rule1.rule');
        const hasRule2 = selectRuleByName(selectRule2, 'passphrase-rule2.rule');
        if (!hasRule1 && selectRule.options.length > 0) selectRule.selectedIndex = 0;
        if (!hasRule2 && selectRule2.options.length > 0) selectRule2.selectedIndex = 0;

        // Populate Mask Profiles (.hcmask)
        if (!masks || masks.length === 0) {
            const opt = document.createElement('option');
            opt.value = "";
            opt.innerText = "No .hcmask found";
            selectMaskProfile.appendChild(opt);
            selectMaskProfile.disabled = true;
        } else {
            selectMaskProfile.disabled = false;
            masks.forEach(mask => {
                const opt = document.createElement('option');
                opt.value = mask.path;
                opt.innerText = mask.name;
                selectMaskProfile.appendChild(opt);
            });
            selectMaskProfile.selectedIndex = 0;
        }

        // Populate Wordlists (Both 1 and 2)
        const populateWlSelect = (select) => {
            if (wordlists.length === 0) {
                const opt = document.createElement('option');
                opt.value = "";
                opt.innerText = "No custom wordlists found";
                select.appendChild(opt);
                select.disabled = true;
            } else {
                select.disabled = false;
                wordlists.forEach(wl => {
                    const opt = document.createElement('option');
                    opt.value = wl.path;
                    
                    if (wl.type === 'directory') {
                        opt.innerText = `📁 ${wl.name.replace('[DIR] ', '')}`;
                        opt.style.fontWeight = 'bold';
                        opt.style.color = 'var(--neon-cyan)';
                    } else {
                        opt.innerText = wl.name;
                    }
                    
                    if (wl.size) {
                        opt.innerText += ` (${wl.size})`;
                    }

                    select.appendChild(opt);
                });
                select.selectedIndex = 0;
            }
        };

        populateWlSelect(selectAircrack);
        populateWlSelect(selectCustom);
        populateWlSelect(selectCustom2);

        const selectPmkWl = document.getElementById('pmk-wordlist-select');
        if (selectPmkWl) populateWlSelect(selectPmkWl);

    } catch (e) {
        console.error("Failed to load resources", e);
    }
}

let slowCandidatesDefault = false;
let deviceDefault = 'all';

function applySlowCandidatesPolicy(mode) {
    const slowCheckbox = document.getElementById('flag-slow');
    if (!slowCheckbox) return;

    if (!isSlowCandidatesCompatible(mode)) {
        slowCheckbox.checked = false;
        slowCheckbox.disabled = true;
    } else {
        slowCheckbox.disabled = false;
        slowCheckbox.checked = !!slowCandidatesDefault;
    }
}

function applyDeviceDefaultSelection() {
    const selectDevice = document.getElementById('crack-device-select');
    if (!selectDevice) return;
    selectDevice.value = deviceDefault || 'all';
    if (selectDevice.value !== (deviceDefault || 'all')) {
        selectDevice.value = 'all';
    }
}

async function loadCrackingDefaults() {
    try {
        const config = await API.getConfig();
        
        // Load flags defaults
        document.getElementById('flag-optimized').checked = config.hashcat_optimized || false;
        slowCandidatesDefault = config.hashcat_slow || false;
        document.getElementById('flag-slow').checked = slowCandidatesDefault;
        deviceDefault = config.hashcat_device_default || 'all';
        
        // Enforce Mode and Workload defaults (Reset to standard)
        document.getElementById('custom-mode-select').value = 'straight';
        document.getElementById('custom-mode-label').innerText = 'STRAIGHT';
        document.getElementById('custom-workload-slider').value = '3';
        document.getElementById('custom-workload-val').innerText = '3';
        
        // Update visibility on open based on default config
        updateWordlistVisibility('straight');
        applySlowCandidatesPolicy('straight');
        applyDeviceDefaultSelection();
        
    } catch (e) {
        console.error("Failed to load config for preview", e);
    }
}

function renderCompactChip(label, value, className = 'crack-summary-chip') {
    if (value === null || value === undefined || value === '') return '';
    return `<span class="${className}"><span>${escapeHtml(label)}</span><b>${escapeHtml(String(value))}</b></span>`;
}

function renderCompactChipRow(chips, className = 'crack-summary-chip-row') {
    const html = chips.filter(Boolean).join('');
    return html ? `<div class="${className}">${html}</div>` : '';
}

function renderWarningBlock(warnings, className = 'crack-summary-warnings') {
    const items = (Array.isArray(warnings) ? warnings : []).filter((warning) => String(warning || '').trim());
    if (!items.length) return '';
    return `<div class="${className}">${items.map((warning) => `<div>${escapeHtml(String(warning))}</div>`).join('')}</div>`;
}

function renderArtifactSummary({ kicker, title, badges = '', chips = [], warnings = [], body = '' }) {
    return `
        <div class="crack-artifact-summary">
            <div class="crack-artifact-summary-head">
                <div>
                    <div class="crack-artifact-summary-kicker">${escapeHtml(kicker || 'Artifact')}</div>
                    <div class="crack-artifact-summary-title">${escapeHtml(title || 'Unknown artifact')}</div>
                </div>
                <div class="crack-artifact-summary-badges">${badges}</div>
            </div>
            ${renderCompactChipRow(chips)}
            ${renderWarningBlock(warnings)}
            ${body}
        </div>
    `;
}

function renderRawContextItemView(item, details = null) {
    const rawItem = item && typeof item === 'object' ? item : {};
    const artifactType = String(rawItem.artifact_type || '').trim().toLowerCase();
    const metaChips = [];
    if (artifactType === 'pcap') {
        if (rawItem.ssid) metaChips.push(renderCompactChip('SSID', rawItem.ssid));
        if (Number.isFinite(Number(rawItem.channel))) metaChips.push(renderCompactChip('CH', Number(rawItem.channel)));
        if (Number.isFinite(Number(rawItem.frequency_mhz))) metaChips.push(renderCompactChip('FREQ', `${Number(rawItem.frequency_mhz)} MHz`));
        if (Number(rawItem.beacon_count || 0) > 0) metaChips.push(renderCompactChip('BEACONS', Number(rawItem.beacon_count || 0)));
        if (Number(rawItem.eapol_count || 0) > 0) metaChips.push(renderCompactChip('EAPOL', Number(rawItem.eapol_count || 0)));
        if (rawItem.processed_at) metaChips.push(renderCompactChip('PROCESSED', formatRawProcessedAt(rawItem.processed_at)));
    } else {
        if (Number(rawItem.valid_hash_lines || 0) > 0) metaChips.push(renderCompactChip('VALID', `${Number(rawItem.valid_hash_lines || 0)} line(s)`));
        if (Number(rawItem.matched_lines || 0) > 0) metaChips.push(renderCompactChip('MATCHED', `${Number(rawItem.matched_lines || 0)} line(s)`));
        if (rawItem.source_raw_file) metaChips.push(renderCompactChip('SOURCE', rawItem.source_raw_file));
        if (rawItem.matched_ssid) metaChips.push(renderCompactChip('MATCHED SSID', rawItem.matched_ssid));
        if (rawItem.primary_ssid) metaChips.push(renderCompactChip('PRIMARY SSID', rawItem.primary_ssid));
    }

    const warnings = Array.isArray(rawItem.warnings) ? rawItem.warnings : [];
    const analysisSummary = rawItem.analysis_summary && typeof rawItem.analysis_summary === 'object'
        ? rawItem.analysis_summary
        : null;
    const analysisChips = [];
    if (analysisSummary) {
        if (analysisSummary.duration_s != null) analysisChips.push(renderCompactChip('DURATION', `${Number(analysisSummary.duration_s).toFixed(Number(analysisSummary.duration_s) >= 10 ? 0 : 1)}s`));
        if (analysisSummary.networks_count != null) analysisChips.push(renderCompactChip('NETWORKS', Number(analysisSummary.networks_count)));
        if (analysisSummary.clients_count != null) analysisChips.push(renderCompactChip('CLIENTS', Number(analysisSummary.clients_count)));
        if (analysisSummary.handshake_candidate_count != null) analysisChips.push(renderCompactChip('CANDIDATES', Number(analysisSummary.handshake_candidate_count)));
        if (analysisSummary.noisy_capture) analysisChips.push(renderCompactChip('CAPTURE', 'Noisy'));
    }
    const analysisBlock = artifactType === 'pcap' && rawItem.analysis_present
        ? `
            <div class="crack-summary-note">RAW Analysis available.</div>
            ${renderCompactChipRow(analysisChips)}
            <button
                type="button"
                class="cyber-button-small bg-cyan fg-black"
                data-open-raw-analysis="true"
                data-raw-item-id="${escapeHtml(String(rawItem.raw_item_id || ''))}"
                data-raw-filename="${escapeHtml(String(rawItem.filename || rawItem.source_file || ''))}"
            >
                <i class="fa-solid fa-chart-column"></i> OPEN RAW ANALYSIS
            </button>
        `
        : '';
    if (rawItem.details_present && rawItem.details_filename) {
        metaChips.push(renderCompactChip('DETAILS', rawItem.details_filename));
    }
    const subtypeLabel = getRawSubtypeLabel(rawItem.source_path_role);
    const subtypeBadge = subtypeLabel
        ? `<span class="file-type-tag badge-details">${escapeHtml(subtypeLabel)}</span>`
        : '';
    const badges = `
        ${artifactType === '22000'
            ? renderSemanticBadge('RAW HASH', 'source-badge badge-role-state-raw')
            : `<span class="${getSourceBadgeClass(rawItem.source)}">${escapeHtml(rawItem.device_label || rawItem.source || 'RAW')}</span>`}
        ${subtypeBadge}
        <span class="file-type-tag ${artifactType === 'pcap' ? 'badge-pcap' : 'badge-hash'}">${artifactType === 'pcap' ? 'RAW PCAP' : 'RAW 22000'}</span>
    `;
    const title = rawItem.filename || rawItem.source_file || 'RAW item';

    if (details && artifactType === 'pcap') {
        return `
            <div class="crack-raw-details-shell">
                ${renderArtifactSummary({
                    kicker: 'RAW PCAP details',
                    title,
                    badges,
                    chips: metaChips,
                    warnings,
                })}
                ${renderDetailsView(details)}
            </div>
        `;
    }

    const detailsBlock = artifactType === 'pcap' && rawItem.details_present
        ? '<div class="crack-summary-note">Details are available for this RAW capture.</div>'
        : '';

    return renderArtifactSummary({
        kicker: artifactType === 'pcap' ? 'RAW capture artifact' : 'RAW hash artifact',
        title,
        badges,
        chips: metaChips,
        warnings,
        body: `
            ${analysisBlock}
            ${artifactType === '22000' ? '<div class="crack-summary-note">RAW hash files can be cracked directly or used to build a canonical WDRS hash for this network.</div>' : ''}
            ${detailsBlock}
        `,
    });
}

function placeConvertHashButton(location = 'default') {
    const button = document.getElementById('btn-convert-hash');
    if (!button) return;

    if (location === 'raw-conversions') {
        const rawSlot = document.getElementById('raw-canonical-conversion-slot');
        if (rawSlot && button.parentElement !== rawSlot) {
            rawSlot.appendChild(button);
        }
        if (rawSlot) rawSlot.style.display = 'flex';
        return;
    }

    const rawSlot = document.getElementById('raw-canonical-conversion-slot');
    if (rawSlot) rawSlot.style.display = 'none';
    const anchor = document.getElementById('btn-convert-hash-anchor');
    if (anchor && anchor.parentElement && anchor.nextElementSibling !== button) {
        anchor.after(button);
    }
}

function placeFileFeedback(location = 'default') {
    const feedback = document.getElementById('crack-file-feedback');
    if (!feedback) return;

    if (location === 'pre-attack') {
        const anchor = document.getElementById('crack-file-feedback-pre-attack-anchor');
        if (anchor && anchor.parentElement && anchor.nextElementSibling !== feedback) {
            anchor.after(feedback);
        }
        return;
    }

    if (location === 'pre-conversions') {
        const anchor = document.getElementById('crack-file-feedback-pre-conversions-anchor');
        if (anchor && anchor.parentElement && anchor.nextElementSibling !== feedback) {
            anchor.after(feedback);
        }
        return;
    }

    const statusContainer = document.querySelector('.crack-status-container');
    if (statusContainer && statusContainer.parentElement && statusContainer.nextElementSibling !== feedback) {
        statusContainer.after(feedback);
        return;
    }

    const defaultAnchor = document.getElementById('crack-file-feedback-default-anchor');
    if (defaultAnchor && defaultAnchor.parentElement && defaultAnchor.nextElementSibling !== feedback) {
        defaultAnchor.after(feedback);
    }
}

function setLegacyCrackingProgress(text, color = null, width = null, indeterminate = null) {
    const progressText = document.getElementById('crack-progress-text');
    const miniBar = document.getElementById('crack-mini-bar');

    if (progressText && text !== null && text !== undefined) {
        progressText.innerText = text;
    }
    if (progressText && color) {
        progressText.style.color = color;
    }
    if (miniBar && width !== null && width !== undefined) {
        miniBar.style.width = width;
    }
    if (miniBar && indeterminate !== null && indeterminate !== undefined) {
        miniBar.classList.toggle('indeterminate', Boolean(indeterminate));
    }
}

function setAttackPanelExpanded(toggle, section, expanded) {
    if (!toggle || !section) return;
    toggle.setAttribute('data-expanded', expanded ? 'true' : 'false');
    section.style.display = expanded ? 'flex' : 'none';
    const arrow = toggle.querySelector('.legacy-toggle-arrow');
    if (arrow) arrow.classList.toggle('legacy-toggle-open', expanded);
}

function closeSiblingAttackPanels(activeToggle = null) {
    if (crackingAttackPanelMode !== 'single') return;
    document.querySelectorAll('[data-attack-panel-toggle]').forEach((toggle) => {
        if (toggle === activeToggle) return;
        const panelId = toggle.getAttribute('data-attack-panel-toggle');
        const section = document.querySelector(`[data-attack-panel-body="${panelId}"]`);
        setAttackPanelExpanded(toggle, section, false);
    });
}

function toggleAttackPanel(toggle, section, onExpanded = null) {
    if (!toggle || !section) return;
    const nextExpanded = toggle.getAttribute('data-expanded') !== 'true';
    if (nextExpanded) closeSiblingAttackPanels(toggle);
    setAttackPanelExpanded(toggle, section, nextExpanded);
    if (nextExpanded && typeof onExpanded === 'function') onExpanded();
}

async function selectFile(file, element) {
    document.querySelectorAll('.file-item').forEach(el => el.classList.remove('selected'));
    element.classList.add('selected');
    updateActiveCaptureGroups(element);
    
    selectedFile = file;
    const actions = document.getElementById('crack-actions');
    const info = document.getElementById('selected-file-info');
    const btnConvert = document.getElementById('btn-convert-hash');
    const btnPcapHash = document.getElementById('btn-pcap-generate-hash');
    const btnAircrack = document.getElementById('btn-quick-attack');
    const btnExtractDetails = document.getElementById('btn-extract-details');
    const typeBadge = document.getElementById('file-type-badge');
    const statusContainer = document.querySelector('.crack-status-container');
    const configPreview = document.getElementById('crack-config-preview');
    const aircrackOptions = document.getElementById('crack-aircrack-options');
    const pcapConversions = document.getElementById('crack-pcap-conversions');
    const fileFeedback = document.getElementById('crack-file-feedback');
    const aircrackToggle = document.getElementById('aircrack-legacy-toggle');

    fileFeedback.classList.remove('crack-feedback-details');
    
    actions.style.display = 'flex';
    const sourceBadge = buildSelectedFileSourceBadge(file);
    info.innerHTML = `
        <span title="${escapeHtml(String(file.name || ''))}">${escapeHtml(String(file.display_name || file.name || ''))}</span>
        ${sourceBadge}
    `;
    
    let displayType = file.type.toUpperCase();
    if (file.type === 'batch') displayType = 'BATCH';
    if (file.type === 'raw_pcap') displayType = 'RAW PCAP';
    if (file.type === 'raw_22000') displayType = 'RAW 22000';
    typeBadge.innerText = displayType;
    
    const targetName22000 = file.name.replace(/\.pcap$/i, '.22000');
    
    const relevantJobs = Object.values(activeProcesses).filter(p => 
        p.details === file.name || p.details === targetName22000
    );

    const runningStatuses = ['RUNNING', 'QUEUED', 'STARTING', 'AUTOTUNING', 'BUILDING CACHE', 'INIT KERNELS'];
    let activeJob = relevantJobs.find(p => runningStatuses.includes(p.status));
    
    if (!activeJob && relevantJobs.length > 0) {
        activeJob = relevantJobs[0];
    }

    if (activeJob) {
        updateCrackingPanelStatus(activeJob);
    } else {
        setLegacyCrackingProgress('READY', '#888', '0%', false);
        const miniBar = document.getElementById('crack-mini-bar');
        if (miniBar) miniBar.style.backgroundColor = 'var(--neon-cyan)';
    }
    
    const isRunning = activeJob && runningStatuses.includes(activeJob.status);

    configPreview.style.display = 'none';
    aircrackOptions.style.display = 'none';
    if (pcapConversions) pcapConversions.style.display = 'none';
    if (aircrackToggle) aircrackToggle.style.display = 'none';
    fileFeedback.style.display = 'none';
    placeConvertHashButton('default');
    placeFileFeedback('default');
    btnConvert.style.display = 'none';
    if (statusContainer) statusContainer.style.display = 'none';
    const pmkToggle = document.getElementById('pmk-section-toggle');
    const pmkOptions = document.getElementById('crack-pmk-options');
    if (pmkToggle) pmkToggle.style.display = 'none';
    if (pmkOptions) pmkOptions.style.display = 'none';
    const wpsToggle = document.getElementById('wps-section-toggle');
    const wpsOptions = document.getElementById('crack-wps-options');
    if (wpsToggle) wpsToggle.style.display = 'none';
    if (wpsOptions) wpsOptions.style.display = 'none';
    if (btnExtractDetails) {
        btnExtractDetails.style.display = 'none';
        btnExtractDetails.disabled = false;
        btnExtractDetails.innerHTML = '<i class="fa-solid fa-magnifying-glass-chart"></i> EXTRACT DETAILS';
    }

    const fileType = file.type;
    if (String(document.getElementById('crack-ssid')?.innerText || '').trim().toUpperCase() === 'BATCH' && fileType !== 'batch') {
        const summaryNode = document.getElementById('crack-handshake-set-summary');
        if (summaryNode) {
            summaryNode.style.display = 'none';
            summaryNode.innerHTML = '';
        }
    }

    switch (fileType) {
        case 'pcap':
            btnConvert.style.display = 'none'; 
            if (pcapConversions) pcapConversions.style.display = 'flex';
            if (aircrackToggle) aircrackToggle.style.display = 'flex';
            if (aircrackOptions) {
                const isExpanded = aircrackToggle?.getAttribute('data-expanded') === 'true';
                aircrackOptions.style.display = isExpanded ? 'flex' : 'none';
            }
            if (pmkToggle) {
                pmkToggle.style.display = 'flex';
                const pmkExp = pmkToggle.getAttribute('data-expanded') === 'true';
                if (pmkOptions) pmkOptions.style.display = pmkExp ? 'flex' : 'none';
                const essidInput = document.getElementById('pmk-essid-input');
                if (essidInput && !essidInput.value) {
                    essidInput.value = document.getElementById('crack-ssid')?.innerText || '';
                }
            }
            if (wpsToggle) {
                wpsToggle.style.display = 'flex';
                const wpsExp = wpsToggle.getAttribute('data-expanded') === 'true';
                if (wpsOptions) wpsOptions.style.display = wpsExp ? 'flex' : 'none';
            }
            
            if (btnExtractDetails) {
                btnExtractDetails.style.display = 'block';
                if (isRunning) {
                    btnExtractDetails.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> BUSY...';
                    btnExtractDetails.disabled = true;
                } else {
                    btnExtractDetails.innerHTML = '<i class="fa-solid fa-magnifying-glass-chart"></i> EXTRACT DETAILS';
                    btnExtractDetails.disabled = false;
                }
            }
            
            if (isRunning) {
                if (btnPcapHash) {
                    btnPcapHash.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> BUSY...';
                    btnPcapHash.disabled = true;
                }
                if (btnAircrack) {
                    btnAircrack.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> BUSY...';
                    btnAircrack.disabled = true;
                }
            } else {
                if (btnPcapHash) {
                    btnPcapHash.innerHTML = '<i class="fa-solid fa-hashtag"></i> GENERATE HASH (22000)';
                    btnPcapHash.disabled = false;
                }
                if (btnAircrack) {
                    btnAircrack.innerHTML = '<i class="fa-solid fa-wind"></i> QUICK ATTACK (AIRCRACK-NG)';
                    btnAircrack.disabled = false;
                }
            }
            break;
        case 'raw_pcap':
            placeFileFeedback('pre-conversions');
            placeConvertHashButton('raw-conversions');
            btnConvert.style.display = 'flex';
            btnConvert.innerHTML = '<i class="fa-solid fa-layer-group"></i> BUILD CANONICAL';
            btnConvert.disabled = Boolean(isRunning);
            if (pcapConversions) pcapConversions.style.display = 'flex';
            if (aircrackToggle) aircrackToggle.style.display = 'flex';
            if (aircrackOptions) {
                const isExpanded = aircrackToggle?.getAttribute('data-expanded') === 'true';
                aircrackOptions.style.display = isExpanded ? 'flex' : 'none';
            }
            if (pmkToggle) {
                pmkToggle.style.display = 'flex';
                const pmkExp = pmkToggle.getAttribute('data-expanded') === 'true';
                if (pmkOptions) pmkOptions.style.display = pmkExp ? 'flex' : 'none';
                const essidInput = document.getElementById('pmk-essid-input');
                if (essidInput && !essidInput.value) {
                    essidInput.value = document.getElementById('crack-ssid')?.innerText || '';
                }
            }
            if (wpsToggle) {
                wpsToggle.style.display = 'flex';
                const wpsExp = wpsToggle.getAttribute('data-expanded') === 'true';
                if (wpsOptions) wpsOptions.style.display = wpsExp ? 'flex' : 'none';
            }
            fileFeedback.style.display = 'flex';
            fileFeedback.style.flexDirection = 'column';
            fileFeedback.style.alignItems = 'stretch';
            fileFeedback.style.gap = '8px';
            fileFeedback.innerHTML = renderRawContextItemView(file.raw_context_item || {}, null);
            if (btnExtractDetails) {
                btnExtractDetails.style.display = 'block';
                btnExtractDetails.innerHTML = '<i class="fa-solid fa-magnifying-glass-chart"></i> EXTRACT DETAILS';
                btnExtractDetails.disabled = Boolean(isRunning);
                if (isRunning) {
                    btnExtractDetails.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> BUSY...';
                }
            }
            if ((file.raw_context_item || {}).details_present && (file.raw_context_item || {}).details_filename) {
                try {
                    const details = await API.getFingerprintDetails({
                        filename: file.raw_context_item.details_filename,
                        captureId: file.capture_id || null,
                    });
                    fileFeedback.classList.add('crack-feedback-details');
                    fileFeedback.innerHTML = renderRawContextItemView(file.raw_context_item || {}, details);
                } catch (_e) {
                    fileFeedback.innerHTML = renderRawContextItemView(file.raw_context_item || {}, null);
                }
            }
            {
                const openRawAnalysisBtn = fileFeedback.querySelector('[data-open-raw-analysis="true"]');
                if (openRawAnalysisBtn) {
                    openRawAnalysisBtn.addEventListener('click', () => {
                        const btnRawView = document.getElementById('btn-raw-view');
                        if (btnRawView) btnRawView.click();
                        document.dispatchEvent(
                            new CustomEvent('kovil:open-raw-analysis', {
                                detail: {
                                    rawItemId: String(file.raw_item_id || ''),
                                    filename: String(file.name || ''),
                                },
                            })
                        );
                    });
                }
            }
            if (isRunning) {
                if (btnPcapHash) {
                    btnPcapHash.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> BUSY...';
                    btnPcapHash.disabled = true;
                }
                if (btnAircrack) {
                    btnAircrack.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> BUSY...';
                    btnAircrack.disabled = true;
                }
            } else {
                if (btnPcapHash) {
                    btnPcapHash.innerHTML = '<i class="fa-solid fa-hashtag"></i> GENERATE HASH (22000)';
                    btnPcapHash.disabled = false;
                }
                if (btnAircrack) {
                    btnAircrack.innerHTML = '<i class="fa-solid fa-wind"></i> QUICK ATTACK (AIRCRACK-NG)';
                    btnAircrack.disabled = false;
                }
            }
            break;
        case 'raw_22000':
            placeFileFeedback('pre-attack');
            btnConvert.style.display = 'flex';
            configPreview.style.display = 'flex';
            if (statusContainer) statusContainer.style.display = 'flex';
            fileFeedback.style.display = 'flex';
            fileFeedback.style.flexDirection = 'column';
            fileFeedback.style.alignItems = 'stretch';
            fileFeedback.style.gap = '8px';
            fileFeedback.innerHTML = renderRawContextItemView(file.raw_context_item || {}, null);
            if (isRunning) {
                btnConvert.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> CRACKING IN PROGRESS...';
                btnConvert.disabled = true;
            } else {
                btnConvert.innerHTML = '<i class="fa-solid fa-cat"></i> START CRACKING (HASHCAT)';
                btnConvert.disabled = false;
            }
            break;
        case '22000':
            btnConvert.style.display = 'flex';
            configPreview.style.display = 'flex';
            if (statusContainer) statusContainer.style.display = 'flex';
            fileFeedback.style.display = 'flex';
            fileFeedback.style.flexDirection = 'column';
            fileFeedback.style.alignItems = 'stretch';
            fileFeedback.style.gap = '8px';
            if (isRunning) {
                btnConvert.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> CRACKING IN PROGRESS...';
                btnConvert.disabled = true;
            } else {
                btnConvert.innerHTML = '<i class="fa-solid fa-cat"></i> START CRACKING (HASHCAT)';
                btnConvert.disabled = false;
            }
            {
                const currentMac = (document.getElementById('crack-mac')?.innerText || '').trim();
                const recommendationQuery = {
                    filename: file.name,
                    captureId: file.capture_id || null,
                    combinedBuildId: file.combined_build_id || null,
                };
                if (isValidMac(currentMac)) {
                    recommendationQuery.mac = currentMac.toUpperCase();
                }
                await loadAttackRecommendation(recommendationQuery, fileFeedback, file.name);
            }
            break;
        case 'batch':
            renderBatchSelectionSummary(file.name);
            btnConvert.style.display = 'flex';
            configPreview.style.display = 'flex';
            fileFeedback.style.display = 'flex';
            fileFeedback.style.flexDirection = 'column';
            fileFeedback.style.alignItems = 'stretch';
            fileFeedback.style.gap = '8px';
            if (isRunning) {
                btnConvert.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> CRACKING IN PROGRESS...';
                btnConvert.disabled = true;
            } else {
                btnConvert.innerHTML = '<i class="fa-solid fa-cat"></i> START CRACKING (HASHCAT)';
                btnConvert.disabled = false;
            }
            {
                const batchRecommendation = getBatchRecommendationRequest(file.name);
                await loadAttackRecommendation(
                    batchRecommendation.query,
                    fileFeedback,
                    batchRecommendation.sourceLabel
                );
            }
            break;
        case 'cracked':
        case 'pcap.cracked':
            fileFeedback.style.display = 'flex';
            fileFeedback.style.flexDirection = 'column';
            fileFeedback.style.alignItems = 'stretch';
            fileFeedback.style.gap = '8px';
            
            fileFeedback.innerHTML = renderArtifactSummary({
                kicker: 'Cracked credential',
                title: file.name,
                badges: '<span class="file-type-tag badge-cracked">CRACKED</span>',
                body: '<div class="crack-summary-note"><i class="fa-solid fa-spinner fa-spin"></i> Loading content...</div>',
            });

            try {
                let content = await API.getFileContent(file.name, {
                    captureId: file.capture_id || null,
                    combinedBuildId: file.combined_build_id || null,
                    mac: file.combined_build_id ? (document.getElementById('crack-mac')?.innerText || '') : null,
                });
                if (content) {
                    content = content.trimEnd();
                }
                
                const formattedContent = `<div class="cracked-content-box">${escapeHtml(content)}</div>`;

                fileFeedback.innerHTML = renderArtifactSummary({
                    kicker: 'CRACKED DATA FOUND',
                    title: file.name,
                    badges: '<span class="file-type-tag badge-cracked">CRACKED</span>',
                    body: formattedContent,
                });
            } catch (e) {
                fileFeedback.innerHTML = renderArtifactSummary({
                    kicker: 'Cracked credential',
                    title: file.name,
                    badges: '<span class="file-type-tag badge-cracked">CRACKED</span>',
                    warnings: ['Failed to load file content.'],
                });
            }
            break;
        case 'try':
            renderHistoryPanel(file.name, fileFeedback, {
                captureId: file.capture_id || null,
                combinedBuildId: file.combined_build_id || null,
                mac: file.combined_build_id ? (document.getElementById('crack-mac')?.innerText || '') : null,
            });
            break;
        case 'details':
            fileFeedback.classList.add('crack-feedback-details');
            fileFeedback.style.display = 'flex';
            fileFeedback.style.flexDirection = 'column';
            fileFeedback.style.alignItems = 'stretch';
            fileFeedback.style.gap = '8px';
            fileFeedback.innerHTML = renderArtifactSummary({
                kicker: 'Fingerprint details',
                title: file.name,
                badges: '<span class="file-type-tag badge-details">DETAILS</span>',
                body: '<div class="crack-summary-note"><i class="fa-solid fa-spinner fa-spin"></i> Loading details...</div>',
            });

            if (pcapConversions) pcapConversions.style.display = 'none';
            if (btnPcapHash) btnPcapHash.style.display = '';
            if (btnExtractDetails) {
                btnExtractDetails.style.display = 'none';
            }

            try {
                const details = await API.getFingerprintDetails({
                    filename: file.name,
                    captureId: file.capture_id || null,
                });
                let recommendation = null;
                try {
                    const targetMac = details?.bssid || (document.getElementById('crack-mac')?.innerText || '');
                    if (targetMac && targetMac.includes(':')) {
                        recommendation = await API.getAttackRecommendation({ mac: targetMac });
                    }
                } catch (insightsError) {
                    // Recommendation is best-effort on details view.
                    recommendation = null;
                }
                fileFeedback.innerHTML = renderDetailsView(details, recommendation);
            } catch (e) {
                fileFeedback.innerHTML = renderArtifactSummary({
                    kicker: 'Fingerprint details',
                    title: file.name,
                    badges: '<span class="file-type-tag badge-details">DETAILS</span>',
                    warnings: [`Failed to load details: ${e.message}`],
                });
            }
            break;
        default:
            fileFeedback.style.display = 'flex';
            fileFeedback.innerHTML = renderArtifactSummary({
                kicker: 'Unsupported file',
                title: file.name || 'Unknown file',
                warnings: ['File type not recognized for direct action.'],
            });
            break;
    }
}

export function updateCrackingPanelStatus(proc) {
    const progressText = document.getElementById('crack-progress-text');
    const miniBar = document.getElementById('crack-mini-bar');

    if (proc.indeterminate) {
        setLegacyCrackingProgress(
            `${proc.status} ${proc.extraInfo ? `| ${proc.extraInfo}` : ''}`,
            null,
            '100%',
            true
        );
    } else {
        setLegacyCrackingProgress(
            `${proc.status} (${proc.percentage}%) ${proc.extraInfo ? `| ${proc.extraInfo}` : ''}`,
            null,
            `${proc.percentage}%`,
            false
        );
    }
    
    let color = 'var(--neon-cyan)';
    if (proc.status === 'COMPLETED' || proc.status === 'CRACKED' || proc.status === 'SUCCESS') color = 'var(--neon-green)';
    if (proc.status === 'FAILED' || proc.status === 'ERROR' || proc.status === 'EXHAUSTED' || proc.status === 'CANCELED') color = 'var(--neon-red)';
    if (proc.status === 'QUEUED') color = 'var(--neon-yellow)';
    
    if (progressText) progressText.style.color = color;
    if (miniBar) miniBar.style.backgroundColor = color;
    
    // Update buttons state
    const isRunning = ['RUNNING', 'QUEUED', 'STARTING', 'AUTOTUNING', 'BUILDING CACHE', 'INIT KERNELS'].includes(proc.status);
    const btnConvert = document.getElementById('btn-convert-hash');
    const btnPcap = document.getElementById('btn-pcap-generate-hash');
    const btnAircrack = document.getElementById('btn-quick-attack');
    
    if (isRunning) {
        if (btnConvert) { btnConvert.disabled = true; btnConvert.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> BUSY...'; }
        if (btnPcap) { btnPcap.disabled = true; btnPcap.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> BUSY...'; }
        if (btnAircrack) { btnAircrack.disabled = true; btnAircrack.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> BUSY...'; }
    } else {
        // Reset buttons
        if (btnConvert) {
            btnConvert.disabled = false;
            btnConvert.innerHTML = selectedFile?.type === 'raw_pcap'
                ? '<i class="fa-solid fa-layer-group"></i> BUILD CANONICAL'
                : '<i class="fa-solid fa-cat"></i> START CRACKING (HASHCAT)';
        }
        if (btnPcap) { btnPcap.disabled = false; btnPcap.innerHTML = '<i class="fa-solid fa-hashtag"></i> GENERATE HASH (22000)'; }
        if (btnAircrack) { btnAircrack.disabled = false; btnAircrack.innerHTML = '<i class="fa-solid fa-wind"></i> QUICK ATTACK (AIRCRACK-NG)'; }
        
        // Set RETRY if failed
        if (proc.status === 'FAILED' || proc.status === 'ERROR' || proc.status === 'CANCELED') {
             if (proc.type.includes("HASHCAT") && btnConvert) btnConvert.innerText = 'RETRY';
             if (proc.type.includes("22000") && btnPcap) btnPcap.innerText = 'RETRY';
             if (proc.type.includes("AIRCRACK") && btnAircrack) btnAircrack.innerText = 'RETRY';
        }
    }
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

export function setupCrackingListeners() {
    crackingAccordionMode = normalizeCrackingAccordionMode(
        document.documentElement?.dataset?.crackingAccordionMode
    );
    crackingAttackPanelMode = normalizeCrackingAttackPanelMode(
        document.documentElement?.dataset?.crackingAttackPanelMode
    );
    if (window.__kovilCrackingConfigAppliedHandler) {
        window.removeEventListener('kovil:config-applied', window.__kovilCrackingConfigAppliedHandler);
    }
    window.__kovilCrackingConfigAppliedHandler = (event) => {
        const config = event?.detail?.config || {};
        crackingAccordionMode = normalizeCrackingAccordionMode(config.ui_cracking_accordion_mode);
        crackingAttackPanelMode = normalizeCrackingAttackPanelMode(config.ui_cracking_attack_panel_mode);
        if (crackingAttackPanelMode === 'single') {
            const expanded = Array.from(document.querySelectorAll('[data-attack-panel-toggle]'))
                .find((toggle) => toggle.getAttribute('data-expanded') === 'true');
            closeSiblingAttackPanels(expanded || null);
        }
    };
    window.addEventListener('kovil:config-applied', window.__kovilCrackingConfigAppliedHandler);

    document.getElementById('btn-toggle-cracking').addEventListener('click', function() {
        STATE.modes.cracking = !STATE.modes.cracking;
        const panel = document.getElementById('cracking-panel');
        panel.style.display = STATE.modes.cracking ? 'flex' : 'none';
        
        if (STATE.modes.cracking) {
            this.classList.add('active');
        } else {
            this.classList.remove('active');
        }
        saveModes();
        notifyRightPanelsModeChanged();
    });

    document.querySelector('#cracking-panel .close-panel').addEventListener('click', () => {
        STATE.modes.cracking = false;
        document.getElementById('cracking-panel').style.display = 'none';
        document.getElementById('btn-toggle-cracking').classList.remove('active');
        saveModes();
        notifyRightPanelsModeChanged();
    });

    document.getElementById('btn-convert-hash').addEventListener('click', handleCrackAction);
    document.getElementById('btn-pcap-generate-hash').addEventListener('click', handleCrackAction); 
    document.getElementById('btn-quick-attack').addEventListener('click', handleAircrackAction);
    const btnAssociationPreview = document.getElementById('btn-association-preview');
    if (btnAssociationPreview) {
        btnAssociationPreview.addEventListener('click', runAssociationPreview);
    }
    const btnExtract = document.getElementById('btn-extract-details');
    if (btnExtract) btnExtract.addEventListener('click', () => startFingerprint('btn-extract-details'));
    const crackFileList = document.getElementById('crack-file-list');
    if (crackFileList) {
        crackFileList.addEventListener('click', (event) => {
            const prepareAllButton = event.target.closest('button[data-action="raw-auto-prepare-all"]');
            if (prepareAllButton) {
                event.preventDefault();
                event.stopPropagation();
                handleRawAutoPrepareAll(prepareAllButton);
            }
        });
    }
    if (window.__kovilRawPrepareAllCompleteHandler) {
        document.removeEventListener(
            'rawPrepareAllComplete',
            window.__kovilRawPrepareAllCompleteHandler
        );
    }
    window.__kovilRawPrepareAllCompleteHandler = async (event) => {
        const detail = event?.detail || {};
        const mac = String(detail.mac || '').trim().toUpperCase();
        const panelMac = String(document.getElementById('crack-mac')?.innerText || '').trim().toUpperCase();
        if (!mac || !panelMac || mac !== panelMac) return;

        const status = String(detail.status || '').toLowerCase();
        const summaryText = detail.summary || null;
        rawPrepareAllRunningMac = null;
        if (summaryText) {
            renderRawContextSummary(currentRawContext, summaryText);
        } else {
            renderRawContextSummary(currentRawContext);
        }
        setRawPrepareAllButtonState({ running: false });

        if (status === 'success' || status === 'success_partial' || status === 'up_to_date') {
            const selectedName = detail.canonical_hash || null;
            const ssid = document.getElementById('crack-ssid')?.innerText || '';
            await openCrackingPanel(panelMac, ssid, selectedName);
        }
    };
    document.addEventListener('rawPrepareAllComplete', window.__kovilRawPrepareAllCompleteHandler);
    
    const legacyToggle = document.getElementById('aircrack-legacy-toggle');
    const legacySection = document.getElementById('crack-aircrack-options');
    if (legacyToggle && legacySection) {
        legacyToggle.addEventListener('click', () => {
            toggleAttackPanel(legacyToggle, legacySection);
        });
    }

    // PMK Database section toggle + actions
    const pmkToggle = document.getElementById('pmk-section-toggle');
    const pmkSection = document.getElementById('crack-pmk-options');
    if (pmkToggle && pmkSection) {
        pmkToggle.addEventListener('click', () => {
            toggleAttackPanel(pmkToggle, pmkSection, refreshPmkDatabases);
        });
    }
    const btnPmkBuild = document.getElementById('btn-pmk-build');
    if (btnPmkBuild) btnPmkBuild.addEventListener('click', startPmkBuild);
    const btnPmkAttack = document.getElementById('btn-pmk-attack');
    if (btnPmkAttack) btnPmkAttack.addEventListener('click', startPmkAttack);
    const btnPmkRefresh = document.getElementById('btn-pmk-refresh');
    if (btnPmkRefresh) btnPmkRefresh.addEventListener('click', refreshPmkDatabases);

    // WPS Attack section toggle + actions
    const wpsToggleEl = document.getElementById('wps-section-toggle');
    const wpsSection = document.getElementById('crack-wps-options');
    if (wpsToggleEl && wpsSection) {
        wpsToggleEl.addEventListener('click', () => {
            toggleAttackPanel(wpsToggleEl, wpsSection);
        });
    }
    const btnWpsAttack = document.getElementById('btn-wps-attack');
    if (btnWpsAttack) btnWpsAttack.addEventListener('click', startWpsAttack);

    // Removed default wordlist toggle

    document.getElementById('custom-mode-select').addEventListener('change', (e) => {
        const mode = e.target.value;
        document.getElementById('custom-mode-label').innerText = getModePanelLabel(mode);
        updateWordlistVisibility(mode);
        applySlowCandidatesPolicy(mode);
    });

    const workloadSlider = document.getElementById('custom-workload-slider');
    if (workloadSlider) {
        workloadSlider.addEventListener('input', (e) => {
            document.getElementById('custom-workload-val').innerText = e.target.value;
        });
    }

    document.getElementById('mask-help-btn').addEventListener('click', () => {
        alert("MASK CHEAT SHEET:\n\n?l = a-z\n?u = A-Z\n?d = 0-9\n?h = 0-9a-f\n?H = 0-9A-F\n?s = Special (!@#$)\n?a = ?l?u?d?s\n?b = 0x00-0xff");
    });

    if (window.__kovilHistoryDetailsClickHandler) {
        document.removeEventListener('click', window.__kovilHistoryDetailsClickHandler);
    }
    window.__kovilHistoryDetailsClickHandler = (e) => {
        const details = e.target.closest('.history-details');
        if (details) {
            details.classList.toggle('expanded');
        }
    };
    document.addEventListener('click', window.__kovilHistoryDetailsClickHandler);
    
    // Listener para o checkbox de Incremento
    document.getElementById('flag-increment').addEventListener('change', (e) => {
        const row = document.getElementById('crack-increment-row');
        if (e.target.checked) {
            row.style.display = 'flex';
        } else {
            row.style.display = 'none';
        }
    });
}

function updateWordlistVisibility(mode) {
    const wordlistRow = document.getElementById('crack-wordlist-row');
    const wordlist2Row = document.getElementById('crack-wordlist-2-row');
    const ruleRow = document.getElementById('crack-rule-row');
    const rule2Row = document.getElementById('crack-rule-2-row');
    const ruleLabel = document.getElementById('crack-rule-label');
    const maskRow = document.getElementById('crack-mask-row');
    const maskProfileRow = document.getElementById('crack-mask-profile-row');
    const associationHintRow = document.getElementById('crack-association-hint-row');
    const associationHintsRow = document.getElementById('crack-association-hints-row');
    const associationPreviewRow = document.getElementById('crack-association-preview-row');
    const incrementContainer = document.getElementById('flag-increment-container');
    const incrementRow = document.getElementById('crack-increment-row');
    const maskInput = document.getElementById('crack-mask-input');
    const autoMaskChk = document.getElementById('auto-mask-chk');
    
    if (!wordlistRow) return;
    
    // Reset all
    wordlistRow.style.display = 'none';
    wordlist2Row.style.display = 'none';
    ruleRow.style.display = 'none';
    rule2Row.style.display = 'none';
    maskRow.style.display = 'none';
    maskProfileRow.style.display = 'none';
    associationHintRow.style.display = 'none';
    associationHintsRow.style.display = 'none';
    if (associationPreviewRow) associationPreviewRow.style.display = 'none';
    incrementContainer.style.display = 'none';
    incrementRow.style.display = 'none';
    
    // Reset checkbox state if hiding
    const incCheckbox = document.getElementById('flag-increment');
    
    // Reset mask input state (enable by default)
    if (maskInput) {
        maskInput.readOnly = false;
        maskInput.style.opacity = '1';
        maskInput.style.cursor = 'text';
    }
    if (autoMaskChk) {
        autoMaskChk.disabled = false;
    }
    
    switch(mode) {
        case 'straight':
            wordlistRow.style.display = 'flex';
            if (ruleLabel) ruleLabel.innerText = 'RULE:';
            break;
        case 'rules':
            wordlistRow.style.display = 'flex';
            ruleRow.style.display = 'flex';
            if (ruleLabel) ruleLabel.innerText = 'RULE:';
            break;
        case 'passphrase':
            // Ordem importa: RULE #1 é aplicada antes de RULE #2 no hashcat.
            wordlistRow.style.display = 'flex';
            ruleRow.style.display = 'flex';
            rule2Row.style.display = 'flex';
            if (ruleLabel) ruleLabel.innerText = 'RULE #1:';
            break;
        case 'association':
            associationHintRow.style.display = 'flex';
            if (associationPreviewRow) associationPreviewRow.style.display = 'flex';
            if (ruleLabel) ruleLabel.innerText = 'RULE:';
            break;
        case 'association_hint_first':
            associationHintsRow.style.display = 'flex';
            if (associationPreviewRow) associationPreviewRow.style.display = 'flex';
            if (ruleLabel) ruleLabel.innerText = 'RULE:';
            break;
        case 'association_hint_rule':
            associationHintsRow.style.display = 'flex';
            ruleRow.style.display = 'flex';
            // Don't show preview button - rules transform candidates making preview impractical
            // Also remove any existing preview card
            removeAssociationPreviewCard();
            if (ruleLabel) ruleLabel.innerText = 'RULE:';
            break;
        case 'combinator':
            wordlistRow.style.display = 'flex';
            wordlist2Row.style.display = 'flex';
            break;
        case 'combinator_passphrase':
            wordlistRow.style.display = 'flex';
            wordlist2Row.style.display = 'flex';
            break;
        case 'digits':
            // 8-Digit Brute Force: Mask controlled by slider (?d)
            maskRow.style.display = 'flex';
            // Disable increment for 8-digit mode (WPA requires min 8 chars anyway)
            incrementContainer.style.display = 'none'; 
            if (incCheckbox) incCheckbox.checked = false;
            
            if (maskInput) {
                maskInput.readOnly = true;
                // maskInput.disabled = true; // Se desabilitar, o valor não é enviado no POST se fosse um form submit, mas aqui pegamos via ID. Visualmente disabled é bom.
                maskInput.style.opacity = '0.7';
                maskInput.style.cursor = 'not-allowed';
            }
            if (autoMaskChk) {
                autoMaskChk.checked = true; // Force Auto ON so slider updates it
                autoMaskChk.disabled = true; // Prevent user from disabling auto
            }
            
            // Force slider to 8 digits default when switching to this mode
            if (incrementSlider) {
                incrementSlider.set([8, 8]);
                updateMaskFromSlider(8);
            }
            break;
        case 'mask':
            maskRow.style.display = 'flex';
            incrementContainer.style.display = 'flex'; // Show increment checkbox
            if (incCheckbox.checked) {
                incrementRow.style.display = 'flex';
            }
            // Re-enable auto mask checkbox if it was disabled by digits mode
            if (autoMaskChk) {
                autoMaskChk.disabled = false;
                // Trigger change event to restore correct state based on checked property
                autoMaskChk.dispatchEvent(new Event('change'));
            }
            break;
        case 'mask_profile':
            maskProfileRow.style.display = 'flex';
            if (incCheckbox) incCheckbox.checked = false;
            break;
        case 'hybrid':
            wordlistRow.style.display = 'flex';
            maskRow.style.display = 'flex';
            incrementContainer.style.display = 'flex'; // Hybrid also supports increment on mask
            if (incCheckbox.checked) {
                incrementRow.style.display = 'flex';
            }
             // Re-enable auto mask checkbox
            if (autoMaskChk) {
                autoMaskChk.disabled = false;
                autoMaskChk.dispatchEvent(new Event('change'));
            }
            break;
        case 'hybrid_reverse':
            maskRow.style.display = 'flex';
            wordlistRow.style.display = 'flex';
            incrementContainer.style.display = 'flex';
            if (incCheckbox.checked) {
                incrementRow.style.display = 'flex';
            }
             // Re-enable auto mask checkbox
            if (autoMaskChk) {
                autoMaskChk.disabled = false;
                autoMaskChk.dispatchEvent(new Event('change'));
            }
            break;
        case 'hybrid_mask_profile':
            wordlistRow.style.display = 'flex';
            maskProfileRow.style.display = 'flex';
            if (incCheckbox) incCheckbox.checked = false;
            break;
        case 'hybrid_reverse_mask_profile':
            wordlistRow.style.display = 'flex';
            maskProfileRow.style.display = 'flex';
            if (incCheckbox) incCheckbox.checked = false;
            break;
        default:
            wordlistRow.style.display = 'flex';
            if (ruleLabel) ruleLabel.innerText = 'RULE:';
    }

    if (!isAssociationMode(mode)) {
        removeAssociationPreviewCard();
    }
}

function handleCrackAction(event) {
    if (!selectedFile) return;
    const actionId = String(event?.currentTarget?.id || '').trim();

    if (selectedFile.type === 'pcap') {
        startConversion();
    } else if (selectedFile.type === 'raw_pcap') {
        if (actionId === 'btn-convert-hash') {
            handleRawAutoPrepare(selectedFile);
            return;
        }
        startConversion();
    } else if (selectedFile.type === '22000' || selectedFile.type === 'batch' || selectedFile.type === 'raw_22000') {
        startCracking();
    }
}

function handleAircrackAction() {
    if (!selectedFile || (selectedFile.type !== 'pcap' && selectedFile.type !== 'raw_pcap')) return;
    startAircrack();
}

async function startFingerprint(buttonId = 'btn-extract-details') {
    if (!selectedFile) return;
    let targetPcap = null;
    let targetCaptureId = selectedFile.capture_id || null;
    let targetRawItemId = selectedFile.raw_item_id || null;
    const wasDetailsSelection = selectedFile.type === 'details' || selectedFile.name.endsWith('.details');

    if (selectedFile.type === 'pcap') {
        targetPcap = selectedFile.name;
    } else if (selectedFile.type === 'raw_pcap') {
        targetPcap = selectedFile.name;
    } else if (wasDetailsSelection) {
        if (selectedFile.capture_id) {
            const captureFiles = getCaptureFiles(selectedFile.capture_id, currentFiles);
            const capturePcap = captureFiles.find((file) => file.type === 'pcap')
                || getCapturePreferredFile(selectedFile.capture_id, currentFiles);
            if (capturePcap?.type === 'pcap') {
                targetPcap = capturePcap.name;
                targetCaptureId = capturePcap.capture_id || targetCaptureId;
            }
        }
        if (!targetPcap) {
            const base = selectedFile.name.replace(/\.details$/i, '');
            const candidates = [`${base}.pcap`, `${base}.pcapng`];
            targetPcap = candidates.find((candidate) => currentFiles.some((file) => {
                if (file.type !== 'pcap' || file.name !== candidate) return false;
                if (!selectedFile.capture_id) return true;
                return file.capture_id === selectedFile.capture_id;
            })) || candidates[0];
        }
    } else {
        return;
    }

    const btn = document.getElementById(buttonId);
    const mac = document.getElementById('crack-mac').innerText;
    const ssid = document.getElementById('crack-ssid').innerText;
    const targetBssid = selectedFile.type === 'raw_pcap' ? mac : null;

    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> EXTRACTING...';
    }

    try {
        const res = await API.extractFingerprint(
            targetPcap,
            false,
            targetCaptureId,
            targetRawItemId,
            targetBssid
        );
        const saved = res.saved_path ? res.saved_path.split('/').pop() : `${selectedFile.name.replace(/\\.pcap(ng)?$/i, '')}.details`;
        log(`Details extracted: ${saved}`, 'success');
        // Keep RAW-derived details inside RAW context instead of promoting them to the
        // main handshake inventory.
        if (selectedFile.type !== 'raw_pcap') {
            const pos = STATE.allPositions[mac];
            if (pos) {
                pos.handshake_files = pos.handshake_files || [];
                if (!pos.handshake_files.includes(saved)) pos.handshake_files.push(saved);
            }
        }
        if (window.refreshPopupDetails && STATE.openPopupMac === mac) {
            const detailsData = res.details || await API.getFingerprintDetails({
                filename: saved,
                captureId: targetCaptureId,
            }).catch(() => null);
            if (detailsData) window.refreshPopupDetails(mac, detailsData);
        }

        const fileToSelect = selectedFile.type === 'raw_pcap'
            ? saved
            : (wasDetailsSelection ? saved : targetPcap);
        await openCrackingPanel(mac, ssid, fileToSelect, selectedFile.type === 'raw_pcap'
            ? { rawItemId: targetRawItemId }
            : null);
    } catch (e) {
        log(`Failed to extract details: ${e.message}`, 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-magnifying-glass-chart"></i> EXTRACT DETAILS';
        }
    }
}

function renderDetailsView(d, recommendation = null) {
    if (!d) {
        return `
            <div class="details-view-scroll">
                <div class="details-card">
                    <div class="details-card-head">
                        <div>
                            <div class="details-card-kicker">Fingerprint details</div>
                            <div class="details-card-title">No details available</div>
                        </div>
                        <div class="details-card-badges">
                            <span class="file-type-tag badge-details">DETAILS</span>
                        </div>
                    </div>
                    <div class="details-footer-meta">Select or extract a details artifact to inspect radio, security and RAW Sniffer evidence.</div>
                </div>
            </div>
        `;
    }
    const sec = d.security || {};
    const wps = d.wps || {};
    const cls = d.classification || {};
    const meta = d.meta || {};
    const radio = d.radio || {};
    const rates = d.rates || {};
    const phy = d.phy || {};
    const caps = d.capabilities || {};
    const qbss = d.qbss || {};
    const raw = d.raw_sniffer || {};
    const rawAggregate = raw.aggregate || {};
    const rawFiles = Array.isArray(raw.files) ? raw.files : [];
    const rawPresent = !!raw.present;

    const list = (arr) => (arr && arr.length ? arr.join(', ') : '—');
    const deviceLabelMap = {
        router_ap: 'Router AP',
        phone_hotspot: 'Phone Hotspot',
        camera_ap: 'Camera AP',
        printer_ap: 'Printer AP',
        iot_ap: 'IoT AP',
        unknown: 'Unknown',
        router: 'Router AP',
    };
    const deviceLabel = deviceLabelMap[String(cls.type || 'unknown').toLowerCase()] || String(cls.type || 'unknown');
    const badgeColor = (cls.type === 'router' || cls.type === 'router_ap') ? 'var(--neon-cyan)' :
        cls.type === 'phone_hotspot' ? 'var(--neon-orange)' :
        cls.type === 'camera_ap' ? 'var(--neon-yellow)' :
        cls.type === 'printer_ap' ? 'var(--neon-purple)' :
        cls.type === 'iot_ap' ? 'var(--neon-green)' :
        'var(--neon-red)';
    const showClass = (cls.confidence || 0) >= 0.6;

    const pills = [
        { label: 'WPA', value: sec.wpa_version || 'Unknown' },
        { label: 'AKM', value: list(sec.akm || []) },
        { label: 'Pair', value: list(sec.pairwise_ciphers || []) },
        { label: 'Group', value: sec.group_cipher || 'Unknown' },
        { label: 'PMF', value: sec.pmf || 'Unknown' },
        { label: 'Vendor', value: d.vendor || 'Unknown' },
    ].map(p => renderCompactChip(p.label, p.value, 'details-chip')).join('');

    const warningsHtml = (meta.warnings || []).map(w => `<li>${escapeHtml(w)}</li>`).join('') || '<li>None</li>';
    const evidenceHtml = (cls.evidence || []).map(e => `<li>${escapeHtml(e)}</li>`).join('') || '<li>None</li>';
    const wpsSummary = wps.present
        ? `${escapeHtml(wps.manufacturer || '—')} | ${escapeHtml((wps.model_name || '').trim() || '—')} | ${escapeHtml((wps.device_name || '').trim() || '—')}`
        : 'Not present';

    const sectionRows = (rows) => rows.map(r => `
        <div class="details-compact-label">${escapeHtml(r.label)}</div>
        <div class="details-compact-value">${escapeHtml(r.value)}</div>
    `).join('');

    const makeSection = (title, rows, options = {}) => {
        if (!rows.length) return '';
        return `
            <div class="details-compact-section${options.wide ? ' details-compact-section--wide' : ''}">
                <div class="details-compact-title">${escapeHtml(title)}</div>
                <div class="details-compact-rows">
                ${sectionRows(rows)}
                </div>
            </div>
        `;
    };

    const radioRows = [];
    const channelParts = [];
    if (radio.channel !== null && radio.channel !== undefined && radio.channel !== '') channelParts.push(`Ch ${radio.channel}`);
    if (radio.band) channelParts.push(`${radio.band}GHz`);
    if (channelParts.length) radioRows.push({ label: 'Channel', value: channelParts.join(' / ') });
    if (radio.frequency_mhz !== null && radio.frequency_mhz !== undefined && radio.frequency_mhz !== '') {
        radioRows.push({ label: 'Freq', value: `${radio.frequency_mhz} MHz` });
    }
    const signalParts = [];
    if (radio.signal_dbm_avg !== null && radio.signal_dbm_avg !== undefined) signalParts.push(`avg ${radio.signal_dbm_avg} dBm`);
    if (radio.signal_dbm_min !== null && radio.signal_dbm_min !== undefined) signalParts.push(`min ${radio.signal_dbm_min}`);
    if (radio.signal_dbm_max !== null && radio.signal_dbm_max !== undefined) signalParts.push(`max ${radio.signal_dbm_max}`);
    if (signalParts.length) radioRows.push({ label: 'Signal', value: signalParts.join(' | ') });
    const dataRateParts = [];
    if (radio.datarate_mbps_avg !== null && radio.datarate_mbps_avg !== undefined) dataRateParts.push(`avg ${radio.datarate_mbps_avg} Mbps`);
    if (radio.datarate_mbps_max !== null && radio.datarate_mbps_max !== undefined) dataRateParts.push(`max ${radio.datarate_mbps_max} Mbps`);
    if (dataRateParts.length) radioRows.push({ label: 'Data rate', value: dataRateParts.join(' | ') });

    const ratesList = (rates.all && rates.all.length) ? rates.all : (rates.supported || []);
    const ratesParts = [];
    if (ratesList.length) ratesParts.push(ratesList.join(', '));
    if (rates.max_rate_mbps !== null && rates.max_rate_mbps !== undefined) {
        ratesParts.push(`max ${rates.max_rate_mbps} Mbps`);
    }
    const ratesRows = ratesParts.length ? [{ label: 'Rates', value: ratesParts.join(' | ') }] : [];

    const phyParts = [];
    if (phy.ht_present) phyParts.push(`HT${phy.ht_width_code ? ` w=${phy.ht_width_code}` : ''}`);
    else if (phy.ht_width_code) phyParts.push(`HT w=${phy.ht_width_code}`);
    if (phy.vht_present) phyParts.push(`VHT${phy.vht_width_code ? ` w=${phy.vht_width_code}` : ''}`);
    else if (phy.vht_width_code) phyParts.push(`VHT w=${phy.vht_width_code}`);
    const phyRows = phyParts.length ? [{ label: 'PHY', value: phyParts.join(' | ') }] : [];

    const capFlags = (caps.flags && caps.flags.length)
        ? caps.flags
        : [
            caps.privacy ? 'PRIVACY' : '',
            caps.short_preamble ? 'SHORT_PREAMBLE' : '',
            caps.short_slot_time ? 'SHORT_SLOT' : '',
            caps.qos ? 'QOS' : '',
            caps.spectrum_mgmt ? 'SPECTRUM_MGMT' : '',
        ].filter(Boolean);
    const capsRows = capFlags.length ? [{ label: 'Caps', value: capFlags.join(', ') }] : [];

    const qbssParts = [];
    if (qbss.station_count !== null && qbss.station_count !== undefined) qbssParts.push(`stations ${qbss.station_count}`);
    if (qbss.channel_utilization !== null && qbss.channel_utilization !== undefined) qbssParts.push(`util ${qbss.channel_utilization}`);
    if (qbss.available_capacity !== null && qbss.available_capacity !== undefined) qbssParts.push(`cap ${qbss.available_capacity}`);
    const qbssRows = qbssParts.length ? [{ label: 'QBSS', value: qbssParts.join(' | ') }] : [];

    const rawRows = [];
    if (rawPresent) {
        rawRows.push({ label: 'Files', value: String(raw.files_count || 0) });
        rawRows.push({
            label: 'Beacon',
            value: `total ${rawAggregate.beacon_count_total || 0} | peak ${rawAggregate.beacon_count_peak || 0}`,
        });
        rawRows.push({
            label: 'EAPOL',
            value: `total ${rawAggregate.eapol_count_total || 0} | peak ${rawAggregate.eapol_count_peak || 0}`,
        });
        rawRows.push({
            label: 'Probes',
            value: `peak ${rawAggregate.probe_client_count_peak || 0}`,
        });
        if (Array.isArray(rawAggregate.channels) && rawAggregate.channels.length) {
            rawRows.push({ label: 'Channels', value: rawAggregate.channels.join(', ') });
        }
        if (Array.isArray(rawAggregate.frequencies_mhz) && rawAggregate.frequencies_mhz.length) {
            rawRows.push({ label: 'Freq', value: `${rawAggregate.frequencies_mhz.join(', ')} MHz` });
        }
        if (rawAggregate.last_seen_offset_s_max !== null && rawAggregate.last_seen_offset_s_max !== undefined) {
            rawRows.push({ label: 'Last offset', value: `${rawAggregate.last_seen_offset_s_max} s` });
        }
    }

    const rawWarnings = Array.isArray(rawAggregate.warnings) ? rawAggregate.warnings : [];
    const rawWarningsHtml = rawWarnings.map(w => `<div>${escapeHtml(String(w))}</div>`).join('') || '<div>None</div>';
    const rawFilesHtml = rawFiles.map((file) => {
        const warnings = Array.isArray(file?.warnings) ? file.warnings : [];
        const warningsText = warnings.length ? warnings.map(w => escapeHtml(String(w))).join('; ') : 'None';
        return `
            <div class="details-raw-file-row">
                <div class="details-raw-file-name">${escapeHtml(file?.source_file || 'unknown')}</div>
                <div class="details-chip-row">
                    ${renderCompactChip('BCN', file?.beacon_count ?? 0, 'details-chip')}
                    ${renderCompactChip('EAPOL', file?.eapol_count ?? 0, 'details-chip')}
                    ${renderCompactChip('PROBES', file?.probe_client_count ?? 0, 'details-chip')}
                    ${renderCompactChip('CH', file?.channel ?? '-', 'details-chip')}
                    ${renderCompactChip('FREQ', `${file?.frequency_mhz ?? '-'} MHz`, 'details-chip')}
                    ${renderCompactChip('SSID', file?.ssid || '<hidden>', 'details-chip')}
                    ${file?.ssid_raw_hex ? renderCompactChip('HEX', file.ssid_raw_hex, 'details-chip') : ''}
                    ${file?.last_seen_offset_s !== null && file?.last_seen_offset_s !== undefined ? renderCompactChip('LAST', `${file.last_seen_offset_s}s`, 'details-chip') : ''}
                </div>
                <div class="details-footer-meta">warnings: ${warningsText}</div>
            </div>
        `;
    }).join('');
    const rawFilesBlock = rawPresent
        ? `
            <div class="details-compact-section details-compact-section--wide">
                <div class="details-compact-title">Raw Files</div>
                <div class="details-raw-file-list">
                    ${rawFilesHtml || '<div class="details-footer-meta">None</div>'}
                </div>
            </div>
            <div class="details-compact-section details-compact-section--wide">
                <div class="details-compact-title">Raw Warnings</div>
                <div class="details-warning-list">${rawWarningsHtml}</div>
            </div>
        `
        : '';

    const insightsSection = recommendation
        ? renderCrackingInsightsView(recommendation, d?.bssid || '', getAreaContextForMac(d?.bssid || ''))
        : '';

    return `
        <div class="details-view-scroll">
            <div class="details-card">
                <div class="details-card-head">
                    <div>
                        <div class="details-card-kicker">Fingerprint details</div>
                        <div class="details-card-title">${escapeHtml(d.ssid || 'SSID')}</div>
                    </div>
                    <div class="details-card-badges">
                        <span class="details-chip"><span>BSSID</span><b>${escapeHtml(d.bssid || '')}</b></span>
                    </div>
                </div>

                <div class="details-chip-row">${pills}</div>
            </div>

            <div class="details-compact-grid">
                <div class="details-compact-section details-compact-section--wide">
                    <div class="details-compact-title">Security profile</div>
                    <div class="details-compact-rows">
                        <div class="details-compact-label">WPS</div>
                        <div class="details-compact-value">${wpsSummary}</div>
                        <div class="details-compact-label">Class</div>
                        <div class="details-compact-value">
                            ${showClass
                                ? `<span style="padding:2px 8px; border:1px solid ${badgeColor}; color:${badgeColor}; border-radius:4px; text-transform:uppercase; letter-spacing:0.4px; font-size:0.68rem;">${escapeHtml(deviceLabel)} (${(cls.confidence || 0).toFixed(2)}${cls.tier ? ` | ${escapeHtml(cls.tier)}` : ''})</span>`
                                : '<span style="color:#888;">Insufficient evidence</span>'}
                        </div>
                    </div>
                    ${showClass ? `<div class="details-warning-list">${evidenceHtml.replace(/<li>/g, '<div>').replace(/<\/li>/g, '</div>')}</div>` : ''}
                </div>

                ${makeSection('Radio', radioRows)}
                ${makeSection('Rates', ratesRows)}
                ${makeSection('PHY', phyRows)}
                ${makeSection('Capabilities', capsRows)}
                ${makeSection('QBSS', qbssRows)}
                ${makeSection('Raw Sniffer', rawRows)}
                ${rawFilesBlock}
            </div>
            ${insightsSection}

            <div class="details-compact-section details-compact-section--wide">
                <div class="details-compact-title">Warnings</div>
                <div class="details-warning-list">${warningsHtml.replace(/<li>/g, '<div>').replace(/<\/li>/g, '</div>')}</div>
            </div>

            <div class="details-footer-meta">Source: ${escapeHtml(meta.source || '')} @ ${escapeHtml(meta.timestamp || '')}</div>
            ${meta.ssid_raw_hex ? `<div class="details-footer-meta">Original SSID hex: ${escapeHtml(meta.ssid_raw_hex)}</div>` : ''}
        </div>
    `;
}


async function startConversion() {
    const btn = document.getElementById('btn-convert-hash');
    const btnPcap = document.getElementById('btn-pcap-generate-hash');
    const ssid = document.getElementById('crack-ssid').innerText;
    
    const targetName = selectedFile.name.replace(/\.pcap$/i, '.22000');
    const isCracking = Object.values(activeProcesses).some(p => 
        p.details === targetName && 
        ['RUNNING', 'QUEUED', 'STARTING', 'AUTOTUNING', 'BUILDING CACHE', 'INIT KERNELS'].includes(p.status)
    );

    if (isCracking) {
        log(`Cannot convert: ${targetName} is currently being cracked. Stop the cracking job first.`, 'error');
        return;
    }

    if(btn) {
        btn.disabled = true;
        btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> CONVERTING...';
    }
    if(btnPcap) {
        btnPcap.disabled = true;
        btnPcap.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> BUSY...';
    }

    setLegacyCrackingProgress('Starting conversion job...', 'var(--text-main)', '10%', false);
    
    try {
        const res = await API.convertPcap(
            selectedFile.name,
            selectedFile.capture_id || null,
            selectedFile.raw_item_id || null
        );
        
        if (res.status === 'started') {
            log(`Conversion started for ${selectedFile.name}`, 'info');
            const mac = document.getElementById('crack-mac').innerText;
            addProcess(res.job_id, "GENERATE HASH (22000)", selectedFile.name, "STARTING", mac);
        } else {
            log(`Conversion failed to start: ${res.message}`, 'error');
            if(btn) {
                btn.disabled = false;
                btn.innerHTML = selectedFile?.type === 'raw_pcap'
                    ? '<i class="fa-solid fa-layer-group"></i> BUILD CANONICAL'
                    : '<i class="fa-solid fa-hashtag"></i> GENERATE HASH';
            }
            if(btnPcap) {
                btnPcap.disabled = false;
                btnPcap.innerHTML = '<i class="fa-solid fa-hashtag"></i> GENERATE HASH (22000)';
            }
            setLegacyCrackingProgress('FAILED TO START', 'var(--neon-red)', '0%', false);
        }
    } catch (e) {
        log(`API Error: ${e.message}`, 'error');
        if(btn) {
            btn.disabled = false;
            btn.innerHTML = selectedFile?.type === 'raw_pcap'
                ? '<i class="fa-solid fa-layer-group"></i> BUILD CANONICAL'
                : '<i class="fa-solid fa-hashtag"></i> GENERATE HASH';
        }
        if(btnPcap) {
            btnPcap.disabled = false;
            btnPcap.innerHTML = '<i class="fa-solid fa-hashtag"></i> GENERATE HASH (22000)';
        }
        setLegacyCrackingProgress('API ERROR', 'var(--neon-red)', null, false);
    }
}


async function startCracking() {
    const btn = document.getElementById('btn-convert-hash');
    const ssid = document.getElementById('crack-ssid').innerText;
    const mac = document.getElementById('crack-mac').innerText;
    
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> CRACKING...';
    setLegacyCrackingProgress('Starting Hashcat job...', 'var(--text-main)', '5%', false);
    
    try {
        let attackMode, workloadProfile, wordlist, ruleFile, customMask, isOptimized, isSlow, deviceId, enablePotfile, wordlist2;
        let maskFile = null, associationHint = null;
        let associationHints = null;
        let enableIncrement = false, incrementMin = null, incrementMax = null;

        attackMode = document.getElementById('custom-mode-select').value;
        workloadProfile = document.getElementById('custom-workload-slider').value;
        const ruleFilePrimary = document.getElementById('crack-rule-select').value;
        const ruleFileSecondary = document.getElementById('crack-rule-2-select')?.value;
        ruleFile = ruleFilePrimary;
        if (attackMode === 'passphrase') {
            ruleFile = `${ruleFilePrimary || ''};${ruleFileSecondary || ''}`;
        }
        maskFile = document.getElementById('crack-mask-profile-select')?.value || null;
        associationHint = document.getElementById('crack-association-hint-input')?.value?.trim() || null;
        associationHints = document.getElementById('crack-association-hints-input')?.value || null;
        if (attackMode !== 'association') {
            associationHint = null;
        }
        if (attackMode !== 'association_hint_first' && attackMode !== 'association_hint_rule') {
            associationHints = null;
        }
        customMask = document.getElementById('crack-mask-input').value;
        isOptimized = document.getElementById('flag-optimized').checked;
        isSlow = document.getElementById('flag-slow').checked;
        if (!isSlowCandidatesCompatible(attackMode)) {
            isSlow = false;
        }
        deviceId = document.getElementById('crack-device-select').value;
        // Potfile is now handled by backend config, but we keep the variable for consistency if needed
        enablePotfile = false; 
        wordlist2 = document.getElementById('crack-wordlist-2-select').value;
        
        enableIncrement = document.getElementById('flag-increment').checked;
        if (enableIncrement && incrementSlider) {
            const values = incrementSlider.get();
            incrementMin = Math.round(values[0]);
            incrementMax = Math.round(values[1]);

            // Auto-generate mask if empty to match slider max (Only for Brute-Force modes)
            const isAuto = document.getElementById('auto-mask-chk')?.checked;
            
            if (isAuto && (attackMode === 'mask' || attackMode === 'digits')) {
                const charSet = (attackMode === 'digits') ? '?d' : '?a';
                customMask = charSet.repeat(incrementMax);
            } else if (customMask) {
                // If mask is provided (Manual Mode), ensure incrementMax doesn't exceed mask length
                const maskLen = getMaskLength(customMask);
                if (maskLen > 0 && incrementMax > maskLen) {
                    incrementMax = maskLen;
                    if (incrementMin > incrementMax) incrementMin = incrementMax;
                }
            }
        }
        
        wordlist = document.getElementById('crack-wordlist-select').value;
        if (!wordlist) wordlist = null;
        if (!wordlist2) wordlist2 = null;

        const modeName = getModeRunLabel(attackMode);
        const label = `HASHCAT [${modeName} - W${workloadProfile || '3'}]`;

        log(`Starting cracking: Mode=${attackMode}, Workload=${workloadProfile}, Wordlist=${wordlist}`, 'info');

        if (modeRequiresWordlist(attackMode) && !wordlist) {
            log("Select a custom wordlist before starting this attack mode.", "error");
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-cat"></i> START CRACKING (HASHCAT)';
            setLegacyCrackingProgress('WORDLIST REQUIRED', 'var(--neon-red)', '0%', false);
            return;
        }

        if (modeRequiresSecondWordlist(attackMode) && !wordlist2) {
            log("Select a second wordlist before starting Combinator Passphrase mode.", "error");
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-cat"></i> START CRACKING (HASHCAT)';
            setLegacyCrackingProgress('SECOND WORDLIST REQUIRED', 'var(--neon-red)', '0%', false);
            return;
        }

        if (modeRequiresMaskProfile(attackMode) && !maskFile) {
            log("Select a .hcmask profile before starting this attack mode.", "error");
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-cat"></i> START CRACKING (HASHCAT)';
            setLegacyCrackingProgress('MASK PROFILE REQUIRED', 'var(--neon-red)', '0%', false);
            return;
        }

        if (modeRequiresAssociationHints(attackMode)) {
            const hasAtLeastOneHint = !!(associationHints && associationHints.split('\n').some(line => line.trim().length > 0));
            if (!hasAtLeastOneHint) {
                log("Add at least one association hint before starting Multi-Hints mode.", "error");
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-cat"></i> START CRACKING (HASHCAT)';
                setLegacyCrackingProgress('HINT REQUIRED', 'var(--neon-red)', '0%', false);
                return;
            }
        }

        const res = await API.startCracking(
            selectedFile.name,
            attackMode,
            workloadProfile,
            wordlist,
            ruleFile,
            customMask,
            isOptimized,
            isSlow,
            deviceId,
            enablePotfile,
            wordlist2,
            enableIncrement,
            incrementMin,
            incrementMax,
            maskFile,
            associationHint,
            associationHints,
            false,
            selectedFile.capture_id || null,
            selectedFile.combined_build_id || null,
            mac,
        );
        
        if (res.status === 'started') {
            log(`Cracking started for ${selectedFile.name}`, 'info');
            addProcess(res.job_id, label, selectedFile.name, "STARTING", mac);
            {
                let recommendationQuery = {
                    filename: selectedFile.name,
                    captureId: selectedFile.capture_id || null,
                    combinedBuildId: selectedFile.combined_build_id || null,
                };
                let sourceLabel = selectedFile.name;
                if (selectedFile.type === 'batch') {
                    const batchRecommendation = getBatchRecommendationRequest(selectedFile.name);
                    recommendationQuery = batchRecommendation.query;
                    sourceLabel = batchRecommendation.sourceLabel;
                }
                await loadAttackRecommendation(
                    recommendationQuery,
                    document.getElementById('crack-file-feedback'),
                    sourceLabel
                );
            }
        } else {
            log(`Cracking failed to start: ${res.message}`, 'error');
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-cat"></i> START CRACKING (HASHCAT)';
            setLegacyCrackingProgress('FAILED TO START', 'var(--neon-red)', '0%', false);
        }
    } catch (e) {
        log(`API Error: ${e.message}`, 'error');
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-cat"></i> START CRACKING (HASHCAT)';
        setLegacyCrackingProgress('API ERROR', 'var(--neon-red)', null, false);
    }
}

async function startAircrack() {
    const btn = document.getElementById('btn-quick-attack');
    const ssid = document.getElementById('crack-ssid').innerText;
    const mac = document.getElementById('crack-mac').innerText;
    const wordlist = document.getElementById('wordlist-select').value;
    if (!wordlist) {
        log("Select a custom wordlist before starting Aircrack-ng.", "error");
        setLegacyCrackingProgress('WORDLIST REQUIRED', 'var(--neon-red)', null, false);
        return;
    }
    
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> BUSY...';
    setLegacyCrackingProgress('Starting Aircrack-ng job...', 'var(--text-main)', '5%', false);
    
    try {
        const res = await API.startAircrack(
            selectedFile.name,
            mac,
            wordlist,
            selectedFile.capture_id || null,
            selectedFile.raw_item_id || null
        );
        
        if (res.status === 'started') {
            log(`Aircrack attack started for ${selectedFile.name}`, 'info');
            addProcess(res.job_id, "AIRCRACK-NG", selectedFile.name, "STARTING", mac);
        } else {
            log(`Aircrack failed to start: ${res.message}`, 'error');
            btn.disabled = false;
            btn.innerHTML = '<i class="fa-solid fa-wind"></i> QUICK ATTACK (AIRCRACK-NG)';
            setLegacyCrackingProgress('FAILED TO START', 'var(--neon-red)', '0%', false);
        }
    } catch (e) {
        log(`API Error: ${e.message}`, 'error');
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-wind"></i> QUICK ATTACK (AIRCRACK-NG)';
        setLegacyCrackingProgress('API ERROR', 'var(--neon-red)', null, false);
    }
}


export async function clearHistory() {
    if (!confirm("Are you sure you want to delete ALL history files (.try)? This cannot be undone.")) {
        return;
    }
    
    try {
        const res = await API.clearHistory();
        if (res && typeof res.deleted_count === 'number') {
            log(`History cleared. Deleted ${res.deleted_count} files.`, 'success');
            if (selectedFile && selectedFile.type === 'try') {
                const mac = document.getElementById('crack-mac').innerText;
                const ssid = document.getElementById('crack-ssid').innerText;
                openCrackingPanel(mac, ssid);
            }
        } else {
            log("Failed to clear history.", "error");
        }
    } catch (e) {
        log(`Error clearing history: ${e.message}`, "error");
    }
}

// ── PMK Database functions ──

async function refreshPmkDatabases() {
    const select = document.getElementById('pmk-db-select');
    if (!select) return;
    try {
        const dbs = await API.listPmkDatabases();
        select.innerHTML = '<option value="">-- select database --</option>';
        if (Array.isArray(dbs) && dbs.length) {
            dbs.forEach((db) => {
                const opt = document.createElement('option');
                opt.value = db.name;
                const sizeKb = Math.round((db.size_bytes || 0) / 1024);
                opt.textContent = `${db.name} (${sizeKb} KB)`;
                select.appendChild(opt);
            });
        }
    } catch (e) {
        log(`Failed to load PMK databases: ${e.message}`, 'error');
    }
}

async function startPmkBuild() {
    const essidInput = document.getElementById('pmk-essid-input');
    const wordlistSelect = document.getElementById('pmk-wordlist-select');
    const statusText = document.getElementById('pmk-status-text');
    const btn = document.getElementById('btn-pmk-build');

    const essid = (essidInput?.value || '').trim();
    if (!essid) {
        log('ESSID is required to build a PMK database.', 'error');
        return;
    }
    const wordlist = wordlistSelect?.value;
    if (!wordlist) {
        log('Select a wordlist to build the PMK database.', 'error');
        return;
    }

    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> BUILDING...';
    statusText.style.display = 'block';
    statusText.textContent = 'Starting PMK build...';

    try {
        const res = await API.buildPmkDatabase(essid, wordlist);
        if (res.status === 'started') {
            log(`PMK build started for ESSID="${essid}" → ${res.db_name}`, 'info');
            statusText.textContent = `Job ${res.job_id} started. DB: ${res.db_name}`;
            addProcess(res.job_id, 'AIROLIB-NG', res.db_name, 'STARTING',
                document.getElementById('crack-mac')?.innerText || '');
            await refreshPmkDatabases();
        } else {
            log(`PMK build failed: ${res.message}`, 'error');
            statusText.textContent = `Error: ${res.message}`;
        }
    } catch (e) {
        log(`PMK build error: ${e.message}`, 'error');
        statusText.textContent = `API Error: ${e.message}`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-database"></i> BUILD PMK DB';
    }
}

async function startPmkAttack() {
    if (!selectedFile) {
        log('Select a PCAP file first.', 'error');
        return;
    }
    const dbSelect = document.getElementById('pmk-db-select');
    const dbName = dbSelect?.value;
    if (!dbName) {
        log('Select a PMK database first.', 'error');
        return;
    }
    const mac = document.getElementById('crack-mac')?.innerText || '';
    const btn = document.getElementById('btn-pmk-attack');
    const statusText = document.getElementById('pmk-status-text');

    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ATTACKING...';
    statusText.style.display = 'block';
    statusText.textContent = 'Starting PMK attack...';

    try {
        const res = await API.startPmkAttack(
            selectedFile.name,
            mac,
            dbName,
            selectedFile.capture_id || null,
            selectedFile.raw_item_id || null
        );
        if (res.status === 'started') {
            log(`PMK attack started using ${dbName}`, 'info');
            statusText.textContent = `Job ${res.job_id} started.`;
            addProcess(res.job_id, 'AIRCRACK-NG (PMK)', selectedFile.name, 'STARTING', mac);
        } else {
            log(`PMK attack failed: ${res.message}`, 'error');
            statusText.textContent = `Error: ${res.message}`;
        }
    } catch (e) {
        log(`PMK attack error: ${e.message}`, 'error');
        statusText.textContent = `API Error: ${e.message}`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-bolt"></i> PMK ATTACK';
    }
}

async function startWpsAttack() {
    const bssid = document.getElementById('crack-mac')?.innerText || '';
    const iface = document.getElementById('wps-iface-input')?.value?.trim() || '';
    const channel = document.getElementById('wps-channel-input')?.value?.trim() || '';
    const tool = document.getElementById('wps-tool-select')?.value || 'reaver';
    const pixieDust = document.getElementById('wps-pixie-dust')?.checked || false;
    const delayVal = document.getElementById('wps-delay-input')?.value;
    const delay = delayVal !== '' && delayVal !== undefined ? parseInt(delayVal, 10) : null;

    if (!bssid) {
        log('Select a target with a BSSID first.', 'error');
        return;
    }
    if (!iface) {
        log('Enter a monitor-mode interface (e.g. wlan0mon).', 'error');
        return;
    }
    if (!channel) {
        log('Enter the target channel.', 'error');
        return;
    }

    const btn = document.getElementById('btn-wps-attack');
    const statusText = document.getElementById('wps-status-text');

    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> ATTACKING...';
    statusText.style.display = 'block';
    statusText.textContent = `Starting WPS attack (${tool})...`;

    try {
        const res = await API.startWpsAttack(bssid, channel, iface, tool, pixieDust, delay);
        if (res.status === 'started') {
            log(`WPS attack started with ${tool} on ${bssid}`, 'info');
            statusText.textContent = `Job ${res.job_id} started.`;
            addProcess(res.job_id, `WPS (${tool.toUpperCase()})`, `WPS_${bssid}`, 'STARTING', bssid);
        } else {
            log(`WPS attack failed: ${res.message}`, 'error');
            statusText.textContent = `Error: ${res.message}`;
        }
    } catch (e) {
        log(`WPS attack error: ${e.message}`, 'error');
        statusText.textContent = `API Error: ${e.message}`;
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-wifi"></i> WPS ATTACK';
    }
}

export const __testUiCrackingHelpers = {
    escapeMaybe,
    isAssociationMode,
    isRawHashFilename,
    getFileStem,
    filterFilesForRawHashScope,
    isValidMac,
    normalizeRawContextPayload,
    formatRawProcessedAt,
    renderRawContextSummary,
    resolveCanonicalHashFromResult,
    setRawPrepareAllButtonState,
};

// Test-only hooks to exercise branch-heavy internal paths.
export const __test = {
    updateWordlistVisibility,
    applySlowCandidatesPolicy,
    loadCrackingDefaults,
    loadCrackingResources,
    selectFile,
    startConversion,
    startCracking,
    runAssociationPreview,
    startAircrack,
    startFingerprint,
    handleCrackAction,
    handleAircrackAction,
    renderDetailsView,
    refreshPmkDatabases,
    startPmkBuild,
    startPmkAttack,
    startWpsAttack,
    setSelectedFile: (file) => { selectedFile = file; },
    getSelectedFile: () => selectedFile,
    setCurrentFiles: (files) => { currentFiles = files || []; },
    setIncrementSlider: (slider) => { incrementSlider = slider; }
};
