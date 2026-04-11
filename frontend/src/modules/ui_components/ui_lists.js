import { STATE } from '../state.js';
import { escapeHtml } from '../utils.js';
import { toggleTarget, toggleFav, focusAndOpenPopup, getMapInstance } from '../map.js';
import { getHudAutoPanPadding } from '../layout.js';
import { openCrackingPanel } from './ui_cracking.js';
import { activeProcesses } from './ui_processes.js';
import { uiConfig } from './ui_settings.js';
import { getSourceTokens, getSourceBadges, matchesSourceFilter } from '../source_tags.js';

function processDetailsToSearchText(details) {
    if (details === null || details === undefined) return '';
    if (typeof details === 'string') return details.toLowerCase();
    if (Array.isArray(details)) {
        return details.map((item) => processDetailsToSearchText(item)).join(' ').toLowerCase();
    }
    try {
        return JSON.stringify(details).toLowerCase();
    } catch (_e) {
        return String(details).toLowerCase();
    }
}

export function updateTargetsList() {
    const list = document.getElementById('targets-list');
    document.getElementById('target-count').innerText = STATE.lists.targets.length;

    const currentItems = Array.from(list.children);
    currentItems.forEach(item => {
        const mac = item.getAttribute('data-mac');
        if (!STATE.lists.targets.includes(mac)) {
            item.remove();
        }
    });

    STATE.lists.targets.forEach(mac => {
        let pos = null;
        Object.values(STATE.allPositions).forEach(p => { if (p.mac === mac) pos = p; });
        
        if (pos) {
            let statusBadge = '';
            const activeJobEntry = Object.entries(activeProcesses).find(([id, p]) => {
                if (!p.details) return false;
                
                const details = processDetailsToSearchText(p.details);
                const ssid = (pos.ssid || '').toLowerCase();
                const macClean = pos.mac.replace(/:/g, '').toLowerCase();
                
                if (details.includes(macClean)) return true;
                if (ssid && ssid.length > 1 && details.includes(ssid)) return true;
                
                return false;
            });

            if (activeJobEntry) {
                const job = activeJobEntry[1];
                let badgeClass = 't-running';
                let statusText = job.status;

                if (['QUEUED', 'PENDING'].includes(job.status)) {
                    badgeClass = 't-queued';
                } else if (['COMPLETED', 'CRACKED', 'SUCCESS'].includes(job.status)) {
                    badgeClass = 't-success';
                    statusText = job.status === 'CRACKED' ? 'CRACKED' : 'SUCCESS';
                } else if (['FAILED', 'ERROR', 'EXHAUSTED'].includes(job.status)) {
                    badgeClass = 't-failed';
                    statusText = job.status === 'EXHAUSTED' ? 'NOT FOUND' : 'FAILED';
                }

                statusBadge = `<span class="target-status ${badgeClass}">${escapeHtml(statusText)}</span>`;
            }

            let item = list.querySelector(`.list-item[data-mac="${mac}"]`);
            const title = escapeHtml(pos.ssid || 'HIDDEN');
            const meta = escapeHtml(pos.mac);
            
            if (item) {
                item.className = 'list-item left-panel-card left-panel-card--target';
                const nameEl = item.querySelector('.item-name');
                if (nameEl) {
                    const newContent = `${title} ${statusBadge}`;
                    if (nameEl.innerHTML.trim() !== newContent.trim()) {
                        nameEl.innerHTML = newContent;
                    }
                }
                const metaEl = item.querySelector('.item-meta');
                if (metaEl && metaEl.textContent !== meta) {
                    metaEl.textContent = meta;
                }
            } else {
                item = document.createElement('div');
                item.className = 'list-item left-panel-card left-panel-card--target';
                item.setAttribute('data-mac', mac);
                item.innerHTML = `
                    <div class="left-panel-card__copy">
                        <div class="item-name">
                            ${title}
                            ${statusBadge}
                        </div>
                        <div class="item-meta">${meta}</div>
                    </div>
                    <i class="fa-solid fa-trash target-remove list-item-action" aria-hidden="true"></i>
                `;
                
                item.addEventListener('click', (e) => {
                    if (e.target.classList.contains('target-remove')) {
                        toggleTarget(mac);
                    } else {
                        focusAndOpenPopup(pos.mac);
                        openCrackingPanel(pos.mac, pos.ssid);
                    }
                });

                list.appendChild(item);
            }
        }
    });
}

export function updateFavsList() {
    const list = document.getElementById('favs-list');
    document.getElementById('fav-count').innerText = STATE.lists.favs.length;

    const currentItems = Array.from(list.children);
    currentItems.forEach(item => {
        const mac = item.getAttribute('data-mac');
        if (!STATE.lists.favs.includes(mac)) {
            item.remove();
        }
    });

    STATE.lists.favs.forEach(mac => {
        let pos = null;
        Object.values(STATE.allPositions).forEach(p => { if (p.mac === mac) pos = p; });
        
        if (pos) {
            let item = list.querySelector(`.list-item[data-mac="${mac}"]`);
            const title = escapeHtml(pos.ssid || 'HIDDEN');
            const meta = escapeHtml(pos.mac);
            
            if (!item) {
                item = document.createElement('div');
                item.className = 'list-item left-panel-card left-panel-card--favorite';
                item.setAttribute('data-mac', mac);
                item.innerHTML = `
                    <div class="left-panel-card__copy">
                        <div class="item-name">${title}</div>
                        <div class="item-meta">${meta}</div>
                    </div>
                    <i class="fa-solid fa-trash fav-remove list-item-action" aria-hidden="true"></i>
                `;
                
                item.addEventListener('click', (e) => {
                    if (e.target.classList.contains('fav-remove')) {
                        toggleFav(mac);
                    } else {
                        focusAndOpenPopup(pos.mac);
                    }
                });

                list.appendChild(item);
            } else {
                item.className = 'list-item left-panel-card left-panel-card--favorite';
                const nameEl = item.querySelector('.item-name');
                if (nameEl && nameEl.textContent !== title) {
                    nameEl.textContent = title;
                }
                const metaEl = item.querySelector('.item-meta');
                if (metaEl && metaEl.textContent !== meta) {
                    metaEl.textContent = meta;
                }
            }
        }
    });
}

function normalizeZones(clusters = []) {
    const normalized = [];
    clusters.forEach((c, idx) => {
        if (Array.isArray(c)) {
            normalized.push({ id: idx, count: c.length, points: c });
            return;
        }
        if (c && Array.isArray(c.parts) && c.parts.length > 1) {
            c.parts.forEach((part, pidx) => {
                normalized.push({
                    id: (c.id || idx) * 100 + pidx,
                    count: c.count,
                    parts: [part]
                });
            });
            return;
        }
        normalized.push(c);
    });
    return normalized;
}

function focusZone(cluster, hasPoints, hasParts) {
    const map = getMapInstance();
    if (!map) return;

    let sourcePoints = [];
    if (cluster.hull && cluster.hull.length >= 3) {
        sourcePoints = cluster.hull;
    } else if (hasPoints) {
        sourcePoints = cluster.points;
    } else if (hasParts) {
        cluster.parts.forEach(part => {
            if (Array.isArray(part)) sourcePoints.push(...part);
        });
    }
    if (sourcePoints.length === 0) return;
    const bounds = L.latLngBounds(sourcePoints.map(p => [p.lat, p.lng]));
    const panPadding = getHudAutoPanPadding();
    map.fitBounds(bounds, {
        paddingTopLeft: panPadding.topLeft,
        paddingBottomRight: panPadding.bottomRight,
        animate: true
    });
}

function renderZoneSection({
    clusters = [],
    listId,
    labelPrefix,
    counterId,
    dividerId = null,
}) {
    const zonesList = document.getElementById(listId);
    if (!zonesList) return 0;
    zonesList.innerHTML = '';
    let zoneCount = 0;

    const normalized = normalizeZones(clusters);

    normalized.forEach((cluster, idx) => {
        if (!cluster) return;
        const hasPoints = Array.isArray(cluster.points) && cluster.points.length > 0;
        const hasParts = Array.isArray(cluster.parts) && cluster.parts.length > 0;
        if (!hasPoints && !hasParts) return;
        zoneCount++;
        const zoneName = cluster.zoneLabel || `${labelPrefix}-${String(idx + 1).padStart(3, '0')}`;
        const countVal = cluster.count || (hasPoints ? cluster.points.length : 0);
        const item = document.createElement('div');
        item.className = 'list-item left-panel-card left-panel-card--zone';
        item.innerHTML = `
            <div class="left-panel-card__copy">
                <div class="item-name">${escapeHtml(zoneName)}</div>
                <div class="item-meta zone-count">${countVal} APs</div>
            </div>
            <div class="zone-count-pill" aria-hidden="true">${countVal}</div>
        `;
        
        item.addEventListener('click', () => {
            focusZone(cluster, hasPoints, hasParts);
        });

        zonesList.appendChild(item);
    });

    if (counterId) {
        const counter = document.getElementById(counterId);
        if (counter) counter.innerText = zoneCount;
    }
    if (dividerId) {
        const divider = document.getElementById(dividerId);
        if (divider) divider.style.display = zoneCount > 0 ? 'flex' : 'none';
    }

    return zoneCount;
}

export function updateZonesList(clusters) {
    renderZoneSection({
        clusters,
        listId: 'conquered-zones-section',
        labelPrefix: 'ZONE',
        counterId: 'conquered-zone-count',
        dividerId: 'conquered-zones-divider'
    });
}

export function updateToConquerZonesList(clusters) {
    renderZoneSection({
        clusters,
        listId: 'to-conquer-zones-section',
        labelPrefix: 'LOCKED',
        counterId: 'to-conquer-zone-count',
        dividerId: 'to-conquer-zones-divider'
    });
}

export function updateDiscoveredZonesList(clusters) {
    renderZoneSection({
        clusters,
        listId: 'discovered-zones-section',
        labelPrefix: 'DISC',
        counterId: 'discovered-zone-count',
        dividerId: 'discovered-zones-divider'
    });
}

export function updateIntelligenceZonesList(clusters) {
    renderZoneSection({
        clusters,
        listId: 'intelligence-zones-section',
        labelPrefix: 'INTEL',
        counterId: 'intelligence-zone-count',
        dividerId: 'intelligence-zones-divider'
    });
}

function getNoGpsUiState() {
    if (!STATE.noGpsUi || typeof STATE.noGpsUi !== 'object') {
        STATE.noGpsUi = {
            search: '',
            device: 'all',
            status: 'all',
            visibility: 'all',
            artifact: 'all'
        };
    }
    const defaults = {
        search: '',
        device: 'all',
        status: 'all',
        visibility: 'all',
        artifact: 'all'
    };
    Object.keys(defaults).forEach((key) => {
        if (STATE.noGpsUi[key] === undefined || STATE.noGpsUi[key] === null) {
            STATE.noGpsUi[key] = defaults[key];
        }
    });
    return STATE.noGpsUi;
}

function syncNoGpsFilterControls(noGpsUi) {
    const searchInput = document.getElementById('no-gps-filter-search');
    const deviceSelect = document.getElementById('no-gps-filter-device');
    const statusSelect = document.getElementById('no-gps-filter-status');
    const visibilitySelect = document.getElementById('no-gps-filter-visibility');
    const artifactSelect = document.getElementById('no-gps-filter-artifact');

    if (searchInput && searchInput.value !== String(noGpsUi.search || '')) {
        searchInput.value = String(noGpsUi.search || '');
    }
    if (deviceSelect && deviceSelect.value !== String(noGpsUi.device || 'all')) {
        deviceSelect.value = String(noGpsUi.device || 'all');
    }
    if (statusSelect && statusSelect.value !== String(noGpsUi.status || 'all')) {
        statusSelect.value = String(noGpsUi.status || 'all');
    }
    if (visibilitySelect && visibilitySelect.value !== String(noGpsUi.visibility || 'all')) {
        visibilitySelect.value = String(noGpsUi.visibility || 'all');
    }
    if (artifactSelect && artifactSelect.value !== String(noGpsUi.artifact || 'all')) {
        artifactSelect.value = String(noGpsUi.artifact || 'all');
    }
}

export function updateNoGpsList() {
    const listPwned = document.getElementById('no-gps-list-pwned');
    const listLocked = document.getElementById('no-gps-list-locked');
    const countInfo = document.getElementById('no-gps-filter-count');
    const noGpsUi = getNoGpsUiState();
    
    if (!listPwned || !listLocked) return;
    syncNoGpsFilterControls(noGpsUi);
    
    listPwned.innerHTML = '';
    listLocked.innerHTML = '';
    
    const noGpsItems = Object.values(STATE.allPositions).filter(pos => pos.type === 'no-gps');
    const searchTerms = [STATE.filters.search, noGpsUi.search]
        .map((value) => String(value || '').trim().toLowerCase())
        .filter(Boolean);
    
    const filteredItems = noGpsItems.filter(pos => {
        const ssid = String(pos.ssid || '');
        const isHidden = !ssid.trim();
        const files = Array.isArray(pos.handshake_files) ? pos.handshake_files : [];
        const hasPcap = hasArtifact(files, '.pcap');
        const has22000 = hasArtifact(files, '.22000');
        const sourceTokens = getSourceTokensForPos(pos);
        const isCracked = !!pos.pass;
        const isOpenLike = isOpenLikeEncryption(pos.encryption);
        const status = isCracked ? 'cracked' : (isOpenLike ? 'open' : 'locked');

        if ((noGpsUi.status || 'all') !== 'all' && status !== noGpsUi.status) {
            return false;
        }

        const visibilityFilter = noGpsUi.visibility || 'all';
        if (visibilityFilter === 'hidden' && !isHidden) {
            return false;
        }
        if (visibilityFilter === 'named' && isHidden) {
            return false;
        }

        const deviceFilter = noGpsUi.device || 'all';
        if (deviceFilter === 'unknown') {
            if (sourceTokens.length > 0) {
                return false;
            }
        } else if (!matchesSourceFilter(pos.sources, deviceFilter)) {
            return false;
        }

        const artifactFilter = noGpsUi.artifact || 'all';
        if (artifactFilter === 'has_pcap' && !hasPcap) {
            return false;
        }
        if (artifactFilter === 'has_22000' && !has22000) {
            return false;
        }
        if (artifactFilter === 'no_artifacts' && (hasPcap || has22000)) {
            return false;
        }

        const normalizedMac = String(pos.mac || '').replace(/[:-]/g, '').toLowerCase();
        const searchable = [
            ssid,
            pos.mac,
            normalizedMac,
            String(pos.encryption || ''),
            sourceTokens.join(' '),
            status,
            isHidden ? 'hidden' : 'named'
        ].join(' ').toLowerCase();

        return searchTerms.every((term) => searchable.includes(term));
    });

    if (countInfo) {
        countInfo.innerText = `${filteredItems.length}/${noGpsItems.length}`;
    }

    if (filteredItems.length === 0) {
        const emptyMsg = '<div style="padding: 20px; text-align: center; color: #666; font-style: italic; font-size: 0.8em;">NO ITEMS</div>';
        listPwned.innerHTML = emptyMsg;
        listLocked.innerHTML = emptyMsg;
        return;
    }

    filteredItems.forEach(pos => {
        const item = document.createElement('div');
        item.className = 'list-item';
        item.style.padding = '12px 8px';
        item.style.fontSize = '0.9em';
        
        let iconClass = 'fa-shield-halved';
        let colorClass = 'icon-locked';
        
        if (pos.pass) {
            iconClass = uiConfig.iconPwned || 'fa-skull'; 
            colorClass = 'icon-cracked';
        } else if (!pos.ssid) {
            iconClass = 'fa-ghost';
            colorClass = 'icon-hidden';
        } else if (pos.encryption === 'OPEN' || pos.encryption === 'WEP') {
            iconClass = uiConfig.iconOpen || 'fa-bolt';
            colorClass = 'icon-open';
        } else {
            iconClass = uiConfig.iconLocked || 'fa-shield-halved'; 
        }

        let fileTags = '';
        if (!pos.pass) { 
            if (pos.handshake_files && pos.handshake_files.length > 0) {
                const hasPcap = pos.handshake_files.some(f => f.endsWith('.pcap'));
                const has22000 = pos.handshake_files.some(f => f.endsWith('.22000'));
                if (hasPcap) fileTags += `<span class="file-type-tag badge-pcap" style="font-size: 0.6em; padding: 1px 3px;">PCAP</span>`;
                if (has22000) fileTags += `<span class="file-type-tag badge-hash" style="font-size: 0.6em; padding: 1px 3px;">22000</span>`;
            }
        }

        const sourceBadges = getSourceBadges(pos.sources);
        const deviceTags = sourceBadges.length > 0
            ? sourceBadges.slice(0, 2).map(b => `<span class="file-type-tag no-gps-source-tag ${escapeHtml(b.className)}" title="${escapeHtml(b.label)}" style="font-size: 0.56rem; padding: 1px 6px;">${escapeHtml(b.label)}</span>`).join('')
            : '<span class="file-type-tag no-gps-source-tag" title="UNKNOWN" style="font-size: 0.56rem; padding: 1px 6px; color: #7a8b92;">UNKNOWN</span>';
        const hiddenTag = !String(pos.ssid || '').trim()
            ? '<span class="file-type-tag no-gps-source-tag" title="HIDDEN" style="font-size: 0.56rem; padding: 1px 6px; color: var(--neon-purple);">HIDDEN</span>'
            : '';

        item.innerHTML = `
            <div style="display: flex; align-items: center; width: 100%; gap: 8px; position: relative;">
                <div class="no-gps-icon ${colorClass}" style="width: 32px; height: 32px; font-size: 14px; display: flex; align-items: center; justify-content: center; flex-shrink: 0;">
                    <i class="fa-solid ${iconClass}"></i>
                </div>
                <div style="flex: 1; overflow: hidden; padding-right: 50px;">
                    <div class="no-gps-ssid" style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(pos.ssid || 'HIDDEN')}</div>
                    <div class="no-gps-mac" style="font-size: 0.7em;">${escapeHtml(pos.mac)}</div>
                    <div class="no-gps-tag-row" style="display:flex; gap:4px; margin-top:3px; flex-wrap:wrap;">
                        ${deviceTags}
                        ${hiddenTag}
                    </div>
                </div>
                ${pos.pass ? '<i class="fa-solid fa-key" style="color: var(--neon-green); font-size: 1em; position: absolute; right: 8px; top: 50%; transform: translateY(-50%);"></i>' : 
                  `<div style="position: absolute; right: 8px; top: 50%; transform: translateY(-50%); display: flex; flex-direction: column; align-items: flex-end; gap: 2px;">${fileTags}</div>`}
            </div>
        `;
        
        item.addEventListener('click', () => {
            openCrackingPanel(pos.mac, pos.ssid);
        });

        if (pos.pass) {
            listPwned.appendChild(item);
        } else {
            listLocked.appendChild(item);
        }
    });
    
    if (listPwned.children.length === 0) {
        listPwned.innerHTML = '<div style="padding: 20px; text-align: center; color: #444; font-style: italic; font-size: 0.8em;">NO CRACKED</div>';
    }
    if (listLocked.children.length === 0) {
        listLocked.innerHTML = '<div style="padding: 20px; text-align: center; color: #444; font-style: italic; font-size: 0.8em;">NO LOCKED</div>';
    }
}

function getMultiUiState() {
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

    if (STATE.multiFilter === 'all' || STATE.multiFilter === 'locked') {
        STATE.multiUi.status = STATE.multiFilter;
    } else {
        STATE.multiFilter = STATE.multiUi.status || 'all';
    }

    return STATE.multiUi;
}

function normalizeEncryption(value) {
    const text = String(value || '').trim().toUpperCase();
    return text || 'UNK';
}

function isOpenLikeEncryption(value) {
    const enc = normalizeEncryption(value);
    return enc.includes('OPEN') || enc.includes('WEP') || enc.includes('OPN') || enc === 'NONE';
}

function hasArtifact(files, extension) {
    return (files || []).some((file) => String(file || '').toLowerCase().endsWith(extension));
}

function getSourceTokensForPos(pos) {
    return getSourceTokens(pos?.sources);
}

export function updateMultiList() {
    const list = document.getElementById('multi-all-list');
    const selectedCountEl = document.getElementById('multi-selected-count');
    const visibleCountEl = document.getElementById('multi-visible-count');
    const eligibleCountEl = document.getElementById('multi-eligible-count');
    const excludedOpenCountEl = document.getElementById('multi-excluded-open-count');
    if (!list) return;

    const multiUi = getMultiUiState();

    const items = Object.values(STATE.allPositions || {});
    const sorted = items.sort((a, b) => {
        const aName = (a.ssid || 'HIDDEN').toLowerCase();
        const bName = (b.ssid || 'HIDDEN').toLowerCase();
        return aName.localeCompare(bName);
    });

    const normalized = sorted.map((pos) => {
        const files = Array.isArray(pos?.handshake_files) ? pos.handshake_files : [];
        const hasPcap = hasArtifact(files, '.pcap');
        const has22000 = hasArtifact(files, '.22000');
        const encryption = normalizeEncryption(pos?.encryption);
        const sourceTokens = getSourceTokensForPos(pos);
        const sourceLabel = sourceTokens.length > 0 ? sourceTokens.join('+') : 'UNK';
        const ssidValue = String(pos?.ssid || '');
        const isHidden = !ssidValue.trim();
        const location = String(pos?.type || '').toLowerCase() === 'no-gps' ? 'no-gps' : 'gps';
        const searchBlob = [
            ssidValue,
            pos?.mac,
            encryption,
            sourceLabel,
            location,
            hasPcap ? 'pcap' : '',
            has22000 ? '22000' : '',
        ].join(' ').toLowerCase();

        return {
            pos,
            mac: pos?.mac,
            hasPcap,
            has22000,
            encryption,
            sourceTokens,
            sourceLabel,
            isHidden,
            location,
            searchBlob,
            isOpenLike: isOpenLikeEncryption(encryption),
        };
    });

    const excludedOpen = normalized.filter((item) => item.isOpenLike).length;
    const eligible = normalized.filter((item) => !item.isOpenLike);

    const validSelectionMacs = new Set(eligible.map((item) => item.mac).filter(Boolean));
    STATE.multiSelection = (STATE.multiSelection || []).filter((mac) => validSelectionMacs.has(mac));
    const selection = new Set(STATE.multiSelection || []);

    const filtered = eligible.filter((item) => {
        if ((multiUi.status || 'all') === 'locked' && item.pos?.pass) {
            return false;
        }

        if ((multiUi.location || 'all') !== 'all' && item.location !== multiUi.location) {
            return false;
        }

        if (!matchesSourceFilter(item.pos?.sources, multiUi.source || 'all')) {
            return false;
        }

        const artifactFilter = multiUi.artifact || 'all';
        if (artifactFilter === 'has_pcap' && !item.hasPcap) {
            return false;
        }
        if (artifactFilter === 'has_22000' && !item.has22000) {
            return false;
        }
        if (artifactFilter === 'no_22000' && item.has22000) {
            return false;
        }

        const search = (multiUi.search || '').trim().toLowerCase();
        if (search && !item.searchBlob.includes(search)) {
            return false;
        }

        return true;
    });

    list.innerHTML = '';

    filtered.forEach((item) => {
        const pos = item.pos;
        const mac = item.mac;
        const isSelected = selection.has(mac);

        const row = document.createElement('div');
        row.className = 'list-item';
        row.style.display = 'flex';
        row.style.alignItems = 'center';
        row.style.justifyContent = 'space-between';
        row.style.gap = '8px';

        const stateClass = pos.pass ? 'multi-item-pwned' : 'multi-item-locked';
        row.classList.add(stateClass);

        const locationLabel = item.location === 'no-gps' ? 'NO-GPS' : 'GPS';
        const sourceLabel = item.sourceLabel || 'UNK';
        const hiddenTag = item.isHidden
            ? '<span class="multi-tag multi-tag-hidden">HIDDEN</span>'
            : '';
        const pcapTag = item.hasPcap
            ? '<span class="multi-tag multi-tag-artifact">PCAP</span>'
            : '';
        const hashTag = item.has22000
            ? '<span class="multi-tag multi-tag-artifact">22000</span>'
            : '';

        row.innerHTML = `
            <div class="multi-row-main">
                <input type="checkbox" class="multi-select-chk" data-mac="${escapeHtml(mac)}" ${isSelected ? 'checked' : ''} ${item.hasPcap ? '' : 'disabled'}>
                <div style="overflow:hidden;">
                    <div class="item-name" style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">
                        ${escapeHtml(pos.ssid || 'HIDDEN')}
                    </div>
                    <div class="item-meta" style="font-size:0.7em; color:#777;">${escapeHtml(mac)}</div>
                    <div class="multi-tags">
                        <span class="multi-tag multi-tag-location">${locationLabel}</span>
                        <span class="multi-tag multi-tag-security">SEC:${escapeHtml(item.encryption)}</span>
                        <span class="multi-tag multi-tag-source">SRC:${escapeHtml(sourceLabel)}</span>
                        ${pcapTag}
                        ${hashTag}
                        ${hiddenTag}
                    </div>
                </div>
            </div>
        `;

        list.appendChild(row);
    });

    if (filtered.length === 0) {
        const empty = document.createElement('div');
        empty.style.padding = '10px';
        empty.style.color = '#666';
        empty.style.fontStyle = 'italic';
        empty.textContent = eligible.length === 0
            ? 'NO ELIGIBLE NETWORKS (OPEN/WEP HIDDEN)'
            : 'NO NETWORKS MATCH CURRENT FILTERS';
        list.appendChild(empty);
    }

    if (selectedCountEl) selectedCountEl.innerText = String((STATE.multiSelection || []).length);
    if (visibleCountEl) visibleCountEl.innerText = `V ${filtered.length}`;
    if (eligibleCountEl) eligibleCountEl.innerText = `E ${eligible.length}`;
    if (excludedOpenCountEl) excludedOpenCountEl.innerText = `X ${excludedOpen}`;
}

export function updateMultiFilesList() {
    const list = document.getElementById('multi-files-list');
    if (!list) return;
    const files = STATE.multiFiles || [];
    list.innerHTML = '';

    if (files.length === 0) {
        list.innerHTML = '<div style="padding: 10px; color:#666; font-style: italic;">NO MULTI FILES</div>';
        return;
    }

    files.forEach(file => {
        const item = document.createElement('div');
        item.className = 'list-item';
        item.style.display = 'flex';
        item.style.alignItems = 'center';
        item.style.justifyContent = 'space-between';
        item.style.gap = '8px';
        item.setAttribute('data-name', file.name);

        const isSelected = STATE.multiSelectedFile === file.name;
        if (isSelected) item.classList.add('selected');

        const sizeKb = (file.size / 1024).toFixed(1);
        const countText = (file.count !== null && file.count !== undefined) ? `${file.count} items` : '';

        item.innerHTML = `
            <div style="display:flex; align-items:center; gap:8px; overflow:hidden;">
                <i class="fa-solid fa-layer-group"></i>
                <div style="overflow:hidden;">
                    <div class="item-name" style="white-space:nowrap; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(file.name)}</div>
                    <div class="item-meta" style="font-size:0.7em; color:#777;">${sizeKb} KB ${countText ? `| ${countText}` : ''}</div>
                </div>
            </div>
            <div style="display:flex; align-items:center; gap:8px;">
                <i class="fa-solid fa-trash multi-delete" data-name="${escapeHtml(file.name)}" title="Delete Multi"></i>
            </div>
        `;

        list.appendChild(item);
    });
}

export function updateMultiContentsList() {
    const list = document.getElementById('multi-contents-list');
    if (!list) return;
    const items = STATE.multiFileContents?.[STATE.multiSelectedFile] || [];
    const sortedItems = [...items].sort((a, b) => {
        const aCracked = !!a.cracked;
        const bCracked = !!b.cracked;
        if (aCracked === bCracked) return 0;
        return aCracked ? -1 : 1;
    });
    list.innerHTML = '';

    if (!STATE.multiSelectedFile) {
        list.innerHTML = '<div style="padding: 10px; color:#666; font-style: italic;">SELECT A MULTI FILE</div>';
        return;
    }
    if (items.length === 0) {
        list.innerHTML = '<div style="padding: 10px; color:#666; font-style: italic;">NO CONTENTS</div>';
        return;
    }

    sortedItems.forEach(item => {
        const row = document.createElement('div');
        row.className = 'list-item';
        if (item.cracked) {
            row.classList.add('batch-item-cracked');
        }
        const status = item.status || '';
        let reasonText = item.reason || '';
        if (!reasonText && status === 'OK') {
            reasonText = 'HANDSHAKE OK';
        } else if (!reasonText && status === 'FAILED') {
            reasonText = 'CONVERSION FAILED';
        }
        let reasonClass = '';
        if (reasonText === 'HANDSHAKE OK') {
            reasonClass = 'batch-reason-ok';
        } else if (reasonText === 'EAPOL MISSING/INVALID' || reasonText === 'EMPTY OUTPUT') {
            reasonClass = 'batch-reason-failed';
        }
        const label = item.ssid ? `${item.ssid}` : (item.filename || 'UNKNOWN');
        const mac = item.mac ? item.mac.toUpperCase() : '';
        row.innerHTML = `
            <div style="display:flex; align-items:center; justify-content:space-between; gap:8px; width:100%;">
                <div style="min-width:0;">
                    <div class="item-name">${escapeHtml(label)}</div>
                    ${mac ? `<div class="item-meta" style="font-size:0.7em; color:#777;">${escapeHtml(mac)}</div>` : ''}
                </div>
                ${reasonText ? `<div class="${reasonClass}" style="display:flex; align-items:center; justify-content:flex-end; min-width:120px; margin-left:auto; font-size:0.7em; color:#888;">${escapeHtml(reasonText)}</div>` : ''}
            </div>
        `;
        list.appendChild(row);
    });
}
