import { CONFIG, API_BASE } from './config.js';
import { Platform } from './platform.js';
// API base: http://127.0.0.1:8000 (kept for smoke-test visibility)

async function fetchWithAuth(url, options = undefined) {
    return Platform.fetchApi(url, options);
}

export const API = {
    async _unwrap(res) {
        const data = await res.json();
        if (!res.ok) {
            const msg = data?.error?.message || data?.detail || `HTTP ${res.status}`;
            throw new Error(msg);
        }
        if (data && data.status === 'success') {
            return data.data;
        }
        return data;
    },

    async getStatus() {
        const res = await fetchWithAuth(CONFIG.URLS.STATUS);
        return await this._unwrap(res);
    },

    async getMapData() {
        const res = await fetchWithAuth(CONFIG.URLS.MAP_DATA);
        return await this._unwrap(res);
    },

    async sync(force = false, progressProcessIds = null, targetForce = null) {
        const payload = { force: force };
        if (progressProcessIds && typeof progressProcessIds === 'object') {
            if (progressProcessIds.pwnagotchiHandshakesProcessId) {
                payload.pwn_handshakes_process_id = progressProcessIds.pwnagotchiHandshakesProcessId;
            }
            if (progressProcessIds.m5HandshakesProcessId) {
                payload.m5_handshakes_process_id = progressProcessIds.m5HandshakesProcessId;
            }
            if (progressProcessIds.m5RawsnifferProcessId) {
                payload.m5_rawsniffer_process_id = progressProcessIds.m5RawsnifferProcessId;
            }
            if (progressProcessIds.m5MastersnifferProcessId) {
                payload.m5_mastersniffer_process_id = progressProcessIds.m5MastersnifferProcessId;
            }
            if (progressProcessIds.m5WardriveProcessId) {
                payload.m5_wardrive_process_id = progressProcessIds.m5WardriveProcessId;
            }
            if (progressProcessIds.bruceHandshakesProcessId) {
                payload.bruce_handshakes_process_id = progressProcessIds.bruceHandshakesProcessId;
            }
            if (progressProcessIds.bruceRawsnifferProcessId) {
                payload.bruce_rawsniffer_process_id = progressProcessIds.bruceRawsnifferProcessId;
            }
            if (progressProcessIds.bruceWardriveProcessId) {
                payload.bruce_wardrive_process_id = progressProcessIds.bruceWardriveProcessId;
            }
        }
        if (targetForce && typeof targetForce === 'object') {
            if (typeof targetForce.pwnagotchi === 'boolean') {
                payload.pwn_force_sync = targetForce.pwnagotchi;
            }
            if (typeof targetForce.m5evil === 'boolean') {
                payload.m5_force_sync = targetForce.m5evil;
            }
            if (typeof targetForce.bruce === 'boolean') {
                payload.bruce_force_sync = targetForce.bruce;
            }
        }
        const res = await fetchWithAuth(CONFIG.URLS.SYNC, { 
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return await this._unwrap(res);
    },

    async trustHostKey(host = null, port = null, replace = false, target = null) {
        const payload = { replace: !!replace };
        if (host) payload.host = host;
        if (port) payload.port = port;
        if (target) payload.target = target;
        const res = await fetchWithAuth(CONFIG.URLS.SYNC_TRUST_HOST_KEY, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return await this._unwrap(res);
    },

    async probePwnagotchiSync(payload = {}) {
        const res = await fetchWithAuth(CONFIG.URLS.SYNC_PWNAGOTCHI_PROBE, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload || {}),
        });
        return await this._unwrap(res);
    },

    async probeM5EvilSync(payload = {}) {
        const res = await fetchWithAuth(CONFIG.URLS.SYNC_M5EVIL_PROBE, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload || {}),
        });
        return await this._unwrap(res);
    },

    async probeBruceSync(payload = {}) {
        const res = await fetchWithAuth(CONFIG.URLS.SYNC_BRUCE_PROBE, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload || {}),
        });
        return await this._unwrap(res);
    },

    async getVendor(mac) {
        const res = await fetchWithAuth(`${CONFIG.URLS.VENDOR}/${mac}`);
        return await this._unwrap(res);
    },

    async getVendorAlt(mac) {
        const res = await fetchWithAuth(`${CONFIG.URLS.VENDOR}/${mac}?source=manuf`);
        return await this._unwrap(res);
    },

    async getConfig() {
        const res = await fetchWithAuth(`${API_BASE}/api/config`);
        return await this._unwrap(res);
    },

    async getZones(payload) {
        const res = await fetchWithAuth(`${API_BASE}/api/zones`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return await this._unwrap(res);
    },

    async getToConquerZones(payload) {
        const res = await fetchWithAuth(`${API_BASE}/api/zones/to-conquer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return await this._unwrap(res);
    },

    async getWardriveHierarchy({ time_window = 'all', source = 'all', session_ids = [] } = {}) {
        const params = new URLSearchParams();
        params.set('time_window', String(time_window || 'all'));
        params.set('source', String(source || 'all'));
        if (Array.isArray(session_ids) && session_ids.length) {
            params.set('session_ids', session_ids.map((item) => String(item || '').trim()).filter(Boolean).join(','));
        }
        const res = await fetchWithAuth(`${API_BASE}/api/wardrive/hierarchy?${params.toString()}`);
        return await this._unwrap(res);
    },

    async getWardriveInventory() {
        const res = await fetchWithAuth(`${API_BASE}/api/wardrive/inventory`);
        return await this._unwrap(res);
    },

    async getWardriveSessions({ time_window = 'all' } = {}) {
        const params = new URLSearchParams();
        params.set('time_window', String(time_window || 'all'));
        const res = await fetchWithAuth(`${API_BASE}/api/wardrive/sessions?${params.toString()}`);
        return await this._unwrap(res);
    },

    async setWardriveSessionTag(session_id, transport_mode = null) {
        const res = await fetchWithAuth(`${API_BASE}/api/wardrive/sessions/tag`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: String(session_id || '').trim(),
                transport_mode: transport_mode == null ? null : String(transport_mode || '').trim(),
            }),
        });
        return await this._unwrap(res);
    },

    async getWardriveSessionTracks(session_ids = []) {
        const res = await fetchWithAuth(`${API_BASE}/api/wardrive/sessions/tracks`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_ids: Array.isArray(session_ids)
                    ? session_ids.map((item) => String(item || '').trim()).filter(Boolean)
                    : [],
            }),
        });
        return await this._unwrap(res);
    },

    async mergeWardriveSessions(session_ids = []) {
        const res = await fetchWithAuth(`${API_BASE}/api/wardrive/sessions/merge`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_ids: Array.isArray(session_ids)
                    ? session_ids.map((item) => String(item || '').trim()).filter(Boolean)
                    : [],
            }),
        });
        return await this._unwrap(res);
    },

    async getWardriveZones(payload) {
        const res = await fetchWithAuth(`${API_BASE}/api/wardrive/zones`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return await this._unwrap(res);
    },

    async refreshWardriveRuntime({ reload_data = true, reload_maps = false } = {}) {
        const res = await fetchWithAuth(`${API_BASE}/api/wardrive/refresh`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                reload_data: !!reload_data,
                reload_maps: !!reload_maps,
            }),
        });
        return await this._unwrap(res);
    },

    async saveConfig(config) {
        const res = await fetchWithAuth(`${API_BASE}/api/config`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(config)
        });
        return await this._unwrap(res);
    },

    // Cracking
    async getHandshakeFiles(mac) {
        const res = await fetchWithAuth(`${API_BASE}/api/handshakes/${mac}/files`);
        return await this._unwrap(res);
    },

    async getHandshakeSet(mac) {
        const res = await fetchWithAuth(`${API_BASE}/api/handshakes/${mac}/set`);
        return await this._unwrap(res);
    },

    async getHandshakeRawContext(mac) {
        const res = await fetchWithAuth(`${API_BASE}/api/handshakes/${mac}/raw-context`);
        return await this._unwrap(res);
    },

    async prepareHandshakeRaw(mac, { source_file = null, raw_item_id = null, force = false } = {}) {
        const res = await fetchWithAuth(`${API_BASE}/api/handshakes/${mac}/raw-prepare`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                source_file,
                raw_item_id,
                force: !!force,
            }),
        });
        return await this._unwrap(res);
    },

    async prepareHandshakeRawAll(mac, { force = false } = {}) {
        const res = await fetchWithAuth(`${API_BASE}/api/handshakes/${mac}/raw-prepare-all`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                force: !!force,
            }),
        });
        return await this._unwrap(res);
    },

    async getFileContent(filename, { captureId = null, combinedBuildId = null, mac = null } = {}) {
        const params = new URLSearchParams();
        if (captureId) params.append('capture_id', captureId);
        if (combinedBuildId) params.append('combined_build_id', combinedBuildId);
        if (mac) params.append('mac', mac);
        const query = params.toString();
        const res = await fetchWithAuth(`${API_BASE}/api/files/${encodeURIComponent(filename)}${query ? `?${query}` : ''}`);
        return await this._unwrap(res);
    },

    async buildCombinedCapture(mac, captureIds = []) {
        const res = await fetchWithAuth(`${API_BASE}/api/handshakes/${mac}/combine-captures`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                capture_ids: Array.isArray(captureIds) ? captureIds : [],
            }),
        });
        return await this._unwrap(res);
    },

    async getCustomWordlists() {
        const res = await fetchWithAuth(`${API_BASE}/api/wordlists/custom`);
        return await this._unwrap(res);
    },

    async getHashcatRules() {
        const res = await fetchWithAuth(`${API_BASE}/api/hashcat/rules`);
        return await this._unwrap(res);
    },

    async getHashcatMasks() {
        const res = await fetchWithAuth(`${API_BASE}/api/hashcat/masks`);
        return await this._unwrap(res);
    },

    async getHashcatDevices() {
        const res = await fetchWithAuth(`${API_BASE}/api/hashcat/devices`);
        return await this._unwrap(res);
    },

    async convertPcap(filename, captureId = null, rawItemId = null) {
        const res = await fetchWithAuth(`${API_BASE}/api/convert/hcx`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                filename,
                capture_id: captureId,
                raw_item_id: rawItemId,
            })
        });
        return await this._unwrap(res);
    },

    async convertMultiPcaps(filenames, captureIds = null) {
        const res = await fetchWithAuth(`${API_BASE}/api/convert/hcx/batch`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                filenames,
                capture_ids: captureIds,
            })
        });
        return await this._unwrap(res);
    },

    async startCracking(filename, attackMode, workloadProfile, wordlist, ruleFile, customMask, isOptimized, isSlow, deviceId, enablePotfile, wordlist2, enableIncrement, incrementMin, incrementMax, maskFile = null, associationHint = null, associationHints = null, skipQualityGate = false, captureId = null, combinedBuildId = null, mac = null) {
        const payload = { 
            filename, 
            capture_id: captureId,
            combined_build_id: combinedBuildId,
            mac,
            attack_mode: attackMode, 
            workload_profile: workloadProfile,
            wordlist: wordlist,
            rule_file: ruleFile,
            custom_mask: customMask,
            is_optimized: isOptimized,
            is_slow: isSlow,
            device_id: deviceId,
            enable_potfile: enablePotfile,
            wordlist_2: wordlist2,
            enable_increment: enableIncrement,
            increment_min: incrementMin,
            increment_max: incrementMax,
            mask_file: maskFile,
            association_hint: associationHint,
            association_hints: associationHints,
            skip_quality_gate: skipQualityGate
        };
        
        const res = await fetchWithAuth(`${API_BASE}/api/hashcat/jobs`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return await this._unwrap(res);
    },

    async previewAssociationCandidates(filename, mode, associationHint = null, associationHints = null, captureId = null, combinedBuildId = null, mac = null) {
        const payload = {
            filename,
            capture_id: captureId,
            combined_build_id: combinedBuildId,
            mac,
            mode,
            association_hint: associationHint,
            association_hints: associationHints
        };
        const res = await fetchWithAuth(`${API_BASE}/api/hashcat/association/preview`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        return await this._unwrap(res);
    },

    async startAircrack(filename, bssid, wordlist, captureId = null, rawItemId = null) {
        const res = await fetchWithAuth(`${API_BASE}/api/aircrack/jobs`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                filename: filename,
                capture_id: captureId,
                raw_item_id: rawItemId,
                bssid: bssid,
                wordlist: wordlist
            })
        });
        return await this._unwrap(res);
    },

    // ── PMK Database ──
    async listPmkDatabases() {
        const res = await fetchWithAuth(`${API_BASE}/api/pmk/databases`);
        return await this._unwrap(res);
    },

    async getPmkDatabaseStats(dbName) {
        const res = await fetchWithAuth(`${API_BASE}/api/pmk/databases/${encodeURIComponent(dbName)}/stats`);
        return await this._unwrap(res);
    },

    async buildPmkDatabase(essid, wordlist, dbName = null) {
        const res = await fetchWithAuth(`${API_BASE}/api/pmk/build`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ essid, wordlist, db_name: dbName })
        });
        return await this._unwrap(res);
    },

    async startPmkAttack(filename, bssid, dbName, captureId = null, rawItemId = null) {
        const res = await fetchWithAuth(`${API_BASE}/api/pmk/attack`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                filename,
                capture_id: captureId,
                raw_item_id: rawItemId,
                bssid: bssid,
                db_name: dbName
            })
        });
        return await this._unwrap(res);
    },

    async deletePmkDatabase(dbName) {
        const res = await fetchWithAuth(`${API_BASE}/api/pmk/databases/${encodeURIComponent(dbName)}`, {
            method: 'DELETE'
        });
        return await this._unwrap(res);
    },

    async startWpsAttack(bssid, channel, iface, tool = 'reaver', pixieDust = false, delay = null) {
        const body = { bssid, channel, interface: iface, tool, pixie_dust: pixieDust };
        if (delay !== null && delay !== undefined) body.delay = delay;
        const res = await fetchWithAuth(`${API_BASE}/api/wps/attack`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        return await this._unwrap(res);
    },

    async listMultiFiles() {
        const res = await fetchWithAuth(`${API_BASE}/api/batches`);
        return await this._unwrap(res);
    },

    async deleteRawSnifferFile(filename) {
        const res = await fetchWithAuth(`${API_BASE}/api/rawsniffer/files/${encodeURIComponent(filename)}`, {
            method: 'DELETE'
        });
        return await this._unwrap(res);
    },

    async getMultiFileContent(filename) {
        const res = await fetchWithAuth(`${API_BASE}/api/batches/${encodeURIComponent(filename)}`);
        return await this._unwrap(res);
    },

    async getBatchFiles(filename) {
        const res = await fetchWithAuth(`${API_BASE}/api/batches/${encodeURIComponent(filename)}/files`);
        return await this._unwrap(res);
    },

    async deleteMultiFile(filename) {
        const res = await fetchWithAuth(`${API_BASE}/api/batches/${encodeURIComponent(filename)}`, {
            method: 'DELETE'
        });
        return await this._unwrap(res);
    },

    async cancelJob(jobId) {
        const res = await fetchWithAuth(`${API_BASE}/api/jobs/${jobId}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: 'canceled' })
        });
        return await this._unwrap(res);
    },

    async getJobStatus(jobId) {
        const res = await fetchWithAuth(`${API_BASE}/api/jobs/${jobId}`);
        return await this._unwrap(res);
    },

    async listJobs() {
        const res = await fetchWithAuth(`${API_BASE}/api/jobs`);
        return await this._unwrap(res);
    },

    async clearHistory() {
        const res = await fetchWithAuth(`${API_BASE}/api/history`, {
            method: 'DELETE'
        });
        return await this._unwrap(res);
    },

    async clearDetailsFiles() {
        const res = await fetchWithAuth(`${API_BASE}/api/maintenance/details`, {
            method: 'DELETE'
        });
        return await this._unwrap(res);
    },

    async clearCache() {
        const res = await fetchWithAuth(`${API_BASE}/api/maintenance/cache`, {
            method: 'DELETE'
        });
        return await this._unwrap(res);
    },

    async getDemoDataStatus() {
        const res = await fetchWithAuth(`${API_BASE}/api/maintenance/demo`);
        return await this._unwrap(res);
    },

    async installDemoData(payload = {}) {
        const res = await fetchWithAuth(`${API_BASE}/api/maintenance/demo/install`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload || {}),
        });
        return await this._unwrap(res);
    },

    async removeDemoData() {
        const res = await fetchWithAuth(`${API_BASE}/api/maintenance/demo`, {
            method: 'DELETE',
        });
        return await this._unwrap(res);
    },

    // Fingerprint
    async extractFingerprint(filename, force = false, captureId = null, rawItemId = null, bssid = null) {
        const res = await fetchWithAuth(`${API_BASE}/api/fingerprint/extract`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                filename,
                capture_id: captureId,
                raw_item_id: rawItemId,
                bssid,
                force,
            })
        });
        return await this._unwrap(res);
    },

    async getFingerprintDetails({ filename, mac, captureId = null }) {
        const params = new URLSearchParams();
        if (filename) params.append('filename', filename);
        if (mac) params.append('mac', mac);
        if (captureId) params.append('capture_id', captureId);
        const res = await fetchWithAuth(`${API_BASE}/api/fingerprint/details?${params.toString()}`);
        return await this._unwrap(res);
    },

    // RawSniffer (Bruce raw_*.pcap)
    async listRawSnifferFiles() {
        const res = await fetchWithAuth(`${API_BASE}/api/rawsniffer/files`);
        return await this._unwrap(res);
    },

    async getRawSnifferHashes() {
        const res = await fetchWithAuth(`${API_BASE}/api/rawsniffer/hashes`);
        return await this._unwrap(res);
    },

    async extractRawSniffer(payload = {}) {
        const res = await fetchWithAuth(`${API_BASE}/api/rawsniffer/extract`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload || {})
        });
        return await this._unwrap(res);
    },

    async getRawSnifferMetadata(filename, refresh = false, rawItemId = null) {
        const params = new URLSearchParams();
        if (filename) params.append('filename', filename);
        if (rawItemId) params.append('raw_item_id', rawItemId);
        if (refresh) params.append('refresh', 'true');
        const res = await fetchWithAuth(`${API_BASE}/api/rawsniffer/metadata?${params.toString()}`);
        return await this._unwrap(res);
    },

    async analyzeRawSniffer(rawItemId, force = false) {
        const res = await fetchWithAuth(`${API_BASE}/api/rawsniffer/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                raw_item_id: rawItemId,
                force: !!force,
            }),
        });
        return await this._unwrap(res);
    },

    async getRawSnifferAnalysis(rawItemId) {
        const res = await fetchWithAuth(`${API_BASE}/api/rawsniffer/analysis/${encodeURIComponent(rawItemId)}`);
        return await this._unwrap(res);
    },

    // Insights and data health
    async getDataHealthSummary() {
        const res = await fetchWithAuth(`${API_BASE}/api/data-health/summary`);
        return await this._unwrap(res);
    },

    async getAttackScore({ mac = null, filename = null, captureId = null, combinedBuildId = null } = {}) {
        const params = new URLSearchParams();
        if (mac) params.append('mac', mac);
        if (filename) params.append('filename', filename);
        if (captureId) params.append('capture_id', captureId);
        if (combinedBuildId) params.append('combined_build_id', combinedBuildId);
        const query = params.toString();
        const res = await fetchWithAuth(`${API_BASE}/api/insights/score${query ? `?${query}` : ''}`);
        return await this._unwrap(res);
    },

    async getAttackRecommendation({ mac = null, filename = null, captureId = null, combinedBuildId = null } = {}) {
        const params = new URLSearchParams();
        if (mac) params.append('mac', mac);
        if (filename) params.append('filename', filename);
        if (captureId) params.append('capture_id', captureId);
        if (combinedBuildId) params.append('combined_build_id', combinedBuildId);
        const query = params.toString();
        const res = await fetchWithAuth(`${API_BASE}/api/insights/attack-recommendation${query ? `?${query}` : ''}`);
        return await this._unwrap(res);
    },

    async getHandshakeReadiness({ mac = null, filename = null, captureId = null, combinedBuildId = null } = {}) {
        const params = new URLSearchParams();
        if (mac) params.append('mac', mac);
        if (filename) params.append('filename', filename);
        if (captureId) params.append('capture_id', captureId);
        if (combinedBuildId) params.append('combined_build_id', combinedBuildId);
        const query = params.toString();
        const res = await fetchWithAuth(`${API_BASE}/api/insights/handshake-readiness${query ? `?${query}` : ''}`);
        return await this._unwrap(res);
    },

    async getQualityGate(filename, attackMode = null, { captureId = null, combinedBuildId = null, mac = null } = {}) {
        const params = new URLSearchParams();
        params.append('filename', filename);
        if (attackMode) params.append('attack_mode', attackMode);
        if (captureId) params.append('capture_id', captureId);
        if (combinedBuildId) params.append('combined_build_id', combinedBuildId);
        if (mac) params.append('mac', mac);
        const res = await fetchWithAuth(`${API_BASE}/api/insights/quality-gate?${params.toString()}`);
        return await this._unwrap(res);
    },

    // Analytics
    async getAnalyticsHeatmap({
        metric = 'opportunity',
        time_window = 'all',
        source = 'all',
        security = 'all',
        device_type = 'all',
        channel = null,
        cell_size_m = 120,
    } = {}) {
        const params = new URLSearchParams();
        params.append('metric', metric);
        params.append('time_window', time_window);
        params.append('source', source);
        params.append('security', security);
        params.append('device_type', device_type);
        params.append('cell_size_m', String(cell_size_m));
        if (channel !== null && channel !== undefined && channel !== '' && channel !== 'all') {
            params.append('channel', String(channel));
        }
        const res = await fetchWithAuth(`${API_BASE}/api/analytics/heatmap?${params.toString()}`);
        return await this._unwrap(res);
    },

    async getAnalyticsChannelSummary({
        metric = 'opportunity',
        time_window = 'all',
        source = 'all',
        security = 'all',
        device_type = 'all',
        channel = null,
    } = {}) {
        const params = new URLSearchParams();
        params.append('metric', metric);
        params.append('time_window', time_window);
        params.append('source', source);
        params.append('security', security);
        params.append('device_type', device_type);
        if (channel !== null && channel !== undefined && channel !== '' && channel !== 'all') {
            params.append('channel', String(channel));
        }
        const res = await fetchWithAuth(`${API_BASE}/api/analytics/channel-summary?${params.toString()}`);
        return await this._unwrap(res);
    },

    async getAnalyticsHotspots({
        metric = 'opportunity',
        time_window = 'all',
        source = 'all',
        security = 'all',
        device_type = 'all',
        channel = null,
        cell_size_m = 120,
        limit = 12,
    } = {}) {
        const params = new URLSearchParams();
        params.append('metric', metric);
        params.append('time_window', time_window);
        params.append('source', source);
        params.append('security', security);
        params.append('device_type', device_type);
        params.append('cell_size_m', String(cell_size_m));
        params.append('limit', String(limit));
        if (channel !== null && channel !== undefined && channel !== '' && channel !== 'all') {
            params.append('channel', String(channel));
        }
        const res = await fetchWithAuth(`${API_BASE}/api/analytics/hotspots?${params.toString()}`);
        return await this._unwrap(res);
    },

    // Recon Center
    async getReconCacheManifest() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/cache-manifest`);
        return await this._unwrap(res);
    },

    async getReconKillChain() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/kill-chain`);
        return await this._unwrap(res);
    },

    async getReconKillChainSummary() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/kill-chain/summary`);
        return await this._unwrap(res);
    },

    async getReconKillChainStage({
        stage,
        search = '',
        limit = 200,
        offset = 0,
    } = {}) {
        const params = new URLSearchParams();
        params.append('stage', String(stage || ''));
        if (search) params.append('search', String(search));
        params.append('limit', String(limit));
        params.append('offset', String(offset));
        const res = await fetchWithAuth(`${API_BASE}/api/recon/kill-chain/stage?${params.toString()}`);
        return await this._unwrap(res);
    },

    async getReconVulnerabilityMatrix({
        sort_by = 'attack_score',
        sort_dir = 'desc',
        encryption = 'all',
        stage = 'all',
        limit = 100,
        offset = 0,
    } = {}) {
        const params = new URLSearchParams();
        params.append('sort_by', sort_by);
        params.append('sort_dir', sort_dir);
        params.append('encryption', encryption);
        params.append('stage', stage);
        params.append('limit', String(limit));
        params.append('offset', String(offset));
        const res = await fetchWithAuth(`${API_BASE}/api/recon/vulnerability-matrix?${params.toString()}`);
        return await this._unwrap(res);
    },

    async getReconTargetDetail({ mac } = {}) {
        const params = new URLSearchParams();
        params.append('mac', String(mac || ''));
        const res = await fetchWithAuth(`${API_BASE}/api/recon/target-detail?${params.toString()}`);
        return await this._unwrap(res);
    },

    async getReconAttackEffectiveness({ period = 'all' } = {}) {
        const params = new URLSearchParams();
        if (period && period !== 'all') params.append('period', period);
        const qs = params.toString();
        const res = await fetchWithAuth(`${API_BASE}/api/recon/attack-effectiveness${qs ? '?' + qs : ''}`);
        return await this._unwrap(res);
    },

    async getReconTemporalIntel() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/temporal-intel`);
        return await this._unwrap(res);
    },

    async getReconAuditReport() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/audit-report`);
        return await this._unwrap(res);
    },

    async getReconProbeIntel({ limit = 200 } = {}) {
        const params = new URLSearchParams();
        params.append('limit', String(limit));
        const res = await fetchWithAuth(`${API_BASE}/api/recon/probe-intel?${params.toString()}`);
        return await this._unwrap(res);
    },

    async getReconDeepAnalysis({ limit = 200 } = {}) {
        const params = new URLSearchParams();
        params.append('limit', String(limit));
        const res = await fetchWithAuth(`${API_BASE}/api/recon/deep-analysis?${params.toString()}`);
        return await this._unwrap(res);
    },

    // Recon lazy-load endpoints
    async getReconProbeIntelStatus() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/probe-intel/status`);
        return await this._unwrap(res);
    },

    async startReconProbeIntelScan({ limit = 200 } = {}) {
        const params = new URLSearchParams();
        params.append('limit', String(limit));
        const res = await fetchWithAuth(`${API_BASE}/api/recon/probe-intel/scan?${params.toString()}`, { method: 'POST' });
        return await this._unwrap(res);
    },

    async getReconDeepAnalysisStatus() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/deep-analysis/status`);
        return await this._unwrap(res);
    },

    async startReconDeepAnalysisScan({ limit = 200 } = {}) {
        const params = new URLSearchParams();
        params.append('limit', String(limit));
        const res = await fetchWithAuth(`${API_BASE}/api/recon/deep-analysis/scan?${params.toString()}`, { method: 'POST' });
        return await this._unwrap(res);
    },

    // ── Phase 3: Kill-Chain Snapshots (S-F3) ────────────────────────────
    async createReconKillChainSnapshot() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/kill-chain/snapshot`, { method: 'POST' });
        return await this._unwrap(res);
    },
    async getReconKillChainHistory() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/kill-chain/history`);
        return await this._unwrap(res);
    },

    // ── Phase 3: Report Snapshots (R-F5) ────────────────────────────────
    async saveReconReportSnapshot() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/audit-report/snapshot`, { method: 'POST' });
        return await this._unwrap(res);
    },
    async listReconReportSnapshots() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/audit-report/snapshots`);
        return await this._unwrap(res);
    },
    async compareReconReportSnapshot(snapshotId) {
        const params = new URLSearchParams({ snapshot_id: snapshotId });
        const res = await fetchWithAuth(`${API_BASE}/api/recon/audit-report/compare?${params.toString()}`);
        return await this._unwrap(res);
    },

    // ── Phase 3: Attack Planner (O-F6) ──────────────────────────────────
    async createReconAttackPlan({ targets, strategy = 'auto', wordlist = null } = {}) {
        const body = { targets, strategy };
        if (wordlist) body.wordlist = wordlist;
        const res = await fetchWithAuth(`${API_BASE}/api/recon/attack-plan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
        });
        return await this._unwrap(res);
    },

    // ── Phase 3: COMMS Intelligence (C-F1, C-F2, C-F3) ─────────────────
    async getReconCommsRelationshipGraph() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/comms/relationship-graph`);
        return await this._unwrap(res);
    },
    async getReconCommsDeviceFingerprints() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/comms/device-fingerprints`);
        return await this._unwrap(res);
    },
    async getReconCommsColocation() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/comms/colocation`);
        return await this._unwrap(res);
    },
    async getReconCommsSpectrum() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/comms/spectrum`);
        return await this._unwrap(res);
    },
    async getReconCommsSignalLandscape() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/comms/signal-landscape`);
        return await this._unwrap(res);
    },

    // ── Phase 3: Probe Extensions (SI-F5, SI-F7) ────────────────────────
    async getReconProbeDerandom() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/probe-intel/derandom`);
        return await this._unwrap(res);
    },
    async getReconProbeGeocorrelation() {
        const res = await fetchWithAuth(`${API_BASE}/api/recon/probe-intel/geocorrelation`);
        return await this._unwrap(res);
    }
};
