import { API } from '../api.js';
import { log } from '../utils.js';
import { setMarkerIcons } from '../map.js';
import { STATE } from '../state.js';
import { updateNoGpsList } from './ui_lists.js';

// Configurações de Interface Padrão
export let uiConfig = {
    visualTheme: 'professional',
    theme: 'slate',
    iconPwned: 'fa-skull',
    iconLocked: 'fa-shield-halved',
    iconOpen: 'fa-bolt',
    iconWardrive: 'fa-tower-broadcast',
    wardriveColor: 'teal',
    wardriveStyle: 'icon'
};

const VISUAL_THEME_ALLOWED = new Set(['cyberpunk', 'professional', 'synthwave', 'military']);
const CYBERPUNK_THEMES = new Set(['cyan', 'purple', 'green', 'pink', 'orange']);
const PROFESSIONAL_THEMES = new Set(['steel', 'slate', 'forest', 'amber', 'rose']);
const SYNTHWAVE_THEMES = new Set(['sunset', 'vapor', 'miami', 'retro', 'plasma']);
const MILITARY_THEMES = new Set(['tactical', 'desert', 'nightvision', 'command', 'stealth']);
const ALL_THEMES = new Set([...CYBERPUNK_THEMES, ...PROFESSIONAL_THEMES, ...SYNTHWAVE_THEMES, ...MILITARY_THEMES]);
const HUD_DENSITY_ALLOWED = new Set(['compact', 'balanced', 'comfortable']);
const SIDEBAR_PRESET_ALLOWED = new Set(['narrow', 'standard', 'wide']);
const FONT_SCALE_ALLOWED = new Set(['90', '100', '110']);
const CRACKING_ACCORDION_MODE_ALLOWED = new Set(['multi', 'single']);
const REPLAY_SPEED_ALLOWED = new Set(['0.05', '0.1', '0.25', '0.5', '1', '1.5', '2', '2.5', '4', '8']);
const REPLAY_TIMING_MODE_ALLOWED = new Set(['real_time', 'compress_idle', 'uniform_path']);
const REPLAY_FOLLOW_ZOOM_ALLOWED = new Set(['current', '13', '15', '17', '19']);
const SESSION_SORT_ALLOWED = new Set(['none', 'date', 'duration', 'distance', 'nets']);
const SORT_DIRECTION_ALLOWED = new Set(['asc', 'desc']);
const WARDRIVE_ACCENT_ALLOWED = new Set([
    'theme',
    'teal',
    'cyan',
    'purple',
    'yellow',
    'green',
    'orange',
    'pink',
    'amber',
    'red',
    'white',
]);
const SETTINGS_SECTION_DEFAULT = 'appearance';
const M5_CARDPUTER_PRESET = Object.freeze({
    host: '192.168.4.1',
    port: '80',
    protocol: 'http',
    adminBasePath: '/evil-menu',
    username: 'evil',
    password: 'test',
    handshakePath: 'evil/handshakes',
    wardrivePath: 'evil/wardriving',
});

const BRUCE_WEBUI_PRESET = Object.freeze({
    host: 'bruce.local',
    port: '80',
    protocol: 'http',
    username: 'admin',
    password: 'bruce',
});

const SIDEBAR_PRESETS = {
    narrow: { left: 250, right: 420 },
    standard: { left: 280, right: 500 },
    wide: { left: 320, right: 560 }
};

function normalizeHudDensity(value) {
    const normalized = String(value || 'balanced').trim().toLowerCase();
    return HUD_DENSITY_ALLOWED.has(normalized) ? normalized : 'balanced';
}

function normalizeSidebarPreset(value) {
    const normalized = String(value || 'standard').trim().toLowerCase();
    return SIDEBAR_PRESET_ALLOWED.has(normalized) ? normalized : 'standard';
}

function normalizeFontScale(value) {
    const normalized = String(value || '100').trim();
    return FONT_SCALE_ALLOWED.has(normalized) ? normalized : '100';
}

function normalizeCrackingAccordionMode(value) {
    const normalized = String(value || 'multi').trim().toLowerCase();
    return CRACKING_ACCORDION_MODE_ALLOWED.has(normalized) ? normalized : 'multi';
}

function normalizeCrackingAttackPanelMode(value) {
    const normalized = String(value || 'multi').trim().toLowerCase();
    return CRACKING_ACCORDION_MODE_ALLOWED.has(normalized) ? normalized : 'multi';
}

function normalizeWardriveReplaySpeedDefault(value) {
    const normalized = String(value || '1').trim();
    return REPLAY_SPEED_ALLOWED.has(normalized) ? normalized : '1';
}

function normalizeWardriveReplayTimingModeDefault(value) {
    const normalized = String(value || 'real_time').trim().toLowerCase();
    return REPLAY_TIMING_MODE_ALLOWED.has(normalized) ? normalized : 'real_time';
}

function normalizeWardriveReplayFollowZoomDefault(value) {
    const normalized = String(value || 'current').trim().toLowerCase();
    return REPLAY_FOLLOW_ZOOM_ALLOWED.has(normalized) ? normalized : 'current';
}

function normalizeWardriveSessionsSortBy(value) {
    const normalized = String(value || 'none').trim().toLowerCase();
    return SESSION_SORT_ALLOWED.has(normalized) ? normalized : 'none';
}

function normalizeSortDirection(value) {
    const normalized = String(value || 'desc').trim().toLowerCase();
    return SORT_DIRECTION_ALLOWED.has(normalized) ? normalized : 'desc';
}

function normalizeVisualTheme(value) {
    const normalized = String(value || 'professional').trim().toLowerCase();
    return VISUAL_THEME_ALLOWED.has(normalized) ? normalized : 'professional';
}

function normalizeThemeForVisual(theme, visualTheme) {
    const vt = normalizeVisualTheme(visualTheme);
    const t = String(theme || '').trim().toLowerCase();
    if (vt === 'professional') {
        return PROFESSIONAL_THEMES.has(t) ? t : 'slate';
    }
    if (vt === 'synthwave') {
        return SYNTHWAVE_THEMES.has(t) ? t : 'sunset';
    }
    if (vt === 'military') {
        return MILITARY_THEMES.has(t) ? t : 'tactical';
    }
    return CYBERPUNK_THEMES.has(t) ? t : 'purple';
}

export function getThemePresetsForVisual(visualTheme) {
    if (visualTheme === 'professional') {
        return [
            { value: 'slate', label: 'Slate Purple (Default)' },
            { value: 'steel', label: 'Steel Blue' },
            { value: 'forest', label: 'Forest Green' },
            { value: 'amber', label: 'Warm Amber' },
            { value: 'rose', label: 'Rose' },
        ];
    }
    if (visualTheme === 'synthwave') {
        return [
            { value: 'sunset', label: 'Sunset (Default)' },
            { value: 'vapor', label: 'Vaporwave' },
            { value: 'miami', label: 'Miami Vice' },
            { value: 'retro', label: 'Retro Gold' },
            { value: 'plasma', label: 'Plasma' },
        ];
    }
    if (visualTheme === 'military') {
        return [
            { value: 'tactical', label: 'Tactical (Default)' },
            { value: 'desert', label: 'Desert Storm' },
            { value: 'nightvision', label: 'Night Vision' },
            { value: 'command', label: 'Command Amber' },
            { value: 'stealth', label: 'Stealth' },
        ];
    }
    return [
        { value: 'purple', label: 'Neon Purple (Default)' },
        { value: 'cyan', label: 'Cyber Cyan' },
        { value: 'green', label: 'Matrix Green' },
        { value: 'pink', label: 'Hot Pink' },
        { value: 'orange', label: 'Electric Orange' },
    ];
}

function updateThemeSelectOptions(visualTheme) {
    const sel = document.getElementById('conf-ui-theme');
    if (!sel) return;
    const presets = getThemePresetsForVisual(visualTheme);
    sel.innerHTML = '';
    presets.forEach(p => {
        const opt = document.createElement('option');
        opt.value = p.value;
        opt.textContent = p.label;
        sel.appendChild(opt);
    });
    sel.value = presets[0].value;
}

export function applyVisualTheme(visualTheme) {
    const vt = normalizeVisualTheme(visualTheme);
    const root = document.documentElement;
    root.classList.remove('theme-cyberpunk', 'theme-professional', 'theme-synthwave', 'theme-military');
    root.classList.add(`theme-${vt}`);
    uiConfig.visualTheme = vt;
}

function normalizeWardriveAccentColor(value, fallback = 'theme') {
    const normalized = String(value || fallback).trim().toLowerCase();
    return WARDRIVE_ACCENT_ALLOWED.has(normalized) ? normalized : fallback;
}

export function applyLayoutSettings(config = {}) {
    const root = document.documentElement;
    const hudLayer = document.getElementById('hud-layer');

    const hudDensity = normalizeHudDensity(config.ui_hud_density);
    const sidebarPreset = normalizeSidebarPreset(config.ui_sidebar_preset);
    const fontScale = normalizeFontScale(config.ui_font_scale);

    if (hudLayer) {
        hudLayer.classList.remove('hud-density-compact', 'hud-density-comfortable');
        if (hudDensity === 'compact') {
            hudLayer.classList.add('hud-density-compact');
        } else if (hudDensity === 'comfortable') {
            hudLayer.classList.add('hud-density-comfortable');
        }
    }

    const preset = SIDEBAR_PRESETS[sidebarPreset] || SIDEBAR_PRESETS.standard;
    root.style.setProperty('--left-sidebar-w', `${preset.left}px`);
    root.style.setProperty('--right-panels-w', `${preset.right}px`);

    const fontFactor = Number(fontScale) / 100;
    root.style.setProperty('--ui-font-scale', `${fontScale}%`);
    root.style.setProperty('--ui-font-scale-factor', String(fontFactor));
}

function setSelectArrowColor(color) {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="292.4" height="292.4"><path fill="${color}" d="M287 69.4a17.6 17.6 0 0 0-13-5.4H18.4c-5 0-9.3 1.8-12.9 5.4A17.6 17.6 0 0 0 0 82.2c0 5 1.8 9.3 5.4 12.9l128 127.9c3.6 3.6 7.8 5.4 12.8 5.4s9.2-1.8 12.8-5.4L287 95c3.5-3.5 5.4-7.8 5.4-12.8 0-5-1.9-9.2-5.5-12.8z"/></svg>`;
    const url = `url("data:image/svg+xml;charset=US-ASCII,${encodeURIComponent(svg)}")`;
    document.documentElement.style.setProperty('--select-arrow', url);
}

export function applyTheme(theme) {
    const root = document.documentElement;
    const vt = uiConfig.visualTheme || 'cyberpunk';

    if (vt === 'professional') {
        switch(theme) {
            case 'slate':
                root.style.setProperty('--neon-cyan', '#9b8ec4');
                root.style.setProperty('--neon-purple', '#6b5fa0');
                setSelectArrowColor('#9b8ec4');
                break;
            case 'forest':
                root.style.setProperty('--neon-cyan', '#4caf7d');
                root.style.setProperty('--neon-purple', '#2d7a50');
                setSelectArrowColor('#4caf7d');
                break;
            case 'amber':
                root.style.setProperty('--neon-cyan', '#d4a12f');
                root.style.setProperty('--neon-purple', '#9a7a2f');
                setSelectArrowColor('#d4a12f');
                break;
            case 'rose':
                root.style.setProperty('--neon-cyan', '#d45b7a');
                root.style.setProperty('--neon-purple', '#9a3a55');
                setSelectArrowColor('#d45b7a');
                break;
            case 'steel':
            default:
                root.style.setProperty('--neon-cyan', '#2faad4');
                root.style.setProperty('--neon-purple', '#5b8a9a');
                setSelectArrowColor('#2faad4');
                break;
        }
        return;
    }

    if (vt === 'synthwave') {
        switch(theme) {
            case 'vapor':
                root.style.setProperty('--neon-cyan', '#00e5ff');
                root.style.setProperty('--neon-purple', '#ff71ce');
                setSelectArrowColor('#00e5ff');
                break;
            case 'miami':
                root.style.setProperty('--neon-cyan', '#ff2d95');
                root.style.setProperty('--neon-purple', '#7b2ff7');
                setSelectArrowColor('#ff2d95');
                break;
            case 'retro':
                root.style.setProperty('--neon-cyan', '#ffd700');
                root.style.setProperty('--neon-purple', '#ff6b35');
                setSelectArrowColor('#ffd700');
                break;
            case 'plasma':
                root.style.setProperty('--neon-cyan', '#b24dff');
                root.style.setProperty('--neon-purple', '#6366f1');
                setSelectArrowColor('#b24dff');
                break;
            case 'sunset':
            default:
                root.style.setProperty('--neon-cyan', '#ff6b9d');
                root.style.setProperty('--neon-purple', '#c44dff');
                setSelectArrowColor('#ff6b9d');
                break;
        }
        return;
    }

    if (vt === 'military') {
        switch(theme) {
            case 'desert':
                root.style.setProperty('--neon-cyan', '#c4a35a');
                root.style.setProperty('--neon-purple', '#8b7340');
                setSelectArrowColor('#c4a35a');
                break;
            case 'nightvision':
                root.style.setProperty('--neon-cyan', '#39ff14');
                root.style.setProperty('--neon-purple', '#1a8a0a');
                setSelectArrowColor('#39ff14');
                break;
            case 'command':
                root.style.setProperty('--neon-cyan', '#d4a017');
                root.style.setProperty('--neon-purple', '#9a7510');
                setSelectArrowColor('#d4a017');
                break;
            case 'stealth':
                root.style.setProperty('--neon-cyan', '#8a9aa0');
                root.style.setProperty('--neon-purple', '#5a6a70');
                setSelectArrowColor('#8a9aa0');
                break;
            case 'tactical':
            default:
                root.style.setProperty('--neon-cyan', '#4a7c3f');
                root.style.setProperty('--neon-purple', '#2d5a28');
                setSelectArrowColor('#4a7c3f');
                break;
        }
        return;
    }

    switch(theme) {
        case 'purple':
            root.style.setProperty('--neon-cyan', '#bc13fe'); 
            root.style.setProperty('--neon-purple', '#00f3ff'); 
            setSelectArrowColor('#bc13fe');
            break;
        case 'green':
            root.style.setProperty('--neon-cyan', '#00ff41'); 
            root.style.setProperty('--neon-purple', '#008f11'); 
            setSelectArrowColor('#00ff41');
            break;
        case 'pink':
            root.style.setProperty('--neon-cyan', '#ff00ff'); 
            root.style.setProperty('--neon-purple', '#00f3ff'); 
            setSelectArrowColor('#ff00ff');
            break;
        case 'orange':
            root.style.setProperty('--neon-cyan', '#ff8c00'); 
            root.style.setProperty('--neon-purple', '#ff003c'); 
            setSelectArrowColor('#ff8c00');
            break;
        case 'cyan':
        default:
            root.style.setProperty('--neon-cyan', '#00f3ff');
            root.style.setProperty('--neon-purple', '#bc13fe');
            setSelectArrowColor('#00f3ff');
            break;
    }
}

export function applyWardriveColor(color) {
    const palette = {
        teal: '#00ffd0',
        cyan: '#00f3ff',
        purple: '#bc13fe',
        yellow: '#fcee0a',
        green: '#00ff41',
        orange: '#ff8c00',
    };
    const resolved = palette[color] || palette.teal;
    document.documentElement.style.setProperty('--wardrive-color', resolved);
}

function setInputValue(id, value, fallback = '') {
    const node = document.getElementById(id);
    if (!node) return;
    node.value = value ?? fallback;
}

function setPasswordInputState(id, configured = false) {
    const node = document.getElementById(id);
    if (!node) return;
    node.value = '';
    node.dataset.configured = configured ? '1' : '0';
    node.placeholder = configured
        ? 'Configured (leave blank to keep current password)'
        : '';
}

function setSyncPasswordStates(config = {}) {
    setPasswordInputState('conf-pass', !!config.pwn_pass_configured);
    setPasswordInputState('conf-m5-password', !!config.m5_web_password_configured);
    setPasswordInputState('conf-bruce-password', !!config.bruce_web_password_configured);
}

function applyM5CardputerPreset() {
    setInputValue('conf-m5-host', M5_CARDPUTER_PRESET.host);
    setInputValue('conf-m5-port', M5_CARDPUTER_PRESET.port);
    setInputValue('conf-m5-user', M5_CARDPUTER_PRESET.username);
    const passwordInput = document.getElementById('conf-m5-password');
    if (passwordInput) {
        passwordInput.value = M5_CARDPUTER_PRESET.password;
        passwordInput.dataset.configured = '1';
        passwordInput.placeholder = 'Configured (leave blank to keep current password)';
    }
}

function setM5ProbeStatus(message = '', tone = 'neutral') {
    const node = document.getElementById('conf-m5-test-status');
    if (!node) return;
    node.textContent = message || '';
    node.dataset.state = tone || 'neutral';
}

function setPwnProbeStatus(message = '', tone = 'neutral') {
    const node = document.getElementById('conf-pwn-test-status');
    if (!node) return;
    node.textContent = message || '';
    node.dataset.state = tone || 'neutral';
}

function setBruceProbeStatus(message = '', tone = 'neutral') {
    const node = document.getElementById('conf-bruce-test-status');
    if (!node) return;
    node.textContent = message || '';
    node.dataset.state = tone || 'neutral';
}

export function renderDemoDataStatus(status = null) {
    const badge = document.getElementById('demo-data-status');
    const summary = document.getElementById('demo-data-summary');
    const installButton = document.getElementById('btn-install-demo-data');
    const removeButton = document.getElementById('btn-remove-demo-data');
    const payload = status && typeof status === 'object' ? status : {};
    const isActive = !!payload.active;
    const activeLabel = String(payload.active_profile_label || payload.active_profile_id || 'showcase-core-v5');
    const metrics = payload.summary && typeof payload.summary === 'object' ? payload.summary : {};

    if (badge) {
        badge.textContent = isActive ? `DEMO DATA: ACTIVE (${activeLabel})` : 'DEMO DATA: INACTIVE';
        badge.dataset.tone = isActive ? 'active' : 'idle';
    }
    if (summary) {
        if (isActive) {
            const networks = Number(metrics.networks_total || 0);
            const wardrive = Number(metrics.wardrive_sessions || 0);
            const raw = Number(metrics.raw_files || 0);
            const snapshotNote = payload.snapshot_available
                ? ' Previous runtime data will be restored when demo mode is removed.'
                : '';
            summary.textContent = `Synthetic showcase pack loaded with ${networks} networks, ${wardrive} Wardrive sessions and ${raw} RAW captures.${snapshotNote}`;
        } else {
            summary.textContent = 'Optional synthetic showcase data for onboarding, screenshots and feature walkthroughs. Real runtime data stays untouched until you install the pack.';
        }
    }
    if (installButton) installButton.disabled = isActive;
    if (removeButton) removeButton.disabled = !isActive;
}

function formatM5ProbeFeedback(result = {}) {
    const details = result?.details || {};
    if (result?.status === 'success') {
        const handshakeCount = Number(details.handshake_files_found || 0);
        const rawsnifferCount = Number(details.rawsniffer_files_found || 0);
        const mastersnifferCount = Number(details.mastersniffer_files_found || 0);
        const wardriveCount = Number(details.wardrive_files_found || 0);
        const summary = `${handshakeCount} handshake file(s) | ${rawsnifferCount} RAW sniffer file(s) | ${mastersnifferCount} Master Sniffer file(s) | ${wardriveCount} Wardrive CSV file(s)`;
        return {
            tone: 'success',
            inline: `Connected: ${summary}`,
            log: `M5Evil Admin WebUI OK: ${summary}`,
            logTone: 'success',
        };
    }

    if (details.connection_ok && details.auth_ok && details.failure_phase === 'browse_root') {
        return {
            tone: 'error',
            inline: 'Connected and authenticated, but Browse SD could not be parsed for this firmware.',
            log: result?.message || 'Connected and authenticated, but Browse SD could not be parsed for this firmware.',
            logTone: 'error',
        };
    }

    if (details.connection_ok && details.auth_ok && details.failure_phase === 'path') {
        return {
            tone: 'error',
            inline: result?.message || 'Connected, but one of the configured SD paths could not be opened.',
            log: result?.message || 'Connected, but one of the configured SD paths could not be opened.',
            logTone: 'error',
        };
    }

    if (details.connection_ok && !details.auth_ok) {
        return {
            tone: 'error',
            inline: 'Reached Admin WebUI, but authentication failed.',
            log: result?.message || 'Reached Admin WebUI, but authentication failed.',
            logTone: 'error',
        };
    }

    return {
        tone: 'error',
        inline: result?.message || 'M5Evil Admin WebUI probe failed.',
        log: result?.message || 'M5Evil Admin WebUI probe failed.',
        logTone: 'error',
    };
}

function buildM5ProbePayload() {
    const passwordNode = document.getElementById('conf-m5-password');
    const payload = {
        m5_sync_enabled: !!document.getElementById('conf-m5-enabled')?.checked,
        m5_host: document.getElementById('conf-m5-host')?.value || M5_CARDPUTER_PRESET.host,
        m5_port: Number(document.getElementById('conf-m5-port')?.value || M5_CARDPUTER_PRESET.port),
        m5_web_protocol: 'http',
        m5_admin_base_path: M5_CARDPUTER_PRESET.adminBasePath,
        m5_web_user: document.getElementById('conf-m5-user')?.value || M5_CARDPUTER_PRESET.username,
        m5_handshake_remote_path: M5_CARDPUTER_PRESET.handshakePath,
        m5_wardrive_remote_path: M5_CARDPUTER_PRESET.wardrivePath,
    };
    const passwordValue = passwordNode?.value || '';
    if (passwordValue) {
        payload.m5_web_password = passwordValue;
    }
    return payload;
}

function formatBruceProbeFeedback(result = {}) {
    const details = result?.details || {};
    if (result?.status === 'success') {
        const handshakeCount = Number(details.handshake_files_found || 0);
        const rawsnifferCount = Number(details.rawsniffer_files_found || 0);
        const wardriveCount = Number(details.wardrive_files_found || 0);
        const isQuickProbe = details.probe_mode === 'quick' || !!details.handshake_file_count_skipped;
        const probeLabel = isQuickProbe ? 'quick probe (deep count skipped)' : '';
        const summaryParts = [];
        if (details.handshake_file_count_skipped && details.handshake_path_ok) {
            summaryParts.push('handshake path reachable');
        } else {
            summaryParts.push(`${handshakeCount} handshake file(s)`);
        }
        summaryParts.push(`${rawsnifferCount} RAW sniffer file(s)`);
        if (wardriveCount > 0) {
            summaryParts.push(`${wardriveCount} Wardrive CSV(s)`);
        } else if (details.wardrive_path_ok) {
            summaryParts.push('Wardrive path reachable');
        }
        const summary = summaryParts.join(' | ');
        return {
            tone: 'success',
            inline: probeLabel ? `Connected (${probeLabel}): ${summary}` : `Connected: ${summary}`,
            log: probeLabel ? `Bruce WebUI OK (${probeLabel}): ${summary}` : `Bruce WebUI OK: ${summary}`,
            logTone: 'success',
        };
    }

    if (details.connection_ok && details.auth_ok && details.failure_phase === 'path') {
        return {
            tone: 'error',
            inline: result?.message || 'Connected, but one of the configured Bruce paths could not be opened.',
            log: result?.message || 'Connected, but one of the configured Bruce paths could not be opened.',
            logTone: 'error',
        };
    }

    if (details.connection_ok && details.auth_ok && details.failure_phase === 'sd_browser') {
        return {
            tone: 'error',
            inline: result?.message || 'Connected, but the Bruce SD Files browser was not detected.',
            log: result?.message || 'Connected, but the Bruce SD Files browser was not detected.',
            logTone: 'error',
        };
    }

    if (details.connection_ok && !details.auth_ok) {
        return {
            tone: 'error',
            inline: 'Reached Bruce WebUI, but authentication failed.',
            log: result?.message || 'Reached Bruce WebUI, but authentication failed.',
            logTone: 'error',
        };
    }

    return {
        tone: 'error',
        inline: result?.message || 'Bruce WebUI probe failed.',
        log: result?.message || 'Bruce WebUI probe failed.',
        logTone: 'error',
    };
}

function buildBruceProbePayload() {
    const passwordNode = document.getElementById('conf-bruce-password');
    const payload = {
        bruce_sync_enabled: !!document.getElementById('conf-bruce-enabled')?.checked,
        bruce_host: document.getElementById('conf-bruce-host')?.value || BRUCE_WEBUI_PRESET.host,
        bruce_port: Number(document.getElementById('conf-bruce-port')?.value || BRUCE_WEBUI_PRESET.port),
        bruce_web_protocol: BRUCE_WEBUI_PRESET.protocol,
        bruce_web_user: document.getElementById('conf-bruce-user')?.value || BRUCE_WEBUI_PRESET.username,
    };
    const passwordValue = passwordNode?.value || '';
    if (passwordValue) {
        payload.bruce_web_password = passwordValue;
    }
    return payload;
}

function formatPwnProbeFeedback(result = {}) {
    const details = result?.details || {};
    if (result?.status === 'success') {
        const filesFound = Number(details.files_found || 0);
        return {
            tone: 'success',
            inline: `Connected: ${filesFound} file(s) visible in remote path`,
            log: `Pwnagotchi SSH OK: ${filesFound} file(s) visible in remote path`,
            logTone: 'success',
        };
    }

    if (details.connection_ok && details.auth_ok === false && details.host_key_trusted === false) {
        return {
            tone: 'error',
            inline: 'Reached SSH, but the host key is not trusted yet.',
            log: result?.message || 'Reached SSH, but the host key is not trusted yet.',
            logTone: 'error',
        };
    }

    if (details.connection_ok && details.auth_ok === false) {
        return {
            tone: 'error',
            inline: 'Reached SSH, but authentication failed.',
            log: result?.message || 'Reached SSH, but authentication failed.',
            logTone: 'error',
        };
    }

    if (details.connection_ok && details.auth_ok && details.remote_path_ok === false) {
        return {
            tone: 'error',
            inline: 'Connected, but the configured remote path could not be opened.',
            log: result?.message || 'Connected, but the configured remote path could not be opened.',
            logTone: 'error',
        };
    }

    return {
        tone: 'error',
        inline: result?.message || 'Pwnagotchi SSH probe failed.',
        log: result?.message || 'Pwnagotchi SSH probe failed.',
        logTone: 'error',
    };
}

function buildPwnProbePayload() {
    const passwordNode = document.getElementById('conf-pass');
    const payload = {
        pwn_host: document.getElementById('conf-ip')?.value || '',
        pwn_port: Number(document.getElementById('conf-port')?.value || 22),
        pwn_user: document.getElementById('conf-user')?.value || '',
        remote_path: document.getElementById('conf-path')?.value || '',
    };
    const passwordValue = passwordNode?.value || '';
    if (passwordValue) {
        payload.pwn_pass = passwordValue;
    }
    return payload;
}

export async function testM5Connection() {
    const probeBtn = document.getElementById('btn-conf-m5-test');
    try {
        if (probeBtn) {
            probeBtn.disabled = true;
        }
        setM5ProbeStatus('Testing Admin WebUI...', 'running');
        const result = await API.probeM5EvilSync(buildM5ProbePayload());
        const feedback = formatM5ProbeFeedback(result);
        setM5ProbeStatus(feedback.inline, feedback.tone);
        log(feedback.log, feedback.logTone);
    } catch (error) {
        setM5ProbeStatus(`Failed: ${error.message}`, 'error');
        log(`M5Evil Admin WebUI probe failed: ${error.message}`, 'error');
    } finally {
        if (probeBtn) {
            probeBtn.disabled = false;
        }
    }
}

export async function testPwnagotchiConnection() {
    const probeBtn = document.getElementById('btn-conf-pwn-test');
    try {
        if (probeBtn) {
            probeBtn.disabled = true;
        }
        setPwnProbeStatus('Testing SSH connection...', 'running');
        const result = await API.probePwnagotchiSync(buildPwnProbePayload());
        const feedback = formatPwnProbeFeedback(result);
        setPwnProbeStatus(feedback.inline, feedback.tone);
        log(feedback.log, feedback.logTone);
    } catch (error) {
        setPwnProbeStatus(`Failed: ${error.message}`, 'error');
        log(`Pwnagotchi SSH probe failed: ${error.message}`, 'error');
    } finally {
        if (probeBtn) {
            probeBtn.disabled = false;
        }
    }
}

export async function testBruceConnection() {
    const probeBtn = document.getElementById('btn-conf-bruce-test');
    try {
        if (probeBtn) {
            probeBtn.disabled = true;
        }
        setBruceProbeStatus('Testing Bruce WebUI...', 'running');
        const result = await API.probeBruceSync(buildBruceProbePayload());
        const feedback = formatBruceProbeFeedback(result);
        setBruceProbeStatus(feedback.inline, feedback.tone);
        log(feedback.log, feedback.logTone);
    } catch (error) {
        setBruceProbeStatus(`Failed: ${error.message}`, 'error');
        log(`Bruce WebUI probe failed: ${error.message}`, 'error');
    } finally {
        if (probeBtn) {
            probeBtn.disabled = false;
        }
    }
}

function setCheckboxValue(id, checked) {
    const node = document.getElementById(id);
    if (!node) return;
    node.checked = !!checked;
}

function setSelectValue(id, value, fallback = '') {
    const node = document.getElementById(id);
    if (!node) return;
    node.value = value ?? fallback;
    if (value != null && node.value !== String(value)) {
        node.value = fallback;
    }
}

function setSettingsSection(sectionId = SETTINGS_SECTION_DEFAULT) {
    const normalized = String(sectionId || SETTINGS_SECTION_DEFAULT).trim() || SETTINGS_SECTION_DEFAULT;
    document.querySelectorAll('[data-settings-section-target]').forEach((button) => {
        button.classList.toggle('active', button.getAttribute('data-settings-section-target') === normalized);
    });
    document.querySelectorAll('[data-settings-panel]').forEach((panel) => {
        panel.style.display = panel.getAttribute('data-settings-panel') === normalized ? 'block' : 'none';
    });
}

function ensureSettingsUiBound() {
    const modal = document.getElementById('settings-modal');
    if (!modal || modal.dataset.sectionsBound === '1') return;

    modal.addEventListener('click', (event) => {
        const sectionBtn = event.target.closest('[data-settings-section-target]');
        if (sectionBtn) {
            event.preventDefault();
            setSettingsSection(sectionBtn.getAttribute('data-settings-section-target'));
            return;
        }

        const shortcutBtn = event.target.closest('[data-settings-shortcut-target]');
        if (shortcutBtn) {
            event.preventDefault();
            const details = document.getElementById('settings-advanced');
            if (details) {
                details.open = true;
            }
            setSettingsSection(shortcutBtn.getAttribute('data-settings-shortcut-target') || SETTINGS_SECTION_DEFAULT);
            return;
        }

        const pwnProbeBtn = event.target.closest('#btn-conf-pwn-test');
        if (pwnProbeBtn) {
            event.preventDefault();
            void testPwnagotchiConnection();
            return;
        }

        const probeBtn = event.target.closest('#btn-conf-m5-test');
        if (probeBtn) {
            event.preventDefault();
            void testM5Connection();
            return;
        }

        const bruceProbeBtn = event.target.closest('#btn-conf-bruce-test');
        if (bruceProbeBtn) {
            event.preventDefault();
            void testBruceConnection();
        }
    });

    // Live preview: visual theme changes
    const vtSelect = document.getElementById('conf-ui-visual-theme');
    if (vtSelect) {
        vtSelect.addEventListener('change', () => {
            const vt = vtSelect.value;
            applyVisualTheme(vt);
            updateThemeSelectOptions(vt);
            applyTheme(document.getElementById('conf-ui-theme')?.value || 'cyan');
        });
    }

    // Live preview: color preset changes
    const themeSelect = document.getElementById('conf-ui-theme');
    if (themeSelect) {
        themeSelect.addEventListener('change', () => {
            applyTheme(themeSelect.value);
        });
    }

    modal.dataset.sectionsBound = '1';
}

export function applyClientConfig(config = {}, options = {}) {
    const { refreshNoGps = false } = options;
    const root = document.documentElement;

    uiConfig.visualTheme = normalizeVisualTheme(config.ui_visual_theme);
    uiConfig.theme = normalizeThemeForVisual(config.ui_theme, uiConfig.visualTheme);
    uiConfig.iconPwned = config.ui_icon_pwned || uiConfig.iconPwned;
    uiConfig.iconLocked = config.ui_icon_locked || uiConfig.iconLocked;
    uiConfig.iconOpen = config.ui_icon_open || uiConfig.iconOpen;
    uiConfig.iconWardrive = config.ui_icon_wardrive || uiConfig.iconWardrive;
    uiConfig.wardriveColor = config.ui_wardrive_color || uiConfig.wardriveColor;
    uiConfig.wardriveStyle = config.ui_wardrive_style || uiConfig.wardriveStyle;
    STATE.ui.hidePasswords = !!config.ui_hide_passwords;

    applyVisualTheme(uiConfig.visualTheme);
    applyTheme(uiConfig.theme);
    applyWardriveColor(uiConfig.wardriveColor);
    applyLayoutSettings(config);
    root.dataset.crackingAccordionMode = normalizeCrackingAccordionMode(config.ui_cracking_accordion_mode);
    root.dataset.crackingAttackPanelMode = normalizeCrackingAttackPanelMode(config.ui_cracking_attack_panel_mode);
    setMarkerIcons(
        uiConfig.iconPwned,
        uiConfig.iconLocked,
        uiConfig.iconWardrive,
        uiConfig.wardriveStyle,
        uiConfig.iconOpen
    );

    if (window.setTileLayer && config.map_tile) {
        window.setTileLayer(config.map_tile);
    }
    if (window.setClusterConfig && config.map_cluster_mode) {
        window.setClusterConfig(config.map_cluster_mode);
    }

    window.dispatchEvent(new CustomEvent('kovil:config-applied', {
        detail: {
            config: {
                ...config,
                ui_hud_density: normalizeHudDensity(config.ui_hud_density),
                ui_sidebar_preset: normalizeSidebarPreset(config.ui_sidebar_preset),
                ui_font_scale: normalizeFontScale(config.ui_font_scale),
                ui_cracking_accordion_mode: normalizeCrackingAccordionMode(config.ui_cracking_accordion_mode),
                ui_cracking_attack_panel_mode: normalizeCrackingAttackPanelMode(config.ui_cracking_attack_panel_mode),
                ui_wardrive_replay_speed_default: normalizeWardriveReplaySpeedDefault(config.ui_wardrive_replay_speed_default),
                ui_wardrive_replay_follow_camera_default: !!config.ui_wardrive_replay_follow_camera_default,
                ui_wardrive_sessions_sort_by: normalizeWardriveSessionsSortBy(config.ui_wardrive_sessions_sort_by),
                ui_wardrive_sessions_sort_direction: normalizeSortDirection(config.ui_wardrive_sessions_sort_direction),
                ui_wardrive_replay_follow_zoom_default: normalizeWardriveReplayFollowZoomDefault(config.ui_wardrive_replay_follow_zoom_default),
                ui_wardrive_replay_timing_mode_default: normalizeWardriveReplayTimingModeDefault(config.ui_wardrive_replay_timing_mode_default),
                ui_wardrive_route_accent_color: normalizeWardriveAccentColor(config.ui_wardrive_route_accent_color, 'theme'),
                ui_wardrive_primary_zone_accent_color: normalizeWardriveAccentColor(config.ui_wardrive_primary_zone_accent_color, 'theme'),
                ui_wardrive_secondary_accent_color: normalizeWardriveAccentColor(config.ui_wardrive_secondary_accent_color, 'amber'),
            },
        },
    }));

    window.dispatchEvent(new Event('resize'));

    if (refreshNoGps && STATE.modes.noGps) {
        updateNoGpsList();
    }
}

export async function openSettings() {
    const modal = document.getElementById('settings-modal');
    if (!modal) return;
    ensureSettingsUiBound();
    modal.style.display = 'flex';
    setSettingsSection(SETTINGS_SECTION_DEFAULT);
    const advanced = document.getElementById('settings-advanced');
    if (advanced) advanced.open = false;
    
    try {
        const [config, devices, demoStatus] = await Promise.all([
            API.getConfig(),
            API.getHashcatDevices(),
            API.getDemoDataStatus().catch(() => null),
        ]);
        renderDemoDataStatus(demoStatus);
        setInputValue('conf-ip', config.pwn_host, '');
        setInputValue('conf-port', config.pwn_port ?? 22, '22');
        setInputValue('conf-user', config.pwn_user, '');
        setSyncPasswordStates(config);
        setInputValue('conf-path', config.remote_path, '');
        setCheckboxValue('conf-pwn-enabled', config.pwn_sync_enabled !== false);
        setCheckboxValue('conf-force-sync', config.pwn_force_sync ?? config.force_sync ?? false);
        setCheckboxValue('conf-m5-enabled', config.m5_sync_enabled || false);
        setCheckboxValue('conf-m5-force-sync', config.m5_force_sync || false);
        setInputValue('conf-m5-host', config.m5_host || M5_CARDPUTER_PRESET.host, M5_CARDPUTER_PRESET.host);
        setInputValue('conf-m5-port', config.m5_port ?? M5_CARDPUTER_PRESET.port, M5_CARDPUTER_PRESET.port);
        setInputValue('conf-m5-user', config.m5_web_user || M5_CARDPUTER_PRESET.username, M5_CARDPUTER_PRESET.username);
        setCheckboxValue('conf-bruce-enabled', config.bruce_sync_enabled || false);
        setCheckboxValue('conf-bruce-force-sync', config.bruce_force_sync || false);
        setInputValue('conf-bruce-host', config.bruce_host || BRUCE_WEBUI_PRESET.host, BRUCE_WEBUI_PRESET.host);
        setInputValue('conf-bruce-port', config.bruce_port ?? BRUCE_WEBUI_PRESET.port, BRUCE_WEBUI_PRESET.port);
        setInputValue('conf-bruce-user', config.bruce_web_user || BRUCE_WEBUI_PRESET.username, BRUCE_WEBUI_PRESET.username);
        setPwnProbeStatus('', 'neutral');
        setM5ProbeStatus('', 'neutral');
        setBruceProbeStatus('', 'neutral');
        setInputValue('conf-hashcat', config.hashcat_path || 'hashcat', 'hashcat');
        setInputValue('conf-hcx', config.hcxpcapngtool_path || 'hcxpcapngtool', 'hcxpcapngtool');
        setInputValue('conf-aircrack', config.aircrack_path || 'aircrack-ng', 'aircrack-ng');
        setInputValue('conf-tshark', config.tshark_path || 'tshark', 'tshark');
        setInputValue('conf-custom-wordlists', config.custom_wordlists_path || '', '');
        setInputValue('conf-custom-rules', config.custom_rules_path || '', '');
        setInputValue('conf-custom-masks', config.custom_masks_path || '', '');
        setInputValue('conf-known-hosts', config.ssh_known_hosts_path || '', '');
        setCheckboxValue('conf-wsl', config.use_wsl || false);
        setSelectValue('conf-map-tile', config.map_tile || 'carto_dark', 'carto_dark');
        setSelectValue('conf-map-cluster', config.map_cluster_mode || 'surgical', 'surgical');
        
        setCheckboxValue('conf-optimized', config.hashcat_optimized || false);
        setCheckboxValue('conf-slow', config.hashcat_slow || false);
        setCheckboxValue('conf-potfile', config.hashcat_potfile || false);
        setSelectValue('conf-attack-mode', config.attack_mode || 'straight', 'straight');
        setSelectValue('conf-workload-profile', String(config.workload_profile || '3'), '3');
        setSelectValue(
            'conf-wardrive-replay-speed-default',
            normalizeWardriveReplaySpeedDefault(config.ui_wardrive_replay_speed_default),
            '1'
        );
        setCheckboxValue('conf-wardrive-replay-autoplay', config.ui_wardrive_replay_autoplay || false);
        setCheckboxValue('conf-wardrive-replay-auto-focus', config.ui_wardrive_replay_auto_focus !== false);
        setCheckboxValue(
            'conf-wardrive-replay-follow-camera-default',
            config.ui_wardrive_replay_follow_camera_default || false
        );
        setSelectValue(
            'conf-wardrive-replay-follow-zoom-default',
            normalizeWardriveReplayFollowZoomDefault(config.ui_wardrive_replay_follow_zoom_default),
            'current'
        );
        setSelectValue(
            'conf-wardrive-replay-timing-mode-default',
            normalizeWardriveReplayTimingModeDefault(config.ui_wardrive_replay_timing_mode_default),
            'real_time'
        );
        setSelectValue(
            'conf-wardrive-sessions-sort-by-default',
            normalizeWardriveSessionsSortBy(config.ui_wardrive_sessions_sort_by),
            'none'
        );
        setSelectValue(
            'conf-wardrive-sessions-sort-direction-default',
            normalizeSortDirection(config.ui_wardrive_sessions_sort_direction),
            'desc'
        );
        setCheckboxValue(
            'conf-wardrive-merge-confirmation',
            config.ui_wardrive_merge_confirmation !== false
        );
        setSelectValue(
            'conf-wardrive-route-accent-color',
            normalizeWardriveAccentColor(config.ui_wardrive_route_accent_color, 'theme'),
            'theme'
        );
        setSelectValue(
            'conf-wardrive-primary-zone-accent-color',
            normalizeWardriveAccentColor(config.ui_wardrive_primary_zone_accent_color, 'theme'),
            'theme'
        );
        setSelectValue(
            'conf-wardrive-secondary-accent-color',
            normalizeWardriveAccentColor(config.ui_wardrive_secondary_accent_color, 'amber'),
            'amber'
        );

        const deviceSelect = document.getElementById('conf-hashcat-device');
        if (deviceSelect) {
            deviceSelect.innerHTML = '';
            const autoOpt = document.createElement('option');
            autoOpt.value = 'all';
            autoOpt.innerText = 'Auto / All';
            deviceSelect.appendChild(autoOpt);
            if (devices && devices.length > 0) {
                devices.forEach(d => {
                    const opt = document.createElement('option');
                    opt.value = d.id;
                    opt.innerText = `Device #${d.id}: ${d.name} (${d.type} - ${d.backend})`;
                    deviceSelect.appendChild(opt);
                });
            }
            const defaultDevice = config.hashcat_device_default || 'all';
            deviceSelect.value = defaultDevice;
            if (deviceSelect.value !== defaultDevice) {
                deviceSelect.value = 'all';
            }
        }
        
        const visTheme = normalizeVisualTheme(config.ui_visual_theme);
        setSelectValue('conf-ui-visual-theme', visTheme, 'professional');
        updateThemeSelectOptions(visTheme);
        const colorPreset = normalizeThemeForVisual(config.ui_theme, visTheme);
        let fallbackTheme = 'purple';
        if (visTheme === 'professional') fallbackTheme = 'slate';
        else if (visTheme === 'synthwave') fallbackTheme = 'sunset';
        else if (visTheme === 'military') fallbackTheme = 'tactical';
        setSelectValue('conf-ui-theme', colorPreset, fallbackTheme);
        setSelectValue('conf-icon-pwned', config.ui_icon_pwned || 'fa-skull', 'fa-skull');
        setSelectValue('conf-icon-locked', config.ui_icon_locked || 'fa-shield-halved', 'fa-shield-halved');
        setSelectValue('conf-icon-open', config.ui_icon_open || 'fa-bolt', 'fa-bolt');
        setSelectValue('conf-icon-wardrive', config.ui_icon_wardrive || 'fa-tower-broadcast', 'fa-tower-broadcast');
        setSelectValue('conf-wardrive-color', config.ui_wardrive_color || 'teal', 'teal');
        setSelectValue('conf-wardrive-style', config.ui_wardrive_style || 'icon', 'icon');
        setCheckboxValue('conf-hide-passwords', config.ui_hide_passwords || false);
        setSelectValue('conf-ui-hud-density', normalizeHudDensity(config.ui_hud_density), 'balanced');
        setSelectValue('conf-ui-sidebar-preset', normalizeSidebarPreset(config.ui_sidebar_preset), 'standard');
        setSelectValue('conf-ui-font-scale', normalizeFontScale(config.ui_font_scale), '100');
        setSelectValue('conf-ui-cracking-accordion-mode', normalizeCrackingAccordionMode(config.ui_cracking_accordion_mode), 'multi');
        setSelectValue('conf-ui-cracking-attack-panel-mode', normalizeCrackingAttackPanelMode(config.ui_cracking_attack_panel_mode), 'multi');
        applyLayoutSettings(config);
        
    } catch (e) {
        log("Failed to load config from backend", "error");
        renderDemoDataStatus(null);
    }
}

export function closeSettings() {
    const modal = document.getElementById('settings-modal');
    if (modal) modal.style.display = 'none';
}

export async function saveSettings() {
    const passwordValue = document.getElementById('conf-pass')?.value || '';
    const m5PasswordValue = document.getElementById('conf-m5-password')?.value || '';
    const brucePasswordValue = document.getElementById('conf-bruce-password')?.value || '';
    const selectedVisualTheme = normalizeVisualTheme(document.getElementById('conf-ui-visual-theme')?.value);
    const config = {
        pwn_sync_enabled: !!document.getElementById('conf-pwn-enabled')?.checked,
        pwn_host: document.getElementById('conf-ip')?.value || '',
        pwn_port: Number(document.getElementById('conf-port')?.value || 22),
        pwn_user: document.getElementById('conf-user')?.value || '',
        remote_path: document.getElementById('conf-path')?.value || '',
        pwn_force_sync: !!document.getElementById('conf-force-sync')?.checked,
        m5_sync_enabled: !!document.getElementById('conf-m5-enabled')?.checked,
        m5_force_sync: !!document.getElementById('conf-m5-force-sync')?.checked,
        m5_host: document.getElementById('conf-m5-host')?.value || M5_CARDPUTER_PRESET.host,
        m5_port: Number(document.getElementById('conf-m5-port')?.value || M5_CARDPUTER_PRESET.port),
        m5_web_protocol: 'http',
        m5_admin_base_path: M5_CARDPUTER_PRESET.adminBasePath,
        m5_web_user: document.getElementById('conf-m5-user')?.value || M5_CARDPUTER_PRESET.username,
        m5_handshake_remote_path: M5_CARDPUTER_PRESET.handshakePath,
        m5_wardrive_remote_path: M5_CARDPUTER_PRESET.wardrivePath,
        bruce_sync_enabled: !!document.getElementById('conf-bruce-enabled')?.checked,
        bruce_force_sync: !!document.getElementById('conf-bruce-force-sync')?.checked,
        bruce_host: document.getElementById('conf-bruce-host')?.value || BRUCE_WEBUI_PRESET.host,
        bruce_port: Number(document.getElementById('conf-bruce-port')?.value || BRUCE_WEBUI_PRESET.port),
        bruce_web_protocol: BRUCE_WEBUI_PRESET.protocol,
        bruce_web_user: document.getElementById('conf-bruce-user')?.value || BRUCE_WEBUI_PRESET.username,
        hashcat_path: document.getElementById('conf-hashcat')?.value || '',
        hcxpcapngtool_path: document.getElementById('conf-hcx')?.value || '',
        aircrack_path: document.getElementById('conf-aircrack')?.value || '',
        tshark_path: document.getElementById('conf-tshark')?.value || '',
        custom_wordlists_path: document.getElementById('conf-custom-wordlists')?.value || '',
        custom_rules_path: document.getElementById('conf-custom-rules')?.value || '',
        custom_masks_path: document.getElementById('conf-custom-masks')?.value || '',
        ssh_known_hosts_path: document.getElementById('conf-known-hosts')?.value || '',
        use_wsl: !!document.getElementById('conf-wsl')?.checked,
        map_tile: document.getElementById('conf-map-tile')?.value || 'carto_dark',
        map_cluster_mode: document.getElementById('conf-map-cluster')?.value || 'surgical',
        force_sync: !!document.getElementById('conf-force-sync')?.checked,
        attack_mode: document.getElementById('conf-attack-mode')?.value || 'straight',
        workload_profile: document.getElementById('conf-workload-profile')?.value || '3',
        hashcat_optimized: !!document.getElementById('conf-optimized')?.checked,
        hashcat_slow: !!document.getElementById('conf-slow')?.checked,
        hashcat_potfile: !!document.getElementById('conf-potfile')?.checked,
        hashcat_device_default: document.getElementById('conf-hashcat-device')?.value || 'all',

        ui_visual_theme: selectedVisualTheme,
        ui_theme: normalizeThemeForVisual(
            document.getElementById('conf-ui-theme')?.value,
            selectedVisualTheme
        ),
        ui_icon_pwned: document.getElementById('conf-icon-pwned')?.value || 'fa-skull',
        ui_icon_locked: document.getElementById('conf-icon-locked')?.value || 'fa-shield-halved',
        ui_icon_open: document.getElementById('conf-icon-open')?.value || 'fa-bolt',
        ui_icon_wardrive: document.getElementById('conf-icon-wardrive')?.value || 'fa-tower-broadcast',
        ui_wardrive_color: document.getElementById('conf-wardrive-color')?.value || 'teal',
        ui_wardrive_style: document.getElementById('conf-wardrive-style')?.value || 'icon',
        ui_hide_passwords: !!document.getElementById('conf-hide-passwords')?.checked,
        ui_hud_density: normalizeHudDensity(document.getElementById('conf-ui-hud-density')?.value),
        ui_sidebar_preset: normalizeSidebarPreset(document.getElementById('conf-ui-sidebar-preset')?.value),
        ui_font_scale: normalizeFontScale(document.getElementById('conf-ui-font-scale')?.value),
        ui_cracking_accordion_mode: normalizeCrackingAccordionMode(
            document.getElementById('conf-ui-cracking-accordion-mode')?.value
        ),
        ui_cracking_attack_panel_mode: normalizeCrackingAttackPanelMode(
            document.getElementById('conf-ui-cracking-attack-panel-mode')?.value
        ),
        ui_wardrive_replay_speed_default: normalizeWardriveReplaySpeedDefault(
            document.getElementById('conf-wardrive-replay-speed-default')?.value
        ),
        ui_wardrive_replay_autoplay: !!document.getElementById('conf-wardrive-replay-autoplay')?.checked,
        ui_wardrive_replay_auto_focus: !!document.getElementById('conf-wardrive-replay-auto-focus')?.checked,
        ui_wardrive_replay_follow_camera_default: !!document.getElementById('conf-wardrive-replay-follow-camera-default')?.checked,
        ui_wardrive_replay_follow_zoom_default: normalizeWardriveReplayFollowZoomDefault(
            document.getElementById('conf-wardrive-replay-follow-zoom-default')?.value
        ),
        ui_wardrive_replay_timing_mode_default: normalizeWardriveReplayTimingModeDefault(
            document.getElementById('conf-wardrive-replay-timing-mode-default')?.value
        ),
        ui_wardrive_sessions_sort_by: normalizeWardriveSessionsSortBy(
            document.getElementById('conf-wardrive-sessions-sort-by-default')?.value
        ),
        ui_wardrive_sessions_sort_direction: normalizeSortDirection(
            document.getElementById('conf-wardrive-sessions-sort-direction-default')?.value
        ),
        ui_wardrive_merge_confirmation: !!document.getElementById('conf-wardrive-merge-confirmation')?.checked,
        ui_wardrive_route_accent_color: normalizeWardriveAccentColor(
            document.getElementById('conf-wardrive-route-accent-color')?.value,
            'theme'
        ),
        ui_wardrive_primary_zone_accent_color: normalizeWardriveAccentColor(
            document.getElementById('conf-wardrive-primary-zone-accent-color')?.value,
            'theme'
        ),
        ui_wardrive_secondary_accent_color: normalizeWardriveAccentColor(
            document.getElementById('conf-wardrive-secondary-accent-color')?.value,
            'amber'
        ),
    };

    if (passwordValue) {
        config.pwn_pass = passwordValue;
    }
    if (m5PasswordValue) {
        config.m5_web_password = m5PasswordValue;
    }
    if (brucePasswordValue) {
        config.bruce_web_password = brucePasswordValue;
    }

    try {
        const savedConfig = await API.saveConfig(config);
        log("Configuration saved to backend.", "success");
        closeSettings();
        applyClientConfig({ ...config, ...(savedConfig || {}) }, { refreshNoGps: true });
    } catch (e) {
        log("Failed to save config.", "error");
    }
}

export const __testUiSettingsHelpers = {
    normalizeVisualTheme,
    normalizeThemeForVisual,
    normalizeHudDensity,
    normalizeSidebarPreset,
    normalizeFontScale,
    normalizeCrackingAccordionMode,
    normalizeWardriveReplaySpeedDefault,
    normalizeWardriveReplayTimingModeDefault,
    normalizeWardriveReplayFollowZoomDefault,
    normalizeWardriveSessionsSortBy,
    normalizeSortDirection,
    normalizeWardriveAccentColor,
    setInputValue,
    setPasswordInputState,
    setSyncPasswordStates,
    setCheckboxValue,
    setSelectValue,
    setPwnProbeStatus,
    setM5ProbeStatus,
    setBruceProbeStatus,
    renderDemoDataStatus,
    formatPwnProbeFeedback,
    formatM5ProbeFeedback,
    formatBruceProbeFeedback,
    setSettingsSection,
    ensureSettingsUiBound,
    applyM5CardputerPreset,
    buildPwnProbePayload,
    buildM5ProbePayload,
    buildBruceProbePayload,
    testPwnagotchiConnection,
    testM5Connection,
    testBruceConnection,
};
