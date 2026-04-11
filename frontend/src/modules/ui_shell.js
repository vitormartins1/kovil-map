const DEFAULT_TITLE = 'KOVIL MAP';
const TITLE_PREFIX = 'KOVIL MAP // CONQUERING';

export const STARTUP_PROGRESS = {
    init: 12,
    connecting: 16,
    backendBusy: 28,
    backendReady: 44,
    loadingData: 68,
    renderingWorkspace: 88,
    online: 100,
    retry: 22,
};

export function setBootVisualState({
    statusText,
    pillText,
    tone = 'boot',
    progress,
    progressLabel,
    subtitle,
    tip,
} = {}) {
    const statusEl = document.getElementById('boot-status');
    if (statusEl && statusText != null) statusEl.innerText = String(statusText).toUpperCase();

    const pillEl = document.getElementById('boot-status-pill');
    if (pillEl) {
        if (pillText != null) pillEl.innerText = String(pillText).toUpperCase();
        pillEl.dataset.tone = tone;
    }

    const barEl = document.getElementById('boot-progress-bar');
    if (barEl && progress != null) barEl.style.width = `${Math.max(0, Math.min(100, Number(progress) || 0))}%`;

    const progressValueEl = document.getElementById('boot-progress-value');
    if (progressValueEl && progress != null) progressValueEl.innerText = `${Math.round(Number(progress) || 0)}%`;

    const progressLabelEl = document.getElementById('boot-progress-label');
    if (progressLabelEl && progressLabel != null) progressLabelEl.innerText = progressLabel;

    const subtitleEl = document.getElementById('boot-subtitle');
    if (subtitleEl && subtitle != null) subtitleEl.innerText = subtitle;

    const tipEl = document.getElementById('boot-tip-copy');
    if (tipEl && tip != null) tipEl.innerText = tip;
}

export function setBootStepState(step, state, metaText) {
    const stepEl = document.querySelector(`[data-boot-step="${step}"]`);
    if (stepEl) {
        stepEl.classList.remove('is-active', 'is-done', 'is-error');
        if (state) stepEl.classList.add(`is-${state}`);
    }
    const metaEl = document.getElementById(`boot-step-${step}-meta`);
    if (metaEl && metaText != null) metaEl.innerText = metaText;
}

export function setAppTitle(text) {
    document.title = text;
    const titleEl = document.querySelector('#title-bar .app-title');
    if (titleEl) {
        titleEl.textContent = '';
        const icon = document.createElement('i');
        icon.className = 'fa-solid fa-ghost';
        titleEl.appendChild(icon);
        titleEl.appendChild(document.createTextNode(` ${text}`));
    }
}

export function buildCrackingTitle(percentage, extra) {
    const pct = Number.isFinite(percentage) ? Math.round(percentage) : 0;
    const extraText = (extra || '').toString().trim();
    return extraText
        ? `${TITLE_PREFIX} ${pct}% ${extraText}`
        : `${TITLE_PREFIX} ${pct}%`;
}

export function resetAppTitle() {
    setAppTitle(DEFAULT_TITLE);
}
