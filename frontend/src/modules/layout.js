const DEFAULT_LAYOUT = {
    leftSidebarW: 280,
    rightPanelsW: 500,
    hudInset: 20,
    hudPanTop: 60,
    hudPanBottom: 30,
};

function readCssNumber(varName, fallback) {
    if (typeof window === 'undefined' || !window.getComputedStyle) {
        return fallback;
    }
    const root = document?.documentElement;
    if (!root) return fallback;
    const raw = window.getComputedStyle(root).getPropertyValue(varName);
    const parsed = Number.parseFloat(String(raw || '').replace('px', '').trim());
    return Number.isFinite(parsed) ? parsed : fallback;
}

export function getHudAutoPanPadding() {
    const leftSidebarW = readCssNumber('--left-sidebar-w', DEFAULT_LAYOUT.leftSidebarW);
    const rightPanelsW = readCssNumber('--right-panels-w', DEFAULT_LAYOUT.rightPanelsW);
    const hudInset = readCssNumber('--hud-inset', DEFAULT_LAYOUT.hudInset);
    const hudPanTop = readCssNumber('--hud-pan-top', DEFAULT_LAYOUT.hudPanTop);
    const hudPanBottom = readCssNumber('--hud-pan-bottom', DEFAULT_LAYOUT.hudPanBottom);

    return {
        topLeft: [Math.round(leftSidebarW + (hudInset * 2)), Math.round(hudPanTop)],
        bottomRight: [Math.round(rightPanelsW + (hudInset * 2)), Math.round(hudPanBottom)],
    };
}

