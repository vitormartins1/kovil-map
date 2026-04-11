export function buildWardriveLoadingRows(count = 4) {
    return Array.from({ length: count }, (_, index) => (
        `<div class="wardrive-loading-row${index === 0 ? ' wardrive-loading-row--strong' : ''}"></div>`
    )).join('');
}

export function buildWardriveLoadingKpiCards(count = 4) {
    return Array.from({ length: count }, () => `
        <div class="wardrive-session-kpi-card wardrive-session-kpi-card--loading">
            <div class="wardrive-loading-row wardrive-loading-row--strong"></div>
            <div class="wardrive-loading-row"></div>
        </div>
    `).join('');
}

export function buildWardriveLoadingBlocks(count = 4) {
    return Array.from({ length: count }, () => '<div class="wardrive-loading-block"></div>').join('');
}

export function buildWardriveSessionLoadingCards(count = 4) {
    return Array.from({ length: count }, () => `
        <div class="wardrive-session-skeleton-card">
            <div class="wardrive-loading-row wardrive-loading-row--strong"></div>
            <div class="wardrive-loading-row"></div>
            <div class="wardrive-loading-row"></div>
        </div>
    `).join('');
}

export function yieldWardriveUiPaint() {
    return new Promise((resolve) => {
        if (typeof MessageChannel !== 'undefined') {
            const channel = new MessageChannel();
            channel.port1.onmessage = () => {
                channel.port1.close?.();
                channel.port2.close?.();
                resolve();
            };
            channel.port2.postMessage(null);
            return;
        }
        Promise.resolve().then(resolve);
    });
}
