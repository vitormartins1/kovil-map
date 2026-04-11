export function getRawSummaryFromPosition(pos) {
    const rawBeaconCount = Number(pos?.raw_beacon_count || 0);
    const rawEapolCount = Number(pos?.raw_eapol_count || 0);
    if (rawBeaconCount <= 0 && rawEapolCount <= 0) {
        return null;
    }
    return {
        rawBeaconCount,
        rawEapolCount,
        summaryText: `beacons ${rawBeaconCount} | eapol ${rawEapolCount}`,
    };
}

export function insertRawSummaryFallbackRow(pos) {
    const summary = getRawSummaryFromPosition(pos);
    if (!summary) return;

    const macKey = pos.mac.replace(/:/g, '');
    const rowsContainer = document.getElementById(`data-rows-${macKey}`);
    if (!rowsContainer) return;

    if (rowsContainer.querySelector('.popup-raw-summary-fallback')) return;

    const rawRowsContainer = document.getElementById(`raw-rows-${macKey}`) || rowsContainer;
    const rawSection = document.getElementById(`raw-section-${macKey}`) || rowsContainer.querySelector('[data-popup-section="raw"]');
    if (rawSection) {
        rawSection.classList.remove('popup-section-empty');
    }

    const row = document.createElement('div');
    row.className = 'data-row detail-row raw-summary-row popup-raw-summary-fallback';

    const labelSpan = document.createElement('span');
    labelSpan.className = 'd-label';
    labelSpan.textContent = 'RAW';

    const valueSpan = document.createElement('span');
    valueSpan.className = 'd-val';
    valueSpan.textContent = summary.summaryText;

    row.appendChild(labelSpan);
    row.appendChild(valueSpan);

    const passRow = document.getElementById(`pass-row-${macKey}`);
    if (rawRowsContainer === rowsContainer && passRow && passRow.parentNode === rowsContainer) {
        rowsContainer.insertBefore(row, passRow);
    } else {
        rawRowsContainer.appendChild(row);
    }
}
