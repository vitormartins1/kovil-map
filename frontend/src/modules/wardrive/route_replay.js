export function createWardriveRouteReplayRenderer(deps) {
    const {
        getNode,
        escapeHtml,
        buildHintTrigger,
        buildWardriveLoadingBlocks,
        buildWardriveLoadingKpiCards,
        buildWardriveLoadingRows,
        formatDistanceMeters,
        formatDuration,
        formatAccuracyMeters,
        formatWardriveReplaySpeed,
        getTransportMeta,
        getWardriveReplayTimingModeMeta,
        getWardriveSelectedSessions,
        getWardriveReplayTracks,
        getActiveWardriveReplayTrack,
        replayTimingModeOptions,
        replayFollowZoomOptions,
        getReplayState,
    } = deps;

    function renderWardriveReplayLoadingState({
        headline = 'Preparing workspace...',
        badge = 'LOADING',
        note = 'Loading route replay...',
    } = {}) {
        const target = getNode('wardrive-route-replay');
        if (!target) return;
        target.innerHTML = `
            <div class="wardrive-route-replay-stack">
                <div class="wardrive-route-replay-head wardrive-route-replay-head--compact">
                    <div class="wardrive-route-replay-mode">
                        <span class="wardrive-route-replay-mode-label">Replay mode</span>
                        <strong class="wardrive-route-replay-mode-value">${escapeHtml(headline)}</strong>
                    </div>
                    <div class="wardrive-route-replay-head-actions">
                        <span class="wardrive-route-replay-badge">${escapeHtml(badge)}</span>
                    </div>
                </div>
                <div class="wardrive-route-replay-loading-grid">
                    <div class="wardrive-loading-row wardrive-loading-row--strong"></div>
                    <div class="wardrive-session-kpi-grid wardrive-route-kpi-grid wardrive-loading-kpi-grid">
                        ${buildWardriveLoadingKpiCards(4)}
                    </div>
                    <div class="wardrive-loading-block-row">
                        ${buildWardriveLoadingBlocks(5)}
                    </div>
                    <div class="wardrive-loading-block-row wardrive-loading-block-row--compact">
                        ${buildWardriveLoadingBlocks(3)}
                    </div>
                    <div class="wardrive-route-replay-note">${escapeHtml(note)}</div>
                    <div class="wardrive-loading-row"></div>
                </div>
            </div>
        `;
    }

    function getWardriveReplayToggleMeta({ isPlaying = false, isReplayComplete = false } = {}) {
        if (isPlaying) {
            return { label: 'Pause replay', icon: 'fa-pause' };
        }
        if (isReplayComplete) {
            return { label: 'Replay route', icon: 'fa-rotate-right' };
        }
        return { label: 'Play replay', icon: 'fa-play' };
    }

    function getWardriveReplayNarrative(selectedCount) {
        const count = Math.max(0, Number(selectedCount || 0));
        if (count <= 0) {
            return {
                title: 'Route Replay',
                label: 'Replay mode',
                value: 'Select 1-3 sessions',
                badge: 'ALL DATA',
                hint: 'Replay supports up to 3 selected Wardrive sessions. With no session selected, the workspace stays scoped to the full WarDrive dataset for the current filters.',
            };
        }
        if (count === 1) {
            return {
                title: 'Single-session playback',
                label: 'Replay mode',
                value: '1 session active',
                badge: '1 SESSION',
                hint: 'Replay the selected drive path on the map and scrub capture history over time. Regions, DBSCAN zones and map markers stay focused on the selected capture window.',
            };
        }
        return {
            title: `Visual compare across ${count} sessions`,
            label: 'Compare mode',
            value: `${count} sessions active`,
            badge: `${count} SESSIONS`,
            hint: 'All selected routes stay visible on the map. One session stays active for playback at a time while regions, DBSCAN zones and markers stay filtered to the selected capture windows.',
        };
    }

    function getWardriveReplayTimingModesHint() {
        const current = getWardriveReplayTimingModeMeta();
        const catalog = replayTimingModeOptions
            .map((item) => `${item.label}: ${item.description}`)
            .join(' | ');
        return `Current mode: ${current.label}. ${current.description} All modes: ${catalog}`;
    }

    function syncWardriveReplayLiveUi() {
        const target = getNode('wardrive-route-replay');
        if (!target) return;

        const replayState = getReplayState();
        const activeTrack = getActiveWardriveReplayTrack();
        const activePoints = Array.isArray(activeTrack?.points) ? activeTrack.points : [];
        const activePointCount = activePoints.length;
        const progressValue = activePointCount > 1 ? Math.round(replayState.replayProgress * 1000) : 0;
        const isPlaying = Boolean(replayState.replayTimer);
        const isReplayComplete = !isPlaying && activePointCount > 1 && replayState.replayProgress >= 1;
        const toggleMeta = getWardriveReplayToggleMeta({ isPlaying, isReplayComplete });

        const toggleBtn = target.querySelector('[data-action="wardrive-replay-toggle"]');
        if (toggleBtn) {
            toggleBtn.disabled = activePointCount <= 1;
            toggleBtn.setAttribute('aria-label', toggleMeta.label);
            toggleBtn.setAttribute('title', toggleMeta.label);
            toggleBtn.setAttribute('data-state', isPlaying ? 'pause' : (isReplayComplete ? 'replay' : 'play'));
            toggleBtn.innerHTML = `<i class="fa-solid ${toggleMeta.icon}" aria-hidden="true"></i>`;
        }

        const resetBtn = target.querySelector('[data-action="wardrive-replay-reset"]');
        if (resetBtn) resetBtn.disabled = activePointCount <= 0;

        const focusBtn = target.querySelector('[data-action="wardrive-replay-focus"]');
        if (focusBtn) focusBtn.disabled = !(activeTrack?.bbox || activePointCount);

        const scrubber = target.querySelector('[data-action="wardrive-replay-scrub"]');
        if (scrubber) {
            scrubber.disabled = activePointCount <= 1;
            const nextValue = String(progressValue);
            if (scrubber.value !== nextValue) scrubber.value = nextValue;
        }

        const speedSelect = target.querySelector('[data-action="wardrive-replay-speed"]');
        if (speedSelect) {
            speedSelect.disabled = activePointCount <= 1;
            const nextSpeed = String(replayState.replaySpeed);
            if (speedSelect.value !== nextSpeed) speedSelect.value = nextSpeed;
        }

        const followBtn = target.querySelector('[data-action="wardrive-replay-follow-camera"]');
        if (followBtn) {
            followBtn.disabled = activePointCount <= 1;
            followBtn.classList.toggle('active', replayState.replayFollowCamera);
            followBtn.setAttribute('aria-pressed', replayState.replayFollowCamera ? 'true' : 'false');
            followBtn.setAttribute('aria-label', replayState.replayFollowCamera ? 'Disable follow camera' : 'Enable follow camera');
            followBtn.setAttribute('title', replayState.replayFollowCamera ? 'Disable follow camera' : 'Enable follow camera');
        }

        const timingModeSelect = target.querySelector('[data-action="wardrive-replay-timing-mode"]');
        if (timingModeSelect) {
            timingModeSelect.disabled = activePointCount <= 1;
            if (timingModeSelect.value !== replayState.replayTimingMode) {
                timingModeSelect.value = replayState.replayTimingMode;
            }
        }

        const zoomSelect = target.querySelector('[data-action="wardrive-replay-follow-zoom"]');
        if (zoomSelect) {
            zoomSelect.disabled = activePointCount <= 1;
            if (zoomSelect.value !== replayState.replayFollowZoom) {
                zoomSelect.value = replayState.replayFollowZoom;
            }
        }
    }

    function renderWardriveRouteReplaySection() {
        const target = getNode('wardrive-route-replay');
        if (!target) return;

        const replayState = getReplayState();
        if (replayState.workspaceBooting) {
            renderWardriveReplayLoadingState({
                headline: 'Preparing workspace...',
                note: 'Loading region hierarchy, sessions and route replay shell...',
            });
            return;
        }

        const selectedSessions = getWardriveSelectedSessions();
        const selectedCount = selectedSessions.length;
        const tracks = getWardriveReplayTracks();
        const activeTrack = getActiveWardriveReplayTrack();
        const activePoints = Array.isArray(activeTrack?.points) ? activeTrack.points : [];
        const activePointCount = activePoints.length;
        const progressValue = activePointCount > 1 ? Math.round(replayState.replayProgress * 1000) : 0;
        const isPlaying = Boolean(replayState.replayTimer);
        const isReplayComplete = !isPlaying && activePointCount > 1 && replayState.replayProgress >= 1;
        const canMergeSessions = (
            !replayState.sessionMergeLoading
            && selectedCount >= 2
            && selectedCount <= 3
            && tracks.length === selectedCount
        );
        const replayNarrative = getWardriveReplayNarrative(selectedCount);
        const toggleMeta = getWardriveReplayToggleMeta({ isPlaying, isReplayComplete });
        const timingModesHint = getWardriveReplayTimingModesHint();
        const replayHead = `
            <div class="wardrive-route-replay-head wardrive-route-replay-head--compact">
                <div class="wardrive-route-replay-mode">
                    <span class="wardrive-route-replay-mode-label">${escapeHtml(replayNarrative.label)}</span>
                    <strong class="wardrive-route-replay-mode-value">${escapeHtml(replayNarrative.value)}</strong>
                </div>
                <div class="wardrive-route-replay-head-actions">
                    <span class="wardrive-route-replay-badge">${escapeHtml(replayNarrative.badge)}</span>
                    ${buildHintTrigger(replayNarrative.hint, {
                        title: replayNarrative.title,
                        label: `Explain ${replayNarrative.title}`,
                        buttonClass: 'wardrive-route-replay-hint',
                        placement: 'top-right',
                    })}
                </div>
            </div>
        `;

        if (selectedCount === 0) {
            target.innerHTML = replayHead;
            return;
        }

        if (selectedCount > 3) {
            target.innerHTML = `
                <div class="wardrive-empty">
                    ${escapeHtml(String(selectedCount))} sessions selected. Route compare supports up to 3 sessions, so narrow the selection to continue.
                </div>
            `;
            return;
        }

        if (replayState.replayLoading) {
            renderWardriveReplayLoadingState({
                headline: replayNarrative.value,
                note: 'Loading route replay tracks...',
            });
            return;
        }

        if (!tracks.length) {
            target.innerHTML = `
                <div class="wardrive-route-replay-stack">
                    ${replayHead}
                    <div class="wardrive-empty">No replayable GPS tracks were found for the selected sessions.</div>
                </div>
            `;
            return;
        }

        const trackSwitcher = tracks.map((track) => {
            const isActive = String(track?.session_id || '') === String(activeTrack?.session_id || '');
            const transport = getTransportMeta(track?.transport_mode);
            return `
                <button
                    type="button"
                    class="wardrive-route-track-pill${isActive ? ' active' : ''}"
                    data-action="wardrive-replay-track"
                    data-session-id="${escapeHtml(String(track?.session_id || ''))}"
                >
                    <span class="wardrive-route-track-pill-icon" aria-hidden="true">
                        <i class="fa-solid ${escapeHtml(transport.icon)}"></i>
                    </span>
                    <span class="wardrive-route-track-pill-label">${escapeHtml(String(track?.label || track?.session_id || 'TRACK'))}</span>
                </button>
            `;
        }).join('');

        target.innerHTML = `
            <div class="wardrive-route-replay-stack">
                ${replayHead}
                <div class="wardrive-route-track-strip">
                    <div class="wardrive-route-track-switcher">
                        ${trackSwitcher}
                    </div>
                </div>

                <div class="wardrive-session-kpi-grid wardrive-route-kpi-grid">
                    <div class="wardrive-session-kpi-card"><span>DISTANCE</span><strong>${escapeHtml(formatDistanceMeters(activeTrack?.distance_m))}</strong></div>
                    <div class="wardrive-session-kpi-card"><span>DURATION</span><strong>${escapeHtml(formatDuration(0, activeTrack?.duration_s || 0))}</strong></div>
                    <div class="wardrive-session-kpi-card"><span>POINTS</span><strong>${escapeHtml(String(activeTrack?.points_count ?? 0))}</strong></div>
                    <div class="wardrive-session-kpi-card"><span>AVG ACC</span><strong>${escapeHtml(formatAccuracyMeters(activeTrack?.avg_accuracy_m))}</strong></div>
                </div>

                <div class="wardrive-route-replay-controls">
                    <button
                        type="button"
                        class="action-btn wardrive-route-replay-icon-btn"
                        data-action="wardrive-replay-toggle"
                        data-state="${isPlaying ? 'pause' : (isReplayComplete ? 'replay' : 'play')}"
                        aria-label="${escapeHtml(toggleMeta.label)}"
                        title="${escapeHtml(toggleMeta.label)}"
                        ${activePointCount > 1 ? '' : 'disabled'}
                    >
                        <i class="fa-solid ${escapeHtml(toggleMeta.icon)}" aria-hidden="true"></i>
                    </button>
                    <button
                        type="button"
                        class="action-btn wardrive-route-replay-icon-btn"
                        data-action="wardrive-replay-reset"
                        aria-label="Reset replay"
                        title="Reset replay"
                    >
                        <i class="fa-solid fa-rotate-left" aria-hidden="true"></i>
                    </button>
                    <button
                        type="button"
                        class="action-btn wardrive-route-replay-icon-btn${replayState.replayFollowCamera ? ' active' : ''}"
                        data-action="wardrive-replay-follow-camera"
                        aria-pressed="${replayState.replayFollowCamera ? 'true' : 'false'}"
                        aria-label="${replayState.replayFollowCamera ? 'Disable follow camera' : 'Enable follow camera'}"
                        title="${replayState.replayFollowCamera ? 'Disable follow camera' : 'Enable follow camera'}"
                        ${activePointCount > 1 ? '' : 'disabled'}
                    >
                        <i class="fa-solid fa-location-crosshairs" aria-hidden="true"></i>
                    </button>
                    <button
                        type="button"
                        class="action-btn wardrive-route-replay-text-btn"
                        data-action="wardrive-replay-focus"
                        title="Focus active track on map"
                        ${activeTrack?.bbox || activePointCount ? '' : 'disabled'}
                    >
                        FOCUS TRACK
                    </button>
                    <button
                        type="button"
                        class="action-btn wardrive-route-replay-text-btn"
                        data-action="wardrive-replay-merge"
                        ${canMergeSessions ? '' : 'disabled'}
                        title="${canMergeSessions ? 'Merge selected Wardrive sessions into one active session' : 'Select 2-3 replayable sessions to merge'}"
                    >
                        ${replayState.sessionMergeLoading ? 'MERGING...' : 'MERGE SESSIONS'}
                    </button>
                </div>

                <div class="wardrive-route-replay-inline-controls">
                    <label class="wardrive-route-replay-field">
                        <span class="wardrive-route-replay-field-head">
                            <span>MODE</span>
                            ${buildHintTrigger(timingModesHint, {
                                title: 'Replay timing modes',
                                label: 'Explain replay timing modes',
                                buttonClass: 'wardrive-route-replay-field-hint',
                                placement: 'top-right',
                            })}
                        </span>
                        <select
                            class="wardrive-route-replay-select"
                            data-action="wardrive-replay-timing-mode"
                            ${activePointCount > 1 ? '' : 'disabled'}
                        >
                            ${replayTimingModeOptions.map((item) => `
                                <option value="${item.value}" ${item.value === replayState.replayTimingMode ? 'selected' : ''}>
                                    ${escapeHtml(item.label)}
                                </option>
                            `).join('')}
                        </select>
                    </label>
                    <label class="wardrive-route-replay-field">
                        <span>ZOOM</span>
                        <select
                            class="wardrive-route-replay-select"
                            data-action="wardrive-replay-follow-zoom"
                            ${activePointCount > 1 ? '' : 'disabled'}
                        >
                            ${replayFollowZoomOptions.map((item) => `
                                <option value="${item.value}" ${item.value === replayState.replayFollowZoom ? 'selected' : ''}>
                                    ${escapeHtml(item.label)}
                                </option>
                            `).join('')}
                        </select>
                    </label>
                    <label class="wardrive-route-replay-field wardrive-route-replay-field--pace">
                        <span>PACE</span>
                        <select
                            class="wardrive-route-replay-select wardrive-route-replay-speed"
                            data-action="wardrive-replay-speed"
                            title="Replay pace"
                            aria-label="Replay pace"
                            ${activePointCount > 1 ? '' : 'disabled'}
                        >
                            ${replayState.replaySpeedOptions.map((speed) => `
                                <option value="${speed}" ${Number(speed) === Number(replayState.replaySpeed) ? 'selected' : ''}>
                                    ${escapeHtml(formatWardriveReplaySpeed(speed))}
                                </option>
                            `).join('')}
                        </select>
                    </label>
                </div>

                <div class="wardrive-route-replay-footer">
                    <div class="wardrive-route-replay-footer-label">TIMELINE</div>
                    <div class="wardrive-route-replay-scrubber-wrap">
                        <input
                            type="range"
                            class="wardrive-route-replay-scrubber"
                            min="0"
                            max="1000"
                            step="1"
                            value="${progressValue}"
                            data-action="wardrive-replay-scrub"
                            ${activePointCount > 1 ? '' : 'disabled'}
                        />
                        <div class="wardrive-route-replay-progress">${progressValue / 10}%</div>
                    </div>
                </div>
            </div>
        `;
    }

    return {
        renderWardriveReplayLoadingState,
        renderWardriveRouteReplaySection,
        syncWardriveReplayLiveUi,
    };
}
