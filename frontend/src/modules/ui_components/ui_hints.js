import { escapeHtml } from '../utils.js';

const HINT_POPOVER_ID = 'ui-hint-popover';

let _activeTrigger = null;
let _isPinned = false;

function _getHintPopover() {
    let popover = document.getElementById(HINT_POPOVER_ID);
    if (popover) return popover;

    popover = document.createElement('div');
    popover.id = HINT_POPOVER_ID;
    popover.className = 'ui-hint-popover';
    popover.setAttribute('role', 'tooltip');
    popover.setAttribute('aria-hidden', 'true');
    popover.innerHTML = `
        <div class="ui-hint-popover-title" hidden></div>
        <div class="ui-hint-popover-body"></div>
    `;
    document.body.appendChild(popover);
    return popover;
}

function _readHintPayload(trigger) {
    const text = String(trigger?.dataset?.uiHint || '').trim();
    const title = String(trigger?.dataset?.uiHintTitle || '').trim();
    return { title, text };
}

function _positionHintPopover(trigger, popover) {
    if (!trigger || !popover) return;
    const rect = trigger.getBoundingClientRect();
    const popoverRect = popover.getBoundingClientRect();
    const gap = 10;
    const placement = String(trigger.dataset.uiHintPlacement || 'auto').toLowerCase();

    const candidates = placement === 'top-left'
        ? ['top-left', 'top-right', 'bottom-left', 'bottom-right']
        : placement === 'right'
            ? ['right', 'top-right', 'bottom-right', 'left']
            : placement === 'left'
                ? ['left', 'top-left', 'bottom-left', 'right']
                : ['top-right', 'top-left', 'bottom-right', 'bottom-left', 'right', 'left'];

    const fits = {
        'top-right': rect.top >= popoverRect.height + gap + 12 && rect.right >= popoverRect.width + 12,
        'top-left': rect.top >= popoverRect.height + gap + 12 && rect.left + popoverRect.width <= window.innerWidth - 12,
        'bottom-right': rect.bottom + popoverRect.height + gap <= window.innerHeight - 12 && rect.right >= popoverRect.width + 12,
        'bottom-left': rect.bottom + popoverRect.height + gap <= window.innerHeight - 12 && rect.left + popoverRect.width <= window.innerWidth - 12,
        right: rect.right + popoverRect.width + gap <= window.innerWidth - 12,
        left: rect.left >= popoverRect.width + gap + 12,
    };

    const chosen = candidates.find((candidate) => fits[candidate]) || 'top-right';
    let left = rect.right - popoverRect.width;
    let top = rect.top - popoverRect.height - gap;

    switch (chosen) {
        case 'top-left':
            left = rect.left;
            top = rect.top - popoverRect.height - gap;
            break;
        case 'bottom-right':
            left = rect.right - popoverRect.width;
            top = rect.bottom + gap;
            break;
        case 'bottom-left':
            left = rect.left;
            top = rect.bottom + gap;
            break;
        case 'right':
            left = rect.right + gap;
            top = rect.top + (rect.height / 2) - (popoverRect.height / 2);
            break;
        case 'left':
            left = rect.left - popoverRect.width - gap;
            top = rect.top + (rect.height / 2) - (popoverRect.height / 2);
            break;
        case 'top-right':
        default:
            left = rect.right - popoverRect.width;
            top = rect.top - popoverRect.height - gap;
            break;
    }

    left = Math.max(12, Math.min(left, window.innerWidth - popoverRect.width - 12));
    top = Math.max(12, Math.min(top, window.innerHeight - popoverRect.height - 12));

    popover.style.left = `${Math.round(left)}px`;
    popover.style.top = `${Math.round(top)}px`;
    popover.dataset.side = chosen;
}

function _setExpanded(trigger, expanded) {
    if (!trigger) return;
    trigger.setAttribute('aria-expanded', expanded ? 'true' : 'false');
}

export function hideGlobalHint() {
    const popover = document.getElementById(HINT_POPOVER_ID);
    if (popover) {
        popover.classList.remove('is-open');
        popover.setAttribute('aria-hidden', 'true');
    }
    _setExpanded(_activeTrigger, false);
    _activeTrigger = null;
    _isPinned = false;
}

export function showGlobalHint(trigger, { pinned = false } = {}) {
    const payload = _readHintPayload(trigger);
    if (!payload.text) {
        hideGlobalHint();
        return;
    }

    const popover = _getHintPopover();
    const titleEl = popover.querySelector('.ui-hint-popover-title');
    const bodyEl = popover.querySelector('.ui-hint-popover-body');
    if (!titleEl || !bodyEl) return;

    titleEl.textContent = payload.title;
    titleEl.hidden = !payload.title;
    bodyEl.textContent = payload.text;

    _setExpanded(_activeTrigger, false);
    _activeTrigger = trigger;
    _isPinned = pinned;
    _setExpanded(trigger, true);

    popover.classList.add('is-open');
    popover.setAttribute('aria-hidden', 'false');
    _positionHintPopover(trigger, popover);
}

export function buildHintTrigger(
    text,
    {
        label = 'Explain this item',
        title = '',
        iconClass = 'fa-circle-question',
        buttonClass = '',
        placement = 'auto',
    } = {},
) {
    const hintText = String(text || '').trim();
    if (!hintText) return '';
    const classes = ['ui-hint-trigger'];
    if (buttonClass) classes.push(buttonClass);
    return `<button type="button" class="${classes.join(' ')}" data-ui-hint="${escapeHtml(hintText)}"${title ? ` data-ui-hint-title="${escapeHtml(title)}"` : ''} data-ui-hint-placement="${escapeHtml(placement)}" aria-label="${escapeHtml(label)}" aria-expanded="false">
        <i class="fa-solid ${escapeHtml(iconClass)}" aria-hidden="true"></i>
    </button>`;
}

export function buildHintLabel(
    label,
    text,
    {
        title = '',
        triggerLabel = '',
        wrapperClass = '',
        labelClass = '',
        buttonClass = '',
        placement = 'auto',
    } = {},
) {
    const classes = ['ui-hint-inline'];
    if (wrapperClass) classes.push(wrapperClass);
    return `<span class="${classes.join(' ')}">
        <span class="${labelClass || 'ui-hint-label'}">${escapeHtml(label)}</span>
        ${buildHintTrigger(text, {
            label: triggerLabel || `Explain ${label}`,
            title,
            buttonClass,
            placement,
        })}
    </span>`;
}

export function setupGlobalHints() {
    if (document.documentElement.dataset.uiHintsBound === '1') return;
    document.documentElement.dataset.uiHintsBound = '1';

    document.addEventListener('mouseover', (event) => {
        const trigger = event.target.closest('[data-ui-hint]');
        if (!trigger || _isPinned) return;
        showGlobalHint(trigger);
    });

    document.addEventListener('mouseout', (event) => {
        if (_isPinned) return;
        const trigger = event.target.closest('[data-ui-hint]');
        if (!trigger || trigger !== _activeTrigger) return;
        const nextTarget = event.relatedTarget;
        if (nextTarget && trigger.contains(nextTarget)) return;
        hideGlobalHint();
    });

    document.addEventListener('focusin', (event) => {
        const trigger = event.target.closest('[data-ui-hint]');
        if (!trigger) return;
        showGlobalHint(trigger);
    });

    document.addEventListener('focusout', (event) => {
        if (_isPinned) return;
        const trigger = event.target.closest('[data-ui-hint]');
        if (!trigger || trigger !== _activeTrigger) return;
        hideGlobalHint();
    });

    document.addEventListener('click', (event) => {
        const trigger = event.target.closest('[data-ui-hint]');
        if (!trigger) {
            if (_isPinned) hideGlobalHint();
            return;
        }
        event.preventDefault();
        if (_activeTrigger === trigger && _isPinned) {
            hideGlobalHint();
            return;
        }
        showGlobalHint(trigger, { pinned: true });
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') hideGlobalHint();
    });

    window.addEventListener('resize', () => {
        const popover = document.getElementById(HINT_POPOVER_ID);
        if (_activeTrigger && popover && popover.classList.contains('is-open')) {
            _positionHintPopover(_activeTrigger, popover);
        }
    });

    window.addEventListener('scroll', () => {
        const popover = document.getElementById(HINT_POPOVER_ID);
        if (_activeTrigger && popover && popover.classList.contains('is-open')) {
            _positionHintPopover(_activeTrigger, popover);
        }
    }, true);
}

export const __testUiHints = {
    _getHintPopover,
    _readHintPayload,
};
