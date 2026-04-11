function getSessionStorage() {
    try {
        return window?.sessionStorage || null;
    } catch (_) {
        return null;
    }
}

export function readSessionStorageJson(key) {
    try {
        const storage = getSessionStorage();
        if (!storage) return null;
        const raw = storage.getItem(String(key || ''));
        if (!raw) return null;
        return JSON.parse(raw);
    } catch (_) {
        return null;
    }
}

export function writeSessionStorageJson(key, value, { maxBytes = Infinity } = {}) {
    try {
        const storage = getSessionStorage();
        if (!storage) return false;
        const payload = JSON.stringify(value);
        if (payload.length > maxBytes) return false;
        storage.setItem(String(key || ''), payload);
        return true;
    } catch (_) {
        return false;
    }
}

export function removeSessionStorageKeysByPrefix(prefix, { except = [] } = {}) {
    try {
        const storage = getSessionStorage();
        if (!storage) return;
        const allowed = new Set((Array.isArray(except) ? except : []).map((item) => String(item)));
        const keysToDelete = [];
        for (let i = 0; i < storage.length; i++) {
            const key = storage.key(i);
            if (!key || !key.startsWith(prefix) || allowed.has(key)) continue;
            keysToDelete.push(key);
        }
        keysToDelete.forEach((key) => storage.removeItem(key));
    } catch (_) {
        /* ignore storage cleanup issues */
    }
}
