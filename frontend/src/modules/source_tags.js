const DEFAULT_SOURCE = "pwnagotchi";

const SOURCE_LABELS = {
    pwnagotchi: "PWNAGOTCHI",
    wardrive: "WARDRIVE",
    brucegotchi: "BRUCEGOTCHI",
    m5evil: "M5Evil",
    rawsniffer: "RAWSNIFFER",
};

const ANALYTICS_LABELS = {
    PWN: SOURCE_LABELS.pwnagotchi,
    WARD: SOURCE_LABELS.wardrive,
    BRUCE: SOURCE_LABELS.brucegotchi,
    M5: SOURCE_LABELS.m5evil,
    RAW: SOURCE_LABELS.rawsniffer,
};

export function normalizeSources(sources) {
    const rawSources = Array.isArray(sources) && sources.length > 0 ? sources : [DEFAULT_SOURCE];
    const normalized = rawSources
        .map((value) => String(value || '').trim().toLowerCase())
        .filter(Boolean)
        .flatMap((value) => {
            if (value === 'bruce_raw' || value === 'bruce_raw_sniffing') {
                return ['brucegotchi', 'rawsniffer'];
            }
            if (value === 'm5evil_raw_sniffing' || value === 'm5evil_master_raw_sniffing') {
                return ['m5evil', 'rawsniffer'];
            }
            if (value === 'rawsniffer') {
                return ['rawsniffer'];
            }
            return [value];
        });

    if (!normalized.length) return [DEFAULT_SOURCE];
    return Array.from(new Set(normalized));
}

export function getSourceFlags(sources) {
    const normalized = normalizeSources(sources);
    return {
        hasPwnagotchi: normalized.includes('pwnagotchi'),
        hasWardrive: normalized.includes('wardrive'),
        hasBrucegotchi: normalized.includes('brucegotchi'),
        hasM5evil: normalized.includes('m5evil'),
        hasRawsniffer: normalized.includes('rawsniffer'),
    };
}

export function getSourceBadges(sources) {
    const flags = getSourceFlags(sources);
    const badges = [];
    if (flags.hasPwnagotchi) {
        badges.push({ label: SOURCE_LABELS.pwnagotchi, className: 'source-badge source-pwnagotchi' });
    }
    if (flags.hasWardrive) {
        badges.push({ label: SOURCE_LABELS.wardrive, className: 'source-badge source-wardrive' });
    }
    if (flags.hasBrucegotchi) {
        badges.push({ label: SOURCE_LABELS.brucegotchi, className: 'source-badge source-brucegotchi' });
    }
    if (flags.hasM5evil) {
        badges.push({ label: SOURCE_LABELS.m5evil, className: 'source-badge source-m5evil' });
    }
    if (flags.hasRawsniffer) {
        badges.push({ label: SOURCE_LABELS.rawsniffer, className: 'source-badge source-rawsniffer' });
    }
    return badges;
}

export function getSourceTokens(sources) {
    const flags = getSourceFlags(sources);
    const tokens = [];
    if (flags.hasPwnagotchi) tokens.push(SOURCE_LABELS.pwnagotchi);
    if (flags.hasWardrive) tokens.push(SOURCE_LABELS.wardrive);
    if (flags.hasBrucegotchi) tokens.push(SOURCE_LABELS.brucegotchi);
    if (flags.hasM5evil) tokens.push(SOURCE_LABELS.m5evil);
    if (flags.hasRawsniffer) tokens.push(SOURCE_LABELS.rawsniffer);
    return tokens;
}

export function matchesSourceFilter(sources, filter) {
    if (!filter || filter === 'all') return true;
    const flags = getSourceFlags(sources);
    if (filter === 'pwn') return flags.hasPwnagotchi;
    if (filter === 'bruce') return flags.hasBrucegotchi;
    if (filter === 'm5') return flags.hasM5evil;
    if (filter === 'ward') return flags.hasWardrive;
    if (filter === 'raw') return flags.hasRawsniffer;
    return true;
}

export function mapAnalyticsSourceLabel(key) {
    const normalized = String(key || '').trim().toUpperCase();
    if (normalized === 'BRUCE_RAW' || normalized === 'BRUCE_RAW_SNIFFING') return 'BRUCE RAW';
    if (normalized === 'M5EVIL_RAW_SNIFFING') return 'M5EVIL RAW';
    if (normalized === 'M5EVIL_MASTER_RAW_SNIFFING') return 'M5EVIL MASTER RAW';
    return ANALYTICS_LABELS[normalized] || normalized;
}
