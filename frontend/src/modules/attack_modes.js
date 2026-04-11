const MODE_CONFIG = {
    straight: {
        panelLabel: 'STRAIGHT',
        runLabel: 'STRAIGHT',
        requiresWordlist: true,
        requiresMaskProfile: false,
        requiresAssociationHints: false,
        slowCandidatesCompatible: true
    },
    rules: {
        panelLabel: 'RULES',
        runLabel: 'RULES',
        requiresWordlist: true,
        requiresMaskProfile: false,
        requiresAssociationHints: false,
        slowCandidatesCompatible: true
    },
    passphrase: {
        panelLabel: 'PASSPHRASE',
        runLabel: 'PASSPHRASE',
        requiresWordlist: true,
        requiresMaskProfile: false,
        requiresAssociationHints: false,
        slowCandidatesCompatible: true
    },
    association: {
        panelLabel: 'ASSOC SSID/HINT',
        runLabel: 'ASSOC SSID/HINT',
        requiresWordlist: false,
        requiresMaskProfile: false,
        requiresAssociationHints: false,
        slowCandidatesCompatible: false
    },
    association_hint_first: {
        panelLabel: 'ASSOC MULTI-HINT',
        runLabel: 'ASSOC MULTI-HINT',
        requiresWordlist: false,
        requiresMaskProfile: false,
        requiresAssociationHints: true,
        slowCandidatesCompatible: false
    },
    association_hint_rule: {
        panelLabel: 'ASSOC HINT + RULE',
        runLabel: 'ASSOC HINT + RULE',
        requiresWordlist: false,
        requiresMaskProfile: false,
        requiresAssociationHints: true,
        slowCandidatesCompatible: true
    },
    combinator: {
        panelLabel: 'COMBINATOR',
        runLabel: 'COMBINATOR',
        requiresWordlist: true,
        requiresSecondWordlist: false,
        requiresMaskProfile: false,
        requiresAssociationHints: false,
        slowCandidatesCompatible: true
    },
    combinator_passphrase: {
        panelLabel: 'COMBINATOR PASS',
        runLabel: 'COMBINATOR PASS',
        requiresWordlist: true,
        requiresSecondWordlist: true,
        requiresMaskProfile: false,
        requiresAssociationHints: false,
        slowCandidatesCompatible: true
    },
    digits: {
        panelLabel: '8-DIGIT',
        runLabel: 'BRUTE-FORCE',
        requiresWordlist: false,
        requiresMaskProfile: false,
        requiresAssociationHints: false,
        slowCandidatesCompatible: false
    },
    mask: {
        panelLabel: 'MASK',
        runLabel: 'BRUTE-FORCE',
        requiresWordlist: false,
        requiresMaskProfile: false,
        requiresAssociationHints: false,
        slowCandidatesCompatible: false
    },
    mask_profile: {
        panelLabel: 'MASK PROFILE',
        runLabel: 'MASK PROFILE',
        requiresWordlist: false,
        requiresMaskProfile: true,
        requiresAssociationHints: false,
        slowCandidatesCompatible: false
    },
    hybrid: {
        panelLabel: 'HYBRID',
        runLabel: 'HYBRID',
        requiresWordlist: true,
        requiresSecondWordlist: false,
        requiresMaskProfile: false,
        requiresAssociationHints: false,
        slowCandidatesCompatible: true
    },
    hybrid_reverse: {
        panelLabel: 'HYBRID (REV)',
        runLabel: 'HYBRID (REV)',
        requiresWordlist: true,
        requiresSecondWordlist: false,
        requiresMaskProfile: false,
        requiresAssociationHints: false,
        slowCandidatesCompatible: true
    },
    hybrid_mask_profile: {
        panelLabel: 'WL + MASK PROFILE',
        runLabel: 'WL + MASK PROFILE',
        requiresWordlist: true,
        requiresSecondWordlist: false,
        requiresMaskProfile: true,
        requiresAssociationHints: false,
        slowCandidatesCompatible: true
    },
    hybrid_reverse_mask_profile: {
        panelLabel: 'MASK PROFILE + WL',
        runLabel: 'MASK PROFILE + WL',
        requiresWordlist: true,
        requiresSecondWordlist: false,
        requiresMaskProfile: false,
        requiresAssociationHints: false,
        slowCandidatesCompatible: true
    }
};

function getConfig(mode) {
    return MODE_CONFIG[mode] || MODE_CONFIG.straight;
}

export function getModePanelLabel(mode) {
    return getConfig(mode).panelLabel;
}

export function getModeRunLabel(mode) {
    return getConfig(mode).runLabel;
}

export function isSlowCandidatesCompatible(mode) {
    return !!getConfig(mode).slowCandidatesCompatible;
}

export function modeRequiresWordlist(mode) {
    return !!getConfig(mode).requiresWordlist;
}

export function modeRequiresSecondWordlist(mode) {
    return !!getConfig(mode).requiresSecondWordlist;
}

export function modeRequiresMaskProfile(mode) {
    return !!getConfig(mode).requiresMaskProfile;
}

export function modeRequiresAssociationHints(mode) {
    return !!getConfig(mode).requiresAssociationHints;
}
