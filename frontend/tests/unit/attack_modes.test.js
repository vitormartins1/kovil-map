const {
  getModePanelLabel,
  getModeRunLabel,
  isSlowCandidatesCompatible,
  modeRequiresAssociationHints,
  modeRequiresMaskProfile,
  modeRequiresWordlist,
} = require("../../src/modules/attack_modes.js");

test("panel labels map correctly for key modes", () => {
  expect(getModePanelLabel("straight")).toBe("STRAIGHT");
  expect(getModePanelLabel("digits")).toBe("8-DIGIT");
  expect(getModePanelLabel("association_hint_first")).toBe("ASSOC MULTI-HINT");
  expect(getModePanelLabel("association_hint_rule")).toBe("ASSOC HINT + RULE");
  expect(getModePanelLabel("mask_profile")).toBe("MASK PROFILE");
});

test("run labels map correctly for key modes", () => {
  expect(getModeRunLabel("straight")).toBe("STRAIGHT");
  expect(getModeRunLabel("mask")).toBe("BRUTE-FORCE");
  expect(getModeRunLabel("digits")).toBe("BRUTE-FORCE");
  expect(getModeRunLabel("hybrid_reverse")).toBe("HYBRID (REV)");
});

test("wordlist requirements are mode-specific", () => {
  expect(modeRequiresWordlist("straight")).toBe(true);
  expect(modeRequiresWordlist("rules")).toBe(true);
  expect(modeRequiresWordlist("passphrase")).toBe(true);
  expect(modeRequiresWordlist("combinator")).toBe(true);
  expect(modeRequiresWordlist("hybrid")).toBe(true);
  expect(modeRequiresWordlist("hybrid_reverse")).toBe(true);

  expect(modeRequiresWordlist("mask")).toBe(false);
  expect(modeRequiresWordlist("digits")).toBe(false);
  expect(modeRequiresWordlist("association")).toBe(false);
  expect(modeRequiresWordlist("association_hint_first")).toBe(false);
  expect(modeRequiresWordlist("mask_profile")).toBe(false);
});

test("mask profile and association hints requirements are explicit", () => {
  expect(modeRequiresMaskProfile("mask_profile")).toBe(true);
  expect(modeRequiresMaskProfile("straight")).toBe(false);

  expect(modeRequiresAssociationHints("association_hint_first")).toBe(true);
  expect(modeRequiresAssociationHints("association_hint_rule")).toBe(true);
  expect(modeRequiresAssociationHints("association")).toBe(false);
});

test("slow candidates compatibility follows mode policy", () => {
  expect(isSlowCandidatesCompatible("straight")).toBe(true);
  expect(isSlowCandidatesCompatible("rules")).toBe(true);
  expect(isSlowCandidatesCompatible("passphrase")).toBe(true);
  expect(isSlowCandidatesCompatible("combinator")).toBe(true);
  expect(isSlowCandidatesCompatible("hybrid")).toBe(true);
  expect(isSlowCandidatesCompatible("hybrid_reverse")).toBe(true);
  expect(isSlowCandidatesCompatible("association_hint_rule")).toBe(true);

  expect(isSlowCandidatesCompatible("association")).toBe(false);
  expect(isSlowCandidatesCompatible("association_hint_first")).toBe(false);
  expect(isSlowCandidatesCompatible("digits")).toBe(false);
  expect(isSlowCandidatesCompatible("mask")).toBe(false);
  expect(isSlowCandidatesCompatible("mask_profile")).toBe(false);
});

test("unknown modes fallback to straight defaults", () => {
  expect(getModePanelLabel("unknown_mode")).toBe("STRAIGHT");
  expect(getModeRunLabel("unknown_mode")).toBe("STRAIGHT");
  expect(modeRequiresWordlist("unknown_mode")).toBe(true);
  expect(modeRequiresMaskProfile("unknown_mode")).toBe(false);
  expect(modeRequiresAssociationHints("unknown_mode")).toBe(false);
  expect(isSlowCandidatesCompatible("unknown_mode")).toBe(true);
});
