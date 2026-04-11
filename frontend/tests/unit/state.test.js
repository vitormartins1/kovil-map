function loadStateModule() {
  jest.resetModules();
  return require("../../src/modules/state.js");
}

test("STATE initializes persisted lists and modes from localStorage", () => {
  localStorage.getItem.mockImplementation((key) => {
    const map = {
      pwn_targets: JSON.stringify(["aa:bb"]),
      pwn_favs: JSON.stringify(["cc:dd"]),
      pwn_mode_zones: "true",
      pwn_mode_to_conquer: "true",
      pwn_mode_targets: "true",
      pwn_mode_favs: "false",
      pwn_mode_cracking: "true",
      pwn_mode_process: "false",
      pwn_mode_logs: "true",
    };
    return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : null;
  });

  const { STATE } = loadStateModule();

  expect(STATE.lists.targets).toEqual(["aa:bb"]);
  expect(STATE.lists.favs).toEqual(["cc:dd"]);
  expect(STATE.modes.zones).toBe(true);
  expect(STATE.modes.toConquer).toBe(true);
  expect(STATE.modes.targets).toBe(true);
  expect(STATE.modes.favs).toBe(false);
  expect(STATE.modes.wardrive).toBe(false);
  expect(STATE.modes.cracking).toBe(true);
  expect(STATE.modes.process).toBe(false);
  expect(STATE.modes.logs).toBe(true);
});

test("saveLists persists target/fav arrays", () => {
  const { STATE, saveLists } = loadStateModule();
  STATE.lists.targets = ["11:22"];
  STATE.lists.favs = ["33:44"];

  saveLists();

  expect(localStorage.setItem).toHaveBeenCalledWith("pwn_targets", JSON.stringify(["11:22"]));
  expect(localStorage.setItem).toHaveBeenCalledWith("pwn_favs", JSON.stringify(["33:44"]));
});

test("saveModes persists panel toggles and always resets wardrive persistence", () => {
  const { STATE, saveModes } = loadStateModule();

  STATE.modes.zones = true;
  STATE.modes.toConquer = false;
  STATE.modes.targets = true;
  STATE.modes.favs = true;
  STATE.modes.wardrive = true;
  STATE.modes.cracking = true;
  STATE.modes.process = true;
  STATE.modes.logs = false;

  saveModes();

  expect(localStorage.setItem).toHaveBeenCalledWith("pwn_mode_zones", JSON.stringify(true));
  expect(localStorage.setItem).toHaveBeenCalledWith("pwn_mode_to_conquer", JSON.stringify(false));
  expect(localStorage.setItem).toHaveBeenCalledWith("pwn_mode_targets", JSON.stringify(true));
  expect(localStorage.setItem).toHaveBeenCalledWith("pwn_mode_favs", JSON.stringify(true));
  expect(localStorage.setItem).toHaveBeenCalledWith("pwn_mode_wardrive", JSON.stringify(false));
  expect(localStorage.setItem).toHaveBeenCalledWith("pwn_mode_cracking", JSON.stringify(true));
  expect(localStorage.setItem).toHaveBeenCalledWith("pwn_mode_process", JSON.stringify(true));
  expect(localStorage.setItem).toHaveBeenCalledWith("pwn_mode_logs", JSON.stringify(false));
});

test("STATE falls back to defaults when localStorage is empty", () => {
  localStorage.getItem.mockReturnValue(null);
  const { STATE } = loadStateModule();

  expect(STATE.modes.zones).toBe(false);
  expect(STATE.modes.toConquer).toBe(false);
  expect(STATE.modes.targets).toBe(false);
  expect(STATE.modes.favs).toBe(false);
  expect(STATE.modes.wardrive).toBe(false);
  expect(STATE.modes.cracking).toBe(false);
  expect(STATE.modes.process).toBe(false);
  expect(STATE.modes.logs).toBe(true);
  expect(STATE.lists.targets).toEqual([]);
  expect(STATE.lists.favs).toEqual([]);
});
