import os

from app.services import crack_service as cs_module


def test_get_custom_wordlists(tmp_path, monkeypatch):
    wordlist_dir = tmp_path / "wordlists"
    wordlist_dir.mkdir()
    (wordlist_dir / "a.txt").write_text("x")
    (wordlist_dir / "b.dic").write_text("x")

    subdir = wordlist_dir / "subdir"
    subdir.mkdir()
    (subdir / "c.lst").write_text("x")

    monkeypatch.setattr(
        cs_module, "load_config", lambda: {"custom_wordlists_path": str(wordlist_dir)}
    )

    service = cs_module.CrackService()
    wordlists = service.get_custom_wordlists()

    names = [w["name"] for w in wordlists]
    assert "a.txt" in names
    assert "b.dic" in names
    assert any(name.startswith("[DIR]") for name in names)


def test_crack_service_helpers_and_delegate_methods(tmp_path, monkeypatch):
    monkeypatch.setattr(
        cs_module, "load_config", lambda: {"custom_wordlists_path": str(tmp_path)}
    )
    service = cs_module.CrackService()

    assert service._format_size(0) == "0B"
    assert service._format_size(1024) == "1.0 KB"

    class _FakeHashcat:
        def __init__(self):
            self.called = None

        def get_available_rules(self):
            return ["r1"]

        def get_available_masks(self):
            return ["m1"]

        def get_devices(self):
            return ["d1"]

        def convert_pcap(self, p, **kwargs):
            return {"pcap": p, **kwargs}

        def convert_multi_pcap(self, p, **kwargs):
            return {"multi": p, **kwargs}

        def run_attack(self, *args, **kwargs):
            self.called = (args, kwargs)
            return {"status": "started"}

        def preview_association_candidates(self, *args, **kwargs):
            self.preview_called = (args, kwargs)
            return {"status": "success", "candidate_count": 3}

    class _FakeAircrack:
        def run_attack(self, pcap, bssid, wordlist, **kwargs):
            return {"pcap": pcap, "bssid": bssid, "wordlist": wordlist, **kwargs}

    fake_hashcat = _FakeHashcat()
    service.hashcat = fake_hashcat
    service.aircrack = _FakeAircrack()

    assert service.get_hashcat_rules() == ["r1"]
    assert service.get_hashcat_masks() == ["m1"]
    assert service.get_hashcat_devices() == ["d1"]
    assert service.convert_pcap("a.pcap") == {
        "pcap": "a.pcap",
        "capture_id": None,
        "raw_item_id": None,
    }
    assert service.convert_pcap_multi(["a.pcap"]) == {
        "multi": ["a.pcap"],
        "capture_ids": [],
    }
    assert service.run_aircrack_attack("a.pcap", "aa:bb", "wl.txt") == {
        "pcap": "a.pcap",
        "bssid": "aa:bb",
        "wordlist": "wl.txt",
        "capture_id": None,
        "raw_item_id": None,
    }

    out = service.run_hashcat(
        "hash.22000",
        attack_mode="association_hint_first",
        association_hints="hint-a\nhint-b",
        association_hint="legacy-hint",
        mask_file="/tmp/x.hcmask",
    )
    assert out["status"] == "started"
    assert fake_hashcat.called[0][-3:] == (
        "/tmp/x.hcmask",
        "legacy-hint",
        "hint-a\nhint-b",
    )
    assert fake_hashcat.called[1] == {
        "capture_id": None,
        "combined_build_id": None,
        "mac": None,
    }

    preview = service.preview_hashcat_association(
        "hash.22000",
        mode="association_hint_first",
        association_hints="hint-a\nhint-b",
    )
    assert preview["status"] == "success"
    assert fake_hashcat.preview_called[0][0] == "hash.22000"
    assert fake_hashcat.preview_called[1]["mode"] == "association_hint_first"

    monkeypatch.setattr(cs_module, "load_config", lambda: {"custom_wordlists_path": ""})
    assert service.get_custom_wordlists() == []


def test_get_custom_wordlists_handles_getsize_and_scandir_errors(tmp_path, monkeypatch):
    wordlist_dir = tmp_path / "wordlists"
    wordlist_dir.mkdir()
    file_path = wordlist_dir / "wl.txt"
    file_path.write_text("abc", encoding="utf-8")

    monkeypatch.setattr(
        cs_module, "load_config", lambda: {"custom_wordlists_path": str(wordlist_dir)}
    )
    service = cs_module.CrackService()

    orig_getsize = os.path.getsize
    monkeypatch.setattr(
        os.path,
        "getsize",
        lambda path: (
            (_ for _ in ()).throw(OSError("size error"))
            if str(path).endswith("wl.txt")
            else orig_getsize(path)
        ),
    )
    wordlists = service.get_custom_wordlists()
    wl = next(w for w in wordlists if w["name"] == "wl.txt")
    assert wl["size"] == ""

    subdir = wordlist_dir / "sub"
    subdir.mkdir()
    (subdir / "inside.txt").write_text("x", encoding="utf-8")
    monkeypatch.setattr(
        os,
        "listdir",
        lambda p: (
            (_ for _ in ()).throw(OSError("list error"))
            if str(p).endswith("/sub")
            else ["inside.txt"]
        ),
    )
    wordlists = service.get_custom_wordlists()
    dir_item = next(w for w in wordlists if w["type"] == "directory")
    assert dir_item["size"] == "0 files"

    monkeypatch.setattr(
        os,
        "scandir",
        lambda _path: (_ for _ in ()).throw(OSError("scan error")),
    )
    assert service.get_custom_wordlists() == []


def test_run_hashcat_runs_even_when_skip_quality_gate_flag_changes():
    service = cs_module.CrackService()

    class _FakeHashcat:
        def __init__(self):
            self.calls = 0

        def run_attack(self, *args, **kwargs):
            self.calls += 1
            return {"status": "started"}

    fake_hashcat = _FakeHashcat()
    service.hashcat = fake_hashcat

    started_default = service.run_hashcat("maybe.22000")
    assert started_default["status"] == "started"
    assert fake_hashcat.calls == 1

    started_skip = service.run_hashcat("maybe.22000", skip_quality_gate=True)
    assert started_skip["status"] == "started"
    assert fake_hashcat.calls == 2
