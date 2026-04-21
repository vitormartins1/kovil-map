import json

from app.services import handshake_catalog
from app.tests.conftest import write_test_pcap
from app.tools import migrate_capture_artifacts


def _patch_catalog_roots(monkeypatch, hand_dir, tmp_path):
    monkeypatch.setattr(handshake_catalog, "HANDSHAKES_DIR", str(hand_dir))
    monkeypatch.setattr(
        handshake_catalog, "BRUCE_HANDSHAKES_DIR", str(tmp_path / "missing-bruce")
    )
    monkeypatch.setattr(
        handshake_catalog, "BRUCE_PCAP_DIR", str(tmp_path / "missing-bruce-root")
    )
    monkeypatch.setattr(
        handshake_catalog, "M5EVIL_HANDSHAKES_DIR", str(tmp_path / "missing-m5")
    )
    monkeypatch.setattr(migrate_capture_artifacts, "HANDSHAKES_DIR", str(hand_dir))


def test_migrate_capture_artifacts_dry_run_does_not_move(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    _patch_catalog_roots(monkeypatch, hand_dir, tmp_path)
    write_test_pcap(hand_dir / "Cafe_aabbccddeeff.pcap")
    capture_id = handshake_catalog.build_handshake_catalog()["AA:BB:CC:DD:EE:FF"][
        "captures"
    ][0]["capture_id"]
    capture_dir = hand_dir / "captures" / capture_id
    capture_dir.mkdir(parents=True)
    (capture_dir / "capture.details").write_text('{"ssid":"Cafe"}', encoding="utf-8")

    report = migrate_capture_artifacts.migrate_capture_artifacts(apply=False)

    assert report["mode"] == "dry-run"
    assert report["moved"][0]["to"].endswith("Cafe_aabbccddeeff.details")
    assert (capture_dir / "capture.details").exists()
    assert not (hand_dir / "Cafe_aabbccddeeff.details").exists()


def test_migrate_capture_artifacts_apply_moves_and_cleans(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    _patch_catalog_roots(monkeypatch, hand_dir, tmp_path)
    write_test_pcap(hand_dir / "Cafe_aabbccddeeff.pcap")
    capture_id = handshake_catalog.build_handshake_catalog()["AA:BB:CC:DD:EE:FF"][
        "captures"
    ][0]["capture_id"]
    capture_dir = hand_dir / "captures" / capture_id
    capture_dir.mkdir(parents=True)
    (capture_dir / "capture.details").write_text('{"ssid":"Cafe"}', encoding="utf-8")
    (capture_dir / "manifest.json").write_text("{}", encoding="utf-8")

    report = migrate_capture_artifacts.migrate_capture_artifacts(apply=True)

    assert report["mode"] == "apply"
    assert (hand_dir / "Cafe_aabbccddeeff.details").exists()
    assert not capture_dir.exists()


def test_migrate_capture_artifacts_merges_history(tmp_path, monkeypatch):
    hand_dir = tmp_path / "handshakes"
    hand_dir.mkdir()
    _patch_catalog_roots(monkeypatch, hand_dir, tmp_path)
    write_test_pcap(hand_dir / "Cafe_aabbccddeeff.pcap")
    capture_id = handshake_catalog.build_handshake_catalog()["AA:BB:CC:DD:EE:FF"][
        "captures"
    ][0]["capture_id"]
    capture_dir = hand_dir / "captures" / capture_id
    capture_dir.mkdir(parents=True)
    (hand_dir / "Cafe_aabbccddeeff.try").write_text(
        json.dumps({"entries": [{"id": "new"}]}), encoding="utf-8"
    )
    (capture_dir / "capture.try").write_text(
        json.dumps({"entries": [{"id": "old"}]}), encoding="utf-8"
    )

    report = migrate_capture_artifacts.migrate_capture_artifacts(apply=True)

    assert report["merged_history"]
    data = json.loads((hand_dir / "Cafe_aabbccddeeff.try").read_text())
    assert {entry["id"] for entry in data["entries"]} == {"new", "old"}
