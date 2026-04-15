import json
from pathlib import Path

import pytest

from app.services import demo_data_service as dds_module


def _write_demo_pack(root: Path) -> None:
    profile_root = root / "showcase-core-v1"
    runtime_root = profile_root / "runtime"
    (runtime_root / "handshakes").mkdir(parents=True, exist_ok=True)
    (runtime_root / "BrucePCAP" / "rawsniffer").mkdir(parents=True, exist_ok=True)
    (runtime_root / "m5evil" / "handshakes").mkdir(parents=True, exist_ok=True)
    (runtime_root / "wardrive").mkdir(parents=True, exist_ok=True)
    (runtime_root / "demo_wordlists").mkdir(parents=True, exist_ok=True)

    (runtime_root / "handshakes" / "RIO_DEMO.pcap").write_text(
        "demo-pcap", encoding="utf-8"
    )
    (runtime_root / "BrucePCAP" / "rawsniffer" / "rio_demo_raw.pcap").write_text(
        "raw-demo",
        encoding="utf-8",
    )
    (runtime_root / "m5evil" / "handshakes" / "HS_DEMO.pcap").write_text(
        "m5-demo",
        encoding="utf-8",
    )
    (runtime_root / "wardrive" / "20260412_demo.csv").write_text(
        "demo-wardrive",
        encoding="utf-8",
    )
    (runtime_root / "demo_wordlists" / "demo_easy.txt").write_text(
        "cafeloop2026\n",
        encoding="utf-8",
    )

    manifest = {
        "profile_id": "showcase-core-v1",
        "label": "Showcase Core v1",
        "description": "Synthetic showcase dataset",
        "version": 1,
        "build_stamp": "2026-04-12T00:00:00Z",
        "runtime_roots": [
            "handshakes",
            "BrucePCAP",
            "m5evil",
            "wardrive",
            "demo_wordlists",
        ],
        "summary": {
            "networks_total": 10,
            "wardrive_sessions": 3,
            "raw_files": 1,
        },
        "ui_seed": {
            "lists": {
                "targets": ["02:11:22:33:44:50"],
                "favs": ["06:11:22:33:44:51"],
            },
            "modes": {
                "zones": True,
                "targets": True,
                "favs": True,
                "process": True,
                "logs": True,
            },
        },
    }
    (profile_root / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )


def _patch_demo_env(monkeypatch, tmp_path: Path):
    demo_root = tmp_path / "demo_data"
    backups_root = tmp_path / "data_backups" / "demo"
    runtime_root = tmp_path / "runtime"
    target_roots = {
        "handshakes": runtime_root / "handshakes",
        "BrucePCAP": runtime_root / "BrucePCAP",
        "m5evil": runtime_root / "m5evil",
        "wardrive": runtime_root / "wardrive",
    }
    for path in target_roots.values():
        path.mkdir(parents=True, exist_ok=True)

    _write_demo_pack(demo_root)

    monkeypatch.setattr(dds_module, "DEMO_DATA_ROOT", demo_root)
    monkeypatch.setattr(dds_module, "DEMO_BACKUPS_ROOT", backups_root)
    monkeypatch.setattr(
        dds_module, "DEMO_ACTIVE_STATE_PATH", backups_root / "active_demo_state.json"
    )
    monkeypatch.setattr(dds_module, "_TARGET_ROOTS", target_roots)
    monkeypatch.setattr(
        dds_module.demo_data_service,
        "_reload_runtime_state",
        lambda: {"reloaded": True},
    )
    monkeypatch.setattr(
        dds_module.demo_data_service,
        "_prewarm_recon",
        lambda: {"probe": {"attempted": False}, "deep_analysis": {"attempted": False}},
    )
    monkeypatch.setattr(dds_module.job_manager, "list_jobs", lambda: [])

    emitted = []

    def _start_multi_job(worker, job_type=None, total_steps=1, meta=None):
        job = {
            "id": "job-demo-1",
            "type": job_type,
            "status": "running",
            "progress_data": {
                "percentage": 0,
                "speed": "",
                "eta": "",
                "stage": "RUNNING",
                "extra": "",
                "current_step": 0,
                "total_steps": total_steps,
            },
            "logs": [],
            "meta": meta or {},
        }
        worker(job, lambda event, payload: emitted.append((event, payload)))
        return "job-demo-1"

    monkeypatch.setattr(dds_module.job_manager, "start_multi_job", _start_multi_job)
    return target_roots, emitted


def test_demo_install_and_remove_restore_snapshot(monkeypatch, tmp_path):
    target_roots, emitted = _patch_demo_env(monkeypatch, tmp_path)
    (target_roots["handshakes"] / "real_capture.pcap").write_text(
        "real", encoding="utf-8"
    )
    (target_roots["wardrive"] / "real_session.csv").write_text(
        "wardrive", encoding="utf-8"
    )

    install = dds_module.demo_data_service.start_install(
        frontend_state={"lists": {"targets": ["AA:BB:CC:DD:EE:FF"]}}
    )
    assert install["job_id"] == "job-demo-1"
    assert (target_roots["handshakes"] / "RIO_DEMO.pcap").exists()
    assert not (target_roots["handshakes"] / "real_capture.pcap").exists()

    status = dds_module.demo_data_service.get_status()
    assert status["active"] is True
    assert status["snapshot_available"] is True

    wordlists = dds_module.demo_data_service.get_demo_wordlists()
    assert wordlists
    assert wordlists[0]["demo"] is True

    remove = dds_module.demo_data_service.start_remove()
    assert remove["restore_mode"] == "snapshot"
    assert (target_roots["handshakes"] / "real_capture.pcap").exists()
    assert not (target_roots["handshakes"] / "RIO_DEMO.pcap").exists()
    assert dds_module.demo_data_service.get_status()["active"] is False
    assert any(
        event == "data_update" and payload == "map_data" for event, payload in emitted
    )


def test_demo_remove_without_snapshot_uses_registry_cleanup(monkeypatch, tmp_path):
    target_roots, _ = _patch_demo_env(monkeypatch, tmp_path)

    dds_module.demo_data_service.start_install(frontend_state={})
    assert dds_module.demo_data_service.get_status()["snapshot_available"] is False
    extra_file = target_roots["handshakes"] / "user_generated_after_demo.pcap"
    extra_file.write_text("keep-me", encoding="utf-8")

    remove = dds_module.demo_data_service.start_remove()
    assert remove["restore_mode"] == "registry"
    assert extra_file.exists()
    assert not (target_roots["handshakes"] / "RIO_DEMO.pcap").exists()


def test_demo_install_blocks_when_active_jobs_exist(monkeypatch, tmp_path):
    _patch_demo_env(monkeypatch, tmp_path)
    monkeypatch.setattr(
        dds_module.job_manager,
        "list_jobs",
        lambda: [{"id": "job-1", "status": "running", "type": "sync_import"}],
    )

    with pytest.raises(dds_module.DemoDataError):
        dds_module.demo_data_service.start_install(frontend_state={})
