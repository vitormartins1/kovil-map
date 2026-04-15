from __future__ import annotations

import json
import logging
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from app.core.config import (
    BASE_DIR,
    BRUCE_PCAP_DIR,
    HANDSHAKES_DIR,
    M5EVIL_DIR,
    WARDRIVE_DIR,
)
from app.core.job_manager import job_manager
from app.services.analytics_service import analytics_service
from app.services.data_loader import reload_data
from app.services.packet_analysis_service import packet_analysis_service
from app.services.probe_service import probe_service
from app.services.rawsniffer_service import rawsniffer_service
from app.services.recon_runtime_service import clear_recon_runtime_cache
from app.services.wardrive_regions_service import wardrive_regions_service

logger = logging.getLogger(__name__)

DEMO_DATA_ROOT = Path(BASE_DIR) / "demo_data"
DEMO_BACKUPS_ROOT = Path(BASE_DIR) / "data_backups" / "demo"
DEMO_ACTIVE_STATE_PATH = DEMO_BACKUPS_ROOT / "active_demo_state.json"

_TARGET_ROOTS = {
    "handshakes": Path(HANDSHAKES_DIR),
    "BrucePCAP": Path(BRUCE_PCAP_DIR),
    "m5evil": Path(M5EVIL_DIR),
    "wardrive": Path(WARDRIVE_DIR),
}
_PROFILE_DEFAULT = "showcase-core-v4"
_TERMINAL_JOB_STATUSES = set(job_manager.TERMINAL_STATUSES)


class DemoDataError(RuntimeError):
    pass


def _safe_json_load(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        logger.exception("Failed to read JSON file: %s", path)
        return None
    return payload if isinstance(payload, dict) else None


def _safe_json_dump(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _has_directory_contents(path: Path) -> bool:
    if not path.exists() or not path.is_dir():
        return False
    try:
        next(path.iterdir())
    except StopIteration:
        return False
    return True


def _remove_tree_contents(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink(missing_ok=True)


def _copy_tree_contents(source: Path, target: Path) -> list[str]:
    copied_files: list[str] = []
    target.mkdir(parents=True, exist_ok=True)
    if not source.exists() or not source.is_dir():
        return copied_files
    for item in sorted(source.rglob("*")):
        relative = item.relative_to(source)
        target_path = target / relative
        if item.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
            continue
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(item, target_path)
        copied_files.append(relative.as_posix())
    return copied_files


def _prune_empty_directories(path: Path) -> None:
    if not path.exists() or not path.is_dir():
        return
    for child in sorted(path.iterdir(), reverse=True):
        if child.is_dir():
            _prune_empty_directories(child)
    try:
        next(path.iterdir())
    except StopIteration:
        path.rmdir()
    except Exception:
        return


class DemoDataService:
    def _profile_root(self, profile_id: str) -> Path:
        return DEMO_DATA_ROOT / str(profile_id or "").strip()

    def _profile_manifest_path(self, profile_id: str) -> Path:
        return self._profile_root(profile_id) / "manifest.json"

    def _load_profile_manifest(self, profile_id: str) -> dict[str, Any]:
        manifest_path = self._profile_manifest_path(profile_id)
        if not manifest_path.exists():
            raise DemoDataError(f"Demo profile not found: {profile_id}")
        payload = _safe_json_load(manifest_path)
        if not payload:
            raise DemoDataError(f"Invalid demo manifest: {manifest_path}")
        return payload

    def _runtime_root_for_profile(self, profile_id: str) -> Path:
        return self._profile_root(profile_id) / "runtime"

    def _list_profiles(self) -> list[dict[str, Any]]:
        profiles: list[dict[str, Any]] = []
        if not DEMO_DATA_ROOT.exists():
            return profiles
        for manifest_path in sorted(DEMO_DATA_ROOT.glob("*/manifest.json")):
            payload = _safe_json_load(manifest_path)
            if not payload:
                continue
            profiles.append(
                {
                    "profile_id": payload.get("profile_id")
                    or manifest_path.parent.name,
                    "label": payload.get("label") or manifest_path.parent.name,
                    "description": payload.get("description") or "",
                    "version": int(payload.get("version") or 1),
                    "build_stamp": payload.get("build_stamp"),
                    "summary": dict(payload.get("summary") or {}),
                }
            )
        return profiles

    def _load_active_state(self) -> dict[str, Any] | None:
        if not DEMO_ACTIVE_STATE_PATH.exists():
            return None
        payload = _safe_json_load(DEMO_ACTIVE_STATE_PATH)
        return payload if payload else None

    def _save_active_state(self, payload: dict[str, Any]) -> None:
        _safe_json_dump(DEMO_ACTIVE_STATE_PATH, payload)

    def _clear_active_state(self) -> None:
        DEMO_ACTIVE_STATE_PATH.unlink(missing_ok=True)

    def _snapshot_runtime_roots(self, session_id: str) -> dict[str, Any]:
        snapshot_root = DEMO_BACKUPS_ROOT / "snapshots" / session_id
        runtime_snapshot_root = snapshot_root / "runtime"
        copied_roots: list[str] = []
        snapshot_files: dict[str, list[str]] = {}
        for root_name, target_path in _TARGET_ROOTS.items():
            if not _has_directory_contents(target_path):
                continue
            copied = _copy_tree_contents(target_path, runtime_snapshot_root / root_name)
            copied_roots.append(root_name)
            snapshot_files[root_name] = copied
        return {
            "session_id": session_id,
            "available": bool(copied_roots),
            "path": str(snapshot_root),
            "roots": copied_roots,
            "files": snapshot_files,
        }

    def _restore_snapshot(self, snapshot_state: dict[str, Any] | None) -> None:
        snapshot_path = Path(str((snapshot_state or {}).get("path") or "")).expanduser()
        runtime_root = snapshot_path / "runtime"
        for root_name, target_path in _TARGET_ROOTS.items():
            _remove_tree_contents(target_path)
            source_root = runtime_root / root_name
            if source_root.exists():
                _copy_tree_contents(source_root, target_path)

    def _remove_registry_files(self, registry: list[str] | None) -> None:
        for rel_path in registry or []:
            rel = Path(str(rel_path or ""))
            if not rel.parts:
                continue
            root_name = rel.parts[0]
            target_root = _TARGET_ROOTS.get(root_name)
            if target_root is None:
                continue
            target_path = target_root.joinpath(*rel.parts[1:])
            try:
                if target_path.is_dir() and not target_path.is_symlink():
                    shutil.rmtree(target_path, ignore_errors=True)
                else:
                    target_path.unlink(missing_ok=True)
            except Exception:
                logger.exception("Failed to remove demo registry file: %s", target_path)
            _prune_empty_directories(target_root)
            target_root.mkdir(parents=True, exist_ok=True)

    def _clear_runtime_roots(self) -> None:
        for path in _TARGET_ROOTS.values():
            _remove_tree_contents(path)

    def _copy_profile_runtime(self, profile_id: str) -> list[str]:
        runtime_root = self._runtime_root_for_profile(profile_id)
        installed_files: list[str] = []
        for root_name, target_path in _TARGET_ROOTS.items():
            source_root = runtime_root / root_name
            copied = _copy_tree_contents(source_root, target_path)
            installed_files.extend([f"{root_name}/{relative}" for relative in copied])
        return installed_files

    def _reload_runtime_state(self) -> dict[str, Any]:
        rawsniffer_service.clear_metadata_cache(remove_files=False)
        analytics_service.clear_cache()
        probe_service.invalidate_cache()
        packet_analysis_service.invalidate_cache()
        clear_recon_runtime_cache()
        wardrive_regions_service.clear_runtime_cache()
        reload_data()
        return {
            "data_cache_reloaded": True,
            "analytics_cache_cleared": True,
            "probe_cache_cleared": True,
            "packet_analysis_cache_cleared": True,
            "recon_runtime_cache_cleared": True,
        }

    def _prewarm_recon(self) -> dict[str, Any]:
        result = {
            "probe": {"attempted": False, "available": False},
            "deep_analysis": {"attempted": False, "available": False},
        }
        try:
            probe_pcaps = probe_service._find_pcaps()  # noqa: SLF001
            if probe_pcaps:
                payload = probe_service.analyse_with_progress(
                    probe_pcaps, emit=None, job=None
                )
                result["probe"] = {
                    "attempted": True,
                    "available": bool(payload.get("available")),
                    "summary": payload.get("summary") or {},
                }
        except Exception:
            logger.exception("Probe prewarm failed")
            result["probe"] = {
                "attempted": True,
                "available": False,
                "error": "probe_prewarm_failed",
            }
        try:
            deep_pcaps = packet_analysis_service._find_pcaps()  # noqa: SLF001
            if deep_pcaps:
                payload = packet_analysis_service.analyse_with_progress(
                    deep_pcaps,
                    emit=None,
                    job=None,
                )
                result["deep_analysis"] = {
                    "attempted": True,
                    "available": bool(payload.get("available")),
                    "summary": payload.get("summary") or {},
                }
        except Exception:
            logger.exception("Deep analysis prewarm failed")
            result["deep_analysis"] = {
                "attempted": True,
                "available": False,
                "error": "deep_analysis_prewarm_failed",
            }
        return result

    def _ensure_no_active_jobs(self) -> None:
        active = []
        for job in job_manager.list_jobs():
            status = str(job.get("status") or "").strip().lower()
            if status and status not in _TERMINAL_JOB_STATUSES:
                active.append(
                    {
                        "id": job.get("id"),
                        "type": job.get("type"),
                        "status": status,
                    }
                )
        if active:
            raise DemoDataError(
                "Demo data install/remove is blocked while active jobs are running."
            )

    def _emit_progress(
        self,
        job: dict[str, Any],
        emit,
        *,
        percentage: int,
        stage: str,
        extra: str,
        current_step: int,
        total_steps: int,
    ) -> None:
        job["progress_data"].update(
            {
                "percentage": int(percentage),
                "stage": str(stage or "RUNNING").upper(),
                "extra": str(extra or ""),
                "current_step": int(current_step),
                "total_steps": int(total_steps),
            }
        )
        emit("job_progress", {"job_id": job["id"], "data": job["progress_data"].copy()})

    def get_status(self) -> dict[str, Any]:
        active_state = self._load_active_state() or {}
        available_profiles = self._list_profiles()
        active_profile_id = str(active_state.get("profile_id") or "").strip() or None
        active_manifest = None
        if active_profile_id:
            try:
                active_manifest = self._load_profile_manifest(active_profile_id)
            except Exception:
                logger.exception("Failed to load active demo manifest")
        return {
            "active": bool(active_state.get("active")),
            "active_profile_id": active_profile_id,
            "active_profile_label": (
                active_manifest.get("label")
                if isinstance(active_manifest, dict)
                else None
            ),
            "snapshot_available": bool(
                ((active_state.get("snapshot") or {}).get("available"))
            ),
            "available_profiles": available_profiles,
            "summary": (
                dict(active_manifest.get("summary") or {})
                if isinstance(active_manifest, dict)
                else None
            ),
        }

    def get_demo_wordlists(self) -> list[dict[str, Any]]:
        active_state = self._load_active_state() or {}
        if not active_state.get("active"):
            return []
        profile_id = str(active_state.get("profile_id") or "").strip()
        if not profile_id:
            return []
        wordlists_root = self._runtime_root_for_profile(profile_id) / "demo_wordlists"
        if not wordlists_root.exists():
            return []
        entries: list[dict[str, Any]] = []
        for path in sorted(wordlists_root.iterdir()):
            if not path.is_file():
                continue
            size_bytes = 0
            try:
                size_bytes = path.stat().st_size
            except OSError:
                size_bytes = 0
            entries.append(
                {
                    "name": f"[DEMO] {path.name}",
                    "path": str(path),
                    "type": "file",
                    "size": f"{size_bytes} B" if size_bytes else "",
                    "demo": True,
                    "profile_id": profile_id,
                }
            )
        return entries

    def start_install(
        self,
        *,
        profile_id: str = _PROFILE_DEFAULT,
        frontend_state: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._ensure_no_active_jobs()
        status = self.get_status()
        if status.get("active"):
            raise DemoDataError(
                "Demo data is already active. Remove it before reinstalling."
            )

        manifest = self._load_profile_manifest(profile_id)
        total_steps = 5
        meta = {
            "display_type": "DEMO DATA",
            "display_details": f"Install {manifest.get('label') or profile_id}",
            "operation": "install",
            "profile_id": profile_id,
            "no_cancel": True,
        }

        def _worker(job, emit):
            self._emit_progress(
                job,
                emit,
                percentage=5,
                stage="RUNNING",
                extra="Scanning current runtime data",
                current_step=1,
                total_steps=total_steps,
            )
            session_id = uuid.uuid4().hex[:16]
            snapshot = self._snapshot_runtime_roots(session_id)
            active_state = {
                "active": True,
                "profile_id": profile_id,
                "profile_label": manifest.get("label") or profile_id,
                "installed_at": None,
                "snapshot": snapshot,
                "installed_files": [],
                "ui_state_before": frontend_state or {},
                "ui_seed": dict(manifest.get("ui_seed") or {}),
                "summary": dict(manifest.get("summary") or {}),
                "restore_mode": "snapshot" if snapshot.get("available") else "registry",
            }
            try:
                self._emit_progress(
                    job,
                    emit,
                    percentage=20,
                    stage="RUNNING",
                    extra="Replacing runtime roots with showcase pack",
                    current_step=2,
                    total_steps=total_steps,
                )
                self._clear_runtime_roots()
                installed_files = self._copy_profile_runtime(profile_id)
                active_state["installed_files"] = installed_files
                self._emit_progress(
                    job,
                    emit,
                    percentage=60,
                    stage="RUNNING",
                    extra="Reloading caches and rebuilding dataset",
                    current_step=3,
                    total_steps=total_steps,
                )
                reload_summary = self._reload_runtime_state()
                self._emit_progress(
                    job,
                    emit,
                    percentage=82,
                    stage="RUNNING",
                    extra="Prewarming Recon caches",
                    current_step=4,
                    total_steps=total_steps,
                )
                prewarm = self._prewarm_recon()
                active_state["reload_summary"] = reload_summary
                active_state["prewarm"] = prewarm
                active_state["installed_at"] = datetime.now().isoformat()
                self._save_active_state(active_state)
                self._emit_progress(
                    job,
                    emit,
                    percentage=100,
                    stage="COMPLETED",
                    extra="Demo pack installed",
                    current_step=5,
                    total_steps=total_steps,
                )
                emit("data_update", "map_data")
            except Exception:
                logger.exception("Demo install failed, attempting rollback")
                try:
                    if snapshot.get("available"):
                        self._restore_snapshot(snapshot)
                    else:
                        self._clear_runtime_roots()
                    self._reload_runtime_state()
                    emit("data_update", "map_data")
                except Exception:
                    logger.exception("Demo install rollback failed")
                self._clear_active_state()
                raise

        job_id = job_manager.start_multi_job(
            _worker,
            job_type="demo_data",
            total_steps=total_steps,
            meta=meta,
        )
        return {
            "job_id": job_id,
            "profile_id": profile_id,
            "label": manifest.get("label") or profile_id,
            "description": manifest.get("description") or "",
            "summary": dict(manifest.get("summary") or {}),
            "ui_seed": dict(manifest.get("ui_seed") or {}),
            "status": "starting",
        }

    def start_remove(self) -> dict[str, Any]:
        self._ensure_no_active_jobs()
        active_state = self._load_active_state()
        if not active_state or not active_state.get("active"):
            raise DemoDataError("No demo data profile is currently active.")

        snapshot = dict(active_state.get("snapshot") or {})
        restore_mode = "snapshot" if snapshot.get("available") else "registry"
        total_steps = 4
        meta = {
            "display_type": "DEMO DATA",
            "display_details": "Remove active demo data",
            "operation": "remove",
            "profile_id": active_state.get("profile_id"),
            "no_cancel": True,
        }

        def _worker(job, emit):
            self._emit_progress(
                job,
                emit,
                percentage=10,
                stage="RUNNING",
                extra="Cleaning active demo dataset",
                current_step=1,
                total_steps=total_steps,
            )
            try:
                if restore_mode == "snapshot":
                    self._emit_progress(
                        job,
                        emit,
                        percentage=45,
                        stage="RUNNING",
                        extra="Restoring previous runtime snapshot",
                        current_step=2,
                        total_steps=total_steps,
                    )
                    self._restore_snapshot(snapshot)
                else:
                    self._emit_progress(
                        job,
                        emit,
                        percentage=45,
                        stage="RUNNING",
                        extra="Removing installed demo files",
                        current_step=2,
                        total_steps=total_steps,
                    )
                    self._remove_registry_files(active_state.get("installed_files"))
                self._emit_progress(
                    job,
                    emit,
                    percentage=75,
                    stage="RUNNING",
                    extra="Reloading caches and runtime data",
                    current_step=3,
                    total_steps=total_steps,
                )
                self._reload_runtime_state()
                self._clear_active_state()
                self._emit_progress(
                    job,
                    emit,
                    percentage=100,
                    stage="COMPLETED",
                    extra="Demo data removed",
                    current_step=4,
                    total_steps=total_steps,
                )
                emit("data_update", "map_data")
            except Exception:
                logger.exception("Failed to remove demo data")
                raise

        job_id = job_manager.start_multi_job(
            _worker,
            job_type="demo_data",
            total_steps=total_steps,
            meta=meta,
        )
        return {
            "job_id": job_id,
            "profile_id": active_state.get("profile_id"),
            "restore_mode": restore_mode,
            "ui_restore": dict(active_state.get("ui_state_before") or {}),
            "status": "starting",
        }


demo_data_service = DemoDataService()
