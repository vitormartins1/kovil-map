import argparse
import json
import os
import shutil
from typing import Any

from app.core.config import HANDSHAKES_DIR
from app.services import handshake_catalog
from app.utils.handshake_artifacts import get_capture_dir, get_source_sidecar_path

LEGACY_CAPTURE_ARTIFACTS = (
    ("capture.details", "details"),
    ("capture.22000", "22000"),
    ("capture.try", "history"),
    ("capture.cracked", "cracked"),
    ("capture.key", "key"),
)


def _read_bytes(path: str) -> bytes | None:
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return None


def _read_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception:
        return None


def _merge_history(old_path: str, new_path: str, apply: bool) -> str:
    old_payload = _read_json(old_path)
    new_payload = _read_json(new_path)
    if isinstance(old_payload, dict) and isinstance(new_payload, dict):
        old_entries = old_payload.get("entries")
        new_entries = new_payload.get("entries")
        if isinstance(old_entries, list) and isinstance(new_entries, list):
            merged = dict(new_payload)
            seen = {
                json.dumps(item, sort_keys=True, ensure_ascii=False)
                for item in new_entries
                if isinstance(item, dict)
            }
            entries = list(new_entries)
            for item in old_entries:
                key = json.dumps(item, sort_keys=True, ensure_ascii=False)
                if key not in seen:
                    entries.append(item)
                    seen.add(key)
            merged["entries"] = entries
            if apply:
                with open(new_path, "w", encoding="utf-8") as handle:
                    json.dump(merged, handle, indent=2, ensure_ascii=False)
                os.remove(old_path)
            return "merged_history"

    return "conflict"


def _same_content(path_a: str, path_b: str) -> bool:
    data_a = _read_bytes(path_a)
    data_b = _read_bytes(path_b)
    return data_a is not None and data_a == data_b


def _cleanup_capture_dir(capture_dir: str, apply: bool) -> bool:
    try:
        names = [
            name
            for name in os.listdir(capture_dir)
            if name not in {".DS_Store"} and not name.startswith(".")
        ]
    except OSError:
        return False
    if not names:
        if apply:
            os.rmdir(capture_dir)
        return True
    if names == ["manifest.json"]:
        if apply:
            os.remove(os.path.join(capture_dir, "manifest.json"))
            os.rmdir(capture_dir)
        return True
    return False


def migrate_capture_artifacts(apply: bool = False) -> dict[str, Any]:
    catalog = handshake_catalog.build_handshake_catalog()
    report: dict[str, Any] = {
        "mode": "apply" if apply else "dry-run",
        "captures_scanned": 0,
        "moved": [],
        "duplicates_removed": [],
        "merged_history": [],
        "conflicts": [],
        "skipped": [],
        "cleaned_dirs": [],
    }

    for handshake_set in catalog.values():
        for capture in handshake_set.get("captures") or []:
            capture_id = str(capture.get("capture_id") or "")
            source_path = str(capture.get("source_path") or "")
            capture_dir = get_capture_dir(capture_id, handshakes_dir=HANDSHAKES_DIR)
            if not capture_id or not source_path or not capture_dir:
                continue
            report["captures_scanned"] += 1
            if not os.path.isdir(capture_dir):
                continue

            for legacy_name, artifact_type in LEGACY_CAPTURE_ARTIFACTS:
                legacy_path = os.path.join(capture_dir, legacy_name)
                if not os.path.exists(legacy_path):
                    continue
                target_path = get_source_sidecar_path(
                    source_path,
                    artifact_type,
                    ensure_parent=apply,
                )
                if not target_path:
                    report["skipped"].append(
                        {
                            "capture_id": capture_id,
                            "legacy_path": legacy_path,
                            "reason": "target_unresolved",
                        }
                    )
                    continue
                entry = {
                    "capture_id": capture_id,
                    "from": legacy_path,
                    "to": target_path,
                }
                if not os.path.exists(target_path):
                    if apply:
                        shutil.move(legacy_path, target_path)
                    report["moved"].append(entry)
                    continue
                if _same_content(legacy_path, target_path):
                    if apply:
                        os.remove(legacy_path)
                    report["duplicates_removed"].append(entry)
                    continue
                if artifact_type == "history":
                    status = _merge_history(legacy_path, target_path, apply)
                    if status == "merged_history":
                        report["merged_history"].append(entry)
                        continue
                report["conflicts"].append(entry)

            if _cleanup_capture_dir(capture_dir, apply):
                report["cleaned_dirs"].append(
                    {"capture_id": capture_id, "path": capture_dir}
                )

    return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Move legacy capture.* artifacts next to their source PCAPs."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply the migration. Without this flag the command is a dry-run.",
    )
    args = parser.parse_args()
    print(json.dumps(migrate_capture_artifacts(apply=args.apply), indent=2))


if __name__ == "__main__":
    main()
