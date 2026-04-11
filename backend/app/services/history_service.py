import json
import os
import uuid
from datetime import datetime
from app.core.config import HANDSHAKES_DIR
from app.utils.handshake_artifacts import (
    get_capture_artifact_path,
    get_combined_artifact_path,
)
import logging

logger = logging.getLogger(__name__)


class HistoryService:
    def get_history_path(
        self,
        base_filename,
        capture_id=None,
        combined_build_id=None,
        mac=None,
    ):
        if capture_id:
            capture_path = get_capture_artifact_path(
                capture_id, "history", handshakes_dir=HANDSHAKES_DIR, ensure_parent=True
            )
            if capture_path:
                return capture_path
        if combined_build_id and mac:
            combined_path = get_combined_artifact_path(
                mac,
                combined_build_id,
                "history",
                handshakes_dir=HANDSHAKES_DIR,
                ensure_parent=True,
            )
            if combined_path:
                return combined_path
        # base_filename is like "SSID_MAC.pcap" or "SSID_MAC.22000"
        # We want "SSID_MAC.try"
        # Remove known extensions
        name = base_filename
        for ext in [".pcap", ".22000", ".cracked"]:
            if name.endswith(ext):
                name = name[: -len(ext)]
                break

        return os.path.join(HANDSHAKES_DIR, f"{name}.try")

    def add_entry(
        self,
        base_filename,
        tool,
        command,
        params=None,
        capture_id=None,
        combined_build_id=None,
        mac=None,
    ):
        try:
            path = self.get_history_path(
                base_filename,
                capture_id=capture_id,
                combined_build_id=combined_build_id,
                mac=mac,
            )
            history = {"entries": []}

            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        history = json.load(f)
                except Exception:
                    pass  # Corrupted or empty, start fresh

            # Filter params to only include those that are not None/False/Empty
            # And simplify file paths to just filenames
            filtered_params = {}
            if params:
                for k, v in params.items():
                    if v is not None and v is not False and v != "":
                        # Check if value looks like a file path
                        if isinstance(v, str) and (os.path.sep in v or "/" in v):
                            filtered_params[k] = os.path.basename(v)
                        else:
                            filtered_params[k] = v

            entry_id = str(uuid.uuid4())
            entry = {
                "id": entry_id,
                "tool": tool,
                "start_time": datetime.now().isoformat(),
                "status": "QUEUED",
                "command": command if isinstance(command, str) else " ".join(command),
                "params": filtered_params,
                "meta": [],
            }

            history["entries"].append(entry)

            with open(path, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2)

            return entry_id
        except Exception as e:
            logger.error(f"Failed to add history entry: {e}")
            return None

    def _format_duration(self, seconds):
        seconds = int(round(seconds))
        if seconds < 60:
            return f"{seconds}s"

        minutes, seconds = divmod(seconds, 60)
        if minutes < 60:
            return f"{minutes}m {seconds}s"

        hours, minutes = divmod(minutes, 60)
        return f"{hours}h {minutes}m {seconds}s"

    def update_entry(
        self,
        base_filename,
        entry_id,
        status,
        result=None,
        meta=None,
        capture_id=None,
        combined_build_id=None,
        mac=None,
    ):
        try:
            path = self.get_history_path(
                base_filename,
                capture_id=capture_id,
                combined_build_id=combined_build_id,
                mac=mac,
            )
            if not os.path.exists(path):
                logger.warning(f"History file not found for update: {path}")
                return

            with open(path, "r", encoding="utf-8") as f:
                history = json.load(f)

            updated = False
            if status == "RUNNING":
                for entry in history.get("entries", []):
                    if entry.get("id") != entry_id and entry.get("status") == "RUNNING":
                        entry["status"] = "INCOMPLETE"
                        entry["end_time"] = datetime.now().isoformat()
                        entry.setdefault("meta", []).append(
                            "Auto-marked as INCOMPLETE due to new running job"
                        )
                        if "start_time" in entry and entry.get("end_time"):
                            try:
                                start = datetime.fromisoformat(entry["start_time"])
                                end = datetime.fromisoformat(entry["end_time"])
                                duration_seconds = (end - start).total_seconds()
                                entry["duration"] = self._format_duration(
                                    duration_seconds
                                )
                            except Exception:
                                pass

            for entry in history["entries"]:
                if entry["id"] == entry_id:
                    entry["status"] = status
                    entry["end_time"] = datetime.now().isoformat()

                    if result:
                        entry["result"] = result

                    # Robust meta handling
                    if meta:
                        if "meta" not in entry:
                            entry["meta"] = []

                        if isinstance(meta, list):
                            entry["meta"].extend(meta)
                        elif isinstance(meta, str):
                            entry["meta"].append(meta)
                        else:
                            entry["meta"].append(str(meta))

                    # Calculate duration if start_time exists
                    if "start_time" in entry and entry["end_time"]:
                        try:
                            start = datetime.fromisoformat(entry["start_time"])
                            end = datetime.fromisoformat(entry["end_time"])
                            duration_seconds = (end - start).total_seconds()
                            entry["duration"] = self._format_duration(duration_seconds)
                        except Exception:
                            pass

                    updated = True
                    break

            if updated:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(history, f, indent=2)
                logger.info(f"Updated history entry {entry_id} to {status}")
            else:
                logger.warning(f"Entry {entry_id} not found in {path}")

        except Exception as e:
            logger.error(f"Failed to update history entry: {e}")

    def clear_all_history(self):
        """Remove todos os arquivos .try do diretório de handshakes"""
        try:
            count = 0
            if not os.path.exists(HANDSHAKES_DIR):
                return 0

            for root, _, files in os.walk(HANDSHAKES_DIR):
                for filename in files:
                    if not filename.endswith(".try"):
                        continue
                    try:
                        os.remove(os.path.join(root, filename))
                        count += 1
                    except Exception as e:
                        logger.error(f"Erro ao remover {filename}: {e}")
            return count
        except Exception as e:
            logger.error(f"Erro ao limpar histórico: {e}")
            return 0


history_service = HistoryService()
