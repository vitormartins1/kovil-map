import glob
import json
import os
from datetime import UTC, datetime

from app.core.config import HANDSHAKES_DIR
from app.services.data_loader import (
    load_real_data,
    list_bruce_handshake_files,
    list_m5evil_handshake_files,
)
from app.services.rawsniffer_service import rawsniffer_service


class DataHealthService:
    SCHEMA_VERSION = 1

    def _is_blank(self, value) -> bool:
        return value is None or not str(value).strip()

    def _safe_json_load(self, path: str):
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def get_summary(self) -> dict:
        data = load_real_data() or {}
        items = list(data.values()) if isinstance(data, dict) else []

        with_gps = 0
        hidden_networks = 0
        source_counts: dict[str, int] = {}
        for item in items:
            if not isinstance(item, dict):
                continue

            lat = item.get("lat")
            lng = item.get("lng")
            if lat is not None and lng is not None:
                with_gps += 1

            if self._is_blank(item.get("ssid")):
                hidden_networks += 1

            sources = (
                item.get("sources") if isinstance(item.get("sources"), list) else []
            )
            for source in sources:
                source_name = str(source).strip()
                if not source_name:
                    continue
                source_counts[source_name] = source_counts.get(source_name, 0) + 1

        total_networks = len(items)
        no_gps = max(0, total_networks - with_gps)

        detail_files = glob.glob(os.path.join(HANDSHAKES_DIR, "*.details"))
        pcap_files = glob.glob(os.path.join(HANDSHAKES_DIR, "*.pcap"))
        detail_bases = {
            os.path.basename(path).rsplit(".", 1)[0] for path in detail_files
        }
        pcap_bases = {os.path.basename(path).rsplit(".", 1)[0] for path in pcap_files}

        invalid_details = 0
        hidden_details = 0
        for path in detail_files:
            try:
                payload = self._safe_json_load(path)
            except Exception:
                invalid_details += 1
                continue

            if isinstance(payload, dict) and self._is_blank(payload.get("ssid")):
                hidden_details += 1

        handshake_without_details = len(
            [base for base in pcap_bases if base not in detail_bases]
        )
        details_without_handshake = len(
            [base for base in detail_bases if base not in pcap_bases]
        )

        bruce_files = list_bruce_handshake_files()
        bruce_hidden_refresh = 0
        bruce_missing_details = 0
        bruce_invalid_details = 0
        for filename in bruce_files:
            base_name = filename.rsplit(".", 1)[0]
            details_path = os.path.join(HANDSHAKES_DIR, f"{base_name}.details")
            if not os.path.exists(details_path):
                bruce_missing_details += 1
                continue
            try:
                payload = self._safe_json_load(details_path)
            except Exception:
                bruce_invalid_details += 1
                continue
            if isinstance(payload, dict) and self._is_blank(payload.get("ssid")):
                bruce_hidden_refresh += 1

        m5evil_files = list_m5evil_handshake_files()
        m5evil_hidden_refresh = 0
        m5evil_missing_details = 0
        m5evil_invalid_details = 0
        for filename in m5evil_files:
            base_name = filename.rsplit(".", 1)[0]
            details_path = os.path.join(HANDSHAKES_DIR, f"{base_name}.details")
            if not os.path.exists(details_path):
                m5evil_missing_details += 1
                continue
            try:
                payload = self._safe_json_load(details_path)
            except Exception:
                m5evil_invalid_details += 1
                continue
            if isinstance(payload, dict) and self._is_blank(payload.get("ssid")):
                m5evil_hidden_refresh += 1

        raw_files = rawsniffer_service.list_files()
        raw_pending = rawsniffer_service.get_pending_files()
        raw_with_warnings = len(
            [item for item in raw_files if int(item.get("warnings_count") or 0) > 0]
        )
        raw_cached_up_to_date = len(
            [item for item in raw_files if bool(item.get("cached_up_to_date"))]
        )

        return {
            "schema_version": self.SCHEMA_VERSION,
            "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "dataset": {
                "total_networks": total_networks,
                "with_gps": with_gps,
                "no_gps": no_gps,
                "hidden_networks": hidden_networks,
                "source_counts": source_counts,
            },
            "handshakes": {
                "pcap_files": len(pcap_files),
                "details_files": len(detail_files),
                "invalid_details": invalid_details,
                "hidden_details": hidden_details,
                "handshake_without_details": handshake_without_details,
                "details_without_handshake": details_without_handshake,
            },
            "bruce": {
                "handshakes_seen": len(bruce_files),
                "hidden_refresh_candidates": bruce_hidden_refresh,
                "missing_details": bruce_missing_details,
                "invalid_details": bruce_invalid_details,
            },
            "m5evil": {
                "handshakes_seen": len(m5evil_files),
                "hidden_refresh_candidates": m5evil_hidden_refresh,
                "missing_details": m5evil_missing_details,
                "invalid_details": m5evil_invalid_details,
            },
            "rawsniffer": {
                "files_seen": len(raw_files),
                "pending_files": len(raw_pending),
                "cached_up_to_date_files": raw_cached_up_to_date,
                "files_with_warnings": raw_with_warnings,
            },
        }


data_health_service = DataHealthService()
