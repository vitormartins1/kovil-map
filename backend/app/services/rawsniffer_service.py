import glob
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import unicodedata
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Tuple

from app.core.config import (
    BRUCE_PCAP_DIR,
    HANDSHAKES_DIR,
    M5EVIL_DIR,
    M5EVIL_MASTERSNIFFER_DIR,
    M5EVIL_RAWSNIFFER_DIR,
    load_config,
)
from app.services.base_service import BaseService
from app.utils.pcap import validate_pcap_file
from app.utils.rawsniffer_parser import (
    decode_ssid,
    normalize_mac,
    parse_output,
    to_float,
    to_int,
)

logger = logging.getLogger(__name__)


class RawSnifferService(BaseService):
    """Extract and cache metadata from Bruce rawsniffer PCAP files."""

    SCHEMA_VERSION = 1

    def __init__(self):
        super().__init__()
        self._aggregate_index_signature: tuple | None = None
        self._aggregate_index_by_bssid: Dict[str, List[Dict]] = {}

    @property
    def metadata_dir(self) -> str:
        path = os.path.join(BRUCE_PCAP_DIR, ".metadata")
        os.makedirs(path, exist_ok=True)
        return path

    def _metadata_dir_for_source(self, source: str) -> str:
        base_dir = (
            M5EVIL_DIR
            if str(source or "").strip().lower() == "m5evil"
            else BRUCE_PCAP_DIR
        )
        path = os.path.join(base_dir, ".metadata")
        os.makedirs(path, exist_ok=True)
        return path

    def _metadata_dirs(self) -> List[str]:
        dirs = [self._metadata_dir_for_source("brucegotchi")]
        m5_dir = self._metadata_dir_for_source("m5evil")
        if m5_dir not in dirs:
            dirs.append(m5_dir)
        return dirs

    def _device_label_for_source(self, source: str) -> str:
        normalized = str(source or "").strip().lower()
        if normalized == "m5evil":
            return "M5Evil"
        return "Bruce"

    def _raw_source_roots(self) -> List[Dict]:
        return [
            {
                "source": "brucegotchi",
                "device_label": "Bruce",
                "source_path_role": "rawsniffer",
                "root": os.path.join(BRUCE_PCAP_DIR, "rawsniffer"),
            },
            {
                "source": "m5evil",
                "device_label": "M5Evil",
                "source_path_role": "rawsniffer",
                "root": M5EVIL_RAWSNIFFER_DIR,
            },
            {
                "source": "m5evil",
                "device_label": "M5Evil",
                "source_path_role": "master_sniffer",
                "root": M5EVIL_MASTERSNIFFER_DIR,
            },
        ]

    def _make_raw_item_id(
        self,
        artifact_type: str,
        source: str,
        source_path_role: str,
        filename: str,
        *,
        source_raw_file: str | None = None,
    ) -> str:
        digest = hashlib.sha1(
            "|".join(
                [
                    str(artifact_type or "").strip().lower(),
                    str(source or "").strip().lower(),
                    str(source_path_role or "").strip().lower(),
                    os.path.basename(str(filename or "").strip()).lower(),
                    os.path.basename(str(source_raw_file or "").strip()).lower(),
                ]
            ).encode("utf-8", errors="ignore")
        ).hexdigest()[:16]
        return f"raw::{str(artifact_type or '').strip().lower()}::{digest}"

    def _safe_raw_stem(self, filename: str | None) -> str:
        stem = os.path.basename(str(filename or "raw_capture")).rsplit(".", 1)[0]
        safe_stem = re.sub(r"[^a-zA-Z0-9._-]+", "_", stem).strip("._") or "raw_capture"
        return safe_stem[:64]

    def _normalize_compact_mac(self, value: str | None) -> str | None:
        normalized = normalize_mac(value)
        if not normalized:
            return None
        return normalized.replace(":", "").lower()

    def _legacy_raw_details_filename(
        self, raw_item_id: str | None, filename: str | None
    ) -> str:
        digest = str(raw_item_id or "").rsplit("::", 1)[-1] or "unknown"
        safe_stem = self._safe_raw_stem(filename)
        return f"__rawdetails__{safe_stem}_{digest}.details"

    def _raw_details_filename(
        self,
        raw_item_id: str | None,
        filename: str | None,
        bssid: str | None = None,
    ) -> str:
        compact_mac = self._normalize_compact_mac(bssid)
        if not compact_mac:
            return self._legacy_raw_details_filename(raw_item_id, filename)
        safe_stem = self._safe_raw_stem(filename)
        return f"__rawdetails__{safe_stem}_{compact_mac}.details"

    def _raw_details_candidates(
        self,
        raw_item_id: str | None,
        filename: str | None,
        bssid: str | None = None,
    ) -> List[str]:
        preferred = self._raw_details_filename(raw_item_id, filename, bssid)
        legacy = self._legacy_raw_details_filename(raw_item_id, filename)
        if legacy == preferred:
            return [preferred]
        return [preferred, legacy]

    def _resolve_existing_raw_details_filename(
        self,
        raw_item_id: str | None,
        filename: str | None,
        bssid: str | None = None,
    ) -> str | None:
        for candidate in self._raw_details_candidates(raw_item_id, filename, bssid):
            if os.path.exists(os.path.join(HANDSHAKES_DIR, candidate)):
                return candidate
        return None

    def _analysis_path_for_record(self, record: Dict) -> str:
        source = str(record.get("source") or "brucegotchi").strip().lower()
        raw_item_id = str(record.get("raw_item_id") or "").strip()
        digest = raw_item_id.rsplit("::", 1)[-1] or "unknown"
        safe_stem = self._safe_raw_stem(
            str(record.get("filename") or record.get("source_file") or "")
        )
        return os.path.join(
            self._metadata_dir_for_source(source),
            f"analysis__{safe_stem}_{digest}.json",
        )

    def _read_analysis_for_record(self, record: Dict) -> Dict | None:
        path = self._analysis_path_for_record(record)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            return payload if isinstance(payload, dict) else None
        except Exception:
            return None

    def _analysis_summary(self, analysis: Dict | None) -> Dict | None:
        if not isinstance(analysis, dict):
            return None
        capture = analysis.get("capture")
        highlights = analysis.get("highlights")
        if not isinstance(capture, dict) or not isinstance(highlights, dict):
            return None
        return {
            "duration_s": capture.get("duration_s"),
            "clients_count": capture.get("clients_count"),
            "networks_count": capture.get("networks_count"),
            "handshake_candidate_count": highlights.get("handshake_candidate_count"),
            "noisy_capture": bool(highlights.get("noisy_capture")),
            "revealed_hidden_count": int(highlights.get("revealed_hidden_count") or 0),
        }

    def _iter_raw_pcap_records(self) -> List[Dict]:
        records: List[Dict] = []
        seen_paths = set()
        for root_info in self._raw_source_roots():
            root = str(root_info.get("root") or "").strip()
            if not root or not os.path.exists(root):
                continue
            try:
                names = os.listdir(root)
            except OSError:
                continue
            for name in sorted(names):
                if not str(name or "").lower().endswith(".pcap"):
                    continue
                if str(name or "").upper().startswith("HS_"):
                    continue
                path = os.path.join(root, name)
                if not os.path.isfile(path):
                    continue
                real_path = os.path.realpath(path)
                if real_path in seen_paths:
                    continue
                seen_paths.add(real_path)
                valid, reason = validate_pcap_file(path)
                if not valid:
                    logger.warning(
                        "Skipping invalid PCAP %s: %s", name, reason
                    )
                    continue
                record = {
                    "artifact_type": "pcap",
                    "filename": os.path.basename(name),
                    "source_file": os.path.basename(name),
                    "path": path,
                    "source": root_info["source"],
                    "device_label": root_info["device_label"],
                    "source_path_role": root_info["source_path_role"],
                }
                record["raw_item_id"] = self._make_raw_item_id(
                    "pcap",
                    record["source"],
                    record["source_path_role"],
                    record["filename"],
                )
                records.append(record)
        records.sort(
            key=lambda item: (
                str(item.get("source") or ""),
                str(item.get("filename") or ""),
                str(item.get("source_path_role") or ""),
            )
        )
        return records

    def _resolve_raw_record(
        self,
        filename: str | None = None,
        *,
        raw_item_id: str | None = None,
    ) -> Dict | None:
        target_item_id = str(raw_item_id or "").strip()
        target_name = os.path.basename(str(filename or "").strip())
        for record in self._iter_raw_pcap_records():
            if target_item_id and record.get("raw_item_id") == target_item_id:
                return dict(record)
            if target_name and record.get("filename") == target_name:
                return dict(record)
        return None

    def resolve_raw_pcap_item(self, raw_item_id: str | None) -> Dict | None:
        record = self._resolve_raw_record(raw_item_id=raw_item_id)
        if not record:
            return None
        return dict(record)

    def resolve_raw_record(
        self,
        filename: str | None = None,
        *,
        raw_item_id: str | None = None,
    ) -> Dict | None:
        record = self._resolve_raw_record(filename, raw_item_id=raw_item_id)
        if not record:
            return None
        return dict(record)

    def _metadata_path_for_record(self, record: Dict) -> str:
        filename = os.path.basename(
            str(record.get("filename") or record.get("source_file") or "").strip()
        )
        source = str(record.get("source") or "brucegotchi").strip().lower()
        source_path_role = (
            str(record.get("source_path_role") or "rawsniffer").strip().lower()
        )
        metadata_dir = self._metadata_dir_for_source(source)
        return os.path.join(
            metadata_dir,
            f"{source}__{source_path_role}__{filename}.json",
        )

    def _metadata_paths_for_record(self, record: Dict) -> List[str]:
        return [self._metadata_path_for_record(record)]

    def _existing_metadata_path_for_record(self, record: Dict) -> str:
        for path in self._metadata_paths_for_record(record):
            if os.path.exists(path):
                return path
        return self._metadata_path_for_record(record)

    def _read_metadata_for_record(self, record: Dict) -> Dict | None:
        for path in self._metadata_paths_for_record(record):
            if not os.path.exists(path):
                continue
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                return payload if isinstance(payload, dict) else None
            except Exception:
                continue
        return None

    def _check_tshark(self) -> str | None:
        conf = load_config()
        tshark_bin = conf.get("tshark_path", "tshark")
        use_wsl = self._should_use_wsl(tshark_bin)
        if use_wsl:
            return tshark_bin if shutil.which("wsl") is not None else None
        if os.path.isabs(tshark_bin):
            exists = os.path.exists(tshark_bin)
        else:
            exists = shutil.which(tshark_bin) is not None
        return tshark_bin if exists else None

    def _build_command(self, pcap_path: str) -> Tuple[List[str], str]:
        conf = load_config()
        tshark_bin = conf.get("tshark_path", "tshark")
        use_wsl = self._should_use_wsl(tshark_bin)
        target_path = self._to_wsl_path(pcap_path) if use_wsl else pcap_path

        fields = [
            "frame.time_epoch",
            "wlan.fc.type_subtype",
            "wlan.bssid",
            "wlan.sa",
            "wlan.da",
            "wlan.ssid",
            "wlan.ds.current_channel",
            "wlan_rsna_eapol.keydes.msgnr",
            "eapol.type",
        ]

        base_cmd = [
            "-r",
            target_path,
            "-Y",
            "(wlan.fc.type_subtype==0x08) or (wlan.fc.type_subtype==0x04) or eapol",
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "quote=n",
        ]
        for field in fields:
            base_cmd.extend(["-e", field])

        if use_wsl:
            cmd = ["wsl", tshark_bin] + base_cmd
        else:
            cmd = [tshark_bin] + base_cmd
        return cmd, " ".join(cmd)

    def _run_tshark(self, pcap_path: str) -> Tuple[str, List[str]]:
        cmd, _ = self._build_command(pcap_path)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            raise RuntimeError("tshark not found")

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        warnings: List[str] = []
        if stderr.strip():
            warnings.extend(
                [line.strip() for line in stderr.splitlines() if line.strip()]
            )
        if proc.returncode != 0 and not stdout.strip():
            raise RuntimeError(stderr.strip() or f"tshark exit {proc.returncode}")
        if proc.returncode != 0 and stdout.strip():
            warnings.append(
                f"tshark exited with code {proc.returncode} but returned partial output"
            )

        return stdout, warnings

    def _metadata_path(self, filename: str) -> str:
        record = self._resolve_raw_record(filename)
        if record:
            return self._metadata_path_for_record(record)
        safe_name = os.path.basename(filename)
        return os.path.join(self.metadata_dir, f"{safe_name}.json")

    def _resolve_raw_file(self, filename: str) -> str | None:
        record = self._resolve_raw_record(filename)
        if record:
            return str(record.get("path") or "")
        if not filename:
            return None
        base = os.path.basename(filename)
        if base.upper().startswith("HS_"):
            return None
        if os.path.isabs(filename):
            if os.path.exists(filename):
                return filename
            return None
        return None

    def _is_cache_fresh(self, metadata: Dict, source_path: str) -> bool:
        try:
            stat = os.stat(source_path)
        except OSError:
            return False

        if metadata.get("schema_version") != self.SCHEMA_VERSION:
            return False
        if metadata.get("source_file") != os.path.basename(source_path):
            return False

        src_size = metadata.get("source_size")
        src_mtime = metadata.get("source_mtime")
        return src_size == stat.st_size and float(src_mtime or 0) == float(
            stat.st_mtime
        )

    def list_files(self) -> List[Dict]:
        files: List[Dict] = []
        for record in self._iter_raw_pcap_records():
            name = str(record.get("filename") or "").strip()
            path = str(record.get("path") or "").strip()
            if not name or not path or not os.path.exists(path):
                continue
            stat = os.stat(path)
            metadata = self._read_metadata_for_record(record)
            metadata_path = self._existing_metadata_path_for_record(record)
            analysis = self._read_analysis_for_record(record)
            analysis_path = self._analysis_path_for_record(record)

            up_to_date = bool(metadata and self._is_cache_fresh(metadata, path))
            analysis_up_to_date = bool(
                analysis and self._is_cache_fresh(analysis, path)
            )
            stats = metadata.get("stats", {}) if isinstance(metadata, dict) else {}
            warnings_count = (
                len(metadata.get("warnings", [])) if isinstance(metadata, dict) else 0
            )

            files.append(
                {
                    "raw_item_id": str(record.get("raw_item_id") or ""),
                    "source": str(record.get("source") or "brucegotchi"),
                    "device_label": str(
                        record.get("device_label")
                        or self._device_label_for_source(
                            record.get("source") or "brucegotchi"
                        )
                    ),
                    "source_path_role": str(
                        record.get("source_path_role") or "rawsniffer"
                    ),
                    "filename": name,
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                    "metadata_path": metadata_path if metadata else None,
                    "analysis_path": analysis_path if analysis else None,
                    "processed_at": (
                        metadata.get("processed_at")
                        if isinstance(metadata, dict)
                        else None
                    ),
                    "cached_up_to_date": up_to_date,
                    "analysis_present": analysis_up_to_date,
                    "analysis_summary": (
                        self._analysis_summary(analysis)
                        if analysis_up_to_date
                        else None
                    ),
                    "networks_count": int(stats.get("networks_count", 0)),
                    "beacon_frames": int(stats.get("beacon_frames", 0)),
                    "eapol_frames": int(stats.get("eapol_frames", 0)),
                    "warnings_count": warnings_count,
                }
            )

        files.sort(key=lambda item: item.get("modified", 0), reverse=True)
        return files

    def _parse_generated_hash_file(self, hash_path: str) -> Dict:
        filename = os.path.basename(hash_path)
        base_name = filename.rsplit(".", 1)[0]
        source_raw_file = f"{base_name}.pcap"

        try:
            stat = os.stat(hash_path)
            size = int(stat.st_size)
            modified = float(stat.st_mtime)
        except OSError:
            size = 0
            modified = 0.0

        valid_hash_lines = 0
        bssid_hits: Dict[str, int] = {}
        bssid_ssids: Dict[str, str] = {}

        try:
            with open(hash_path, "r", encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line:
                        continue
                    parts = line.split("*")
                    if (
                        not parts
                        or not parts[0].upper().startswith("WPA")
                        or len(parts) <= 5
                        or not parts[2]
                        or not parts[3]
                        or not parts[4]
                        or not parts[5]
                    ):
                        continue

                    valid_hash_lines += 1
                    bssid = normalize_mac(parts[3])
                    if not bssid:
                        continue
                    bssid_hits[bssid] = int(bssid_hits.get(bssid, 0)) + 1

                    ssid, _ = decode_ssid(parts[5])
                    if ssid and not bssid_ssids.get(bssid):
                        bssid_ssids[bssid] = ssid
        except Exception:
            pass

        sorted_bssids = sorted(
            bssid_hits.items(),
            key=lambda entry: (-int(entry[1]), entry[0]),
        )
        primary_bssid = sorted_bssids[0][0] if sorted_bssids else None
        primary_ssid = bssid_ssids.get(primary_bssid or "", "")
        related_bssids = sorted(bssid_hits.keys())

        return {
            "filename": filename,
            "size": size,
            "modified": modified,
            "source_raw_file": source_raw_file,
            "valid_hash_lines": valid_hash_lines,
            "primary_bssid": primary_bssid,
            "primary_ssid": primary_ssid,
            "bssid_count": len(related_bssids),
            "has_context": bool(primary_bssid),
            "_bssids": related_bssids,
            "_bssid_hits": bssid_hits,
            "_bssid_ssids": bssid_ssids,
        }

    def _list_generated_hashes_internal(self) -> List[Dict]:
        if not os.path.exists(HANDSHAKES_DIR):
            return []

        hashes: List[Dict] = []
        for name in os.listdir(HANDSHAKES_DIR):
            normalized_name = str(name or "").lower()
            if not normalized_name.startswith("raw_") or not normalized_name.endswith(
                ".22000"
            ):
                continue
            path = os.path.join(HANDSHAKES_DIR, name)
            if not os.path.isfile(path):
                continue
            hashes.append(self._parse_generated_hash_file(path))

        hashes.sort(key=lambda item: float(item.get("modified") or 0), reverse=True)
        return hashes

    def list_generated_hashes(self) -> List[Dict]:
        out: List[Dict] = []
        for item in self._list_generated_hashes_internal():
            clean = dict(item)
            clean.pop("_bssids", None)
            clean.pop("_bssid_hits", None)
            clean.pop("_bssid_ssids", None)
            out.append(clean)
        return out

    def get_generated_hashes_for_bssid(self, bssid: str | None) -> List[Dict]:
        normalized = normalize_mac(bssid)
        if not normalized:
            return []

        matches: List[Dict] = []
        for item in self._list_generated_hashes_internal():
            related_bssids = item.get("_bssids") or []
            if normalized not in related_bssids:
                continue
            clean = dict(item)
            clean.pop("_bssids", None)
            bssid_hits = (
                item.get("_bssid_hits")
                if isinstance(item.get("_bssid_hits"), dict)
                else {}
            )
            bssid_ssids = (
                item.get("_bssid_ssids")
                if isinstance(item.get("_bssid_ssids"), dict)
                else {}
            )
            clean["matched_bssid"] = normalized
            clean["matched_lines"] = int(bssid_hits.get(normalized) or 0)
            clean["matched_ssid"] = str(bssid_ssids.get(normalized) or "").strip()
            clean.pop("_bssid_hits", None)
            clean.pop("_bssid_ssids", None)
            matches.append(clean)
        return matches

    def get_pending_files(self) -> List[str]:
        return [
            f["filename"] for f in self.list_files() if not f.get("cached_up_to_date")
        ]

    def get_metadata(
        self, filename: str | None, *, raw_item_id: str | None = None
    ) -> Dict | None:
        record = self._resolve_raw_record(filename, raw_item_id=raw_item_id)
        if record:
            return self._read_metadata_for_record(record)
        if not filename:
            return None
        metadata_path = self._metadata_path(filename)
        if not os.path.exists(metadata_path):
            return None
        try:
            with open(metadata_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def delete_file(self, filename: str) -> Dict:
        record = self._resolve_raw_record(filename)
        source_path = (
            str(record.get("path") or "")
            if record
            else self._resolve_raw_file(filename)
        )
        if not source_path or not record:
            return {"status": "error", "message": f"Raw PCAP not found: {filename}"}

        source_file = os.path.basename(source_path)
        metadata_paths = self._metadata_paths_for_record(record)
        analysis_path = self._analysis_path_for_record(record)
        hash_filename = f"{os.path.splitext(source_file)[0]}.22000"
        hash_path = os.path.join(HANDSHAKES_DIR, hash_filename)

        deleted: List[str] = []
        metadata_deleted = False
        analysis_deleted = False
        hash_deleted = False

        for path in [source_path, *metadata_paths, analysis_path, hash_path]:
            if not os.path.exists(path):
                continue
            try:
                os.remove(path)
                deleted.append(os.path.basename(path))
                if path in metadata_paths:
                    metadata_deleted = True
                elif path == analysis_path:
                    analysis_deleted = True
                elif path == hash_path:
                    hash_deleted = True
            except Exception as exc:
                return {
                    "status": "error",
                    "message": str(exc),
                    "source_file": source_file,
                    "deleted": deleted,
                }

        self._aggregate_index_signature = None
        self._aggregate_index_by_bssid = {}

        return {
            "status": "success",
            "source_file": source_file,
            "deleted": deleted,
            "metadata_deleted": metadata_deleted,
            "analysis_deleted": analysis_deleted,
            "hash_deleted": hash_deleted,
            "hash_file": hash_filename if hash_deleted else None,
        }

    def clear_metadata_cache(self, remove_files: bool = True) -> Dict:
        deleted = 0
        failed = 0

        if remove_files:
            for metadata_dir in self._metadata_dirs():
                for metadata_path in glob.glob(os.path.join(metadata_dir, "*.json")):
                    try:
                        os.remove(metadata_path)
                        deleted += 1
                    except Exception:
                        failed += 1

        self._aggregate_index_signature = None
        self._aggregate_index_by_bssid = {}

        return {
            "deleted_count": deleted,
            "failed_count": failed,
            "removed_files": bool(remove_files),
        }

    def _metadata_index_signature(self) -> tuple:
        signature_parts = [self.SCHEMA_VERSION]
        for metadata_dir in self._metadata_dirs():
            for metadata_path in sorted(
                glob.glob(os.path.join(metadata_dir, "*.json"))
            ):
                if os.path.basename(metadata_path).startswith("analysis__"):
                    continue
                try:
                    stat = os.stat(metadata_path)
                except OSError:
                    continue
                signature_parts.append(
                    (
                        metadata_dir,
                        os.path.basename(metadata_path),
                        stat.st_size,
                        stat.st_mtime_ns,
                    )
                )
        return tuple(signature_parts)

    def _build_aggregate_index(self) -> Dict[str, List[Dict]]:
        index: Dict[str, List[Dict]] = {}

        for metadata_dir in self._metadata_dirs():
            for metadata_path in sorted(
                glob.glob(os.path.join(metadata_dir, "*.json"))
            ):
                if os.path.basename(metadata_path).startswith("analysis__"):
                    continue
                try:
                    with open(metadata_path, "r", encoding="utf-8") as f:
                        metadata = json.load(f)
                except Exception as exc:
                    logger.warning(
                        "Failed to read rawsniffer metadata %s: %s", metadata_path, exc
                    )
                    continue

                source_file = str(
                    metadata.get("source_file")
                    or os.path.splitext(os.path.basename(metadata_path))[0]
                )
                source = str(metadata.get("source") or "").strip().lower()
                if not source:
                    source = (
                        "m5evil"
                        if metadata_dir.startswith(M5EVIL_DIR)
                        else "brucegotchi"
                    )
                source_path_role = (
                    str(metadata.get("source_path_role") or "").strip().lower()
                    or "rawsniffer"
                )
                device_label = str(
                    metadata.get("device_label") or ""
                ).strip() or self._device_label_for_source(source)
                raw_item_id = str(
                    metadata.get("raw_item_id") or ""
                ).strip() or self._make_raw_item_id(
                    "pcap",
                    source,
                    source_path_role,
                    source_file,
                )
                processed_at = metadata.get("processed_at")
                processed_at = (
                    processed_at
                    if isinstance(processed_at, str) and processed_at.strip()
                    else None
                )
                metadata_warnings = metadata.get("warnings")
                clean_warnings = []
                if isinstance(metadata_warnings, list):
                    for warning in metadata_warnings:
                        text = str(warning).strip()
                        if text:
                            clean_warnings.append(text)

                networks = metadata.get("networks")
                if not isinstance(networks, list):
                    continue

                per_bssid: Dict[str, Dict] = {}
                for net in networks:
                    if not isinstance(net, dict):
                        continue
                    normalized_bssid = normalize_mac(net.get("bssid"))
                    if not normalized_bssid:
                        continue

                    entry = per_bssid.get(normalized_bssid)
                    if entry is None:
                        entry = {
                            "artifact_type": "pcap",
                            "raw_item_id": raw_item_id,
                            "source": source,
                            "device_label": device_label,
                            "source_path_role": source_path_role,
                            "filename": source_file,
                            "source_file": source_file,
                            "processed_at": processed_at,
                            "ssid": "",
                            "ssid_raw_hex": None,
                            "channel": None,
                            "frequency_mhz": None,
                            "beacon_count": 0,
                            "eapol_count": 0,
                            "probe_client_count": 0,
                            "last_seen_offset_s": None,
                            "warnings": clean_warnings,
                        }
                        per_bssid[normalized_bssid] = entry

                    ssid = str(net.get("ssid") or "").strip()
                    if ssid and not entry["ssid"]:
                        entry["ssid"] = ssid

                    ssid_raw_hex = net.get("ssid_raw_hex")
                    if ssid_raw_hex and not entry["ssid_raw_hex"]:
                        entry["ssid_raw_hex"] = str(ssid_raw_hex)

                    channel = to_int(net.get("channel"))
                    if channel is not None and entry["channel"] is None:
                        entry["channel"] = channel

                    frequency_mhz = to_int(net.get("frequency_mhz"))
                    if frequency_mhz is not None and entry["frequency_mhz"] is None:
                        entry["frequency_mhz"] = frequency_mhz

                    beacon_count = int(to_int(net.get("beacon_count")) or 0)
                    eapol_count = int(to_int(net.get("eapol_count")) or 0)
                    probe_count = int(to_int(net.get("probe_client_count")) or 0)
                    entry["beacon_count"] += beacon_count
                    entry["eapol_count"] += eapol_count
                    entry["probe_client_count"] = max(
                        entry["probe_client_count"], probe_count
                    )

                    last_seen_offset = to_float(net.get("last_seen_offset_s"))
                    if last_seen_offset is not None:
                        current_offset = entry["last_seen_offset_s"]
                        if current_offset is None or last_seen_offset > current_offset:
                            entry["last_seen_offset_s"] = round(last_seen_offset, 6)

                for normalized_bssid, entry in per_bssid.items():
                    index.setdefault(normalized_bssid, []).append(entry)

        return index

    def _ensure_aggregate_index(self) -> None:
        signature = self._metadata_index_signature()
        if signature == self._aggregate_index_signature:
            return
        self._aggregate_index_by_bssid = self._build_aggregate_index()
        self._aggregate_index_signature = signature

    def get_aggregated_metadata_for_bssid(self, bssid: str | None) -> Dict:
        normalized_bssid = normalize_mac(bssid)
        if not normalized_bssid:
            return {"present": False}

        self._ensure_aggregate_index()
        matched_files = list(self._aggregate_index_by_bssid.get(normalized_bssid, []))
        if not matched_files:
            return {"present": False}

        matched_files.sort(
            key=lambda item: (
                int(item.get("beacon_count") or 0),
                int(item.get("eapol_count") or 0),
                int(item.get("probe_client_count") or 0),
            ),
            reverse=True,
        )

        channels: set[int] = set()
        frequencies: set[int] = set()
        beacon_total = 0
        eapol_total = 0
        beacon_peak = 0
        eapol_peak = 0
        probe_peak = 0
        last_seen_offset_max: float | None = None
        warnings_agg: List[str] = []
        warnings_seen = set()
        out_files: List[Dict] = []

        for item in matched_files:
            beacon_count = int(item.get("beacon_count") or 0)
            eapol_count = int(item.get("eapol_count") or 0)
            probe_count = int(item.get("probe_client_count") or 0)

            beacon_total += beacon_count
            eapol_total += eapol_count
            beacon_peak = max(beacon_peak, beacon_count)
            eapol_peak = max(eapol_peak, eapol_count)
            probe_peak = max(probe_peak, probe_count)

            channel = item.get("channel")
            frequency_mhz = item.get("frequency_mhz")
            if channel is not None:
                channels.add(int(channel))
            if frequency_mhz is not None:
                frequencies.add(int(frequency_mhz))

            offset = to_float(item.get("last_seen_offset_s"))
            if offset is not None:
                if last_seen_offset_max is None or offset > last_seen_offset_max:
                    last_seen_offset_max = offset

            file_warnings = (
                item.get("warnings") if isinstance(item.get("warnings"), list) else []
            )
            for warning in file_warnings:
                warning_text = str(warning).strip()
                if not warning_text:
                    continue
                labeled = f"[{item['source_file']}] {warning_text}"
                if labeled in warnings_seen:
                    continue
                warnings_seen.add(labeled)
                warnings_agg.append(labeled)

            out_files.append(
                {
                    "artifact_type": "pcap",
                    "raw_item_id": item.get("raw_item_id"),
                    "source": item.get("source"),
                    "device_label": item.get("device_label"),
                    "source_path_role": item.get("source_path_role"),
                    "filename": item.get("filename") or item.get("source_file"),
                    "source_file": item.get("source_file"),
                    "processed_at": item.get("processed_at"),
                    "ssid": item.get("ssid") or "",
                    "ssid_raw_hex": item.get("ssid_raw_hex"),
                    "channel": item.get("channel"),
                    "frequency_mhz": item.get("frequency_mhz"),
                    "beacon_count": beacon_count,
                    "eapol_count": eapol_count,
                    "probe_client_count": probe_count,
                    "last_seen_offset_s": item.get("last_seen_offset_s"),
                    "warnings": file_warnings,
                }
            )

        return {
            "present": True,
            "bssid": normalized_bssid,
            "files_count": len(out_files),
            "aggregate": {
                "beacon_count_total": beacon_total,
                "beacon_count_peak": beacon_peak,
                "eapol_count_total": eapol_total,
                "eapol_count_peak": eapol_peak,
                "probe_client_count_peak": probe_peak,
                "channels": sorted(channels),
                "frequencies_mhz": sorted(frequencies),
                "last_seen_offset_s_max": (
                    round(last_seen_offset_max, 6)
                    if last_seen_offset_max is not None
                    else None
                ),
                "warnings": warnings_agg,
            },
            "files": out_files,
        }

    def get_raw_context_for_bssid(self, bssid: str | None) -> Dict:
        aggregated = self.get_aggregated_metadata_for_bssid(bssid)
        normalized_bssid = normalize_mac(bssid)
        hash_files_in = self.get_generated_hashes_for_bssid(normalized_bssid)
        if not isinstance(hash_files_in, list):
            hash_files_in = []

        files_in = aggregated.get("files")
        if not isinstance(files_in, list):
            files_in = []

        files_out: List[Dict] = []
        for item in files_in:
            if not isinstance(item, dict):
                continue
            source_file = os.path.basename(str(item.get("source_file") or "").strip())
            if not source_file:
                continue
            raw_item_id = str(
                item.get("raw_item_id") or ""
            ).strip() or self._make_raw_item_id(
                "pcap",
                str(item.get("source") or "brucegotchi"),
                str(item.get("source_path_role") or "rawsniffer"),
                source_file,
            )
            details_filename = self._resolve_existing_raw_details_filename(
                raw_item_id, source_file, normalized_bssid
            ) or self._raw_details_filename(raw_item_id, source_file, normalized_bssid)
            details_path = (
                os.path.join(HANDSHAKES_DIR, details_filename)
                if details_filename
                else None
            )
            details_exists = bool(details_path and os.path.exists(details_path))
            details_size = None
            details_modified = None
            if details_exists and details_path:
                try:
                    details_stat = os.stat(details_path)
                    details_size = int(details_stat.st_size)
                    details_modified = float(details_stat.st_mtime)
                except OSError:
                    details_size = None
                    details_modified = None
            analysis_record = self._resolve_raw_record(
                source_file, raw_item_id=raw_item_id
            )
            analysis = (
                self._read_analysis_for_record(analysis_record)
                if analysis_record
                else None
            )
            analysis_present = bool(
                analysis
                and analysis_record
                and self._is_cache_fresh(
                    analysis, str(analysis_record.get("path") or "")
                )
            )
            files_out.append(
                {
                    "artifact_type": "pcap",
                    "raw_item_id": raw_item_id,
                    "source": str(item.get("source") or "brucegotchi"),
                    "device_label": str(
                        item.get("device_label")
                        or self._device_label_for_source(
                            item.get("source") or "brucegotchi"
                        )
                    ),
                    "source_path_role": str(
                        item.get("source_path_role") or "rawsniffer"
                    ),
                    "filename": source_file,
                    "source_file": source_file,
                    "bssid": normalized_bssid,
                    "ssid": str(item.get("ssid") or "").strip(),
                    "channel": item.get("channel"),
                    "frequency_mhz": item.get("frequency_mhz"),
                    "beacon_count": int(item.get("beacon_count") or 0),
                    "eapol_count": int(item.get("eapol_count") or 0),
                    "processed_at": item.get("processed_at"),
                    "warnings": (
                        item.get("warnings")
                        if isinstance(item.get("warnings"), list)
                        else []
                    ),
                    "details_filename": details_filename,
                    "details_present": details_exists,
                    "details_size": details_size,
                    "details_modified": details_modified,
                    "analysis_present": analysis_present,
                    "analysis_summary": (
                        self._analysis_summary(analysis) if analysis_present else None
                    ),
                }
            )

        file_matches_by_name: Dict[str, List[Dict]] = {}
        for item in files_out:
            key = str(item.get("source_file") or "").strip().lower()
            if not key:
                continue
            file_matches_by_name.setdefault(key, []).append(item)

        hash_files_out: List[Dict] = []
        valid_hash_file_names: set[str] = set()
        for item in hash_files_in:
            if not isinstance(item, dict):
                continue
            filename = os.path.basename(str(item.get("filename") or "").strip())
            if not filename:
                continue
            valid_hash_file_names.add(filename)
            source_raw_file = os.path.basename(
                str(item.get("source_raw_file") or "").strip()
            )
            matched_entries = file_matches_by_name.get(source_raw_file.lower(), [])
            if not matched_entries:
                matched_entries = [
                    {
                        "source": "brucegotchi",
                        "device_label": "Bruce",
                        "source_path_role": "rawsniffer",
                        "source_file": source_raw_file,
                        "details_present": False,
                        "details_filename": None,
                    }
                ]
            for match in matched_entries:
                hash_raw_item_id = self._make_raw_item_id(
                    "22000",
                    str(match.get("source") or "brucegotchi"),
                    str(match.get("source_path_role") or "rawsniffer"),
                    filename,
                    source_raw_file=source_raw_file,
                )
                hash_files_out.append(
                    {
                        "artifact_type": "22000",
                        "raw_item_id": hash_raw_item_id,
                        "source": str(match.get("source") or "brucegotchi"),
                        "device_label": str(
                            match.get("device_label")
                            or self._device_label_for_source(
                                match.get("source") or "brucegotchi"
                            )
                        ),
                        "source_path_role": str(
                            match.get("source_path_role") or "rawsniffer"
                        ),
                        "filename": filename,
                        "bssid": normalized_bssid,
                        "valid_hash_lines": int(item.get("valid_hash_lines") or 0),
                        "matched_lines": int(item.get("matched_lines") or 0),
                        "source_raw_file": source_raw_file or None,
                        "matched_ssid": str(item.get("matched_ssid") or "").strip()
                        or None,
                        "primary_ssid": str(item.get("primary_ssid") or "").strip()
                        or None,
                        "modified": (
                            float(item.get("modified"))
                            if item.get("modified") is not None
                            else None
                        ),
                        "size": int(item.get("size") or 0),
                        "details_present": bool(match.get("details_present")),
                        "details_filename": match.get("details_filename"),
                        "details_size": match.get("details_size"),
                        "details_modified": match.get("details_modified"),
                        "analysis_present": bool(match.get("analysis_present")),
                        "analysis_summary": match.get("analysis_summary"),
                    }
                )

        files_out.sort(
            key=lambda entry: (
                int(entry.get("eapol_count") or 0),
                int(entry.get("beacon_count") or 0),
                entry.get("source_file") or "",
            ),
            reverse=True,
        )

        hash_files_out.sort(
            key=lambda entry: (
                int(entry.get("valid_hash_lines") or 0),
                float(entry.get("modified") or 0.0),
                str(entry.get("filename") or ""),
            ),
            reverse=True,
        )

        has_pcap_context = bool(aggregated.get("present")) and len(files_out) > 0
        has_hash_context = len(hash_files_out) > 0
        if not has_pcap_context and not has_hash_context:
            return {"present": False}

        return {
            "present": True,
            "bssid": aggregated.get("bssid") or normalized_bssid,
            "files_count": len(files_out),
            "hash_files_count": len(valid_hash_file_names),
            "aggregate": aggregated.get("aggregate") or {},
            "files": files_out,
            "hash_files": hash_files_out,
        }

    def _slugify_label(self, value: str) -> str:
        text = unicodedata.normalize("NFKD", str(value or ""))
        text = text.encode("ascii", "ignore").decode("ascii")
        text = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower())
        return text.strip("-") or "hidden"

    def _canonical_hash_basename(self, bssid: str, ssid_hint: str | None = None) -> str:
        mac_clean = bssid.replace(":", "").lower()
        ssid_slug = self._slugify_label(ssid_hint or "hidden")
        return f"{ssid_slug}_{mac_clean}__wdrs__"

    def _canonical_hash_filename(self, bssid: str, ssid_hint: str | None = None) -> str:
        return f"{self._canonical_hash_basename(bssid, ssid_hint)}.22000"

    def _canonical_hash_path(self, bssid: str, ssid_hint: str | None = None) -> str:
        return os.path.join(
            HANDSHAKES_DIR, self._canonical_hash_filename(bssid, ssid_hint)
        )

    def _canonical_sidecar_path(self, canonical_hash_path: str) -> str:
        return f"{canonical_hash_path}.wdrs.json"

    def _safe_read_json(self, path: str) -> Dict | None:
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
            return payload if isinstance(payload, dict) else None
        except Exception:
            return None

    def _signature_for_source_file(self, source_file: str) -> Dict | None:
        source_path = self._resolve_raw_file(source_file)
        if not source_path:
            return None
        try:
            stat = os.stat(source_path)
        except OSError:
            return None
        return {
            "source_file": os.path.basename(source_file),
            "size": int(stat.st_size),
            "mtime": float(stat.st_mtime),
        }

    def _signature_for_hash_file(self, hash_file: str) -> Dict | None:
        normalized_name = os.path.basename(str(hash_file or "").strip())
        if not normalized_name:
            return None
        hash_path = os.path.join(HANDSHAKES_DIR, normalized_name)
        if not os.path.exists(hash_path):
            return None
        try:
            stat = os.stat(hash_path)
        except OSError:
            return None
        return {
            "source_file": normalized_name,
            "size": int(stat.st_size),
            "mtime": float(stat.st_mtime),
        }

    def _build_signature_map(self, source_files: List[str]) -> Dict[str, Dict]:
        signature_map: Dict[str, Dict] = {}
        for source_file in source_files:
            base = os.path.basename(str(source_file or "").strip())
            if not base:
                continue
            signature = self._signature_for_source_file(base)
            if signature is None:
                continue
            signature_map[base] = signature
        return signature_map

    def _build_signature_map_for_sources(
        self,
        source_files: List[str],
        *,
        hash_sources: set[str] | None = None,
    ) -> Dict[str, Dict]:
        signature_map: Dict[str, Dict] = {}
        normalized_hash_sources = {str(name or "") for name in (hash_sources or set())}
        for source_file in source_files:
            base = os.path.basename(str(source_file or "").strip())
            if not base:
                continue
            if base in normalized_hash_sources:
                signature = self._signature_for_hash_file(base)
            else:
                signature = self._signature_for_source_file(base)
            if signature is None:
                continue
            signature_map[base] = signature
        return signature_map

    def _normalize_source_subset(
        self,
        source_files: List[str] | None,
        context_files: List[Dict],
    ) -> Tuple[List[str], List[str]]:
        context_lookup = {
            os.path.basename(
                str(item.get("source_file") or "").strip()
            ).lower(): os.path.basename(str(item.get("source_file") or "").strip())
            for item in context_files
            if isinstance(item, dict) and str(item.get("source_file") or "").strip()
        }
        if not source_files:
            selected = sorted(set(context_lookup.values()))
            return selected, []

        requested = [
            os.path.basename(str(source_file or "").strip()).lower()
            for source_file in source_files
            if str(source_file or "").strip()
        ]
        selected = []
        missing = []
        for key in requested:
            source_name = context_lookup.get(key)
            if source_name:
                selected.append(source_name)
            else:
                missing.append(key)
        selected = sorted(set(selected))
        missing = sorted(set(missing))
        return selected, missing

    def _signature_matches(self, left: Dict, right: Dict) -> bool:
        if not isinstance(left, dict) or not isinstance(right, dict):
            return False
        return int(left.get("size") or -1) == int(right.get("size") or -2) and float(
            left.get("mtime") or -1.0
        ) == float(right.get("mtime") or -2.0)

    def _is_canonical_up_to_date(
        self,
        metadata: Dict | None,
        signature_map: Dict[str, Dict],
        canonical_hash_path: str,
        full_refresh: bool,
    ) -> bool:
        if not metadata or not signature_map:
            return False
        if not os.path.exists(canonical_hash_path):
            return False
        try:
            if os.path.getsize(canonical_hash_path) <= 0:
                return False
        except OSError:
            return False

        if full_refresh:
            stored_full = metadata.get("full_signature")
            if not isinstance(stored_full, dict):
                return False
            if set(stored_full.keys()) != set(signature_map.keys()):
                return False
            for source_file, signature in signature_map.items():
                if not self._signature_matches(
                    signature, stored_full.get(source_file) or {}
                ):
                    return False
            return True

        per_source = metadata.get("per_source_signature")
        if not isinstance(per_source, dict):
            return False
        for source_file, signature in signature_map.items():
            if not self._signature_matches(
                signature, per_source.get(source_file) or {}
            ):
                return False
        return True

    def _build_focused_extract_command(
        self, tshark_bin: str, source_path: str, output_path: str, bssid: str
    ) -> List[str]:
        use_wsl = self._should_use_wsl(tshark_bin)
        source_target = self._to_wsl_path(source_path) if use_wsl else source_path
        output_target = self._to_wsl_path(output_path) if use_wsl else output_path
        bssid_l = bssid.lower()
        # Include SA/DA in addition to BSSID so focused extraction still works in
        # captures where BSSID isn't present in all relevant frames.
        display_filter = (
            f"(wlan.bssid == {bssid_l})"
            f" or (wlan.sa == {bssid_l})"
            f" or (wlan.da == {bssid_l})"
        )
        base_cmd = [
            "-r",
            source_target,
            "-Y",
            display_filter,
            "-w",
            output_target,
        ]
        if use_wsl:
            return ["wsl", tshark_bin] + base_cmd
        return [tshark_bin] + base_cmd

    def _parse_hash_line(self, raw_line: str) -> Tuple[bool, str | None]:
        line = str(raw_line or "").strip()
        if not line:
            return False, None
        parts = line.split("*")
        if (
            not parts
            or not parts[0].upper().startswith("WPA")
            or len(parts) <= 5
            or not parts[2]
            or not parts[3]
            or not parts[4]
            or not parts[5]
        ):
            return False, None
        return True, normalize_mac(parts[3])

    def _extract_hash_lines_for_bssid(self, hash_path: str, bssid: str) -> List[str]:
        normalized = normalize_mac(bssid)
        if not normalized or not os.path.exists(hash_path):
            return []
        lines: List[str] = []
        try:
            with open(hash_path, "r", encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    line = str(raw_line or "").strip()
                    if not line:
                        continue
                    valid, line_bssid = self._parse_hash_line(line)
                    if not valid:
                        continue
                    if line_bssid and line_bssid != normalized:
                        continue
                    lines.append(line)
        except Exception:
            return []
        return lines

    def _write_canonical_hash_atomic(
        self, canonical_hash_path: str, lines: List[str]
    ) -> None:
        tmp_path = f"{canonical_hash_path}.tmp.{uuid.uuid4().hex[:8]}"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            if lines:
                handle.write("\n".join(lines).strip() + "\n")
            else:
                handle.write("")
        os.replace(tmp_path, canonical_hash_path)

    def _write_canonical_sidecar_atomic(self, sidecar_path: str, payload: Dict) -> None:
        tmp_path = f"{sidecar_path}.tmp.{uuid.uuid4().hex[:8]}"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, ensure_ascii=False)
        os.replace(tmp_path, sidecar_path)

    def prepare_canonical_hash_for_bssid(
        self,
        bssid: str | None,
        *,
        force: bool = False,
        source_files: List[str] | None = None,
        ssid_hint: str | None = None,
        convert_func=None,
        progress_callback=None,
    ) -> Dict:
        normalized_bssid = normalize_mac(bssid)
        if not normalized_bssid:
            return {
                "status": "error",
                "code": "invalid_bssid",
                "message": "Invalid BSSID",
            }

        context = self.get_raw_context_for_bssid(normalized_bssid)
        if not context.get("present"):
            return {
                "status": "error",
                "code": "raw_context_missing",
                "message": "No RAW context found for this BSSID",
            }

        context_files = context.get("files")
        if not isinstance(context_files, list):
            context_files = []
        context_hash_files = context.get("hash_files")
        if not isinstance(context_hash_files, list):
            context_hash_files = []

        pcap_lookup: Dict[str, str] = {}
        for item in context_files:
            if not isinstance(item, dict):
                continue
            source_name = os.path.basename(str(item.get("source_file") or "").strip())
            if source_name:
                pcap_lookup[source_name.lower()] = source_name

        hash_lookup: Dict[str, str] = {}
        for item in context_hash_files:
            if not isinstance(item, dict):
                continue
            filename = os.path.basename(str(item.get("filename") or "").strip())
            if filename:
                hash_lookup[filename.lower()] = filename

        selected_plan: List[Tuple[str, str]] = []
        fallback_plan: List[Tuple[str, str]] = []
        missing_sources: List[str] = []
        selected_seen = set()

        if isinstance(source_files, list) and len(source_files) > 0:
            for source_file in source_files:
                requested = os.path.basename(str(source_file or "").strip())
                if not requested:
                    continue
                key = requested.lower()
                source_name = hash_lookup.get(key)
                source_kind = "hash"
                if not source_name:
                    source_name = pcap_lookup.get(key)
                    source_kind = "pcap"
                if not source_name:
                    missing_sources.append(key)
                    continue
                if source_name in selected_seen:
                    continue
                selected_seen.add(source_name)
                selected_plan.append((source_kind, source_name))
        else:
            selected_hash_sources = sorted(set(hash_lookup.values()))
            selected_pcap_sources = sorted(set(pcap_lookup.values()))
            if selected_hash_sources:
                selected_plan.extend([("hash", name) for name in selected_hash_sources])
                fallback_plan.extend([("pcap", name) for name in selected_pcap_sources])
            else:
                selected_plan.extend([("pcap", name) for name in selected_pcap_sources])

        missing_sources = sorted(set(missing_sources))
        if missing_sources:
            return {
                "status": "error",
                "code": "source_not_in_context",
                "message": "source_file is not linked to this BSSID RAW context",
                "missing_sources": missing_sources,
            }
        if not selected_plan:
            return {
                "status": "error",
                "code": "raw_context_empty",
                "message": "No RAW source files available for this BSSID",
            }

        preferred_ssid = str(ssid_hint or "").strip()
        if not preferred_ssid:
            selected_names = {name for _, name in selected_plan}
            for item in context_files:
                if not isinstance(item, dict):
                    continue
                source_name = os.path.basename(
                    str(item.get("source_file") or "").strip()
                )
                if source_name not in selected_names:
                    continue
                candidate = str(item.get("ssid") or "").strip()
                if candidate:
                    preferred_ssid = candidate
                    break
        if not preferred_ssid:
            for item in context_hash_files:
                if not isinstance(item, dict):
                    continue
                candidate = (
                    str(item.get("matched_ssid") or "").strip()
                    or str(item.get("primary_ssid") or "").strip()
                )
                if candidate:
                    preferred_ssid = candidate
                    break

        canonical_hash = self._canonical_hash_filename(normalized_bssid, preferred_ssid)
        canonical_hash_path = os.path.join(HANDSHAKES_DIR, canonical_hash)
        canonical_sidecar_path = self._canonical_sidecar_path(canonical_hash_path)
        full_refresh = source_files is None

        signature_sources: List[str]
        if full_refresh:
            signature_sources = sorted(
                set(list(hash_lookup.values()) + list(pcap_lookup.values()))
            )
        else:
            signature_sources = [name for _, name in selected_plan]
        signature_map = self._build_signature_map_for_sources(
            signature_sources,
            hash_sources=set(hash_lookup.values()),
        )
        sidecar = self._safe_read_json(canonical_sidecar_path)
        if not force and self._is_canonical_up_to_date(
            sidecar,
            signature_map,
            canonical_hash_path,
            full_refresh=full_refresh,
        ):
            return {
                "status": "up_to_date",
                "message": "Canonical WDRS hash is already up to date",
                "bssid": normalized_bssid,
                "canonical_hash": canonical_hash,
                "processed": 0,
                "succeeded": 0,
                "failed": 0,
                "artifacts": {"hash_file": canonical_hash, "pcap_file": None},
            }

        if convert_func is None:
            from app.services.crack_service import crack_service

            convert_func = crack_service.convert_pcap_now

        existing_lines: List[str] = []
        if not full_refresh:
            existing_lines = self._extract_hash_lines_for_bssid(
                canonical_hash_path, normalized_bssid
            )
        merged_lines = list(existing_lines)
        seen_lines = set(existing_lines)

        processed = 0
        succeeded = 0
        failed = 0
        item_results: List[Dict] = []
        total_steps = len(selected_plan)
        if full_refresh and fallback_plan:
            total_steps += len(fallback_plan)

        tshark_bin: str | None = None
        tshark_missing_emitted = False

        def _emit_progress(
            source_name: str,
            status_text: str,
            *,
            reason: str | None = None,
            valid_lines: int | None = None,
            added_lines: int | None = None,
        ) -> None:
            if not callable(progress_callback):
                return
            payload: Dict = {
                "index": processed,
                "total": total_steps,
                "source_file": source_name,
                "status": status_text,
            }
            if reason:
                payload["reason"] = reason
            if isinstance(valid_lines, int):
                payload["valid_lines"] = valid_lines
            if isinstance(added_lines, int):
                payload["added_lines"] = added_lines
            progress_callback(payload)

        def _append_failure(source_name: str, reason: str) -> None:
            nonlocal failed
            failed += 1
            item_result = {
                "source_file": source_name,
                "status": "error",
                "reason": reason,
            }
            item_results.append(item_result)
            _emit_progress(source_name, "error", reason=reason)

        def _merge_hash_lines(source_name: str, lines: List[str]) -> None:
            nonlocal succeeded
            added_count = 0
            for line in lines:
                if line in seen_lines:
                    continue
                merged_lines.append(line)
                seen_lines.add(line)
                added_count += 1
            succeeded += 1
            item_results.append(
                {
                    "source_file": source_name,
                    "status": "success",
                    "valid_lines": len(lines),
                    "added_lines": added_count,
                }
            )
            _emit_progress(
                source_name,
                "success",
                valid_lines=len(lines),
                added_lines=added_count,
            )

        def _process_hash_source(source_name: str) -> None:
            nonlocal processed
            processed += 1
            hash_path = os.path.join(HANDSHAKES_DIR, source_name)
            if not os.path.exists(hash_path):
                _append_failure(source_name, "raw_hash_missing")
                return
            lines = self._extract_hash_lines_for_bssid(hash_path, normalized_bssid)
            if not lines:
                _append_failure(source_name, "no_valid_hash_lines")
                return
            _merge_hash_lines(source_name, lines)

        def _process_pcap_source(source_name: str) -> None:
            nonlocal processed, tshark_bin, tshark_missing_emitted
            processed += 1
            source_path = self._resolve_raw_file(source_name)
            if not source_path:
                _append_failure(source_name, "raw_source_missing")
                return

            metadata_result = self.extract_metadata(source_name, force=force)
            if metadata_result.get("status") != "success":
                _append_failure(
                    source_name,
                    str(metadata_result.get("message") or "metadata_extract_failed"),
                )
                return

            if tshark_bin is None and not tshark_missing_emitted:
                tshark_bin = self._check_tshark()
                if not tshark_bin:
                    tshark_missing_emitted = True
            if tshark_missing_emitted:
                _append_failure(source_name, "tshark_missing")
                return

            temp_pcap = tempfile.NamedTemporaryFile(
                prefix=f"wdrs_{normalized_bssid.replace(':', '').lower()}_",
                suffix=".pcap",
                delete=False,
                dir="/tmp",
            )
            temp_pcap_path = temp_pcap.name
            temp_pcap.close()

            temp_hash = tempfile.NamedTemporaryFile(
                prefix=f"wdrs_{normalized_bssid.replace(':', '').lower()}_",
                suffix=".22000",
                delete=False,
                dir="/tmp",
            )
            temp_hash_path = temp_hash.name
            temp_hash.close()

            try:
                command = self._build_focused_extract_command(
                    tshark_bin,
                    source_path,
                    temp_pcap_path,
                    normalized_bssid,
                )
                proc = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if proc.returncode != 0:
                    _append_failure(
                        source_name, f"focused_pcap_failed_exit_{proc.returncode}"
                    )
                    return

                if (
                    not os.path.exists(temp_pcap_path)
                    or os.path.getsize(temp_pcap_path) <= 0
                ):
                    _append_failure(source_name, "focused_pcap_empty")
                    return

                try:
                    conversion = convert_func(
                        temp_pcap_path, output_filename=temp_hash_path
                    )
                except TypeError:
                    conversion = convert_func(temp_pcap_path, temp_hash_path)
                except Exception as exc:
                    conversion = {"status": "error", "message": str(exc)}

                if (
                    not isinstance(conversion, dict)
                    or conversion.get("status") != "success"
                ):
                    _append_failure(
                        source_name,
                        (
                            str(conversion.get("message") or "hash_conversion_failed")
                            if isinstance(conversion, dict)
                            else "hash_conversion_failed"
                        ),
                    )
                    return

                lines = self._extract_hash_lines_for_bssid(
                    temp_hash_path, normalized_bssid
                )
                if not lines:
                    _append_failure(source_name, "no_valid_hash_lines")
                    return

                _merge_hash_lines(source_name, lines)
            finally:
                for temp_path in (temp_pcap_path, temp_hash_path):
                    if not temp_path:
                        continue
                    try:
                        if os.path.exists(temp_path):
                            os.remove(temp_path)
                    except OSError:
                        pass

        for source_kind, source_name in selected_plan:
            if source_kind == "hash":
                _process_hash_source(source_name)
            else:
                _process_pcap_source(source_name)

        should_run_fallback = bool(full_refresh and fallback_plan and not merged_lines)
        if should_run_fallback:
            for _, source_name in fallback_plan:
                _process_pcap_source(source_name)

        if not merged_lines:
            return {
                "status": "error",
                "code": "no_hash_lines",
                "message": "No valid hash lines were extracted for this BSSID",
                "bssid": normalized_bssid,
                "canonical_hash": canonical_hash,
                "processed": processed,
                "succeeded": succeeded,
                "failed": failed,
                "items": item_results,
                "artifacts": {"hash_file": None, "pcap_file": None},
            }

        self._write_canonical_hash_atomic(canonical_hash_path, merged_lines)

        now_iso = datetime.now(timezone.utc).isoformat()
        next_sidecar = sidecar if isinstance(sidecar, dict) else {}
        per_source_signature = (
            dict(next_sidecar.get("per_source_signature"))
            if isinstance(next_sidecar.get("per_source_signature"), dict)
            else {}
        )
        per_source_signature.update(signature_map)
        sidecar_payload = {
            "schema_version": 2,
            "updated_at": now_iso,
            "bssid": normalized_bssid,
            "canonical_hash": canonical_hash,
            "full_signature": (
                signature_map
                if full_refresh
                else next_sidecar.get("full_signature") or {}
            ),
            "per_source_signature": per_source_signature,
            "last_run": {
                "mode": "full" if full_refresh else "subset",
                "strategy": "hash_first_with_pcap_fallback",
                "processed": processed,
                "succeeded": succeeded,
                "failed": failed,
                "source_files": [name for _, name in selected_plan],
                "fallback_files": [name for _, name in fallback_plan],
            },
        }
        self._write_canonical_sidecar_atomic(canonical_sidecar_path, sidecar_payload)

        status = "success"
        message = "Canonical WDRS hash updated"
        if failed > 0 and succeeded > 0:
            status = "success_partial"
            message = "Canonical WDRS hash updated with partial source failures"
        elif failed > 0 and succeeded == 0:
            status = "error"
            message = "Failed to update canonical WDRS hash from selected sources"

        return {
            "status": status,
            "message": message,
            "bssid": normalized_bssid,
            "canonical_hash": canonical_hash,
            "processed": processed,
            "succeeded": succeeded,
            "failed": failed,
            "items": item_results,
            "artifacts": {"hash_file": canonical_hash, "pcap_file": None},
        }

    def prepare_focused_capture_for_bssid(
        self,
        bssid: str | None,
        source_file: str,
        *,
        force: bool = False,
        ssid_hint: str | None = None,
        convert_func=None,
    ) -> Dict:
        return self.prepare_canonical_hash_for_bssid(
            bssid,
            force=force,
            source_files=[source_file],
            ssid_hint=ssid_hint,
            convert_func=convert_func,
        )

    def prepare_raw_item_for_bssid(
        self,
        bssid: str | None,
        *,
        raw_item_id: str | None = None,
        source_file: str | None = None,
        force: bool = False,
        ssid_hint: str | None = None,
        convert_func=None,
    ) -> Dict:
        raw_item_key = str(raw_item_id or "").strip()
        if not raw_item_key:
            if not source_file:
                return {
                    "status": "error",
                    "message": "raw_item_id or source_file is required",
                }
            try:
                result = self.prepare_focused_capture_for_bssid(
                    bssid,
                    source_file,
                    force=force,
                    ssid_hint=ssid_hint,
                    convert_func=convert_func,
                )
            except TypeError:
                result = self.prepare_focused_capture_for_bssid(
                    bssid,
                    source_file,
                    force=force,
                )
            result.setdefault("source_file", source_file)
            return result

        context = self.get_raw_context_for_bssid(bssid)
        if not context.get("present"):
            return {
                "status": "error",
                "message": "No RAW context found for this BSSID",
            }

        target_item = None
        for group_name in ("files", "hash_files"):
            for item in context.get(group_name) or []:
                if not isinstance(item, dict):
                    continue
                if str(item.get("raw_item_id") or "").strip() == raw_item_key:
                    target_item = item
                    break
            if target_item:
                break

        if not target_item:
            return {
                "status": "error",
                "message": "raw_item_id is not linked to this BSSID RAW context",
            }

        target_source = (
            str(target_item.get("filename") or "").strip()
            if str(target_item.get("artifact_type") or "").strip() == "22000"
            else str(
                target_item.get("source_file") or target_item.get("filename") or ""
            ).strip()
        )
        result = self.prepare_canonical_hash_for_bssid(
            bssid,
            force=force,
            source_files=[target_source],
            ssid_hint=ssid_hint,
            convert_func=convert_func,
        )
        result.setdefault("raw_item_id", raw_item_key)
        result.setdefault("source_file", target_source)
        return result

    def extract_metadata(
        self,
        filename: str,
        force: bool = False,
        *,
        raw_item_id: str | None = None,
    ) -> Dict:
        tshark_bin = self._check_tshark()
        if not tshark_bin:
            return {"status": "error", "message": "tshark not configured or not found"}

        record = self._resolve_raw_record(filename, raw_item_id=raw_item_id)
        source_path = (
            str(record.get("path") or "")
            if record
            else self._resolve_raw_file(filename)
        )
        if not source_path or not record:
            target_name = raw_item_id or filename
            return {"status": "error", "message": f"Raw PCAP not found: {target_name}"}

        source_file = os.path.basename(source_path)
        metadata_path = self._metadata_path_for_record(record)

        cached = self._read_metadata_for_record(record)

        if not force and cached and self._is_cache_fresh(cached, source_path):
            return {
                "status": "success",
                "cached": True,
                "metadata_path": metadata_path,
                "data": cached,
            }

        try:
            stat = os.stat(source_path)
            output, warnings = self._run_tshark(source_path)
            parsed = parse_output(
                output,
                warnings,
                source_file,
                stat,
                schema_version=self.SCHEMA_VERSION,
            )
            parsed["artifact_type"] = "pcap"
            parsed["raw_item_id"] = record.get("raw_item_id")
            parsed["source"] = record.get("source")
            parsed["device_label"] = record.get("device_label")
            parsed["source_path_role"] = record.get("source_path_role")
            parsed["filename"] = source_file

            with open(metadata_path, "w", encoding="utf-8") as f:
                json.dump(parsed, f, indent=2, ensure_ascii=False)
            self._aggregate_index_signature = None

            return {
                "status": "success",
                "cached": False,
                "metadata_path": metadata_path,
                "data": parsed,
            }
        except Exception as exc:
            return {
                "status": "error",
                "message": str(exc),
            }

    def _build_raw_analysis(
        self,
        record: Dict,
        source_stat,
        output: str,
        runtime_warnings: List[str],
        metadata: Dict | None,
    ) -> Dict:
        first_ts: float | None = None
        last_ts: float | None = None
        metadata_networks = {
            str(item.get("bssid") or "").upper(): dict(item)
            for item in ((metadata or {}).get("networks") or [])
            if isinstance(item, dict) and str(item.get("bssid") or "").strip()
        }
        networks: Dict[str, Dict] = {}
        clients: Dict[str, Dict] = {}

        def ensure_network(bssid: str) -> Dict:
            normalized = normalize_mac(bssid) or str(bssid or "").upper()
            net = networks.get(normalized)
            if net is not None:
                return net
            seed = metadata_networks.get(normalized, {})
            net = {
                "bssid": normalized,
                "ssid": str(seed.get("ssid") or "").strip(),
                "ssid_raw_hex": seed.get("ssid_raw_hex"),
                "channel": seed.get("channel"),
                "frequency_mhz": seed.get("frequency_mhz"),
                "beacon_count": int(seed.get("beacon_count") or 0),
                "eapol_count": int(seed.get("eapol_count") or 0),
                "probe_client_count": int(seed.get("probe_client_count") or 0),
                "last_seen_offset_s": seed.get("last_seen_offset_s"),
                "clients": set(),
                "eapol_message_numbers": set(),
                "hidden_observed": False,
                "revealed_after_hidden": False,
            }
            networks[normalized] = net
            return net

        def ensure_client(mac: str) -> Dict:
            normalized = normalize_mac(mac) or str(mac or "").upper()
            client = clients.get(normalized)
            if client is not None:
                return client
            client = {
                "mac": normalized,
                "probe_count": 0,
                "eapol_count": 0,
                "total_frames": 0,
                "networks": set(),
                "probe_ssids": set(),
            }
            clients[normalized] = client
            return client

        for raw_line in str(output or "").splitlines():
            if not raw_line.strip():
                continue
            parts = raw_line.split("\t")
            if len(parts) < 9:
                parts += [""] * (9 - len(parts))
            parts = parts[:9]

            ts = to_float(parts[0])
            subtype_raw = (parts[1] or "").strip().lower()
            subtype_int = None
            try:
                subtype_int = (
                    int(subtype_raw, 16)
                    if subtype_raw.startswith("0x")
                    else int(float(subtype_raw or "0"))
                )
            except Exception:
                subtype_int = None
            bssid = normalize_mac(parts[2])
            sa = normalize_mac(parts[3])
            da = normalize_mac(parts[4])
            raw_ssid = parts[5]
            channel = to_int(parts[6])
            eapol_msgnr = (parts[7] or "").strip()
            eapol_type = (parts[8] or "").strip()

            if ts is not None:
                if first_ts is None or ts < first_ts:
                    first_ts = ts
                if last_ts is None or ts > last_ts:
                    last_ts = ts

            is_beacon = subtype_raw in {"0x0008", "0x08"} or subtype_int == 8
            is_probe = subtype_raw in {"0x0004", "0x04"} or subtype_int == 4
            is_eapol = bool(
                eapol_type
                or eapol_msgnr
                or subtype_raw in {"0x0028", "0x28"}
                or subtype_int == 40
            )

            if is_beacon and bssid:
                net = ensure_network(bssid)
                if not metadata_networks.get(net["bssid"]):
                    net["beacon_count"] += 1
                if channel is not None and net.get("channel") is None:
                    net["channel"] = channel
                if net.get("frequency_mhz") is None and channel is not None:
                    net["frequency_mhz"] = (
                        2484
                        if channel == 14
                        else (
                            2407 + channel * 5
                            if 1 <= channel <= 13
                            else (5000 + channel * 5 if 32 <= channel <= 196 else None)
                        )
                    )

                decoded_ssid, ssid_raw_hex = decode_ssid(raw_ssid)
                hidden_seen = not str(raw_ssid or "").strip() or str(
                    raw_ssid or ""
                ).strip().lower() in {
                    "<missing>",
                    "<hidden>",
                    "<broadcast>",
                }
                if hidden_seen:
                    net["hidden_observed"] = True
                elif decoded_ssid:
                    if net["hidden_observed"]:
                        net["revealed_after_hidden"] = True
                    if not net.get("ssid"):
                        net["ssid"] = decoded_ssid
                    if ssid_raw_hex and not net.get("ssid_raw_hex"):
                        net["ssid_raw_hex"] = ssid_raw_hex

            if is_probe and sa:
                client = ensure_client(sa)
                client["probe_count"] += 1
                client["total_frames"] += 1
                probe_ssid, _ = decode_ssid(raw_ssid)
                if probe_ssid:
                    client["probe_ssids"].add(probe_ssid)
                target_bssid = None
                if bssid and bssid != "FF:FF:FF:FF:FF:FF":
                    target_bssid = bssid
                elif da and da != "FF:FF:FF:FF:FF:FF":
                    target_bssid = da
                if target_bssid:
                    net = ensure_network(target_bssid)
                    net["clients"].add(client["mac"])
                    client["networks"].add(net["bssid"])

            if is_eapol:
                target_bssid = None
                for candidate in (bssid, da, sa):
                    if candidate and candidate != "FF:FF:FF:FF:FF:FF":
                        target_bssid = candidate
                        break
                client_mac = None
                if target_bssid:
                    for candidate in (sa, da):
                        if (
                            candidate
                            and candidate != target_bssid
                            and candidate != "FF:FF:FF:FF:FF:FF"
                        ):
                            client_mac = candidate
                            break
                if target_bssid:
                    net = ensure_network(target_bssid)
                    if not metadata_networks.get(net["bssid"]):
                        net["eapol_count"] += 1
                    if eapol_msgnr:
                        try:
                            msg_nr = int(float(eapol_msgnr))
                        except Exception:
                            msg_nr = None
                        if msg_nr in {1, 2, 3, 4}:
                            net["eapol_message_numbers"].add(msg_nr)
                    if client_mac:
                        net["clients"].add(client_mac)
                        client = ensure_client(client_mac)
                        client["eapol_count"] += 1
                        client["total_frames"] += 1
                        client["networks"].add(net["bssid"])

        duration_s = None
        if first_ts is not None and last_ts is not None:
            duration_s = round(max(0.0, last_ts - first_ts), 6)

        network_rows: List[Dict] = []
        handshake_candidates: List[Dict] = []
        hidden_count = 0
        revealed_count = 0

        for bssid, net in sorted(
            networks.items(),
            key=lambda item: (
                int(item[1].get("eapol_count") or 0),
                int(item[1].get("beacon_count") or 0),
                len(item[1].get("clients") or []),
                item[0],
            ),
            reverse=True,
        ):
            message_numbers = sorted(
                int(value)
                for value in (net.get("eapol_message_numbers") or set())
                if int(value) in {1, 2, 3, 4}
            )
            likely_complete = set(message_numbers) >= {1, 2, 3, 4} or set(
                message_numbers
            ) >= {2, 3, 4}
            if (
                likely_complete
                or len(message_numbers) >= 2
                or int(net.get("eapol_count") or 0) >= 2
            ):
                tier = "high" if likely_complete else "medium"
            elif int(net.get("eapol_count") or 0) > 0:
                tier = "low"
            else:
                tier = "none"

            if net.get("hidden_observed"):
                hidden_count += 1
            if net.get("revealed_after_hidden"):
                revealed_count += 1

            client_list = sorted(net.get("clients") or [])
            row = {
                "bssid": bssid,
                "ssid": str(net.get("ssid") or "").strip(),
                "ssid_raw_hex": net.get("ssid_raw_hex"),
                "channel": net.get("channel"),
                "frequency_mhz": net.get("frequency_mhz"),
                "beacon_count": int(net.get("beacon_count") or 0),
                "eapol_count": int(net.get("eapol_count") or 0),
                "probe_client_count": int(
                    net.get("probe_client_count") or len(client_list)
                ),
                "client_count": len(client_list),
                "clients": client_list[:25],
                "last_seen_offset_s": net.get("last_seen_offset_s"),
                "hidden_observed": bool(net.get("hidden_observed")),
                "revealed_after_hidden": bool(net.get("revealed_after_hidden")),
                "handshake_evidence": {
                    "message_numbers": message_numbers,
                    "message_count": len(message_numbers),
                    "likely_complete": bool(likely_complete),
                    "tier": tier,
                },
            }
            network_rows.append(row)
            if row["eapol_count"] > 0:
                handshake_candidates.append(
                    {
                        "bssid": bssid,
                        "ssid": row["ssid"],
                        "eapol_count": row["eapol_count"],
                        "message_numbers": message_numbers,
                        "tier": tier,
                    }
                )

        client_rows = []
        for client in sorted(
            clients.values(),
            key=lambda item: (
                int(item.get("eapol_count") or 0),
                int(item.get("total_frames") or 0),
                len(item.get("networks") or []),
                item.get("mac") or "",
            ),
            reverse=True,
        ):
            client_rows.append(
                {
                    "mac": client["mac"],
                    "probe_count": int(client.get("probe_count") or 0),
                    "eapol_count": int(client.get("eapol_count") or 0),
                    "total_frames": int(client.get("total_frames") or 0),
                    "network_count": len(client.get("networks") or []),
                    "networks": sorted(client.get("networks") or [])[:20],
                    "probe_ssids": sorted(client.get("probe_ssids") or [])[:10],
                }
            )

        capture_stats = (
            (metadata or {}).get("stats") if isinstance(metadata, dict) else {}
        )
        channels = sorted(
            {
                int(row["channel"])
                for row in network_rows
                if row.get("channel") is not None
            }
        )
        frequencies = sorted(
            {
                int(row["frequency_mhz"])
                for row in network_rows
                if row.get("frequency_mhz") is not None
            }
        )
        combined_warnings = []
        seen_warning = set()
        for warning in list((metadata or {}).get("warnings") or []) + list(
            runtime_warnings or []
        ):
            warning_text = str(warning or "").strip()
            if not warning_text or warning_text in seen_warning:
                continue
            seen_warning.add(warning_text)
            combined_warnings.append(warning_text)

        noisy_capture = (
            len(network_rows) >= 12
            or len(client_rows) >= 24
            or (
                int(capture_stats.get("parsed_lines") or 0) >= 5000
                and not handshake_candidates
            )
        )

        return {
            "schema_version": self.SCHEMA_VERSION,
            "analysis_version": 1,
            "artifact_type": "raw_analysis",
            "source_file": os.path.basename(str(record.get("filename") or "")),
            "source_size": source_stat.st_size,
            "source_mtime": source_stat.st_mtime,
            "raw_item_id": str(record.get("raw_item_id") or ""),
            "source": str(record.get("source") or ""),
            "device_label": str(record.get("device_label") or ""),
            "source_path_role": str(record.get("source_path_role") or ""),
            "generated_at": datetime.now(timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "capture": {
                "duration_s": duration_s,
                "parsed_lines": int(capture_stats.get("parsed_lines") or 0),
                "frame_totals": {
                    "beacons": int(capture_stats.get("beacon_frames") or 0),
                    "probe_requests": int(capture_stats.get("probe_requests") or 0),
                    "eapol": int(capture_stats.get("eapol_frames") or 0),
                },
                "networks_count": len(network_rows),
                "clients_count": len(client_rows),
                "channels": channels,
                "frequencies_mhz": frequencies,
                "warnings": combined_warnings,
            },
            "networks": network_rows,
            "clients": client_rows,
            "highlights": {
                "handshake_candidate_count": len(handshake_candidates),
                "handshake_candidates": handshake_candidates[:8],
                "top_networks": network_rows[:8],
                "top_clients": client_rows[:8],
                "hidden_network_count": hidden_count,
                "revealed_hidden_count": revealed_count,
                "noisy_capture": noisy_capture,
            },
        }

    def get_analysis(self, raw_item_id: str | None) -> Dict | None:
        record = self._resolve_raw_record(raw_item_id=raw_item_id)
        if not record:
            return None
        analysis = self._read_analysis_for_record(record)
        source_path = str(record.get("path") or "")
        if (
            not analysis
            or not source_path
            or not self._is_cache_fresh(analysis, source_path)
        ):
            return None
        return analysis

    def extract_analysis(
        self,
        raw_item_id: str | None,
        *,
        force: bool = False,
    ) -> Dict:
        raw_item_key = str(raw_item_id or "").strip()
        if not raw_item_key:
            return {"status": "error", "message": "raw_item_id is required"}

        tshark_bin = self._check_tshark()
        if not tshark_bin:
            return {"status": "error", "message": "tshark not configured or not found"}

        record = self._resolve_raw_record(raw_item_id=raw_item_key)
        source_path = str(record.get("path") or "") if record else ""
        if not record or not source_path or not os.path.exists(source_path):
            return {"status": "error", "message": f"Raw PCAP not found: {raw_item_key}"}

        analysis_path = self._analysis_path_for_record(record)
        cached = self._read_analysis_for_record(record)
        if not force and cached and self._is_cache_fresh(cached, source_path):
            return {
                "status": "success",
                "cached": True,
                "analysis_path": analysis_path,
                "data": cached,
            }

        metadata_result = self.extract_metadata(
            str(record.get("filename") or ""),
            force=force,
            raw_item_id=raw_item_key,
        )
        if metadata_result.get("status") != "success":
            return metadata_result
        metadata = (
            metadata_result.get("data") if isinstance(metadata_result, dict) else None
        )

        try:
            source_stat = os.stat(source_path)
            output, warnings = self._run_tshark(source_path)
            analysis = self._build_raw_analysis(
                record,
                source_stat,
                output,
                warnings,
                metadata if isinstance(metadata, dict) else {},
            )
            with open(analysis_path, "w", encoding="utf-8") as handle:
                json.dump(analysis, handle, indent=2, ensure_ascii=False)
            return {
                "status": "success",
                "cached": False,
                "analysis_path": analysis_path,
                "data": analysis,
            }
        except Exception as exc:
            return {"status": "error", "message": str(exc)}


rawsniffer_service = RawSnifferService()
