import json
import os
import re
from copy import deepcopy
from datetime import datetime, timezone

from app.core.config import BRUCE_PCAP_DIR, HANDSHAKES_DIR
from app.services.data_loader import load_real_data
from app.services.history_service import history_service
from app.services.rawsniffer_service import rawsniffer_service
from app.utils.handshake_artifacts import resolve_artifact_path


class InsightsService:
    _MAC_HEX_RE = re.compile(r"([0-9A-Fa-f]{12})")
    _ATTEMPT_PARAM_KEYS = (
        "workload",
        "device",
        "optimized",
        "slow",
        "wordlist",
        "rule",
        "mask",
        "wordlist_2",
    )

    def _normalize_mac(self, value: str | None) -> str | None:
        if not value:
            return None
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(value))
        if len(cleaned) != 12:
            return None
        cleaned = cleaned.upper()
        return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))

    def _mac_to_clean(self, value: str | None) -> str | None:
        normalized = self._normalize_mac(value)
        return normalized.replace(":", "").lower() if normalized else None

    def _extract_mac_from_filename(self, filename: str | None) -> str | None:
        if not filename:
            return None
        base = os.path.basename(str(filename))
        if base.upper().startswith("HS_"):
            hs_part = base[3:]
            match = self._MAC_HEX_RE.search(hs_part)
            if match:
                return self._normalize_mac(match.group(1))
        matches = self._MAC_HEX_RE.findall(base)
        if not matches:
            return None
        return self._normalize_mac(matches[-1])

    def _resolve_hash_path(
        self,
        filename: str | None,
        capture_id: str | None = None,
        combined_build_id: str | None = None,
        mac: str | None = None,
    ) -> str | None:
        if not filename:
            return None
        return resolve_artifact_path(
            filename,
            handshakes_dir=HANDSHAKES_DIR,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
            mac=mac,
        )

    def _safe_load_json(self, path: str):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        except Exception:
            return None

    def _find_matching_paths(self, token: str | None, suffix: str) -> list[str]:
        if not token or not os.path.exists(HANDSHAKES_DIR):
            return []
        token_lower = str(token).lower()
        matches = []
        try:
            for name in os.listdir(HANDSHAKES_DIR):
                if token_lower not in name.lower():
                    continue
                if not name.lower().endswith(suffix.lower()):
                    continue
                full_path = os.path.join(HANDSHAKES_DIR, name)
                if os.path.exists(full_path):
                    matches.append(full_path)
        except Exception:
            return []
        matches.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        return matches

    def _find_details_path(
        self, mac: str | None, filename: str | None, capture_id: str | None = None
    ) -> str | None:
        if filename:
            base = os.path.basename(filename).rsplit(".", 1)[0]
            candidate = resolve_artifact_path(
                f"{base}.details",
                handshakes_dir=HANDSHAKES_DIR,
                capture_id=capture_id,
            )
            if candidate and os.path.exists(candidate):
                return candidate

        mac_clean = self._mac_to_clean(mac)
        if not mac_clean:
            return None
        matches = self._find_matching_paths(mac_clean, ".details")
        if not matches:
            return None
        return matches[0]

    def _resolve_history_path(
        self,
        filename: str | None,
        mac: str | None,
        capture_id: str | None = None,
        combined_build_id: str | None = None,
    ) -> str | None:
        history_path = None
        if filename:
            history_path = history_service.get_history_path(
                os.path.basename(filename),
                capture_id=capture_id,
                combined_build_id=combined_build_id,
                mac=mac,
            )
            if not os.path.exists(history_path):
                history_path = None
        if history_path is None and mac:
            mac_clean = self._mac_to_clean(mac)
            if mac_clean:
                matches = self._find_matching_paths(mac_clean, ".try")
                if matches:
                    history_path = matches[0]
        return history_path

    def _load_history_entries(
        self,
        filename: str | None,
        mac: str | None,
        capture_id: str | None = None,
        combined_build_id: str | None = None,
    ) -> list[dict]:
        history_path = self._resolve_history_path(
            filename,
            mac,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
        )
        if not history_path or not os.path.exists(history_path):
            return []
        payload = self._safe_load_json(history_path)
        entries = payload.get("entries", []) if isinstance(payload, dict) else []
        return [entry for entry in entries if isinstance(entry, dict)]

    def _count_history_statuses(
        self,
        filename: str | None,
        mac: str | None,
        capture_id: str | None = None,
        combined_build_id: str | None = None,
    ) -> dict:
        entries = self._load_history_entries(
            filename,
            mac,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
        )
        if not entries:
            return {"total": 0, "cracked": 0, "exhausted": 0, "failed": 0, "running": 0}

        stats = {"total": 0, "cracked": 0, "exhausted": 0, "failed": 0, "running": 0}
        for entry in entries:
            status = str(entry.get("status") or "").strip().upper()
            if not status:
                continue
            stats["total"] += 1
            if status == "CRACKED":
                stats["cracked"] += 1
            elif status == "SUCCESS":
                # SUCCESS is also used by non-cracking tools (e.g. fingerprint extraction
                # and pcap->22000 conversion). Counting it as cracked creates false positives.
                pass
            elif status == "EXHAUSTED":
                stats["exhausted"] += 1
            elif status in {"FAILED", "ERROR", "INCOMPLETE"}:
                stats["failed"] += 1
            elif status in {"RUNNING", "QUEUED"}:
                stats["running"] += 1
        return stats

    def _is_hashcat_history_entry(self, entry: dict) -> bool:
        tool = str(entry.get("tool") or "").strip().lower()
        if "hashcat" in tool:
            return True

        command = entry.get("command")
        if isinstance(command, list):
            command = " ".join(str(part) for part in command if part is not None)
        command = str(command or "").strip().lower()
        if not command:
            return False

        first_part = command.split()[0] if command else ""
        return "hashcat" in os.path.basename(first_part)

    def _parse_sortable_iso(self, value: str | None) -> float:
        if not value:
            return 0.0
        text = str(value).strip()
        if not text:
            return 0.0
        try:
            if text.endswith("Z"):
                dt = datetime.fromisoformat(f"{text[:-1]}+00:00")
            else:
                dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except Exception:
            return 0.0

    def _normalize_attempt_outcome(self, entry: dict) -> str:
        status = str(entry.get("status") or "").strip().upper()
        if status == "CRACKED":
            return "cracked"
        if status == "EXHAUSTED":
            return "exhausted"
        if status in {"FAILED", "ERROR", "INCOMPLETE", "TIMEOUT"}:
            return "fatal"
        if status in {
            "RUNNING",
            "QUEUED",
            "STARTING",
            "AUTOTUNING",
            "BUILDING CACHE",
            "INIT KERNELS",
        }:
            return "running"
        if status == "SUCCESS":
            result_text = str(entry.get("result") or "").lower()
            if "password" in result_text or "cracked" in result_text:
                return "cracked"
            return "other"
        return "other"

    def _sanitize_attempt_param_value(self, value):
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value

        text = str(value).strip()
        if not text:
            return None

        if ";" in text:
            segments = [segment.strip() for segment in text.split(";")]
            text = ";".join(
                (
                    os.path.basename(segment)
                    if ("/" in segment or "\\" in segment)
                    else segment
                )
                for segment in segments
                if segment
            )
        elif "/" in text or "\\" in text:
            text = os.path.basename(text)

        if len(text) > 90:
            text = f"{text[:87]}..."
        return text

    def _compact_attempt_params(self, params: dict | None) -> dict:
        if not isinstance(params, dict):
            return {}

        mask_value = params.get("mask")
        if mask_value in (None, ""):
            mask_value = params.get("custom_mask")
        if mask_value in (None, ""):
            mask_value = params.get("mask_file")

        compact = {
            "workload": params.get("workload"),
            "device": params.get("device"),
            "optimized": params.get("optimized"),
            "slow": params.get("slow"),
            "wordlist": params.get("wordlist"),
            "rule": params.get("rule"),
            "mask": mask_value,
            "wordlist_2": params.get("wordlist_2"),
        }

        sanitized = {}
        for key in self._ATTEMPT_PARAM_KEYS:
            cleaned = self._sanitize_attempt_param_value(compact.get(key))
            if cleaned is None:
                continue
            sanitized[key] = cleaned
        return sanitized

    def _extract_attempt_mode(self, entry: dict) -> str:
        params = entry.get("params")
        if isinstance(params, dict):
            mode = str(params.get("attack_mode") or "").strip().lower()
            if mode:
                return mode

        command = entry.get("command")
        command_text = ""
        if isinstance(command, list):
            command_text = " ".join(str(part) for part in command if part is not None)
        else:
            command_text = str(command or "")
        command_text = command_text.strip()
        if command_text:
            parts = command_text.split()
            if "-a" in parts:
                try:
                    idx = parts.index("-a")
                    mode_id = parts[idx + 1]
                    mode_map = {
                        "0": "straight",
                        "1": "combinator",
                        "3": "mask",
                        "6": "hybrid",
                        "7": "hybrid_reverse",
                    }
                    return mode_map.get(mode_id, f"a{mode_id}")
                except Exception:
                    pass
        return "unknown"

    def _build_attempt_tip(self, totals: dict, recent: list[dict]) -> str | None:
        attempts = int(totals.get("attempts") or 0)
        exhausted = int(totals.get("exhausted") or 0)
        fatal = int(totals.get("fatal") or 0)
        cracked = int(totals.get("cracked") or 0)

        if attempts == 0:
            return None
        if fatal >= 3:
            return "Multiple fatal runs; retry with simpler mode and adjusted workload/device."
        if exhausted >= 3:
            return "Repeated exhausted runs; change mode or candidate source before retrying."

        recent_resolved = [
            item for item in recent if item.get("outcome") in {"exhausted", "fatal"}
        ]
        if len(recent_resolved) >= 3:
            top_modes = [
                str(item.get("mode") or "unknown") for item in recent_resolved[:3]
            ]
            if top_modes and len(set(top_modes)) == 1:
                return f"Mode '{top_modes[0]}' repeated with no success; change at least one key parameter."

        if attempts >= 4 and cracked == 0:
            return "No successful hashcat run yet; try a different mode or stronger wordlist/rules."
        return None

    def build_attempt_feedback(
        self,
        filename: str | None = None,
        mac: str | None = None,
        recent_limit: int = 8,
        capture_id: str | None = None,
        combined_build_id: str | None = None,
    ) -> dict | None:
        history_entries = self._load_history_entries(
            filename,
            mac,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
        )
        if not history_entries:
            return None

        hashcat_entries = [
            entry for entry in history_entries if self._is_hashcat_history_entry(entry)
        ]
        if not hashcat_entries:
            return None

        parsed_entries = []
        for entry in hashcat_entries:
            started_at = (
                str(entry.get("start_time") or entry.get("end_time") or "").strip()
                or None
            )
            parsed_entries.append(
                {
                    "started_at": started_at,
                    "sort_ts": self._parse_sortable_iso(started_at),
                    "mode": self._extract_attempt_mode(entry),
                    "outcome": self._normalize_attempt_outcome(entry),
                    "params": self._compact_attempt_params(entry.get("params")),
                }
            )

        parsed_entries.sort(key=lambda item: item.get("sort_ts", 0.0), reverse=True)
        recent = parsed_entries[: max(1, int(recent_limit or 8))]

        totals = {
            "attempts": len(parsed_entries),
            "distinct_modes": len(set(item["mode"] for item in parsed_entries)),
            "exhausted": sum(
                1 for item in parsed_entries if item["outcome"] == "exhausted"
            ),
            "fatal": sum(1 for item in parsed_entries if item["outcome"] == "fatal"),
            "cracked": sum(
                1 for item in parsed_entries if item["outcome"] == "cracked"
            ),
        }

        by_mode_index = {}
        for item in parsed_entries:
            mode = item["mode"]
            mode_bucket = by_mode_index.setdefault(
                mode,
                {
                    "mode": mode,
                    "attempts": 0,
                    "exhausted": 0,
                    "fatal": 0,
                    "cracked": 0,
                    "last_used": item.get("started_at"),
                    "_last_used_sort": item.get("sort_ts", 0.0),
                },
            )
            mode_bucket["attempts"] += 1
            if item["outcome"] == "exhausted":
                mode_bucket["exhausted"] += 1
            elif item["outcome"] == "fatal":
                mode_bucket["fatal"] += 1
            elif item["outcome"] == "cracked":
                mode_bucket["cracked"] += 1

            if item.get("sort_ts", 0.0) > mode_bucket.get("_last_used_sort", 0.0):
                mode_bucket["last_used"] = item.get("started_at")
                mode_bucket["_last_used_sort"] = item.get("sort_ts", 0.0)

        by_mode = sorted(
            by_mode_index.values(),
            key=lambda item: (
                item.get("attempts", 0),
                item.get("_last_used_sort", 0.0),
            ),
            reverse=True,
        )
        for mode_item in by_mode:
            mode_item.pop("_last_used_sort", None)

        recent_items = [
            {
                "started_at": item.get("started_at"),
                "mode": item.get("mode"),
                "outcome": item.get("outcome"),
                "params": item.get("params", {}),
            }
            for item in recent
        ]

        return {
            "scope": "hashcat",
            "totals": totals,
            "by_mode": by_mode,
            "recent": recent_items,
            "tip": self._build_attempt_tip(totals, recent),
        }

    def _inspect_hash_file(self, hash_path: str | None) -> dict:
        result = {
            "exists": False,
            "size_bytes": 0,
            "total_lines": 0,
            "valid_hash_lines": 0,
            "invalid_hash_lines": 0,
            "essid_count": 0,
        }
        if not hash_path or not os.path.exists(hash_path):
            return result

        result["exists"] = True
        try:
            result["size_bytes"] = os.path.getsize(hash_path)
        except Exception:
            result["size_bytes"] = 0

        essids = set()
        try:
            with open(hash_path, "r", encoding="utf-8", errors="replace") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line:
                        continue
                    result["total_lines"] += 1
                    parts = line.split("*")
                    if (
                        parts
                        and parts[0].upper().startswith("WPA")
                        and len(parts) > 5
                        and parts[2]
                        and parts[3]
                        and parts[4]
                        and parts[5]
                    ):
                        result["valid_hash_lines"] += 1
                        essids.add(parts[5])
                    else:
                        result["invalid_hash_lines"] += 1
        except Exception:
            # Keep best-effort metrics from size/existence only.
            pass

        result["essid_count"] = len(essids)
        return result

    def _is_already_cracked(
        self,
        mac: str | None,
        filename: str | None,
        capture_id: str | None = None,
        combined_build_id: str | None = None,
    ) -> bool:
        if filename:
            base = os.path.basename(filename).rsplit(".", 1)[0]
            cracked_names = (
                ["combined.cracked"]
                if combined_build_id
                else [f"{base}.cracked", f"{base}.pcap.cracked"]
            )
            for cracked_name in cracked_names:
                cracked_candidate = resolve_artifact_path(
                    cracked_name,
                    handshakes_dir=HANDSHAKES_DIR,
                    capture_id=capture_id,
                    combined_build_id=combined_build_id,
                    mac=mac,
                )
                if cracked_candidate and os.path.exists(cracked_candidate):
                    return True

        mac_clean = self._mac_to_clean(mac)
        if not mac_clean:
            return False
        return bool(self._find_matching_paths(mac_clean, ".pcap.cracked"))

    def _resolve_network_context(
        self, mac: str | None, filename: str | None
    ) -> tuple[str | None, dict]:
        dataset = load_real_data() or {}
        normalized_mac = self._normalize_mac(mac) or self._extract_mac_from_filename(
            filename
        )
        network = {}
        if normalized_mac and isinstance(dataset, dict):
            network = dataset.get(normalized_mac) or {}
        return normalized_mac, network if isinstance(network, dict) else {}

    def _score_context(self, context: dict) -> tuple[int, list]:
        score = 35
        reasons = []

        def add(delta: int, reason: str):
            nonlocal score
            score += delta
            reasons.append({"delta": delta, "reason": reason})

        network = context["network"]
        details = context["details"]
        hash_info = context["hash"]
        history_stats = context["history"]
        raw = context["raw_aggregate"]
        already_cracked = context["already_cracked"]

        encryption = str(network.get("encryption") or "").upper()
        ssid = str(network.get("ssid") or "")
        wps_present = (
            bool(details.get("wps", {}).get("present"))
            if isinstance(details, dict)
            else False
        )
        pmf = (
            str(details.get("security", {}).get("pmf") or "")
            if isinstance(details, dict)
            else ""
        )

        if encryption == "OPEN":
            score = 0
            reasons.append(
                {"delta": -100, "reason": "Network is OPEN; cracking is not required."}
            )
            return score, reasons

        if already_cracked:
            score = 0
            reasons.append({"delta": -100, "reason": "Network already cracked."})
            return score, reasons

        previously_cracked = int(history_stats.get("cracked") or 0)
        if previously_cracked > 0:
            add(
                -8,
                f"{previously_cracked} prior cracked attempts in history; verify if target credentials were rotated.",
            )

        if hash_info["valid_hash_lines"] > 0:
            add(30, f"Valid WPA hashes available ({hash_info['valid_hash_lines']}).")
            if hash_info["valid_hash_lines"] >= 3:
                add(8, "Multiple valid hash lines increase cracking confidence.")
        elif hash_info["exists"]:
            add(-25, "Hash file exists but has no valid WPA lines.")
        else:
            add(-20, "No .22000 hash file found for target.")

        if bool(network.get("handshake")):
            add(8, "Handshake source files detected.")

        raw_eapol = int(network.get("raw_eapol_count") or 0)
        raw_beacon = int(network.get("raw_beacon_count") or 0)
        if raw.get("present"):
            raw_eapol = max(
                raw_eapol, int(raw["aggregate"].get("eapol_count_total") or 0)
            )
            raw_beacon = max(
                raw_beacon, int(raw["aggregate"].get("beacon_count_total") or 0)
            )
        if raw_eapol > 0:
            add(12, f"RawSniffer observed EAPOL frames ({raw_eapol}).")
        if raw_beacon > 0:
            add(4, f"RawSniffer observed beacon activity ({raw_beacon}).")

        if not ssid.strip():
            add(-6, "SSID still hidden/blank; targeting strategy is less precise.")

        if wps_present:
            add(6, "WPS metadata present; dictionary/rules attack can be prioritized.")

        if pmf.lower() == "required":
            add(-8, "PMF required; may indicate hardened AP profile.")
        elif pmf.lower() == "none":
            add(4, "PMF disabled; security posture is weaker.")

        exhausted = int(history_stats.get("exhausted") or 0)
        failed = int(history_stats.get("failed") or 0)
        if exhausted >= 3:
            add(-10, f"{exhausted} exhausted attempts recorded.")
        if failed >= 3:
            add(-6, f"{failed} failed attempts recorded.")

        score = max(0, min(100, int(round(score))))
        return score, reasons

    def _priority_from_score(self, score: int) -> str:
        if score >= 70:
            return "high"
        if score >= 45:
            return "medium"
        return "low"

    def _collect_raw_enrichment_state(self, raw_aggregate: dict) -> dict:
        files = raw_aggregate.get("files") if isinstance(raw_aggregate, dict) else []
        if not isinstance(files, list):
            files = []

        source_raw_files = []
        seen_raw = set()
        existing_hash_files = []
        pending_hash_files = []

        for item in files:
            if not isinstance(item, dict):
                continue
            source_file = os.path.basename(str(item.get("source_file") or ""))
            if not source_file:
                continue
            if source_file not in seen_raw:
                seen_raw.add(source_file)
                source_raw_files.append(source_file)

            base = source_file.rsplit(".", 1)[0]
            hash_name = f"{base}.22000"
            hash_path = os.path.join(HANDSHAKES_DIR, hash_name)
            raw_path = os.path.join(BRUCE_PCAP_DIR, source_file)

            needs_refresh = True
            if os.path.exists(hash_path):
                try:
                    if os.path.getsize(hash_path) > 0:
                        needs_refresh = False
                        if os.path.exists(raw_path) and os.path.getmtime(
                            raw_path
                        ) > os.path.getmtime(hash_path):
                            needs_refresh = True
                except OSError:
                    needs_refresh = True

            if needs_refresh:
                if hash_name not in pending_hash_files:
                    pending_hash_files.append(hash_name)
            else:
                if hash_name not in existing_hash_files:
                    existing_hash_files.append(hash_name)

        return {
            "source_raw_files": source_raw_files,
            "existing_hash_files": existing_hash_files,
            "pending_hash_files": pending_hash_files,
            "enrichment_available": bool(source_raw_files),
            "needs_enrichment": bool(pending_hash_files),
        }

    def _build_handshake_readiness(self, context: dict) -> dict:
        network = context.get("network") or {}
        hash_info = context.get("hash") or {}
        already_cracked = bool(context.get("already_cracked"))
        raw_aggregate = context.get("raw_aggregate") or {"present": False}

        raw_eapol = int(network.get("raw_eapol_count") or 0)
        raw_beacon = int(network.get("raw_beacon_count") or 0)
        raw_files_count = 0
        raw_warnings_count = 0

        if raw_aggregate.get("present"):
            aggregate = raw_aggregate.get("aggregate") or {}
            raw_eapol = max(raw_eapol, int(aggregate.get("eapol_count_total") or 0))
            raw_beacon = max(raw_beacon, int(aggregate.get("beacon_count_total") or 0))
            raw_files_count = int(raw_aggregate.get("files_count") or 0)
            raw_warnings_count = len(aggregate.get("warnings") or [])

        enrichment = self._collect_raw_enrichment_state(raw_aggregate)

        encryption = str(network.get("encryption") or "").upper()
        valid_hash_lines = int(hash_info.get("valid_hash_lines") or 0)

        status = "not_ready"
        reason = "No valid WPA hashes and no meaningful RAW EAPOL signals yet."
        score = 5

        if encryption == "OPEN":
            status = "open"
            reason = "OPEN network; handshake cracking is not required."
            score = 100
        elif already_cracked:
            status = "already_cracked"
            reason = "Target already has cracked credentials artifact."
            score = 100
        elif valid_hash_lines > 0:
            status = "ready"
            reason = f"Valid WPA hash lines available ({valid_hash_lines})."
            score = min(100, 70 + min(30, valid_hash_lines * 10))
        elif raw_eapol > 0:
            status = "weak_ready"
            reason = f"RAW capture observed EAPOL frames ({raw_eapol}), but no valid .22000 yet."
            score = 55
        elif raw_beacon > 0:
            status = "observed_only"
            reason = f"RAW capture has beacon activity ({raw_beacon}) but no EAPOL."
            score = 25

        if raw_warnings_count > 0 and status not in {"open", "already_cracked"}:
            score = max(0, score - min(10, raw_warnings_count * 2))

        return {
            "status": status,
            "score": int(score),
            "reason": reason,
            "signals": {
                "valid_hash_lines": valid_hash_lines,
                "raw_eapol_total": raw_eapol,
                "raw_beacon_total": raw_beacon,
                "raw_files_count": raw_files_count,
                "raw_warnings_count": raw_warnings_count,
                "already_cracked": already_cracked,
                "hash_exists": bool(hash_info.get("exists")),
            },
            "enrichment": enrichment,
        }

    def build_context(
        self,
        mac: str | None = None,
        filename: str | None = None,
        capture_id: str | None = None,
        combined_build_id: str | None = None,
    ) -> dict:
        normalized_mac, network = self._resolve_network_context(mac, filename)
        details_path = self._find_details_path(normalized_mac, filename, capture_id)
        details = self._safe_load_json(details_path) if details_path else None
        details = details if isinstance(details, dict) else {}

        hash_path = self._resolve_hash_path(
            filename,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
            mac=normalized_mac or mac,
        )
        if not hash_path and normalized_mac:
            clean = self._mac_to_clean(normalized_mac)
            candidates = self._find_matching_paths(clean, ".22000")
            if candidates:
                hash_path = candidates[0]

        hash_info = self._inspect_hash_file(hash_path)
        history_stats = self._count_history_statuses(
            filename or hash_path,
            normalized_mac,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
        )
        already_cracked = self._is_already_cracked(
            normalized_mac,
            filename or hash_path,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
        )

        raw_aggregate = {"present": False}
        if normalized_mac:
            raw_aggregate = rawsniffer_service.get_aggregated_metadata_for_bssid(
                normalized_mac
            )

        return {
            "mac": normalized_mac,
            "filename": (
                os.path.basename(filename)
                if filename
                else (os.path.basename(hash_path) if hash_path else None)
            ),
            "network": network,
            "details": details,
            "details_path": details_path,
            "hash_path": hash_path,
            "hash": hash_info,
            "history": history_stats,
            "raw_aggregate": raw_aggregate,
            "already_cracked": already_cracked,
            "capture_id": capture_id,
            "combined_build_id": combined_build_id,
        }

    def get_attack_score(
        self,
        mac: str | None = None,
        filename: str | None = None,
        capture_id: str | None = None,
        combined_build_id: str | None = None,
    ) -> dict:
        context = self.build_context(
            mac=mac,
            filename=filename,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
        )
        score, reasons = self._score_context(context)
        readiness = self._build_handshake_readiness(context)

        return {
            "present": bool(context["mac"] or context["filename"]),
            "target": {
                "mac": context["mac"],
                "filename": context["filename"],
            },
            "score": score,
            "priority": self._priority_from_score(score),
            "score_reasons": reasons,
            "signals": {
                "hash": deepcopy(context["hash"]),
                "history": deepcopy(context["history"]),
                "already_cracked": context["already_cracked"],
                "raw_present": bool(context["raw_aggregate"].get("present")),
                "ssid": context["network"].get("ssid"),
                "encryption": context["network"].get("encryption"),
                "handshake_readiness": readiness,
            },
        }

    def get_handshake_readiness(
        self,
        mac: str | None = None,
        filename: str | None = None,
        capture_id: str | None = None,
        combined_build_id: str | None = None,
    ) -> dict:
        context = self.build_context(
            mac=mac,
            filename=filename,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
        )
        return {
            "present": bool(context["mac"] or context["filename"]),
            "target": {
                "mac": context["mac"],
                "filename": context["filename"],
            },
            "readiness": self._build_handshake_readiness(context),
        }

    def evaluate_quality_gate(
        self,
        filename: str,
        attack_mode: str | None = None,
        capture_id: str | None = None,
        combined_build_id: str | None = None,
        mac: str | None = None,
    ) -> dict:
        context = self.build_context(
            filename=filename,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
            mac=mac,
        )
        hash_info = context["hash"]
        checks = []

        def check(
            check_id: str,
            passed: bool,
            severity: str,
            message: str,
            can_override: bool = False,
        ):
            checks.append(
                {
                    "id": check_id,
                    "passed": passed,
                    "severity": severity,
                    "message": message,
                    "can_override": can_override,
                }
            )

        hash_exists = bool(hash_info.get("exists"))
        check(
            "hash_exists",
            hash_exists,
            "error",
            "Hash file exists." if hash_exists else "Hash file not found.",
            can_override=False,
        )

        not_empty = bool(hash_info.get("size_bytes", 0) > 0)
        check(
            "hash_not_empty",
            not_empty,
            "error",
            "Hash file has content." if not_empty else "Hash file is empty.",
            can_override=False,
        )

        valid_lines = int(hash_info.get("valid_hash_lines") or 0)
        has_valid_hashes = valid_lines > 0
        check(
            "valid_hash_lines",
            has_valid_hashes,
            "error",
            (
                f"Valid WPA hash lines: {valid_lines}."
                if has_valid_hashes
                else "No valid WPA hash lines were found."
            ),
            can_override=False,
        )

        already_cracked = bool(context.get("already_cracked"))
        check(
            "already_cracked",
            not already_cracked,
            "warning",
            (
                "Target has not been cracked yet."
                if not already_cracked
                else "Target already has a cracked password artifact."
            ),
            can_override=True,
        )

        exhausted_attempts = int(context["history"].get("exhausted") or 0)
        has_many_exhausted = exhausted_attempts >= 3
        check(
            "repeated_exhausted",
            not has_many_exhausted,
            "warning",
            (
                "No heavy exhausted history detected."
                if not has_many_exhausted
                else f"{exhausted_attempts} exhausted attempts detected; consider changing strategy."
            ),
            can_override=True,
        )

        # Check if current attack mode has an EXHAUSTED history entry
        mode_exhausted = False
        if attack_mode:
            normalized_mode = str(attack_mode).strip().lower()
            if normalized_mode and normalized_mode != "unknown":
                entries = self._load_history_entries(
                    filename,
                    mac,
                    capture_id=capture_id,
                    combined_build_id=combined_build_id,
                )
                for entry in entries:
                    entry_mode = self._extract_attempt_mode(entry)
                    if entry_mode == normalized_mode:
                        status = str(entry.get("status") or "").strip().upper()
                        if status == "EXHAUSTED":
                            mode_exhausted = True
                            break

        check(
            "history_exhausted",
            not mode_exhausted,
            "error",
            (
                "No exhausted history for this attack mode."
                if not mode_exhausted
                else f"Attack mode '{attack_mode}' already exhausted for this target."
            ),
            can_override=False,
        )

        blocking = [c for c in checks if not c["passed"] and c["severity"] == "error"]
        overridable = [c for c in checks if not c["passed"] and c.get("can_override")]
        if blocking:
            # Check if the specific history_exhausted check is the one blocking
            history_exhausted_check = next(
                (c for c in blocking if c["id"] == "history_exhausted"), None
            )
            if history_exhausted_check:
                return {
                    "passed": False,
                    "code": "history_exhausted",
                    "message": history_exhausted_check["message"],
                    "checks": checks,
                    "can_override": False,
                    "attack_mode": attack_mode,
                }
            return {
                "passed": False,
                "code": "quality_gate_blocked",
                "message": blocking[0]["message"],
                "checks": checks,
                "can_override": False,
                "attack_mode": attack_mode,
            }
        if overridable:
            return {
                "passed": False,
                "code": "quality_gate_overrideable",
                "message": overridable[0]["message"],
                "checks": checks,
                "can_override": True,
                "attack_mode": attack_mode,
            }
        return {
            "passed": True,
            "code": "quality_gate_passed",
            "message": "Quality gate passed.",
            "checks": checks,
            "can_override": True,
            "attack_mode": attack_mode,
        }

    def get_attack_recommendation(
        self,
        mac: str | None = None,
        filename: str | None = None,
        capture_id: str | None = None,
        combined_build_id: str | None = None,
    ) -> dict:
        context = self.build_context(
            mac=mac,
            filename=filename,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
        )
        score_payload = self.get_attack_score(
            mac=mac,
            filename=filename,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
        )
        score = int(score_payload["score"])
        network = context["network"]
        details = context["details"] if isinstance(context["details"], dict) else {}

        recommendation = {
            "target": score_payload["target"],
            "attack_score": {
                "score": score,
                "priority": score_payload["priority"],
                "score_reasons": score_payload["score_reasons"],
            },
            "handshake_readiness": self._build_handshake_readiness(context),
            "attempt_feedback": self.build_attempt_feedback(
                filename=context.get("filename"),
                mac=context.get("mac"),
                capture_id=capture_id,
                combined_build_id=combined_build_id,
            ),
            "action": "run",
            "recommended_mode": "rules",
            "candidate_modes": ["rules", "straight", "hybrid"],
            "suggested_hints": [],
            "reasons": [],
            "quality_gate": None,
        }

        if context["already_cracked"]:
            recommendation["action"] = "skip"
            recommendation["recommended_mode"] = "none"
            recommendation["candidate_modes"] = []
            recommendation["reasons"].append("Target already cracked.")
            recommendation["quality_gate"] = {
                "passed": False,
                "code": "already_cracked",
                "message": "Target already cracked.",
                "can_override": True,
            }
            return recommendation

        if str(network.get("encryption") or "").upper() == "OPEN":
            recommendation["action"] = "skip"
            recommendation["recommended_mode"] = "none"
            recommendation["candidate_modes"] = []
            recommendation["reasons"].append(
                "OPEN network does not require handshake cracking."
            )
            recommendation["quality_gate"] = {
                "passed": False,
                "code": "open_network",
                "message": "OPEN network.",
                "can_override": False,
            }
            return recommendation

        hash_file = context["hash"]
        if int(hash_file.get("valid_hash_lines") or 0) == 0:
            recommendation["action"] = "prepare"
            recommendation["recommended_mode"] = "convert_hcx"
            recommendation["candidate_modes"] = ["convert_hcx", "fingerprint_refresh"]
            recommendation["reasons"].append(
                "No valid .22000 hashes; convert/re-capture first."
            )
            if recommendation["handshake_readiness"]["enrichment"].get(
                "needs_enrichment"
            ):
                pending = recommendation["handshake_readiness"]["enrichment"].get(
                    "pending_hash_files", []
                )
                recommendation["reasons"].append(
                    f"RAW auto-enrichment pending for {len(pending)} hash file(s)."
                )
            recommendation["quality_gate"] = self.evaluate_quality_gate(
                filename=context["filename"] or (filename or ""),
                capture_id=capture_id,
                combined_build_id=combined_build_id,
                mac=mac,
            )
            return recommendation

        wps_present = (
            bool(details.get("wps", {}).get("present"))
            if isinstance(details, dict)
            else False
        )
        ssid = str(network.get("ssid") or "").strip()

        if not ssid:
            recommendation["recommended_mode"] = "association_hint_first"
            recommendation["candidate_modes"] = [
                "association_hint_first",
                "rules",
                "straight",
            ]
            recommendation["reasons"].append(
                "SSID hidden; use multi-hints association mode to generate directed candidates."
            )
            if filename:
                base = os.path.basename(filename).rsplit(".", 1)[0]
                if "_" in base:
                    hint = base.rsplit("_", 1)[0].strip()
                    if hint and not hint.upper().startswith("HS"):
                        recommendation["suggested_hints"].append(hint)
        elif wps_present:
            recommendation["recommended_mode"] = "rules"
            recommendation["candidate_modes"] = ["rules", "straight", "passphrase"]
            recommendation["reasons"].append(
                "WPS metadata present; rules-based dictionary attack preferred."
            )
        elif score < 45:
            recommendation["recommended_mode"] = "straight"
            recommendation["candidate_modes"] = ["straight", "rules"]
            recommendation["reasons"].append(
                "Low score target; run a lighter straight attack first."
            )
        else:
            recommendation["recommended_mode"] = "rules"
            recommendation["candidate_modes"] = ["rules", "hybrid", "straight"]
            recommendation["reasons"].append(
                "Good score target; rules attack offers best cost/benefit."
            )

        recommendation["quality_gate"] = self.evaluate_quality_gate(
            filename=context["filename"] or (filename or ""),
            attack_mode=recommendation["recommended_mode"],
            capture_id=capture_id,
            combined_build_id=combined_build_id,
            mac=mac,
        )
        return recommendation


insights_service = InsightsService()
