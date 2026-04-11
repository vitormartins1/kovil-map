"""Advanced Packet Analysis Service.

Scans PCAP files with tshark to detect deauthentication attacks,
disassociation frames, and other 802.11 threat indicators.  Feeds the
Recon Center INTEL tab with per-BSSID threat intelligence.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections import defaultdict
from typing import Any, List, Tuple

from app.core.config import (
    HANDSHAKES_DIR,
    BRUCE_HANDSHAKES_DIR,
    BRUCE_PCAP_DIR,
    M5EVIL_HANDSHAKES_DIR,
    load_config,
)
from app.services.base_service import BaseService
from app.utils.pcap import build_pcap_search_roots, validate_pcap_file

# 802.11 reason codes for deauth / disassoc
REASON_CODES: dict[int, str] = {
    1: "Unspecified",
    2: "Previous auth no longer valid",
    3: "Station leaving / has left",
    4: "Inactivity",
    5: "AP unable to handle stations",
    6: "Class-2 frame from non-authed station",
    7: "Class-3 frame from non-assoc station",
    8: "Station leaving / has left BSS",
}


class PacketAnalysisService(BaseService):
    """Detect deauth/disassoc attacks and other threats in PCAPs."""

    def __init__(self):
        super().__init__()
        self.conf = load_config()
        # Cache: result + signature for staleness detection
        self._cache: dict[str, Any] | None = None
        self._cache_signature: tuple[int, float] | None = None

    # ------------------------------------------------------------------
    # Caching
    # ------------------------------------------------------------------

    def _compute_signature(self, pcaps: list[str]) -> tuple[int, float]:
        """Return (count, total_mtime) for staleness detection."""
        total_mtime = 0.0
        for p in pcaps:
            try:
                total_mtime += os.path.getmtime(p)
            except OSError:
                pass
        return (len(pcaps), total_mtime)

    def get_cache_status(self) -> dict[str, Any]:
        """Return cache metadata for the frontend (no heavy processing)."""
        pcaps = self._find_pcaps()
        current_sig = self._compute_signature(pcaps)
        cached = self._cache is not None
        stale = cached and self._cache_signature != current_sig
        return {
            "cached": cached,
            "stale": stale,
            "pcap_count": len(pcaps),
            "result": self._cache if cached else None,
        }

    def invalidate_cache(self) -> None:
        self._cache = None
        self._cache_signature = None

    # ------------------------------------------------------------------
    # tshark helpers (same pattern as ProbeService / FingerprintService)
    # ------------------------------------------------------------------

    def _pcap_search_roots(self) -> tuple[str, ...]:
        return build_pcap_search_roots(
            HANDSHAKES_DIR,
            BRUCE_HANDSHAKES_DIR,
            BRUCE_PCAP_DIR,
            M5EVIL_HANDSHAKES_DIR,
        )

    def _check_tshark(self) -> str | None:
        tshark_bin = self.conf.get("tshark_path", "tshark")
        if os.path.isabs(tshark_bin):
            exists = os.path.exists(tshark_bin)
        else:
            exists = shutil.which(tshark_bin) is not None
        return tshark_bin if exists else None

    def _build_command(self, base_cmd: List[str]) -> Tuple[List[str], str]:
        tshark_bin = self.conf.get("tshark_path", "tshark")
        use_wsl = self._should_use_wsl(tshark_bin)
        if use_wsl:
            cmd = ["wsl", tshark_bin] + base_cmd
        else:
            cmd = [tshark_bin] + base_cmd
        return cmd, " ".join(cmd)

    def _run_tshark(self, base_cmd: List[str]) -> Tuple[str, List[str]]:
        cmd, cmd_str = self._build_command(base_cmd)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                cwd=None,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            if proc.returncode != 0 and not stdout.strip():
                if "damaged or corrupt" in stderr.lower():
                    self.logger.debug("Skipping corrupt PCAP: %s", stderr.strip())
                    return "", []
                raise RuntimeError(stderr.strip() or f"tshark exit {proc.returncode}")
            warnings: list[str] = []
            if stderr.strip():
                warnings.append(stderr.strip())
            return stdout, warnings
        except FileNotFoundError:
            raise RuntimeError("tshark not found")

    def _parse_rows(self, raw: str, expected_cols: int) -> List[List[str]]:
        rows: list[list[str]] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < expected_cols:
                parts += [""] * (expected_cols - len(parts))
            rows.append(parts[:expected_cols])
        return rows

    # ------------------------------------------------------------------
    # PCAP discovery (shared pattern)
    # ------------------------------------------------------------------

    def _find_pcaps(self) -> list[str]:
        paths: list[str] = []
        seen: set[str] = set()
        for root in self._pcap_search_roots():
            if not os.path.isdir(root):
                continue
            for name in os.listdir(root):
                if not (name.endswith(".pcap") or name.endswith(".pcapng")):
                    continue
                full = os.path.join(root, name)
                real = os.path.realpath(full)
                if real in seen:
                    continue
                seen.add(real)
                valid, reason = validate_pcap_file(full)
                if not valid:
                    self.logger.warning("Skipping invalid PCAP %s: %s", name, reason)
                    continue
                paths.append(full)
        return paths

    # ------------------------------------------------------------------
    # Core extraction
    # ------------------------------------------------------------------

    def _extract_deauth(self, pcap_path: str) -> list[dict]:
        """Extract deauthentication frames (subtype 0x0c)."""
        stdout, _ = self._run_tshark(
            [
                "-r",
                pcap_path,
                "-Y",
                "wlan.fc.type_subtype==0x0c",
                "-T",
                "fields",
                "-E",
                "separator=\t",
                "-e",
                "frame.time_epoch",
                "-e",
                "wlan.sa",
                "-e",
                "wlan.da",
                "-e",
                "wlan.bssid",
                "-e",
                "wlan.fixed.reason_code",
            ]
        )
        return self._parse_mgmt_rows(stdout)

    def _extract_disassoc(self, pcap_path: str) -> list[dict]:
        """Extract disassociation frames (subtype 0x0a)."""
        stdout, _ = self._run_tshark(
            [
                "-r",
                pcap_path,
                "-Y",
                "wlan.fc.type_subtype==0x0a",
                "-T",
                "fields",
                "-E",
                "separator=\t",
                "-e",
                "frame.time_epoch",
                "-e",
                "wlan.sa",
                "-e",
                "wlan.da",
                "-e",
                "wlan.bssid",
                "-e",
                "wlan.fixed.reason_code",
            ]
        )
        return self._parse_mgmt_rows(stdout)

    def _parse_mgmt_rows(self, raw: str) -> list[dict]:
        """Parse tab-separated deauth/disassoc rows."""
        rows = self._parse_rows(raw, 5)
        results: list[dict] = []
        for ts_str, src, dst, bssid, reason_str in rows:
            if not bssid:
                continue
            try:
                ts = float(ts_str.strip())
            except (ValueError, TypeError):
                ts = 0.0
            try:
                reason = int(reason_str.strip())
            except (ValueError, TypeError):
                reason = 0
            results.append(
                {
                    "timestamp": ts,
                    "src": src.strip().lower(),
                    "dst": dst.strip().lower(),
                    "bssid": bssid.strip().lower(),
                    "reason_code": reason,
                    "reason_text": REASON_CODES.get(reason, "Unknown"),
                }
            )
        return results

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    def analyse(self, *, limit: int = 200) -> dict[str, Any]:
        """Run deep analysis across all PCAPs."""
        tshark_bin = self._check_tshark()
        if not tshark_bin:
            return {
                "available": False,
                "error": "tshark not found",
                "threats_by_bssid": {},
                "summary": {},
            }

        pcaps = self._find_pcaps()
        if not pcaps:
            return self._empty_result(0)

        all_deauth: list[dict] = []
        all_disassoc: list[dict] = []
        pcaps_ok = 0
        for pcap in pcaps:
            try:
                all_deauth.extend(self._extract_deauth(pcap))
                all_disassoc.extend(self._extract_disassoc(pcap))
                pcaps_ok += 1
            except Exception as exc:
                self.logger.warning("Deep analysis failed for %s: %s", pcap, exc)

        return self._build_threat_intel(all_deauth, all_disassoc, pcaps_ok, limit)

    def analyse_with_progress(
        self,
        pcaps: list[str],
        *,
        limit: int = 200,
        emit=None,
        job=None,
    ) -> dict[str, Any]:
        """Run deep analysis with per-PCAP progress emission.

        Used by background jobs.
        """
        tshark_bin = self._check_tshark()
        if not tshark_bin:
            return {
                "available": False,
                "error": "tshark not found",
                "threats_by_bssid": {},
                "summary": {},
            }

        if not pcaps:
            return self._empty_result(0)

        total = len(pcaps)
        all_deauth: list[dict] = []
        all_disassoc: list[dict] = []
        pcaps_ok = 0
        for idx, pcap in enumerate(pcaps):
            if job and emit:
                job["progress_data"]["current_step"] = idx + 1
                job["progress_data"]["percentage"] = int(((idx + 1) / total) * 100)
                job["progress_data"]["stage"] = "RUNNING"
                job["progress_data"]["extra"] = os.path.basename(pcap)
                emit(
                    "job_progress",
                    {"job_id": job["id"], "data": job["progress_data"].copy()},
                )
            try:
                all_deauth.extend(self._extract_deauth(pcap))
                all_disassoc.extend(self._extract_disassoc(pcap))
                pcaps_ok += 1
            except Exception as exc:
                self.logger.warning("Deep analysis failed for %s: %s", pcap, exc)

        result = self._build_threat_intel(all_deauth, all_disassoc, pcaps_ok, limit)

        # Store in cache
        sig = self._compute_signature(pcaps)
        self._cache = result
        self._cache_signature = sig

        return result

    def analyse_pcap(self, pcap_path: str, *, limit: int = 200) -> dict[str, Any]:
        """Run deep analysis on a single PCAP."""
        tshark_bin = self._check_tshark()
        if not tshark_bin:
            return {
                "available": False,
                "error": "tshark not found",
                "threats_by_bssid": {},
                "summary": {},
            }
        deauth = self._extract_deauth(pcap_path)
        disassoc = self._extract_disassoc(pcap_path)
        return self._build_threat_intel(deauth, disassoc, 1, limit)

    def _empty_result(self, pcaps_scanned: int) -> dict[str, Any]:
        return {
            "available": True,
            "threats_by_bssid": {},
            "summary": {
                "total_deauth": 0,
                "total_disassoc": 0,
                "targeted_bssids": 0,
                "pcaps_scanned": pcaps_scanned,
                "deauth_flood_detected": False,
            },
        }

    def _build_threat_intel(
        self,
        deauth_frames: list[dict],
        disassoc_frames: list[dict],
        pcaps_scanned: int,
        limit: int,
    ) -> dict[str, Any]:
        """Aggregate per-BSSID threat intelligence."""
        if not deauth_frames and not disassoc_frames:
            return self._empty_result(pcaps_scanned)

        # Per-BSSID aggregation
        bssid_data: dict[str, dict] = defaultdict(
            lambda: {
                "deauth_count": 0,
                "disassoc_count": 0,
                "reason_codes": defaultdict(int),
                "unique_sources": set(),
                "unique_targets": set(),
                "first_seen": float("inf"),
                "last_seen": 0.0,
            }
        )

        for frame in deauth_frames:
            bd = bssid_data[frame["bssid"]]
            bd["deauth_count"] += 1
            bd["reason_codes"][frame["reason_code"]] += 1
            bd["unique_sources"].add(frame["src"])
            bd["unique_targets"].add(frame["dst"])
            if frame["timestamp"] > 0:
                bd["first_seen"] = min(bd["first_seen"], frame["timestamp"])
                bd["last_seen"] = max(bd["last_seen"], frame["timestamp"])

        for frame in disassoc_frames:
            bd = bssid_data[frame["bssid"]]
            bd["disassoc_count"] += 1
            bd["reason_codes"][frame["reason_code"]] += 1
            bd["unique_sources"].add(frame["src"])
            bd["unique_targets"].add(frame["dst"])
            if frame["timestamp"] > 0:
                bd["first_seen"] = min(bd["first_seen"], frame["timestamp"])
                bd["last_seen"] = max(bd["last_seen"], frame["timestamp"])

        # Build serialisable output, sorted by total frame count
        threats: list[dict] = []
        deauth_flood = False
        for bssid, bd in bssid_data.items():
            total = bd["deauth_count"] + bd["disassoc_count"]
            top_reasons = sorted(
                bd["reason_codes"].items(), key=lambda x: x[1], reverse=True
            )[:5]
            # Flood heuristic: > 50 deauth frames from a single source
            source_is_flood = bd["deauth_count"] > 50
            if source_is_flood:
                deauth_flood = True
            threats.append(
                {
                    "bssid": bssid,
                    "deauth_count": bd["deauth_count"],
                    "disassoc_count": bd["disassoc_count"],
                    "total_frames": total,
                    "unique_sources": len(bd["unique_sources"]),
                    "unique_targets": len(bd["unique_targets"]),
                    "top_reasons": [
                        {
                            "code": code,
                            "text": REASON_CODES.get(code, "Unknown"),
                            "count": cnt,
                        }
                        for code, cnt in top_reasons
                    ],
                    "first_seen": (
                        bd["first_seen"] if bd["first_seen"] != float("inf") else None
                    ),
                    "last_seen": bd["last_seen"] if bd["last_seen"] > 0 else None,
                    "flood_indicator": source_is_flood,
                }
            )
        threats.sort(key=lambda t: t["total_frames"], reverse=True)

        return {
            "available": True,
            "threats_by_bssid": threats[:limit],
            "summary": {
                "total_deauth": len(deauth_frames),
                "total_disassoc": len(disassoc_frames),
                "targeted_bssids": len(bssid_data),
                "pcaps_scanned": pcaps_scanned,
                "deauth_flood_detected": deauth_flood,
            },
        }


packet_analysis_service = PacketAnalysisService()
