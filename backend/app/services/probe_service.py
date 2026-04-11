"""Probe Request Intelligence Service.

Extracts probe request frames from PCAP files using tshark and builds
client intelligence: which devices are probing for which SSIDs, timing
patterns, device OUI mapping, and network-to-client relationships.
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
from app.utils.pcap import build_pcap_search_roots


class ProbeService(BaseService):
    """Analyse PCAP files for probe request intelligence."""

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
    # tshark helpers (same pattern as FingerprintService)
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
                # Corrupt / damaged PCAPs are expected in the wild — skip quietly
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
    # PCAP discovery
    # ------------------------------------------------------------------

    def _find_pcaps(self) -> list[str]:
        """Return paths to all .pcap / .pcapng files across search roots."""
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
                paths.append(full)
        return paths

    # ------------------------------------------------------------------
    # Core extraction
    # ------------------------------------------------------------------

    def extract_probes(self, pcap_path: str) -> list[dict]:
        """Extract probe request frames from a single PCAP file.

        Returns list of dicts with keys:
          client_mac, ssid, timestamp, signal
        """
        tshark_bin = self._check_tshark()
        if not tshark_bin:
            raise RuntimeError("tshark not available")

        maybe_wsl = self._should_use_wsl(tshark_bin)
        read_path = self._to_wsl_path(pcap_path) if maybe_wsl else pcap_path

        stdout, _ = self._run_tshark(
            [
                "-r",
                read_path,
                "-Y",
                "wlan.fc.type_subtype==0x04",
                "-T",
                "fields",
                "-E",
                "separator=\t",
                "-e",
                "frame.time_epoch",
                "-e",
                "wlan.sa",
                "-e",
                "wlan.ssid",
                "-e",
                "radiotap.dbm_antsignal",
            ]
        )

        rows = self._parse_rows(stdout, 4)
        results: list[dict] = []
        for ts_str, client_mac, ssid, signal_str in rows:
            if not client_mac:
                continue
            client_mac = client_mac.strip().lower()
            ssid = ssid.strip()
            try:
                ts = float(ts_str.strip())
            except (ValueError, TypeError):
                ts = 0.0
            try:
                signal = int(signal_str.strip().split(",")[0])
            except (ValueError, TypeError, IndexError):
                signal = None

            results.append(
                {
                    "client_mac": client_mac,
                    "ssid": ssid,
                    "timestamp": ts,
                    "signal": signal,
                }
            )
        return results

    # ------------------------------------------------------------------
    # Aggregation / intelligence
    # ------------------------------------------------------------------

    def analyse(self, *, limit: int = 200) -> dict[str, Any]:
        """Run probe intelligence across all available PCAPs.

        Returns aggregated intelligence dict.
        """
        tshark_bin = self._check_tshark()
        if not tshark_bin:
            return {
                "available": False,
                "error": "tshark not found",
                "clients": [],
                "ssids": [],
                "summary": {},
            }

        pcaps = self._find_pcaps()
        if not pcaps:
            return {
                "available": True,
                "clients": [],
                "ssids": [],
                "summary": {
                    "total_probes": 0,
                    "unique_clients": 0,
                    "unique_ssids": 0,
                    "pcaps_scanned": 0,
                    "broadcast_probes": 0,
                },
            }

        # Accumulate raw probes from all PCAPs
        all_probes: list[dict] = []
        pcaps_ok = 0
        for pcap in pcaps:
            try:
                probes = self.extract_probes(pcap)
                all_probes.extend(probes)
                pcaps_ok += 1
            except Exception as exc:
                self.logger.warning("Probe extract failed for %s: %s", pcap, exc)

        return self._build_intelligence(all_probes, pcaps_ok, limit)

    def analyse_with_progress(
        self,
        pcaps: list[str],
        *,
        limit: int = 200,
        emit=None,
        job=None,
    ) -> dict[str, Any]:
        """Run probe intelligence with per-PCAP progress emission.

        Used by background jobs.  Falls back to normal analyse() behaviour
        when *emit* is ``None``.
        """
        tshark_bin = self._check_tshark()
        if not tshark_bin:
            return {
                "available": False,
                "error": "tshark not found",
                "clients": [],
                "ssids": [],
                "summary": {},
            }

        if not pcaps:
            return {
                "available": True,
                "clients": [],
                "ssids": [],
                "summary": {
                    "total_probes": 0,
                    "unique_clients": 0,
                    "unique_ssids": 0,
                    "pcaps_scanned": 0,
                    "broadcast_probes": 0,
                },
            }

        total = len(pcaps)
        all_probes: list[dict] = []
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
                probes = self.extract_probes(pcap)
                all_probes.extend(probes)
                pcaps_ok += 1
            except Exception as exc:
                self.logger.warning("Probe extract failed for %s: %s", pcap, exc)

        result = self._build_intelligence(all_probes, pcaps_ok, limit)

        # Store in cache
        sig = self._compute_signature(pcaps)
        self._cache = result
        self._cache_signature = sig

        return result

    def analyse_pcap(self, pcap_path: str, *, limit: int = 200) -> dict[str, Any]:
        """Run probe intelligence on a single PCAP."""
        tshark_bin = self._check_tshark()
        if not tshark_bin:
            return {
                "available": False,
                "error": "tshark not found",
                "clients": [],
                "ssids": [],
                "summary": {},
            }

        probes = self.extract_probes(pcap_path)
        return self._build_intelligence(probes, 1, limit)

    def _build_intelligence(
        self, probes: list[dict], pcaps_scanned: int, limit: int
    ) -> dict[str, Any]:
        """Aggregate raw probe list into intelligence report."""
        # Per-client aggregation
        client_data: dict[str, dict] = defaultdict(
            lambda: {
                "ssids": set(),
                "probe_count": 0,
                "signals": [],
                "first_seen": float("inf"),
                "last_seen": 0.0,
            }
        )
        # Per-SSID aggregation
        ssid_data: dict[str, dict] = defaultdict(
            lambda: {"clients": set(), "probe_count": 0}
        )
        broadcast_count = 0

        for p in probes:
            mac = p["client_mac"]
            ssid = p["ssid"]
            ts = p["timestamp"]
            sig = p["signal"]

            cd = client_data[mac]
            cd["probe_count"] += 1
            if ssid:
                cd["ssids"].add(ssid)
                ssid_data[ssid]["clients"].add(mac)
                ssid_data[ssid]["probe_count"] += 1
            else:
                broadcast_count += 1
            if sig is not None:
                cd["signals"].append(sig)
            if ts > 0:
                if ts < cd["first_seen"]:
                    cd["first_seen"] = ts
                if ts > cd["last_seen"]:
                    cd["last_seen"] = ts

        # Build client list sorted by probe count desc
        clients: list[dict] = []
        for mac, cd in client_data.items():
            avg_signal = (
                round(sum(cd["signals"]) / len(cd["signals"]))
                if cd["signals"]
                else None
            )
            clients.append(
                {
                    "client_mac": mac,
                    "oui_prefix": mac[:8],
                    "probe_count": cd["probe_count"],
                    "ssids_probed": sorted(cd["ssids"]),
                    "unique_ssids": len(cd["ssids"]),
                    "avg_signal": avg_signal,
                    "first_seen": (
                        cd["first_seen"] if cd["first_seen"] != float("inf") else None
                    ),
                    "last_seen": cd["last_seen"] if cd["last_seen"] > 0 else None,
                }
            )
        clients.sort(key=lambda c: c["probe_count"], reverse=True)

        # Build SSID list sorted by client count desc
        ssids: list[dict] = []
        for ssid_name, sd in ssid_data.items():
            ssids.append(
                {
                    "ssid": ssid_name,
                    "client_count": len(sd["clients"]),
                    "probe_count": sd["probe_count"],
                }
            )
        ssids.sort(key=lambda s: s["client_count"], reverse=True)

        return {
            "available": True,
            "clients": clients[:limit],
            "ssids": ssids[:limit],
            "summary": {
                "total_probes": len(probes),
                "unique_clients": len(client_data),
                "unique_ssids": len(ssid_data),
                "pcaps_scanned": pcaps_scanned,
                "broadcast_probes": broadcast_count,
            },
        }


probe_service = ProbeService()
