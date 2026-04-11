import os
import re
from .base_service import BaseService
from app.core.config import (
    HANDSHAKES_DIR,
    BRUCE_HANDSHAKES_DIR,
    BRUCE_PCAP_DIR,
    M5EVIL_HANDSHAKES_DIR,
)
from app.utils.pcap import build_pcap_search_roots, resolve_pcap_reference
from app.utils.handshake_artifacts import get_capture_artifact_path
from app.core.job_manager import job_manager
from app.services.history_service import history_service

_ALLOWED_TOOLS = {"reaver", "bully"}


class WpsService(BaseService):
    """WPS PIN brute-force attacks using reaver or bully."""

    def _pcap_search_roots(self):
        return build_pcap_search_roots(
            HANDSHAKES_DIR,
            BRUCE_HANDSHAKES_DIR,
            BRUCE_PCAP_DIR,
            M5EVIL_HANDSHAKES_DIR,
        )

    # ------------------------------------------------------------------
    # Attack
    # ------------------------------------------------------------------
    def start_attack(
        self,
        bssid,
        channel,
        interface,
        tool="reaver",
        pixie_dust=False,
        delay=None,
        extra_args=None,
    ):
        if not bssid or not bssid.strip():
            return {"status": "error", "message": "BSSID is required"}
        if not channel:
            return {"status": "error", "message": "Channel is required"}
        if not interface or not interface.strip():
            return {"status": "error", "message": "Interface is required"}

        tool = (tool or "reaver").strip().lower()
        if tool not in _ALLOWED_TOOLS:
            return {"status": "error", "message": f"Unsupported tool: {tool}. Use reaver or bully."}

        bssid = bssid.strip()
        interface = interface.strip()
        channel = str(channel).strip()

        conf = self._get_config()
        use_wsl = False

        cmd_args = []

        if tool == "reaver":
            reaver_bin = conf.get("reaver_path", "reaver")
            use_wsl = self._should_use_wsl(reaver_bin)
            if use_wsl:
                cmd_args.append("wsl")
            cmd_args.extend([reaver_bin, "-i", interface, "-b", bssid, "-c", channel, "-vv"])
            if pixie_dust:
                cmd_args.append("-K")
            if delay is not None:
                cmd_args.extend(["-d", str(int(delay))])
        else:  # bully
            bully_bin = conf.get("bully_path", "bully")
            use_wsl = self._should_use_wsl(bully_bin)
            if use_wsl:
                cmd_args.append("wsl")
            cmd_args.extend([bully_bin, "-b", bssid, "-c", channel, interface])
            if pixie_dust:
                cmd_args.extend(["-d"])
            if delay is not None:
                cmd_args.extend(["--pin-delay", str(int(delay))])

        if extra_args and isinstance(extra_args, list):
            # Sanitize extra args: only allow simple flag-like strings
            for arg in extra_args:
                s = str(arg).strip()
                if s and re.match(r'^-{1,2}[\w-]+(=[\w./-]*)?$', s):
                    cmd_args.append(s)

        self.logger.info(f"WPS attack: {cmd_args}")

        display_label = f"WPS_{bssid.replace(':', '')}"

        entry_id = history_service.add_entry(
            display_label,
            tool,
            cmd_args,
            {"bssid": bssid, "channel": channel, "interface": interface, "pixie_dust": pixie_dust},
        )

        def on_complete(job):
            pin = self._parse_pin(job)
            if pin:
                job["progress_data"]["stage"] = "CRACKED"
                job["progress_data"]["pin"] = pin
                history_service.update_entry(
                    display_label, entry_id, "CRACKED", f"WPS PIN found: {pin}"
                )
                self.logger.info(f"WPS PIN found: {pin} for {bssid}")
            else:
                rc = job.get("return_code")
                if rc == 0:
                    job["progress_data"]["stage"] = "COMPLETE"
                    history_service.update_entry(
                        display_label, entry_id, "COMPLETE", "WPS attack finished"
                    )
                else:
                    job["progress_data"]["stage"] = "FAILED"
                    history_service.update_entry(
                        display_label, entry_id, "FAILED", "WPS attack failed"
                    )

        job_id = job_manager.start_job(
            cmd_args, job_type="wps", cwd=None, on_complete=on_complete
        )

        return {"status": "started", "job_id": job_id, "tool": tool, "bssid": bssid}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _parse_pin(self, job):
        """Extract WPS PIN from job logs (reaver or bully output)."""
        patterns = [
            r"WPS PIN:\s*'?(\d{4,8})'?",
            r"Pin found:\s*(\d{4,8})",
            r"\[PIN\]\s+(\d{4,8})",
        ]
        for line in job.get("logs", []):
            for pattern in patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    return match.group(1)
        return None


wps_service = WpsService()
