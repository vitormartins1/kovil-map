import os
import re
from .base_service import BaseService
from app.core.config import (
    PMK_DIR,
    HANDSHAKES_DIR,
    BRUCE_HANDSHAKES_DIR,
    BRUCE_PCAP_DIR,
    M5EVIL_HANDSHAKES_DIR,
)
from app.utils.pcap import build_pcap_search_roots, resolve_pcap_reference
from app.utils.handshake_artifacts import get_capture_artifact_path
from app.core.job_manager import job_manager
from app.services.history_service import history_service


class PmkService(BaseService):
    """Manages airolib-ng PMK precomputation databases."""

    def _pcap_search_roots(self):
        return build_pcap_search_roots(
            HANDSHAKES_DIR,
            BRUCE_HANDSHAKES_DIR,
            BRUCE_PCAP_DIR,
            M5EVIL_HANDSHAKES_DIR,
        )

    def _db_path(self, db_name):
        safe = re.sub(r"[^\w\-.]", "_", db_name)
        if not safe.endswith(".db"):
            safe += ".db"
        return os.path.join(PMK_DIR, safe)

    # ------------------------------------------------------------------
    # List / Status
    # ------------------------------------------------------------------
    def list_databases(self):
        if not os.path.isdir(PMK_DIR):
            return []
        dbs = []
        for f in sorted(os.listdir(PMK_DIR)):
            if f.endswith(".db"):
                full = os.path.join(PMK_DIR, f)
                dbs.append(
                    {
                        "name": f,
                        "size_bytes": os.path.getsize(full),
                        "modified": os.path.getmtime(full),
                    }
                )
        return dbs

    def get_database_stats(self, db_name):
        db_file = self._db_path(db_name)
        if not os.path.exists(db_file):
            return {"error": f"Database not found: {db_name}"}

        conf = self._get_config()
        airolib_bin = conf.get("airolib_path", "airolib-ng")
        use_wsl = self._should_use_wsl(airolib_bin)

        cmd = []
        if use_wsl:
            cmd.append("wsl")
            cmd.extend([airolib_bin, self._to_wsl_path(db_file), "--stats"])
        else:
            cmd.extend([airolib_bin, db_file, "--stats"])

        import subprocess

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )
            output = result.stdout + result.stderr
            return {
                "name": db_name,
                "size_bytes": os.path.getsize(db_file),
                "stats_raw": output.strip(),
            }
        except FileNotFoundError:
            return {"error": "airolib-ng not found"}
        except subprocess.TimeoutExpired:
            return {"error": "Stats command timed out"}
        except Exception as e:
            return {"error": str(e)}

    # ------------------------------------------------------------------
    # Build database (long-running job)
    # ------------------------------------------------------------------
    def build_database(self, essid, wordlist_path, db_name=None):
        if not essid or not essid.strip():
            return {"status": "error", "message": "ESSID is required"}
        if not wordlist_path or not os.path.exists(wordlist_path):
            return {
                "status": "error",
                "message": f"Wordlist not found: {wordlist_path}",
            }

        essid = essid.strip()
        if not db_name:
            safe_essid = re.sub(r"[^\w\-]", "_", essid)
            db_name = f"pmk_{safe_essid}"

        db_file = self._db_path(db_name)
        conf = self._get_config()
        airolib_bin = conf.get("airolib_path", "airolib-ng")
        use_wsl = self._should_use_wsl(airolib_bin)

        # Write temporary ESSID file
        essid_file = os.path.join(PMK_DIR, f".essid_{os.getpid()}.tmp")
        try:
            with open(essid_file, "w", encoding="utf-8") as f:
                f.write(essid + "\n")
        except Exception as e:
            return {"status": "error", "message": f"Failed to write ESSID file: {e}"}

        # Build the three airolib-ng commands chained with &&
        if use_wsl:
            wsl_db = self._to_wsl_path(db_file)
            wsl_essid = self._to_wsl_path(essid_file)
            wsl_wordlist = self._to_wsl_path(wordlist_path)
            shell_cmd = (
                f"wsl {airolib_bin} {wsl_db} --import essid {wsl_essid} && "
                f"wsl {airolib_bin} {wsl_db} --import passwd {wsl_wordlist} && "
                f"wsl {airolib_bin} {wsl_db} --batch"
            )
        else:
            shell_cmd = (
                f"{airolib_bin} {db_file} --import essid {essid_file} && "
                f"{airolib_bin} {db_file} --import passwd {wordlist_path} && "
                f"{airolib_bin} {db_file} --batch"
            )

        # We use shell=True via a wrapper list so job_manager can spawn it
        cmd_args = ["sh", "-c", shell_cmd]

        self.logger.info(f"Building PMK database: {db_file} for ESSID={essid}")

        entry_id = history_service.add_entry(
            db_name,
            "airolib-ng",
            cmd_args,
            {"essid": essid, "wordlist": wordlist_path},
        )

        def on_complete(job):
            # Clean up temp file
            try:
                if os.path.exists(essid_file):
                    os.remove(essid_file)
            except Exception:
                pass

            success = job.get("return_code") == 0 and os.path.exists(db_file)
            if success:
                job["progress_data"]["stage"] = "COMPLETE"
                history_service.update_entry(
                    db_name, entry_id, "COMPLETE", "PMK database built"
                )
                self.logger.info(f"PMK database built: {db_file}")
            else:
                job["progress_data"]["stage"] = "FAILED"
                history_service.update_entry(
                    db_name, entry_id, "FAILED", "PMK build failed"
                )
                self.logger.error(f"PMK database build failed for {db_file}")

        job_id = job_manager.start_job(
            cmd_args, job_type="pmk", cwd=PMK_DIR, on_complete=on_complete
        )

        return {
            "status": "started",
            "job_id": job_id,
            "db_name": os.path.basename(db_file),
        }

    # ------------------------------------------------------------------
    # Attack using PMK database
    # ------------------------------------------------------------------
    def attack_with_pmk(
        self,
        pcap_filename,
        bssid,
        db_name,
        capture_id=None,
        raw_item_id=None,
    ):
        db_file = self._db_path(db_name)
        if not os.path.exists(db_file):
            return {"status": "error", "message": f"PMK database not found: {db_name}"}

        conf = self._get_config()
        aircrack_bin = conf.get("aircrack_path", "aircrack-ng")
        use_wsl = self._should_use_wsl(aircrack_bin)

        resolved = resolve_pcap_reference(
            pcap_filename,
            capture_id=capture_id,
            raw_item_id=raw_item_id,
            search_roots=self._pcap_search_roots(),
        )
        pcap_path = resolved.get("path") if resolved else None
        display_filename = resolved.get("filename") if resolved else pcap_filename
        base_name = (resolved or {}).get("basename") or str(pcap_filename).rsplit(
            ".", 1
        )[0]

        if not pcap_path or not os.path.exists(pcap_path):
            return {
                "status": "error",
                "message": f"PCAP file not found: {pcap_filename}",
            }

        artifact_dir = (
            get_capture_artifact_path(capture_id)
            if capture_id and not raw_item_id
            else os.path.dirname(pcap_path)
        )
        key_file = os.path.join(
            artifact_dir,
            "capture.key" if capture_id and not raw_item_id else f"{base_name}.key",
        )

        cmd_args = []
        cwd = None
        if use_wsl:
            cmd_args.append("wsl")
            cmd_args.append(aircrack_bin)
            wsl_pcap = self._to_wsl_path(pcap_path)
            wsl_db = self._to_wsl_path(db_file)
            wsl_key = self._to_wsl_path(key_file)
            cmd_args.extend(["-r", wsl_db, "-b", bssid, wsl_pcap, "-l", wsl_key])
        else:
            cmd_args.append(aircrack_bin)
            if os.path.isabs(aircrack_bin):
                cwd = os.path.dirname(aircrack_bin)
            cmd_args.extend(["-r", db_file, "-b", bssid, pcap_path, "-l", key_file])

        self.logger.info(f"PMK attack: {cmd_args} (CWD: {cwd})")

        entry_id = history_service.add_entry(
            display_filename,
            "aircrack-ng (PMK)",
            cmd_args,
            {"bssid": bssid, "pmk_db": db_name},
            capture_id=capture_id if not raw_item_id else None,
        )

        def on_complete(job):
            found = self._check_key_found(job, key_file, base_name, capture_id)
            if found:
                job["progress_data"]["stage"] = "CRACKED"
                history_service.update_entry(
                    display_filename,
                    entry_id,
                    "CRACKED",
                    "Password found (PMK)",
                    capture_id=capture_id if not raw_item_id else None,
                )
                from app.services.data_loader import reload_data

                reload_data()
            else:
                job["progress_data"]["stage"] = "EXHAUSTED"
                history_service.update_entry(
                    display_filename,
                    entry_id,
                    "EXHAUSTED",
                    "Password not found (PMK)",
                    capture_id=capture_id if not raw_item_id else None,
                )

        job_id = job_manager.start_job(
            cmd_args, job_type="aircrack", cwd=cwd, on_complete=on_complete
        )

        return {"status": "started", "job_id": job_id}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _check_key_found(self, job, key_file, base_name, capture_id=None):
        import re as _re

        try:
            if os.path.exists(key_file):
                with open(key_file, "r") as f:
                    password = f.read().strip()
                if password:
                    cracked_path = os.path.join(
                        HANDSHAKES_DIR, f"{base_name}.pcap.cracked"
                    )
                    os.makedirs(os.path.dirname(cracked_path), exist_ok=True)
                    with open(cracked_path, "w", encoding="utf-8") as f:
                        f.write(password)
                    try:
                        os.remove(key_file)
                    except Exception:
                        pass
                    self.logger.info(
                        f"PMK attack: password '{password}' saved to {cracked_path}"
                    )
                    return True

            # Fallback: parse logs
            for line in job.get("logs", []):
                if "KEY FOUND!" in line:
                    match = _re.search(r"KEY FOUND! \[ (.*) \]", line)
                    if match:
                        password = match.group(1)
                        cracked_path = os.path.join(
                            HANDSHAKES_DIR, f"{base_name}.pcap.cracked"
                        )
                        os.makedirs(os.path.dirname(cracked_path), exist_ok=True)
                        with open(cracked_path, "w", encoding="utf-8") as f:
                            f.write(password)
                        self.logger.info(
                            f"PMK attack (log parse): password '{password}' saved"
                        )
                        return True
            return False
        except Exception as e:
            self.logger.error(f"Error processing PMK attack result: {e}")
            return False

    def delete_database(self, db_name):
        db_file = self._db_path(db_name)
        if not os.path.exists(db_file):
            return {"error": f"Database not found: {db_name}"}
        try:
            os.remove(db_file)
            self.logger.info(f"Deleted PMK database: {db_file}")
            return {"deleted": db_name}
        except Exception as e:
            return {"error": str(e)}


pmk_service = PmkService()
