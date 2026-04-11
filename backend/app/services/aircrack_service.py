import os
import re
from .base_service import BaseService
from app.core.config import (
    HANDSHAKES_DIR,
    BRUCE_HANDSHAKES_DIR,
    BRUCE_PCAP_DIR,
    M5EVIL_HANDSHAKES_DIR,
)
from app.utils.pcap import (
    build_pcap_search_roots,
    resolve_pcap_reference,
)
from app.utils.handshake_artifacts import get_capture_artifact_path
from app.core.job_manager import job_manager
from app.services.history_service import history_service


class AircrackService(BaseService):
    def _pcap_search_roots(self):
        return build_pcap_search_roots(
            HANDSHAKES_DIR,
            BRUCE_HANDSHAKES_DIR,
            BRUCE_PCAP_DIR,
            M5EVIL_HANDSHAKES_DIR,
        )

    def run_attack(
        self,
        pcap_filename,
        bssid,
        wordlist_path=None,
        capture_id=None,
        raw_item_id=None,
    ):
        try:
            conf = self._get_config()
            aircrack_bin = conf.get("aircrack_path", "aircrack-ng")
            target_wordlist = wordlist_path

            if not target_wordlist:
                return {"status": "error", "message": "No wordlist selected"}

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

            use_wsl = self._should_use_wsl(aircrack_bin)
            capture_cracked_path = (
                get_capture_artifact_path(
                    capture_id,
                    "cracked",
                    handshakes_dir=HANDSHAKES_DIR,
                    ensure_parent=True,
                )
                if capture_id and not raw_item_id
                else os.path.join(HANDSHAKES_DIR, f"{base_name}.pcap.cracked")
            )
            artifact_dir = (
                os.path.dirname(capture_cracked_path)
                if capture_cracked_path
                else HANDSHAKES_DIR
            )
            key_file = os.path.join(
                artifact_dir,
                "capture.key" if capture_id and not raw_item_id else f"{base_name}.key",
            )

            cwd = None
            cmd_args = []

            if use_wsl:
                cmd_args.append("wsl")
                cmd_args.append(aircrack_bin)

                wsl_pcap = self._to_wsl_path(pcap_path)
                wsl_wordlist = self._to_wsl_path(target_wordlist)
                wsl_key = self._to_wsl_path(key_file)

                cmd_args.extend(
                    ["-w", wsl_wordlist, "-b", bssid, wsl_pcap, "-l", wsl_key]
                )
            else:
                cmd_args.append(aircrack_bin)
                if os.path.isabs(aircrack_bin):
                    cwd = os.path.dirname(aircrack_bin)

                cmd_args.extend(
                    ["-w", target_wordlist, "-b", bssid, pcap_path, "-l", key_file]
                )

            self.logger.info(f"Iniciando Aircrack-ng: {cmd_args} (CWD: {cwd})")

            # Register history with filtered params
            entry_id = history_service.add_entry(
                display_filename,
                "aircrack-ng",
                cmd_args,
                {"bssid": bssid, "wordlist": target_wordlist},
                capture_id=capture_id if not raw_item_id else None,
            )

            def on_complete(job):
                success = self.process_success(
                    job,
                    key_file,
                    base_name,
                    cracked_output_path=capture_cracked_path,
                )
                if success:
                    job["progress_data"]["stage"] = "CRACKED"
                    history_service.update_entry(
                        display_filename,
                        entry_id,
                        "CRACKED",
                        "Password found",
                        capture_id=capture_id if not raw_item_id else None,
                    )
                    # Invalida cache para atualizar status no mapa
                    from app.services.data_loader import reload_data

                    reload_data()
                else:
                    job["progress_data"]["stage"] = "EXHAUSTED"
                    history_service.update_entry(
                        display_filename,
                        entry_id,
                        "EXHAUSTED",
                        "Password not found",
                        capture_id=capture_id if not raw_item_id else None,
                    )

            job_id = job_manager.start_job(
                cmd_args, job_type="aircrack", cwd=cwd, on_complete=on_complete
            )

            return {"status": "started", "job_id": job_id}

        except Exception as e:
            self.logger.error(f"Erro ao iniciar Aircrack-ng: {e}")
            return {"status": "error", "message": str(e)}

    def process_success(self, job, key_file, base_name, cracked_output_path=None):
        try:
            self.logger.info(
                f"Processando resultado do Aircrack para job {job['id']}..."
            )
            found = False

            if os.path.exists(key_file):
                with open(key_file, "r") as f:
                    password = f.read().strip()

                if password:
                    pcap_cracked_path = cracked_output_path or os.path.join(
                        HANDSHAKES_DIR, f"{base_name}.pcap.cracked"
                    )
                    os.makedirs(os.path.dirname(pcap_cracked_path), exist_ok=True)
                    with open(pcap_cracked_path, "w", encoding="utf-8") as f:
                        f.write(password)

                    try:
                        os.remove(key_file)
                    except Exception:
                        pass

                    self.logger.info(
                        f"Aircrack: Senha '{password}' salva em {pcap_cracked_path}"
                    )
                    found = True
                else:
                    self.logger.warning("Aircrack: Arquivo de chave vazio.")
            else:
                self.logger.info(
                    f"Arquivo de chave {key_file} não encontrado. Tentando parsear logs..."
                )
                for line in job["logs"]:
                    if "KEY FOUND!" in line:
                        match = re.search(r"KEY FOUND! \[ (.*) \]", line)
                        if match:
                            password = match.group(1)
                            pcap_cracked_path = cracked_output_path or os.path.join(
                                HANDSHAKES_DIR, f"{base_name}.pcap.cracked"
                            )
                            os.makedirs(
                                os.path.dirname(pcap_cracked_path), exist_ok=True
                            )
                            with open(pcap_cracked_path, "w", encoding="utf-8") as f:
                                f.write(password)
                            self.logger.info(
                                f"Aircrack (Log Parse): Senha '{password}' salva em {pcap_cracked_path}"
                            )
                            found = True
                            break

                if not found:
                    self.logger.info(
                        "Aircrack finalizou mas nenhuma senha foi encontrada (ou falha no parse)."
                    )

            return found

        except Exception as e:
            self.logger.error(f"Erro ao processar resultado do Aircrack: {e}")
            return False
