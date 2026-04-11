import subprocess
import threading
import uuid
import time
import logging
import psutil
import re
import asyncio
import os
from datetime import datetime
from collections import deque

logger = logging.getLogger(__name__)


class JobManager:
    TERMINAL_STATUSES = {"success", "failed", "canceled", "error"}

    def __init__(self):
        self.jobs = {}
        self.cracking_queue = deque()
        self.is_cracking_active = False
        self.queue_lock = threading.Lock()
        self.active_processes = {}
        self.event_callback = None  # Callback para WebSockets
        self.main_loop = None  # Referência ao loop principal do FastAPI
        self.max_terminal_jobs = self._normalize_retention_value(
            os.getenv("JOB_MANAGER_MAX_TERMINAL_JOBS"), 500
        )
        self.terminal_ttl_seconds = self._normalize_retention_value(
            os.getenv("JOB_MANAGER_TERMINAL_TTL_SECONDS"), 24 * 60 * 60
        )

    def _normalize_retention_value(self, raw_value, default):
        try:
            parsed = int(raw_value)
            if parsed > 0:
                return parsed
        except Exception:
            pass
        return default

    def _parse_job_end_ts(self, job):
        end_time = job.get("end_time")
        if not end_time:
            return None
        try:
            return datetime.fromisoformat(str(end_time)).timestamp()
        except Exception:
            return None

    def _prune_jobs(self):
        if not self.jobs:
            return

        now_ts = time.time()
        terminal_jobs = []

        for job_id, job in list(self.jobs.items()):
            if job.get("status") not in self.TERMINAL_STATUSES:
                continue

            end_ts = self._parse_job_end_ts(job)
            if end_ts is None:
                end_ts = now_ts

            if (now_ts - end_ts) > self.terminal_ttl_seconds:
                self.jobs.pop(job_id, None)
                continue

            terminal_jobs.append((job_id, end_ts))

        overflow = len(terminal_jobs) - self.max_terminal_jobs
        if overflow > 0:
            terminal_jobs.sort(key=lambda item: item[1])  # oldest first
            for job_id, _ in terminal_jobs[:overflow]:
                self.jobs.pop(job_id, None)

    def set_event_callback(self, callback):
        """Define a função que será chamada para enviar updates via WebSocket"""
        self.event_callback = callback

    def set_main_loop(self, loop):
        """Define o loop de eventos principal para agendamento thread-safe"""
        self.main_loop = loop

    async def _emit_event(self, event_type, data):
        """Dispara o evento para o callback (geralmente o WebSocket manager)"""
        if self.event_callback:
            try:
                # O callback pode ser async ou sync, vamos tentar lidar com ambos
                if asyncio.iscoroutinefunction(self.event_callback):
                    await self.event_callback(event_type, data)
                else:
                    self.event_callback(event_type, data)
            except Exception as e:
                logger.error(f"Erro ao emitir evento: {e}")

    def _fire_and_forget_emit(self, event_type, data):
        """Helper para emitir eventos de dentro de threads síncronas de forma segura"""
        if self.event_callback and self.main_loop:
            try:
                # Agenda a execução da corrotina no loop principal
                asyncio.run_coroutine_threadsafe(
                    self._emit_event(event_type, data), self.main_loop
                )
            except Exception as e:
                logger.error(f"Erro ao agendar evento WS thread-safe: {e}")

    def start_job(
        self,
        command,
        job_type="generic",
        cwd=None,
        on_complete=None,
        on_start=None,
        total_steps=1,
    ):
        job_id = str(uuid.uuid4())
        self._prune_jobs()
        self.jobs[job_id] = {
            "id": job_id,
            "type": job_type,
            "command": command,
            "cwd": cwd,
            "status": "pending",
            "start_time": None,
            "end_time": None,
            "logs": [],
            "progress_data": {  # Dados estruturados para o frontend
                "percentage": 0,
                "speed": "",
                "eta": "",
                "stage": "PENDING",
                "extra": "",  # Campo para candidatos ou info extra
                "current_step": 0,
                "total_steps": total_steps,
            },
            "return_code": None,
            "on_complete": on_complete,
            "on_start": on_start,
        }

        if job_type == "cracking" or job_type == "aircrack":
            with self.queue_lock:
                self.jobs[job_id]["status"] = "queued"
                self.cracking_queue.append(job_id)

                # Notifica fila
                self._fire_and_forget_emit("job_update", self.get_job(job_id))
                self._check_queue_unsafe()
        else:
            self.jobs[job_id]["status"] = "running"
            self.jobs[job_id]["start_time"] = datetime.now().isoformat()

            # Notifica inicio
            self._fire_and_forget_emit("job_update", self.get_job(job_id))

            thread = threading.Thread(target=self._run_process, args=(job_id,))
            thread.start()

        return job_id

    def _decode_hashcat_hex_candidates(self, text):
        if not text:
            return text

        def _clean_decoded(value):
            return "".join(ch if ch.isprintable() else "" for ch in value)

        def _repl(match):
            hex_str = match.group(1)
            if not hex_str or len(hex_str) % 2 != 0:
                return match.group(0)
            try:
                decoded = bytes.fromhex(hex_str).decode("utf-8", errors="replace")
            except Exception:
                return match.group(0)
            cleaned = _clean_decoded(decoded)
            return cleaned if cleaned else match.group(0)

        return re.sub(r"\$HEX\[([0-9a-fA-F]+)\]", _repl, text)

    def start_multi_job(
        self,
        worker,
        job_type="conversion_multi",
        on_complete=None,
        on_start=None,
        total_steps=1,
        meta=None,
    ):
        job_id = str(uuid.uuid4())
        self._prune_jobs()
        self.jobs[job_id] = {
            "id": job_id,
            "type": job_type,
            "command": "internal:multi",
            "cwd": None,
            "status": "running",
            "start_time": datetime.now().isoformat(),
            "end_time": None,
            "logs": [],
            "meta": meta or {},
            "progress_data": {
                "percentage": 0,
                "speed": "",
                "eta": "",
                "stage": "RUNNING",
                "extra": "",
                "current_step": 0,
                "total_steps": total_steps,
            },
            "return_code": None,
            "on_complete": on_complete,
            "on_start": on_start,
        }

        # Notifica inicio
        self._fire_and_forget_emit("job_update", self.get_job(job_id))

        thread = threading.Thread(target=self._run_multi_worker, args=(job_id, worker))
        thread.start()
        return job_id

    def _run_multi_worker(self, job_id, worker):
        job = self.jobs[job_id]
        on_complete = job.get("on_complete")
        on_start = job.get("on_start")

        if on_start:
            try:
                on_start(job)
            except Exception as e:
                logger.error(f"Callback Error on Start: {str(e)}")

        try:
            worker(job, self._fire_and_forget_emit)
            if job["status"] not in ["failed", "canceled", "error"]:
                job["status"] = "success"
            job["return_code"] = 0 if job["status"] == "success" else 1
        except Exception as e:
            job["status"] = "failed"
            job["logs"].append(f"Exception: {str(e)}")
            job["return_code"] = 1
        finally:
            job["end_time"] = datetime.now().isoformat()
            if on_complete:
                try:
                    on_complete(job)
                except Exception as e:
                    logger.error(f"Callback Error: {e}")
            self._prune_jobs()
            self._fire_and_forget_emit("job_complete", self.get_job(job_id))

    def _check_queue_unsafe(self):
        if self.is_cracking_active:
            return

        if self.cracking_queue:
            job_id = self.cracking_queue.popleft()
            self.is_cracking_active = True

            self.jobs[job_id]["status"] = "running"
            self.jobs[job_id]["start_time"] = datetime.now().isoformat()

            self._fire_and_forget_emit("job_update", self.get_job(job_id))

            thread = threading.Thread(target=self._run_process, args=(job_id, True))
            thread.start()

    def _run_process(self, job_id, is_cracking=False):
        job = self.jobs[job_id]
        command = job["command"]
        cwd = job["cwd"]
        on_complete = job.get("on_complete")
        on_start = job.get("on_start")

        if on_start:
            try:
                on_start(job)
            except Exception as e:
                logger.error(f"Callback Error on Start: {str(e)}")

        try:
            if not isinstance(command, (list, tuple)) or not command:
                raise ValueError(
                    f"Invalid command format for job {job_id}. Expected a non-empty argv list."
                )

            safe_command = [str(part) for part in command]
            logger.info(f"Job {job_id} ({job['type']}) started.")

            process = subprocess.Popen(
                safe_command,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
            )

            self.active_processes[job_id] = process
            MAX_LOG_LINES = 1000

            # Controle de Throttle para WebSockets
            last_emit_time = 0
            emit_interval = 0.5  # 500ms

            # Loop de leitura de logs
            for line in process.stdout:
                clean_line = line.strip()
                if clean_line:
                    job["logs"].append(clean_line)
                    if len(job["logs"]) > MAX_LOG_LINES:
                        del job["logs"][:100]

                    # --- PARSING EM TEMPO REAL ---
                    parsed_info = None
                    if "hashcat" in job["type"] or job["type"] == "cracking":
                        parsed_info = self._parse_hashcat_line(
                            clean_line, job["progress_data"]
                        )
                    elif "aircrack" in job["type"]:
                        parsed_info = self._parse_aircrack_line(
                            clean_line, job["progress_data"]
                        )

                    # Se houve atualização relevante de progresso, emite evento com throttle
                    if parsed_info:
                        old_stage = job["progress_data"].get("stage")
                        job["progress_data"].update(parsed_info)
                        new_stage = job["progress_data"].get("stage")

                        current_time = time.time()
                        # Emite imediatamente se o estágio mudou (prioridade) ou se passou o tempo do throttle
                        if (new_stage != old_stage) or (
                            current_time - last_emit_time >= emit_interval
                        ):
                            self._fire_and_forget_emit(
                                "job_progress",
                                {"job_id": job_id, "data": job["progress_data"].copy()},
                            )
                            last_emit_time = current_time

            process.wait()
            job["return_code"] = process.returncode
            job["end_time"] = datetime.now().isoformat()

            # Lógica de Status Final (Sucesso/Falha/Exhausted)
            final_status = "failed"

            if job["status"] == "canceled":
                final_status = "canceled"
            elif process.returncode == 0:
                final_status = "success"
            elif is_cracking:
                # Lógica específica de retorno para ferramentas de cracking
                is_exhausted = process.returncode == 1  # Hashcat exhausted

                # Verifica logs para confirmação extra
                if not is_exhausted:
                    for line in job["logs"][-50:]:
                        if "Status..........." in line and "Exhausted" in line:
                            is_exhausted = True
                            break
                        if "Passphrase not in dictionary" in line:
                            is_exhausted = True
                            break
                        # Novo: Detecta erro de máscara inválida
                        if "Invalid mask" in line:
                            job["progress_data"]["stage"] = "ERROR"
                            job["progress_data"]["extra"] = "Invalid Mask"
                            final_status = "failed"
                            break

                if is_exhausted:
                    final_status = "success"  # Tecnicamente rodou com sucesso, só não achou a senha
                    job["progress_data"]["stage"] = "EXHAUSTED"
                elif final_status != "failed":  # Se não foi marcado como failed acima
                    final_status = "failed"
            else:
                final_status = "failed"

            job["status"] = final_status

            # Callbacks (Executa sempre que termina, independente do status)
            if on_complete:
                try:
                    on_complete(job)
                except Exception as e:
                    logger.error(f"Callback Error: {e}")
                    # Não alteramos o status aqui para não mascarar o resultado original,
                    # mas logamos o erro do callback.

            # Emite evento final
            self._prune_jobs()
            self._fire_and_forget_emit("job_complete", self.get_job(job_id))

        except Exception as e:
            job["status"] = "error"
            job["end_time"] = datetime.now().isoformat()
            job["logs"].append(f"Exception: {str(e)}")
            self._prune_jobs()
            self._fire_and_forget_emit("job_complete", self.get_job(job_id))

        finally:
            if job_id in self.active_processes:
                del self.active_processes[job_id]
            if is_cracking:
                with self.queue_lock:
                    self.is_cracking_active = False
                    self._check_queue_unsafe()

    # --- PARSERS (Portados do JS para Python) ---

    def _parse_hashcat_line(self, line, current_data):
        """Retorna dict com updates se a linha for relevante, ou None"""
        updates = {}
        total_steps = current_data.get("total_steps", 1)
        is_multi_step = total_steps > 1

        # Status
        m_status = re.search(r"Status\.+:\s*(.+)", line, re.IGNORECASE)
        if m_status:
            status_val = m_status.group(1).strip().upper()
            # Ignora "EXHAUSTED" durante a execução para evitar piscar status em ataques com múltiplos arquivos
            # O status final será definido pelo return code
            if status_val != "EXHAUSTED":
                updates["stage"] = status_val
        elif "All hashes found" in line:
            updates["stage"] = "CRACKED"
        # elif "Exhausted" in line:  <-- REMOVIDO para evitar falso positivo em multi-file
        #    updates["stage"] = "EXHAUSTED"
        elif "Invalid mask" in line:
            updates["stage"] = "ERROR"
            updates["extra"] = "Invalid Mask"

        # Detecta mudança de dicionário
        dict_found = False
        filename = None

        # Caso 1: Dictionary cache hit: filename (mesma linha)
        if "Dictionary cache hit:" in line:
            parts = line.split("Dictionary cache hit:")
            if len(parts) > 1 and parts[1].strip():
                filename = os.path.basename(parts[1].strip())
                dict_found = True

        # Caso 2: * Filename..: path/to/file (linha separada)
        elif "* Filename..:" in line:
            parts = line.split("* Filename..:")
            if len(parts) > 1:
                filename = os.path.basename(parts[1].strip())
                dict_found = True

        # Caso 3: Guess.Base.......: File (path/to/file)
        elif "Guess.Base.......:" in line:
            match = re.search(r"File \((.+)\)", line)
            if match:
                filename = os.path.basename(match.group(1).strip())
                dict_found = True

        # Caso 4: Starting attack on '...'
        elif "Starting attack on" in line:
            match = re.search(r"Starting attack on '(.+?)'", line)
            if match:
                filename = os.path.basename(match.group(1))
                dict_found = True

        # Se detectou um novo dicionário, atualiza o passo e o status
        if dict_found and filename:
            current_step = current_data.get("current_step", 0)

            # Incrementa passo apenas se o nome do arquivo mudou (para evitar duplicatas em logs repetidos)
            last_file = current_data.get("last_file")
            if filename != last_file:
                current_step += 1
                updates["current_step"] = current_step
                updates["last_file"] = filename

            # Só mostra [X/Y] se for multi-step
            if is_multi_step:
                updates["extra"] = f"[{current_step}/{total_steps}] {filename}"
            else:
                updates["extra"] = f"Dict: {filename}"

            updates["stage"] = "RUNNING"

        # Progress
        m_prog = re.search(
            r"Progress\.+:\s*[\d\/]+\s*\((\d+\.\d+)%\)", line, re.IGNORECASE
        )
        if m_prog:
            local_percentage = float(m_prog.group(1))

            # Calcula progresso global
            current_step = current_data.get("current_step", 1)

            # Se current_step for 0 (ainda não detectou arquivo), assume 1
            step_idx = max(1, current_step) - 1

            # Cada arquivo representa (100 / total_steps)% do total
            step_weight = 100.0 / max(1, total_steps)
            global_percentage = (step_idx * step_weight) + (
                local_percentage * step_weight / 100.0
            )

            # Arredonda para inteiro
            updates["percentage"] = int(min(99, global_percentage))

            # Se tem progresso, com certeza está rodando
            if current_data.get("stage") == "AUTOTUNING":
                updates["stage"] = "RUNNING"

        # Speed
        m_speed = re.search(r"Speed\.#\d+\.+:\s*(.+)", line, re.IGNORECASE)
        if m_speed:
            updates["speed"] = m_speed.group(1).split("@")[0].strip()

        # ETA
        if "Time.Estimated" in line:
            # Só atualiza ETA se NÃO for multi-step (pastas)
            if not is_multi_step:
                parts = line.split("(")
                if len(parts) > 1:
                    updates["eta"] = parts[1].replace(")", "").strip()
                else:
                    m_eta = re.search(
                        r"Time\.Estimated\.+:\s*(.+)", line, re.IGNORECASE
                    )
                    if m_eta:
                        updates["eta"] = m_eta.group(1).strip()

        # Candidates (Adicionado)
        m_cand = re.search(r"Candidates\.#\d+\.+:\s*(.+)", line, re.IGNORECASE)
        if m_cand:
            candidates_raw = m_cand.group(1).strip()
            candidates_decoded = self._decode_hashcat_hex_candidates(candidates_raw)
            candidates_str = f"[{candidates_decoded}]"

            if is_multi_step:
                # Em multi-step, concatena candidatos com a info do passo atual
                # Recupera info do passo atual (pode estar em updates ou current_data)
                c_step = updates.get(
                    "current_step", current_data.get("current_step", 0)
                )
                l_file = updates.get("last_file", current_data.get("last_file", ""))

                # Formato: [1/50] filename [cand1 -> cand2]
                prefix = f"[{c_step}/{total_steps}] {l_file}"
                updates["extra"] = f"{prefix} {candidates_str}"
            else:
                # Em single-step, mostra apenas os candidatos (comportamento original)
                updates["extra"] = candidates_str

        # Autotune / Init
        if "Starting autotune" in line:
            updates["stage"] = "AUTOTUNING"
        elif "Initializing device kernels" in line:
            updates["stage"] = "INIT KERNELS"

        return updates if updates else None

    def _parse_aircrack_line(self, line, current_data):
        updates = {}

        # [00:00:03] 420 keys tested (145.34 k/s)
        m_status = re.search(
            r"\[(\d+:\d+:\d+)\]\s+(\d+)\s+keys tested\s+\(([\d\.]+)\s+k\/s\)", line
        )
        if m_status:
            updates["stage"] = "RUNNING"
            updates["speed"] = f"{m_status.group(3)} k/s"
            updates["extra"] = f"{m_status.group(2)} keys"
            updates["percentage"] = (
                100  # Aircrack não tem progresso definido, usamos 100 (indeterminado no front)
            )
            return updates

        if "KEY FOUND!" in line:
            updates["stage"] = "CRACKED"
            updates["percentage"] = 100
            return updates

        if "Passphrase not in dictionary" in line:
            updates["stage"] = "EXHAUSTED"
            return updates

        return None

    def cancel_job(self, job_id):
        job = self.jobs.get(job_id)
        if not job:
            return False, "Job not found"

        with self.queue_lock:
            if job_id in self.cracking_queue:
                self.cracking_queue.remove(job_id)
                job["status"] = "canceled"
                job["end_time"] = datetime.now().isoformat()
                self._prune_jobs()
                self._fire_and_forget_emit("job_complete", self.get_job(job_id))
                return True, "Job removed from queue"

        if job_id in self.active_processes:
            process = self.active_processes[job_id]
            try:
                job["status"] = "canceled"
                parent = psutil.Process(process.pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
                # O evento job_complete será emitido no bloco finally do _run_process
                return True, "Process killed"
            except Exception as e:
                return False, f"Error killing process: {str(e)}"

        return False, "Job state unknown"

    def kill_all(self):
        for job_id, process in list(self.active_processes.items()):
            try:
                parent = psutil.Process(process.pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
            except Exception:
                pass
        self.active_processes.clear()

    def get_job(self, job_id):
        self._prune_jobs()
        job = self.jobs.get(job_id)
        if not job:
            return None

        # Retorna cópia limpa
        job_clean = job.copy()
        if "on_complete" in job_clean:
            del job_clean["on_complete"]
        if "on_start" in job_clean:
            del job_clean["on_start"]

        # Filtra logs para não enviar MBs de texto via WS
        # O frontend pode pedir logs completos via API REST se precisar
        job_clean["logs"] = job_clean["logs"][-20:]

        return job_clean

    def list_jobs(self):
        self._prune_jobs()
        jobs = []
        for jid in list(self.jobs.keys()):
            job = self.get_job(jid)
            if job is not None:
                jobs.append(job)
        return jobs


job_manager = JobManager()
