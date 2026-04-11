from unittest.mock import MagicMock, patch

import pytest

from app.core.job_manager import JobManager


class TestJobManagerCancellation:
    """
    Testes unitários focados na lógica de cancelamento de tarefas do JobManager.
    Cobre cancelamento de jobs em execução, inexistentes e já finalizados.
    """

    @pytest.fixture
    def manager(self):
        """Fixture para instância limpa do JobManager."""
        jm = JobManager()
        # Reset manual de estado se necessário (assumindo estrutura interna comum)
        if hasattr(jm, "jobs"):
            jm.jobs = {}
        if hasattr(jm, "queue"):
            # Esvazia fila se existir
            while not jm.queue.empty():
                jm.queue.get()
        # Reset active processes if exists
        if hasattr(jm, "active_processes"):
            jm.active_processes = {}
        return jm

    @patch("app.core.job_manager.psutil")
    @patch("subprocess.Popen")
    def test_cancel_running_job(self, mock_popen, mock_psutil, manager):
        """
        Valida o cancelamento de um job em estado 'running'.
        Deve chamar terminate() no processo e atualizar status para 'cancelled'.
        """
        # Mock do processo subprocess
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Processo ainda rodando
        # Mock do processo psutil para verificar kill
        mock_psutil_proc = MagicMock()
        mock_psutil.Process.return_value = mock_psutil_proc
        mock_psutil_proc.children.return_value = []
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        # Injeta um job manualmente para evitar race conditions com threads
        job_id = "manual_job_1"
        manager.jobs[job_id] = {
            "id": job_id,
            "status": "running",
            "process": None,
            "command": ["sleep", "60"],
        }

        # Garante que active_processes existe e popula
        if not hasattr(manager, "active_processes"):
            manager.active_processes = {}
        manager.active_processes[job_id] = mock_process

        # Executa cancelamento
        success, msg = manager.cancel_job(job_id)

        # Asserções
        assert success is True
        # Verifica se tentou encerrar o processo
        assert (
            mock_process.terminate.called
            or mock_process.kill.called
            or mock_psutil_proc.kill.called
        )
        # Verifica status final
        assert manager.jobs[job_id]["status"] == "canceled"

    def test_cancel_non_existent_job(self, manager):
        """Valida tentativa de cancelar job ID desconhecido."""
        success, msg = manager.cancel_job("id_inexistente_123")
        assert success is False

    def test_cancel_completed_job(self, manager):
        """Valida tentativa de cancelar job já finalizado."""
        # Cria entrada manual de job finalizado
        job_id = "job_completed_1"
        manager.jobs[job_id] = {
            "status": "completed",
            "process": None,
            "cmd": ["echo", "done"],
        }

        success, msg = manager.cancel_job(job_id)

        # Não deve crashar e o status deve permanecer inalterado
        assert success is False
        assert manager.jobs[job_id]["status"] == "completed"
