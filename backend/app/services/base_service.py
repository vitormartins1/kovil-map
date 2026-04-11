import logging
from app.core.config import load_config

logger = logging.getLogger(__name__)


class BaseService:
    def __init__(self):
        self.logger = logger

    def _to_wsl_path(self, win_path):
        """Converte caminho Windows para WSL (ex: C:\\Users -> /mnt/c/Users)"""
        try:
            if not win_path:
                return ""
            # Se já não tem dois pontos, assume que é relativo ou já formatado
            if ":" not in win_path:
                return win_path.replace("\\", "/")

            drive, path = win_path.split(":", 1)
            drive = drive.lower()
            path = path.replace("\\", "/")
            return f"/mnt/{drive}{path}"
        except Exception as e:
            self.logger.error(f"Erro ao converter caminho para WSL: {e}")
            return win_path.replace("\\", "/")

    def _get_config(self):
        return load_config()

    def _should_use_wsl(self, binary_path):
        """Determina se deve usar WSL baseado na config e no binário"""
        conf = self._get_config()
        use_wsl = conf.get("use_wsl", False)

        # Se o binário parece ser Windows (.exe ou caminho com drive), força nativo
        is_windows_binary = binary_path.endswith(".exe") or ":" in binary_path

        return use_wsl and not is_windows_binary
