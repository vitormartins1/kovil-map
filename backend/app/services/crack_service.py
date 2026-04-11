import logging
from app.services.hashcat_service import HashcatService
from app.services.aircrack_service import AircrackService
from app.core.config import load_config

logger = logging.getLogger(__name__)


class CrackService:
    def __init__(self):
        self.hashcat = HashcatService()
        self.aircrack = AircrackService()

    def _format_size(self, size_bytes):
        if size_bytes == 0:
            return "0B"
        size_name = ("B", "KB", "MB", "GB", "TB")
        import math

        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return "%s %s" % (s, size_name[i])

    def get_custom_wordlists(self):
        import glob
        import os

        conf = load_config()
        custom_path = conf.get("custom_wordlists_path", "")

        if not custom_path or not os.path.exists(custom_path):
            return []

        wordlists = []
        try:
            # 1. Listar arquivos de texto
            extensions = ["*.txt", "*.dic", "*.lst"]
            for ext in extensions:
                files = glob.glob(os.path.join(custom_path, ext))
                for f in files:
                    size_str = ""
                    try:
                        size = os.path.getsize(f)
                        size_str = self._format_size(size)
                    except Exception:
                        pass

                    wordlists.append(
                        {
                            "name": os.path.basename(f),
                            "path": f,
                            "type": "file",
                            "size": size_str,
                        }
                    )

            # 2. Listar subdiretórios (que contêm wordlists)
            # Hashcat aceita diretórios como entrada e processa todos os arquivos dentro
            with os.scandir(custom_path) as entries:
                for entry in entries:
                    if entry.is_dir():
                        # Tenta contar arquivos dentro para dar uma ideia de tamanho
                        count = 0
                        try:
                            count = len(
                                [
                                    name
                                    for name in os.listdir(entry.path)
                                    if os.path.isfile(os.path.join(entry.path, name))
                                ]
                            )
                        except Exception:
                            pass

                        wordlists.append(
                            {
                                "name": f"[DIR] {entry.name}",
                                "path": entry.path,
                                "type": "directory",
                                "size": f"{count} files",
                            }
                        )

            return sorted(wordlists, key=lambda x: x["name"])
        except Exception as e:
            logger.error(f"Erro ao listar wordlists customizadas: {e}")
            return []

    def get_hashcat_rules(self):
        return self.hashcat.get_available_rules()

    def get_hashcat_masks(self):
        return self.hashcat.get_available_masks()

    def get_hashcat_devices(self):
        return self.hashcat.get_devices()

    def convert_pcap(self, pcap_filename=None, capture_id=None, raw_item_id=None):
        return self.hashcat.convert_pcap(
            pcap_filename,
            capture_id=capture_id,
            raw_item_id=raw_item_id,
        )

    def convert_pcap_multi(self, pcap_filenames=None, capture_ids=None):
        return self.hashcat.convert_multi_pcap(
            pcap_filenames or [], capture_ids=capture_ids or []
        )

    def convert_pcap_now(
        self, pcap_filename, output_filename=None, capture_id=None, raw_item_id=None
    ):
        return self.hashcat.convert_pcap_now(
            pcap_filename,
            output_filename=output_filename,
            capture_id=capture_id,
            raw_item_id=raw_item_id,
        )

    def run_hashcat(
        self,
        hash_filename,
        attack_mode=None,
        workload_profile=None,
        wordlist=None,
        rule_file=None,
        custom_mask=None,
        is_optimized=False,
        is_slow=False,
        device_id=None,
        enable_potfile=False,
        wordlist_2=None,
        enable_increment=False,
        increment_min=None,
        increment_max=None,
        mask_file=None,
        association_hint=None,
        association_hints=None,
        skip_quality_gate=False,
        capture_id=None,
        combined_build_id=None,
        mac=None,
    ):
        return self.hashcat.run_attack(
            hash_filename,
            attack_mode,
            workload_profile,
            wordlist,
            rule_file,
            custom_mask,
            is_optimized,
            is_slow,
            device_id,
            enable_potfile,
            wordlist_2,
            enable_increment,
            increment_min,
            increment_max,
            mask_file,
            association_hint,
            association_hints,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
            mac=mac,
        )

    def preview_hashcat_association(
        self,
        hash_filename,
        mode="association",
        association_hint=None,
        association_hints=None,
        capture_id=None,
        combined_build_id=None,
        mac=None,
    ):
        return self.hashcat.preview_association_candidates(
            hash_filename,
            mode=mode,
            association_hint=association_hint,
            association_hints=association_hints,
            capture_id=capture_id,
            combined_build_id=combined_build_id,
            mac=mac,
        )

    def build_combined_candidate(self, mac, capture_ids=None):
        return self.hashcat.build_combined_candidate(mac, capture_ids=capture_ids)

    def run_aircrack_attack(
        self,
        pcap_filename=None,
        bssid=None,
        wordlist_path=None,
        capture_id=None,
        raw_item_id=None,
    ):
        return self.aircrack.run_attack(
            pcap_filename,
            bssid,
            wordlist_path,
            capture_id=capture_id,
            raw_item_id=raw_item_id,
        )


crack_service = CrackService()
