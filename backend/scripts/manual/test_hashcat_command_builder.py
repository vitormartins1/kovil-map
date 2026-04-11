import sys
from pathlib import Path

# Adiciona o diretório pai ao path para importar os módulos
sys.path.append(str(Path(__file__).resolve().parents[2]))

from app.services.hashcat_service import HashcatService


# Mock do config para não depender do arquivo real
class MockHashcatService(HashcatService):
    def _get_config(self):
        return {
            "hashcat_path": "hashcat",
            "wordlist_path": "rockyou.txt",
            "attack_mode": "straight",
            "workload_profile": "3",
            "use_wsl": False,
        }

    def _should_use_wsl(self, bin_path):
        return False

    def _to_wsl_path(self, path):
        return path

    # Sobrescreve run_attack para apenas retornar o comando, sem executar
    def run_attack_dry(
        self,
        hash_filename,
        attack_mode=None,
        workload_profile=None,
        rule_file=None,
        custom_mask=None,
        is_optimized=False,
        is_slow=False,
        device_id=None,
        enable_potfile=False,
    ):

        # Copia da lógica de construção do comando do run_attack original
        # (Simplificada para focar na validação dos argumentos)

        cmd_args = ["hashcat"]
        cmd_args.extend(["-m", "22000"])
        cmd_args.extend(["-w", str(workload_profile or "3")])

        if is_optimized:
            cmd_args.append("-O")
        if is_slow:
            cmd_args.append("-S")

        # LÓGICA DE DEVICE A SER VALIDADA
        if device_id and device_id != "all":
            cmd_args.extend(["-d", str(device_id)])

        cmd_args.append(hash_filename)  # Hash file

        if attack_mode == "straight" or not attack_mode:
            cmd_args.extend(["-a", "0"])
            cmd_args.append("wordlist.txt")

        if not enable_potfile:
            cmd_args.append("--potfile-disable")

        return cmd_args


service = MockHashcatService()

print("--- TESTE DE CONSTRUÇÃO DE COMANDO HASHCAT ---\n")

# Cenário 1: Auto / All (device_id = "all")
cmd1 = service.run_attack_dry("target.22000", device_id="all")
print(f"1. Auto/All: {' '.join(cmd1)}")
if "-d" not in cmd1:
    print("   [OK] Flag -d ausente (Hashcat decidirá)")
else:
    print("   [FAIL] Flag -d presente incorretamente")

# Cenário 2: Device Específico (device_id = "1")
cmd2 = service.run_attack_dry("target.22000", device_id="1")
print(f"\n2. Device 1: {' '.join(cmd2)}")
if "-d" in cmd2 and cmd2[cmd2.index("-d") + 1] == "1":
    print("   [OK] Flag -d 1 presente")
else:
    print("   [FAIL] Flag -d 1 ausente ou incorreta")

# Cenário 3: Device Específico Inteiro (device_id = 2)
cmd3 = service.run_attack_dry("target.22000", device_id=2)
print(f"\n3. Device 2 (Int): {' '.join(cmd3)}")
if "-d" in cmd3 and cmd3[cmd3.index("-d") + 1] == "2":
    print("   [OK] Flag -d 2 presente")
else:
    print("   [FAIL] Flag -d 2 ausente ou incorreta")

# Cenário 4: Sem device_id (None)
cmd4 = service.run_attack_dry("target.22000", device_id=None)
print(f"\n4. Sem Device (None): {' '.join(cmd4)}")
if "-d" not in cmd4:
    print("   [OK] Flag -d ausente")
else:
    print("   [FAIL] Flag -d presente incorretamente")
