import subprocess
import re
import os
import json

# Configuração Hardcoded para teste
# HASHCAT_PATH = r"C:\hashcat-6.2.6\hashcat.exe"
HASHCAT_PATH = r"/OPT/HOMEBREW/BIN/HASHCAT";
USE_WSL = False

def get_devices_debug():
    print(f"--- DEBUG HASHCAT DEVICES ---")
    print(f"Path: {HASHCAT_PATH}")
    
    # Define o diretório de trabalho como a pasta do executável
    cwd = os.path.dirname(HASHCAT_PATH)
    print(f"Working Directory (CWD): {cwd}")
    
    cmd = [HASHCAT_PATH, "-I"]
    print(f"Executando comando: {cmd}")
    
    try:
        # Executa o comando definindo cwd
        result = subprocess.run(
            cmd, 
            cwd=cwd, # <--- O PULO DO GATO ESTÁ AQUI
            capture_output=True, 
            text=True, 
            encoding='utf-8', 
            errors='replace'
        )
        
        print(f"Return Code: {result.returncode}")
        
        if result.returncode != 0:
            print("ERRO NO COMANDO:")
            print(result.stderr)
            # Hashcat as vezes retorna info no stdout mesmo com erro, ou vice versa
            print(result.stdout) 
            return

        output = result.stdout
        print("\n--- SAÍDA BRUTA (STDOUT) ---")
        print(output)
        print("----------------------------\n")

        # Tenta fazer o parsing
        print("--- TENTANDO PARSEAR ---")
        devices = []
        current_device = {}
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if not line: continue
            
            if line.startswith("Backend Device ID:"):
                if current_device: 
                    devices.append(current_device)
                
                dev_id = line.split(":", 1)[1].strip()
                current_device = {"id": dev_id}
                
            elif line.startswith("Name:") and current_device:
                name = line.split(":", 1)[1].strip()
                current_device["name"] = name
                
            elif line.startswith("Type:") and current_device:
                dtype = line.split(":", 1)[1].strip()
                current_device["type"] = dtype
        
        if current_device:
            devices.append(current_device)
            
        print(f"\n--- RESULTADO FINAL ---")
        print(json.dumps(devices, indent=2))

    except Exception as e:
        print(f"EXCEÇÃO CRÍTICA: {e}")

if __name__ == "__main__":
    if not os.path.exists(HASHCAT_PATH):
        print(f"ERRO: Executável não encontrado em {HASHCAT_PATH}")
    else:
        get_devices_debug()