import subprocess
import os
import sys

# CONFIGURAÇÃO
# Ajuste o caminho para o seu executável do Hashcat se não estiver no PATH
HASHCAT_BIN = r"C:\hashcat-6.2.6\hashcat.exe" 
# Use um arquivo de exemplo ou crie um dummy
HASH_FILE = "test_hash.22000" 

def create_dummy_hash_file():
    if not os.path.exists(HASH_FILE):
        with open(HASH_FILE, "w") as f:
            # Exemplo de hash WPA2 (PMKID) dummy
            f.write("WPA*01*49455206090949303932350965768322*020304050607*08090a0b0c0d*6d7973736964***")
        print(f"[+] Created dummy hash file: {HASH_FILE}")

def run_test(mask, inc_min, inc_max):
    print(f"\n--- TESTING: Mask='{mask}', Min={inc_min}, Max={inc_max} ---")
    
    # Caminho absoluto para o arquivo de hash (pois mudaremos o CWD)
    abs_hash_file = os.path.abspath(HASH_FILE)
    
    cmd = [
        HASHCAT_BIN,
        "-m", "22000",       # Mode WPA2
        "-a", "3",           # Brute-force
        abs_hash_file,
        mask,
        "--increment",
        "--increment-min", str(inc_min),
        "--increment-max", str(inc_max),
        "--potfile-disable",
        "--quiet"            # Menos output
    ]
    
    print(f"Command: {' '.join(cmd)}")
    
    # Diretório do executável do Hashcat
    hashcat_dir = os.path.dirname(HASHCAT_BIN)
    
    try:
        # Executa e captura stdout e stderr
        # IMPORTANTE: cwd=hashcat_dir para ele achar a pasta OpenCL
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            encoding='utf-8', 
            errors='replace',
            cwd=hashcat_dir
        )
        
        print(f"Return Code: {result.returncode}")
        
        if result.stdout:
            print("STDOUT (first 500 chars):")
            print(result.stdout[:500])
            
        if result.stderr:
            print("STDERR:")
            print(result.stderr)
            
        # Análise básica de erro
        if result.returncode != 0:
            if "mask length" in result.stderr.lower() or "mask length" in result.stdout.lower():
                print(">> DETECTED: Mask length error!")
            elif "increment-max" in result.stderr.lower():
                print(">> DETECTED: Increment max error!")
            else:
                print(">> ERROR: Unknown error.")
        else:
            print(">> SUCCESS: Hashcat started/ran successfully.")
            
    except FileNotFoundError:
        print(f">> ERROR: Hashcat binary not found at {HASHCAT_BIN}")
    except Exception as e:
        print(f">> EXCEPTION: {e}")

if __name__ == "__main__":
    create_dummy_hash_file()
    
    if not os.path.exists(HASHCAT_BIN):
        print(f"WARNING: Hashcat binary not found at {HASHCAT_BIN}. Please edit the script.")
        # Tenta achar no path
        import shutil
        if shutil.which("hashcat"):
            HASHCAT_BIN = "hashcat"
            print("Found 'hashcat' in PATH, using it.")
        else:
            sys.exit(1)

    # CENÁRIO 1: Máscara MENOR que Increment Max (O que estava falhando)
    # Mask: ?a?a?a?a?a (5 chars)
    # Min: 1
    # Max: 10
    run_test("?a?a?a?a?a", 1, 10)

    # CENÁRIO 2: Máscara MAIOR que Increment Max (Deve funcionar, mas corta?)
    # Mask: ?a?a?a?a?a (5 chars)
    # Min: 1
    # Max: 3
    run_test("?a?a?a?a?a", 1, 3)

    # CENÁRIO 3: Máscara IGUAL ao Increment Max (Ideal)
    # Mask: ?a?a?a?a?a (5 chars)
    # Min: 1
    # Max: 5
    run_test("?a?a?a?a?a", 1, 5)
