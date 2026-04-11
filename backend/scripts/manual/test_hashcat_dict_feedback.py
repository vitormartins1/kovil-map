import os
import subprocess
import json

def run_test():
    # Configurações do teste
    hashcat_bin = r"C:\hashcat-6.2.6\hashcat.exe"
    hash_file = r"C:\Users\vitor\RiderProjects\mockgotchi\desktop-app\APT403_d06ede842968.22000"
    wordlist_dir = r"C:\my-wordlists\musicas"
    
    # Verifica se os arquivos existem
    if not os.path.exists(hashcat_bin):
        print(f"ERRO: Hashcat não encontrado em {hashcat_bin}")
        return
    if not os.path.exists(hash_file):
        print(f"ERRO: Arquivo de hash não encontrado em {hash_file}")
        hash_file = os.path.abspath(hash_file)
        if not os.path.exists(hash_file):
             print(f"ERRO FATAL: Hash file {hash_file} não existe.")
             return

    if not os.path.exists(wordlist_dir):
        print(f"ERRO: Diretório de wordlists não encontrado em {wordlist_dir}")
        return

    # Comando Hashcat
    cmd = [
        hashcat_bin,
        "-m", "22000",
        "-a", "0",
        hash_file,
        wordlist_dir,
        "--status",
        "--status-timer", "1",
        "--force",
        "-w", "3",
        "--potfile-disable"  # <--- ADICIONADO: Ignora senhas já quebradas para forçar o ataque
    ]
    
    print(f"Executando: {' '.join(cmd)}")
    print("-" * 50)
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            cwd=os.path.dirname(hashcat_bin)
        )
        
        # Captura e imprime o output linha a linha
        for line in process.stdout:
            line = line.strip()
            print(f"[LOG] {line}")
            
            # Simula a lógica de detecção do JobManager para debug
            if "Dictionary cache hit:" in line:
                print(f"   >>> DETECTADO (Cache Hit): {line}")
            elif "Starting attack on" in line:
                print(f"   >>> DETECTADO (Starting Attack): {line}")
            elif "Recovering" in line:
                 print(f"   >>> DETECTADO (Recovering): {line}")
            
        process.wait()
        print("-" * 50)
        print(f"Return Code: {process.returncode}")
        
    except Exception as e:
        print(f"Exceção durante execução: {e}")

if __name__ == "__main__":
    run_test()