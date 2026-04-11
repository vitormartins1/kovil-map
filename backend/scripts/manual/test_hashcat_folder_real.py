import os
import subprocess
import sys

def run_test():
    # Configurações
    # Tenta achar o hashcat no caminho padrão do projeto ou assume PATH
    hashcat_bin = r"C:\hashcat-6.2.6\hashcat.exe" 
    if not os.path.exists(hashcat_bin):
        hashcat_bin = "hashcat"
        
    wordlist_dir = r"C:\my-wordlists\musicas"
    hash_file = "test_md5.hash"
    
    print(f"Verificando diretório de wordlists: {wordlist_dir}")
    if not os.path.exists(wordlist_dir):
        print(f"AVISO: O diretório '{wordlist_dir}' não existe na máquina onde este script está rodando.")
        print("Por favor, edite o script 'test_hashcat_folder_real.py' com o caminho correto ou crie a pasta.")
        return

    # Cria hash MD5 de teste ('password')
    with open(hash_file, "w") as f:
        f.write("5f4dcc3b5aa765d61d8327deb882cf99") 

    # Comando
    # -m 0 (MD5)
    # -a 0 (Wordlist)
    # --status (Ativa status automatico)
    # --status-timer 1 (1 segundo)
    cmd = [
        hashcat_bin, 
        "-m", "0", 
        "-a", "0", 
        hash_file, 
        wordlist_dir, 
        "--status", 
        "--status-timer", "1", 
        "--force"
    ]
    
    print(f"Executando: {' '.join(cmd)}")
    print("-" * 40)

    try:
        cwd = os.path.dirname(hashcat_bin) if os.path.isabs(hashcat_bin) else None
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            cwd=cwd
        )
        
        for line in process.stdout:
            print(f"[LOG] {line.strip()}")
            
        process.wait()
        print("-" * 40)
        print(f"Processo terminou com código: {process.returncode}")
        
    except Exception as e:
        print(f"Erro ao executar: {e}")
    finally:
        if os.path.exists(hash_file):
            os.remove(hash_file)

if __name__ == "__main__":
    run_test()