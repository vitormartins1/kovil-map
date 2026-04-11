import os
import subprocess
import shutil

def create_dummy_wordlists(base_dir):
    if os.path.exists(base_dir):
        shutil.rmtree(base_dir)
    os.makedirs(base_dir)
    
    for i in range(5):
        with open(os.path.join(base_dir, f"wl_{i}.txt"), "w") as f:
            f.write(f"password{i}\n123456{i}\n")
            
    return base_dir

def run_test():
    # Setup
    wl_dir = "temp_wordlists"
    create_dummy_wordlists(wl_dir)
    
    # Hash de teste (MD5: 8743b52063cd84097a65d1633f5c74f5 -> 'password')
    # Mas vamos usar WPA (2500/22000) simulado ou MD5 mesmo só pra ver o fluxo de wordlists
    # Hashcat aceita MD5 (-m 0) que é mais rápido pra teste
    hash_file = "test.hash"
    with open(hash_file, "w") as f:
        f.write("8743b52063cd84097a65d1633f5c74f5") # 'password' (não está nas wordlists geradas acima de propósito pra forçar exhausted)

    hashcat_bin = r"C:\hashcat-6.2.6\hashcat.exe" # Assumindo que está no PATH ou use caminho absoluto
    
    # Comando: hashcat -m 0 -a 0 test.hash temp_wordlists --status --status-timer 1
    cmd = [hashcat_bin, "-m", "0", "-a", "0", hash_file, wl_dir, "--status", "--status-timer", "1", "--force"]
    
    print(f"Executando: {' '.join(cmd)}")
    
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
        
        for line in process.stdout:
            print(f"[STDOUT] {line.strip()}")
            
        process.wait()
        print(f"Return Code: {process.returncode}")
        
    except Exception as e:
        print(f"Erro: {e}")
    finally:
        # Cleanup
        if os.path.exists(wl_dir):
            shutil.rmtree(wl_dir)
        if os.path.exists(hash_file):
            os.remove(hash_file)

if __name__ == "__main__":
    run_test()