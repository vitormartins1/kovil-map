import subprocess

def check_wsl_access():
    try:
        # Tenta listar arquivos no C: via WSL
        cmd = 'wsl ls /mnt/c'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("WSL Access: OK")
            return True
        else:
            print(f"WSL Access: FAILED (Code {result.returncode})")
            print(f"Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"WSL Check Exception: {e}")
        return False

if __name__ == "__main__":
    check_wsl_access()