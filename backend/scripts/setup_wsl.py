import subprocess
import sys
import os

def check_wsl():
    try:
        result = subprocess.run(["wsl", "--list", "--verbose"], capture_output=True, text=True)
        if result.returncode == 0:
            print("WSL is installed and accessible.")
            print(result.stdout)
            return True
        else:
            print("WSL command failed.")
            return False
    except FileNotFoundError:
        print("WSL executable not found.")
        return False

def install_dependencies():
    print("Installing dependencies in WSL (Ubuntu)...")
    commands = [
        "sudo apt-get update",
        "sudo apt-get install -y hashcat hcxtools aircrack-ng"
    ]
    
    for cmd in commands:
        print(f"Running: {cmd}")
        # Executa no WSL
        full_cmd = f'wsl -d Ubuntu bash -c "{cmd}"'
        subprocess.run(full_cmd, shell=True)

if __name__ == "__main__":
    if check_wsl():
        install_dependencies()
    else:
        print("Please install WSL first.")
