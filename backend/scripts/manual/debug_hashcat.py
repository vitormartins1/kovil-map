import subprocess
import os

def test_hashcat():
    # Teste simples para ver se o hashcat roda
    cmd = ["hashcat", "--version"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(f"Hashcat Version: {result.stdout.strip()}")
    except FileNotFoundError:
        print("Hashcat not found in PATH")

if __name__ == "__main__":
    test_hashcat()