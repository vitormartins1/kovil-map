import os
import subprocess
import shutil
import re
import sys

# --- MOCK PARSING LOGIC (From job_manager.py) ---
def parse_line(line):
    updates = {}
    dict_found = False
    
    # Logic from job_manager.py
    if "Dictionary cache hit:" in line:
        parts = line.split("Dictionary cache hit:")
        if len(parts) > 1:
            # Remove potential ANSI codes from the filename part
            raw_filename = parts[1].strip()
            # Simple ANSI strip regex
            clean_filename = re.sub(r'\x1b\[[0-9;]*m', '', raw_filename)
            
            filename = os.path.basename(clean_filename)
            updates["extra"] = f"Dict: {filename}"
            dict_found = True
            
    elif "Starting attack on" in line:
         match = re.search(r"Starting attack on '(.+?)'", line)
         if match:
             filename = os.path.basename(match.group(1))
             updates["extra"] = f"Dict: {filename}"
             dict_found = True
             
    return updates, dict_found

# --- TEST SETUP ---
def create_dummy_wordlists(base_dir):
    if os.path.exists(base_dir):
        shutil.rmtree(base_dir)
    os.makedirs(base_dir)
    
    for i in range(3):
        with open(os.path.join(base_dir, f"wordlist_{i}.txt"), "w") as f:
            f.write(f"password{i}\n123456{i}\n")
    return base_dir

def run_test():
    wl_dir = "temp_wordlists_test"
    create_dummy_wordlists(wl_dir)
    
    hash_file = "test_parsing.hash"
    with open(hash_file, "w") as f:
        f.write("8743b52063cd84097a65d1633f5c74f5") # MD5 'password'

    # Try to find hashcat
    hashcat_bin = r"C:\hashcat-6.2.6\hashcat.exe"
    if not os.path.exists(hashcat_bin):
        hashcat_bin = "hashcat"
        if not shutil.which(hashcat_bin):
            print("Hashcat binary not found. Please edit script with correct path.")
            return

    cmd = [hashcat_bin, "-m", "0", "-a", "0", hash_file, wl_dir, "--status", "--status-timer", "1", "--force"]
    
    print(f"Running: {' '.join(cmd)}")
    print("-" * 60)

    try:
        # Run with cwd as hashcat dir to avoid issues
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
            line = line.strip()
            if not line: continue
            
            # Test Parsing
            updates, found = parse_line(line)
            
            if found:
                print(f"[MATCH] '{line}' -> {updates}")
            elif "Dictionary" in line or "Starting" in line:
                print(f"[FAIL?] '{line}'")
            else:
                # Print only status lines to reduce noise
                if "Status" in line or "Progress" in line:
                    print(f"[LOG]   {line}")

        process.wait()
        
    except Exception as e:
        print(f"Execution Error: {e}")
    finally:
        if os.path.exists(wl_dir):
            shutil.rmtree(wl_dir)
        if os.path.exists(hash_file):
            os.remove(hash_file)

if __name__ == "__main__":
    run_test()