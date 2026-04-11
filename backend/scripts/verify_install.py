import shutil

def check_tool(name):
    path = shutil.which(name)
    print(f"{name}: {'FOUND' if path else 'MISSING'} ({path})")

if __name__ == "__main__":
tools = ["hashcat", "hcxpcapngtool", "aircrack-ng"]
    for t in tools:
        check_tool(t)
