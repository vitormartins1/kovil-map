# Installation Guide

This guide covers installing **KOVIL MAP** on Windows, Linux, and macOS.

## System Requirements

Before you start, make sure the machine meets the minimum requirements:

### Hardware

- **CPU:** modern x64 or ARM64 processor
- **RAM:** at least 4 GB, with 8 GB recommended for large maps
- **GPU:** a dedicated NVIDIA or AMD GPU is strongly recommended for Hashcat workloads
- **Disk:** around 500 MB for the application, plus space for wordlists and logs

### External Tools

To use cracking and fingerprinting features, install the following tools:

1. **Hashcat:** https://hashcat.net/hashcat/
2. **HCXTools:** required for `.pcap` to `.22000` conversion
   - Linux: `sudo apt install hcxtools`
   - Windows: use WSL or a ported binary
3. **Aircrack-ng:** optional CPU-based cracking fallback
4. **Wireshark/Tshark:** used for passive fingerprinting

---

## Option 1: End Users

The easiest way to use KOVIL MAP is through the packaged releases.

1. Open the GitHub **Releases** page.
2. Download the build for your platform:
   - `KOVIL-MAP-Setup-x.x.x.exe` on Windows
   - `KOVIL-MAP-x.x.x.AppImage` or `.deb` on Linux
   - `KOVIL-MAP-x.x.x.dmg` on macOS
3. Run the installer and follow the on-screen instructions.
4. On first launch, open **Settings** and configure the paths for `hashcat`, `hcxpcapngtool`, and `tshark`.

Packaged releases start the backend for you. See [Runtime Modes](runtime-modes.md) if you want the exact differences between packaged and development behavior.

---

## Option 2: Developers

Use this path if you want the latest development build or plan to contribute.

### Development Requirements

- Git
- Python 3.12+
- Node.js 18+ LTS

### Step 1: Clone the Repository

```bash
git clone https://github.com/vitormartins1/kovil-map.git
cd kovil-map
```

### Step 2: Backend Setup

```bash
cd backend
python -m venv .venv

# Windows
.\.venv\Scripts\Activate.ps1

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
python main.py
```

### Step 3: Frontend Setup

Open a second terminal:

```bash
cd frontend
npm install
npm start
```

In development, the backend is started manually and logs stay visible in your terminal. See [Runtime Modes](runtime-modes.md) for the complete comparison.

---

## Installation Troubleshooting

### Windows: "Script running is disabled"

If PowerShell blocks venv activation:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Linux: Port 8000 is Busy

If the backend cannot bind to port 8000, check whether another service is already using it. Avoid running the dev backend as root; instead, change the port if needed.

### "Backend Busy" or White Screen

If the frontend opens but never finishes loading:

1. Confirm the backend terminal is running without errors.
2. Check whether `KOVIL_API_TOKEN` is set. If it is, the frontend must know the same token.

### Hashcat: "CL_DEVICE_NOT_FOUND"

This usually points to a GPU driver issue.

- Update your NVIDIA or AMD drivers.
- On Linux, make sure the proprietary GPU drivers and OpenCL packages are installed.

---

## Next Steps

- [First Run Guide](first-run.md)
- [Current Product Surface](current-product-surface.md)
- [Runtime Modes](runtime-modes.md)
- [Remote Sync](../02-FEATURES/sync-remote.md)
