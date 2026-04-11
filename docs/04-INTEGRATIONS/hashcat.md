# Hashcat Integration

Hashcat is KOVIL MAP's main GPU cracking engine. The app does not reimplement cracking logic; it orchestrates the Hashcat binary and manages jobs around it.

## Installation

KOVIL MAP does not ship with Hashcat. Install it separately.

- **Windows:** download the latest binary package from hashcat.net
- **Linux:** use your package manager or the official archive
- **macOS:** install via Homebrew

---

## Configuration

Set the Hashcat path in Settings or in `backend/config.json`.

Example:

```json
{
  "hashcat_path": "/usr/bin/hashcat",
  "hashcat_optimized": true,
  "hashcat_device_default": "all"
}
```

If you prefer WSL on Windows, enable the WSL option and point to the Linux path inside the WSL environment.

---

## GPU Drivers

Use current GPU drivers that support the required OpenCL or CUDA stack.

- NVIDIA: official Game Ready or Studio drivers
- AMD: Adrenalin Edition
- Intel: OpenCL-capable graphics drivers

---

## Troubleshooting

- **No devices found / `CL_DEVICE_NOT_FOUND`** - reinstall the GPU driver
- **Device signature verification failed** - usually a Linux/WSL driver mismatch
- **Output separator mismatch** - clear the potfile or rebuild the output format
- **Slow performance or throttling** - check cooling and workload settings
- **`wsl: command not found`** - disable WSL mode or install WSL
