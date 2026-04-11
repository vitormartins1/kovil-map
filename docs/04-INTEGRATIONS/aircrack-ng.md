# Aircrack-ng Integration

Aircrack-ng is KOVIL MAP's CPU fallback cracking tool. It is useful for quick validation and for systems that do not have a suitable GPU.

## When to Use It

- quick validation with small wordlists
- machines without a dedicated GPU
- direct PCAP testing when you do not want to convert to `.22000`
- debugging handshake quality

---

## Installation

- **Windows:** download the Windows build and point KOVIL MAP at the executable
- **Linux:** install from your package manager
- **macOS:** install via Homebrew

---

## Configuration

Set the Aircrack path in Settings or let the app use the system `PATH`.

---

## Running an Attack

Choose a target, open the cracking panel, select the Aircrack/CPU path, and start the job.

The backend can also launch Aircrack directly through the API.

---

## Troubleshooting

- **No valid handshake found** - the capture is incomplete or corrupted
- **Command not found** - verify the executable path in Settings
