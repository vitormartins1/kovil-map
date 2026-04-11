# HCXTools Integration

HCXTools, especially `hcxpcapngtool`, bridges raw `.pcap` captures and the Hashcat cracking pipeline.

## Role in KOVIL MAP

KOVIL MAP uses `hcxpcapngtool` in the background to:

1. convert `.pcap` or `.pcapng` into `.22000`
2. extract PMKID and EAPOL data
3. drop invalid or irrelevant packets
4. prepare batch-oriented hash files

---

## Installation

- **Linux:** install `hcxtools` from your package manager
- **macOS:** install via Homebrew
- **Windows:** use WSL or a trusted ported binary

---

## Configuration

Set the `hcxpcapngtool` path in Settings or let the backend discover it automatically.

---

## How It Is Used

Normally you do not run it manually:

- when cracking a single `.pcap`, KOVIL MAP converts it to `.22000`
- when building a batch, the backend merges the valid hashes and writes a manifest

---

## Troubleshooting

- **Conversion failed / empty `.22000`** - the capture does not contain valid handshake material
- **Command not found** - install the tool or add it to PATH
- **Windows issues** - use WSL if the native binary is not reliable
