# Common Issues & FAQ

Quick answers for the problems new users hit most often.

For a full troubleshooting flow, see the [Troubleshooting Guide](../07-OPERATIONS/troubleshooting.md).

---

## Installation and Startup

### The app is stuck on "Backend Busy" or "Connecting..."

The frontend cannot reach the Python backend.

- See [Troubleshooting](../07-OPERATIONS/troubleshooting.md#1-backend-busy-or-infinite-loading-screen)

### The map is gray or does not load

This usually means the base map tiles could not be fetched.

- See [Troubleshooting](../07-OPERATIONS/troubleshooting.md#2-map-does-not-load-gray-screen)

### Windows permission errors

PowerShell scripts may be blocked by the execution policy.

- See [Installation](installation.md#windows-script-running-is-disabled)

---

## Cracking and Tools

### Hashcat does not start

This is usually a GPU driver issue or an invalid executable path in Settings.

- See [Troubleshooting](../07-OPERATIONS/troubleshooting.md#1-hashcat-fails-to-start-exit-code-255-or-similar)

### "No valid handshake found"

The `.pcap` file may be incomplete or corrupted and may not contain the required EAPOL frames.

---

## Sync and Pwnagotchi

### "Connection refused" or timeout during sync

The Pwnagotchi host is not reachable, usually because of a USB cable or IP issue.

### "Authentication failed"

The SSH username or password in Settings is incorrect.

---

## Other Questions

### Do I need a dedicated GPU?

No, but a GPU is strongly recommended if you want usable Hashcat performance. Without one, you will be limited to very slow CPU-based fallback attacks.

### Where are the logs?

- **Backend:** in the terminal running `python main.py` or the packaged executable
- **Frontend:** open DevTools with `Ctrl+Shift+I` and check the Console tab
- **Files:** the backend may write logs to `backend/kovil.log` depending on the configuration
