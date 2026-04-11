# SSH & SFTP Remote Integration

KOVIL MAP uses SSH and SFTP to communicate with remote devices, especially Pwnagotchi-style systems.

This integration lets the desktop app manage captures from headless devices without removing storage media.

## Architecture

The backend `SyncService` handles the connection using Paramiko.

### Connection flow

1. Connect to port 22 on the configured host.
2. Authenticate with the configured credentials.
3. Optionally validate the host key against `known_hosts`.
4. Open an SFTP session.
5. List files, read metadata, and download changed files.
6. Close the connection when the job finishes.

---

## Configuration

Use `backend/config.json` or the Settings UI.

| Field | Example |
|---|---|
| `pwn_host` | `10.0.0.2` |
| `pwn_user` | `pi` |
| `pwn_pass` | `raspberry` |
| `remote_path` | `/home/pi/handshakes` |
| `ssh_known_hosts_path` | `C:\Users\Vitor\.ssh\known_hosts` |

---

## Host Key Verification

KOVIL MAP supports strict host-key verification to reduce MITM risk.

- permissive mode uses trust-on-first-use
- strict mode rejects unknown host keys
- in strict mode, you usually seed `known_hosts` with a manual SSH login first

---

## Smart Sync

The sync logic compares remote file metadata with local files.

- new files are downloaded
- changed files are re-downloaded
- identical files are skipped
- force sync bypasses the cache

---

## Extensibility

Although centered on Pwnagotchi, the sync service can work with any SSH host that exposes `.pcap` or `.json` capture files.

---
