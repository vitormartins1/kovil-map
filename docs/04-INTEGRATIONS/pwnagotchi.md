# Pwnagotchi Integration

Pwnagotchi is a portable Wi-Fi auditing companion. KOVIL MAP acts as the desktop companion that takes the captures it produces and turns them into map data, cracking jobs, and session history.

## What KOVIL MAP Does

- downloads files from the device
- plots GPS-backed captures on the map
- sends handshakes to the cracking pipeline
- keeps a local history of imported data

---

## Supported File Types

### Handshakes

Standard `.pcap` captures with EAPOL or PMKID data.

### Geolocation

Common GPS sidecar files such as `.gps.json`, `.geo.json`, and `.paw-gps.json`.

### RAW captures

`raw_*.pcap` files from Bruce-style devices and similar sources.

---

## Recommended Configuration

Use SSH access and point KOVIL MAP at the folder where the device stores captures.

| Setting | Typical value |
|---|---|
| Host | `10.0.0.2` |
| User | `pi` |
| Password | `raspberry` |
| Remote path | `/home/pi/handshakes` |

---

## Workflow

1. Connect the device over USB or network.
2. Open KOVIL MAP and run Sync.
3. The app downloads only the files that changed.
4. New networks appear on the map and in the cracking workflow.

---

## Local Import Relationship

Remote sync is primarily documented for Pwnagotchi-style SSH/SFTP workflows.

Brucegotchi and M5 Evil captures are supported by the handshake catalog too, but they are typically added through the local folder layout:

- Brucegotchi handshakes: `backend/data/BrucePCAP/handshakes/`
- Bruce RAW captures: `backend/data/BrucePCAP/rawsniffer/`
- M5 Evil handshakes: `backend/data/m5evil/handshakes/`
- M5 Evil RAW captures: `backend/data/m5evil/rawsniffer/`

Use [`../00-GETTING_STARTED/manual-import-layout.md`](../00-GETTING_STARTED/manual-import-layout.md) for the current local import structure.

---

## Troubleshooting

- if nothing downloads, check the remote path and SSH permissions
- if networks appear without GPS, make sure the device actually wrote the sidecar file
- KOVIL MAP never deletes files from the remote device
