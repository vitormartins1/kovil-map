# Remote Sync How-To

This guide explains how to use the shared `Sync` flow for remote devices.

Current automated targets:

- `Pwnagotchi`
- `M5Evil Cardputer`
- `Bruce`

## Requirements

### Pwnagotchi

- device reachable over the network
- SSH enabled
- valid SSH username and password
- the most practical setup is usually the USB/RNDIS network exposed when the device is connected by cable

### M5Evil Cardputer

- device reachable through the `Admin WebUI` endpoint
- `Admin WebUI` enabled on the device
- the SD card content available under the `evil/` folder

Do **not** use `SSH Shell` for desktop import. That feature is a client shell on the device, not the KOVIL MAP transport.

### Bruce

- device reachable through the `Bruce WebUI` endpoint
- valid HTTP Basic Auth credentials
- expected remote folders on the SD filesystem

## Configuration

Set the connection in Settings or in `backend/config.json`.

The repository version of `backend/config.json` is sanitized for public publication. Fill in your device-specific values locally.

### Pwnagotchi profile

| Field | Default |
| --- | --- |
| `pwn_host` | `10.0.0.2` |
| `pwn_port` | `22` |
| `pwn_user` | `pi` |
| `pwn_pass` | `raspberry` |
| `remote_path` | `/home/pi/handshakes` |

Use `TEST CONNECTION` in `PWNAGOTCHI SSH SYNC` after connecting the device by USB and confirming the desktop can reach the mapped SSH IP.

### M5Evil Cardputer profile

| Field | Default |
| --- | --- |
| `m5_sync_enabled` | `false` |
| `m5_host` | `192.168.4.1` fallback; normally the IP shown by the Cardputer |
| `m5_port` | `80` |
| `m5_web_protocol` | `http` |
| `m5_admin_base_path` | `/evil-menu` |
| `m5_web_user` | `evil` |
| `m5_web_password` | `test` |
| internal handshake path | `evil/handshakes` |
| internal Wardrive path | `evil/wardriving` |
| internal RAW Sniffer path | `evil/sniffer` |

The Settings modal keeps M5Evil defaults filled in, but the normal workflow is replacing `M5EVIL HOST` with the IP shown by the Cardputer after it joins the same network as the desktop.

### Bruce profile

| Field | Default |
| --- | --- |
| `bruce_sync_enabled` | `false` |
| `bruce_host` | `bruce.local` |
| `bruce_port` | `80` |
| `bruce_web_protocol` | `http` |
| `bruce_web_user` | `admin` |
| `bruce_web_password` | `bruce` |
| internal handshake path | `/BrucePCAP/handshakes` |
| internal RAW path | `/BrucePCAP` |
| internal Wardrive path | `/BruceWardriving` |

These Bruce remote paths are fixed in the backend and are not user-editable in the Settings modal.

### Reachability modes

#### Same-network WebUI

- recommended day-to-day workflow
- configure `wifi_ssid=` and `wifi_password=` in the device `config.txt`
- let the Cardputer join the same Wi-Fi/network as the desktop running KOVIL MAP
- use the IP shown by the Cardputer after it connects
- replace `m5_host` with that IP instead of relying on the fallback default
- then run `Start Captive Portal`
- if the browser works with a URL like `http://<device-ip>/check-sd-file?dir=/evil/handshakes`, the current Cardputer defaults in KOVIL MAP should already match that storage layout

#### Remote exposure

- `UPnP NAT` exposes the internal WebUI port `80` on another reachable host/port
- `Reverse TCP Tunnel` requires `tcp_host=` and `tcp_port=` in the device `config.txt`
- if the device shows `Error check TCP host in config file`, set `tcp_host=` first
- KOVIL MAP should use the final reachable WebUI endpoint only; it does not manage NAT or tunnel setup

### Config ownership

Device-side `config.txt`:

- `wifi_ssid`
- `wifi_password`
- `tcp_host`
- `tcp_port`
- `webpassword`

KOVIL MAP-side settings:

- `m5_host`
- `m5_port`
- `m5_web_protocol`
- `m5_admin_base_path`
- `m5_web_user`
- `m5_web_password`

Use `webpassword=...` in the device config as the source of truth. The KOVIL MAP preset keeps `test` as a convenience default for the current setup, but firmware/config variants may differ.

## Running Sync

1. Enable the desired profile(s) in **System Configuration > Device Sync**.
2. Put the Cardputer on the same Wi-Fi/network as the desktop and replace `M5EVIL HOST` with the IP shown by the Cardputer after it connects.
3. Run `Start Captive Portal` on the Cardputer.
4. If you are using NAT / tunnel exposure instead, replace `M5EVIL HOST` and `WEB PORT` with the final reachable endpoint you exposed.
5. Use `TEST CONNECTION` to validate reachability, auth, and the fixed Cardputer storage paths before syncing.
6. Click **Sync**.
7. Review imported handshakes, RAW captures, and Wardrive CSVs.

Use force sync if you need to re-download everything.

## Pwnagotchi USB SSH Notes

- connect the Pwnagotchi to the desktop by USB
- wait for the USB/RNDIS network interface to appear on the host
- use the SSH IP exposed on that mapped interface in `TARGET IP`
- use `TEST CONNECTION` before clicking `Sync`
- if SSH host-key trust blocks the test, trust the key and retry

## What Gets Imported

### Pwnagotchi

- classic handshake `.pcap`
- GPS sidecars such as `.gps.json`, `.geo.json`, `.paw-gps.json`

### M5Evil Cardputer

- `HS_*.pcap` into `backend/data/m5evil/handshakes/`
- `RawSniff_*.pcap` into `backend/data/m5evil/rawsniffer/`
- `masterSniffer_*.pcap` into `backend/data/m5evil/mastersniffer/`
- WiGLE-style `.csv` into `backend/data/wardrive/` with an `m5evil__` filename prefix

### Bruce

- `HS_*.pcap` from `/BrucePCAP/handshakes` into `backend/data/BrucePCAP/handshakes/`
- RAW `.pcap` from `/BrucePCAP` into `backend/data/BrucePCAP/rawsniffer/`
- Wardrive `.csv` from `/BruceWardriving` into `backend/data/wardrive/`

Anything else outside these fixed Cardputer paths still remains outside the current auto-sync scope.

## Result Feedback

The UI now logs target-specific sync feedback, for example:

- `Pwnagotchi remote sync: ...`
- `M5Evil Admin WebUI sync: ...`
- `Bruce WebUI sync: ...`

The Process panel also creates dedicated M5Evil sync entries for each imported artifact group:

- `M5Evil handshakes`
- `M5Evil raw sniffer`
- `M5Evil master sniffer`
- `M5Evil Wardrive CSVs`

And dedicated Bruce sync entries:

- `Bruce handshakes`
- `Bruce raw sniffer`
- `Bruce Wardrive CSVs`

## Troubleshooting

- connection refused or timeout: in normal same-network use, prefer the IP shown by the Cardputer on the current network and make sure `Start Captive Portal` is already running
- connected and authenticated, but Browse SD could not be parsed: the firmware WebUI is reachable, but the current Browse SD page shape does not match the parser yet
- authentication failed: confirm the `Admin WebUI` username/password, defaulting to `evil / test`
- invalid M5 listing: confirm `Admin WebUI` is enabled and the expected Cardputer storage paths exist
- reverse tunnel error on device: `Error check TCP host in config file` means `tcp_host=` is missing from the device `config.txt`
- no new files found: confirm the exported files are under the configured `evil/...` directories
- Pwnagotchi host key verification failed: trust the SSH host key and retry
- M5Evil Wardrive files not showing up: confirm the exports are WiGLE-compatible `.csv`
