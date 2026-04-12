# Sync Remote

**Sync Remote** is KOVIL MAP's automated remote-ingest pipeline. One `Sync` run can orchestrate:

1. `Pwnagotchi` over `SSH/SFTP`
2. `M5Evil` over `Admin WebUI`
3. `Bruce` over `WebUI`
4. local reload and downstream planning

## Current Supported Targets

### Pwnagotchi

- downloads classic handshake captures and GPS sidecars
- writes into `backend/data/handshakes/`
- keeps the existing SSH/SFTP workflow intact

### M5Evil Cardputer

- downloads `HS_*.pcap` handshake captures into `backend/data/m5evil/handshakes/`
- downloads `RawSniff_*.pcap` captures from `evil/sniffer` into `backend/data/m5evil/rawsniffer/`
- downloads `masterSniffer_*.pcap` captures from `evil/handshakes` into `backend/data/m5evil/mastersniffer/`
- downloads WiGLE-style Wardrive `.csv` files into `backend/data/wardrive/`
- prefixes imported Wardrive files as `m5evil__<remote_filename>` to avoid collisions
- uses the device `Admin WebUI` at `/evil-menu`, not `SSH Shell`
- authenticates with HTTP Basic Auth
- works best in normal use when the Cardputer joins the same Wi-Fi/network as the desktop and `m5_host` is set to the IP shown by the device
- in the workflow validated so far, operators connect the Cardputer to the same network first and then run `Start Captive Portal`
- keeps `192.168.4.1` only as an internal/default fallback value
- also supports LAN, `UPnP NAT`, or `Reverse TCP Tunnel` exposure if those paths make the same WebUI reachable

### Bruce

- downloads `HS_*.pcap` handshake captures into `backend/data/BrucePCAP/handshakes/`
- downloads RAW `.pcap` captures from `/BrucePCAP` into `backend/data/BrucePCAP/rawsniffer/`
- downloads Wardrive `.csv` files from `/BruceWardriving` into `backend/data/wardrive/`
- uses the device `WebUI` with HTTP Basic Auth
- uses fixed remote paths in the backend (not user-editable):
	- `/BrucePCAP/handshakes`
	- `/BrucePCAP`
	- `/BruceWardriving`

## Smart Incremental Sync

To reduce transfer time on slow or unstable links, the sync service compares:

- file name
- local presence

Only new files are downloaded unless `FORCE SYNC` is enabled.

## Downstream Processing

After remote downloads finish, the sync pipeline automatically:

- reloads the local dataset when at least one remote target succeeded
- refreshes map and Wardrive views through the normal `data_update` flow
- plans local fingerprint extraction for Brucegotchi and M5Evil handshakes that still need `.details`
- enqueues RAW metadata extraction for pending RAW files already present locally

For M5Evil specifically:

- downloaded handshakes are fed into the existing M5Evil fingerprint planning flow
- downloaded `RawSniff_*.pcap` and `masterSniffer_*.pcap` are fed into the unified RAW pipeline
- downloaded Wardrive CSVs are picked up by the normal Wardrive loader and manifest sync

## Security Model

- `Pwnagotchi` keeps strict SSH host-key verification through `known_hosts`
- `M5Evil` does **not** use SSH host-key trust in this flow
- the current M5Evil implementation expects a reachable `Admin WebUI` endpoint, whether through AP mode, LAN exposure, Reverse TCP Tunnel, or UPnP NAT

## Observability

The sync result exposes separate remote stages for each profile:

- `sync_stages.pwnagotchi_remote_sync`
- `sync_stages.m5evil_remote_sync`
- `sync_stages.bruce_remote_sync`
- `sync_stages.bruce_fingerprint`
- `sync_stages.m5evil_fingerprint`
- `sync_stages.rawsniffer_extract`

The frontend also creates dedicated Process panel entries for:

- `Pwnagotchi handshakes`
- `M5Evil handshakes`
- `M5Evil raw sniffer`
- `M5Evil master sniffer`
- `M5Evil Wardrive CSVs`
- `Bruce handshakes`
- `Bruce raw sniffer`
- `Bruce Wardrive CSVs`

## Configuration

### Pwnagotchi fields

| Parameter | Description | Default |
| --- | --- | --- |
| `pwn_host` | remote device IP address | `10.0.0.2` on USB RNDIS |
| `pwn_port` | SSH port | `22` |
| `pwn_user` | SSH username | `pi` |
| `pwn_pass` | SSH password stored locally | `raspberry` |
| `remote_path` | remote handshake root | `/home/pi/handshakes` |

### M5Evil fields

| Parameter | Description | Default |
| --- | --- | --- |
| `m5_sync_enabled` | enables M5Evil auto-sync during `Sync` | `false` |
| `m5_host` | Admin WebUI host, normally the IP shown by the Cardputer on the current network | `192.168.4.1` fallback |
| `m5_port` | Admin WebUI port | `80` |
| `m5_web_protocol` | web transport protocol | `http` |
| `m5_admin_base_path` | Admin WebUI base path | `/evil-menu` |
| `m5_web_user` | Basic Auth username | `evil` |
| `m5_web_password` | Basic Auth password stored locally | `test` |
| `m5_handshake_remote_path` | handshake directory path inside the web server; kept internally as the fixed Cardputer default | `evil/handshakes` |
| `m5_wardrive_remote_path` | Wardrive directory path inside the web server; kept internally as the fixed Cardputer default | `evil/wardriving` |

Related device-side `config.txt` values are outside KOVIL MAP and include:

- `wifi_ssid`
- `wifi_password`
- `tcp_host`
- `tcp_port`
- `webpassword`

### Shared field

| Parameter | Description | Default |
| --- | --- | --- |
| `ssh_known_hosts_path` | trusted host keys file for SSH targets | empty |

### Bruce fields

| Parameter | Description | Default |
| --- | --- | --- |
| `bruce_sync_enabled` | enables Bruce auto-sync during `Sync` | `false` |
| `bruce_host` | Bruce WebUI host | `bruce.local` |
| `bruce_port` | Bruce WebUI port | `80` |
| `bruce_web_protocol` | web transport protocol | `http` |
| `bruce_web_user` | Basic Auth username | `admin` |
| `bruce_web_password` | Basic Auth password stored locally | `bruce` |
| internal handshake path | fixed on device filesystem | `/BrucePCAP/handshakes` |
| internal RAW path | fixed on device filesystem | `/BrucePCAP` |
| internal Wardrive path | fixed on device filesystem | `/BruceWardriving` |

## Current Scope Limits

- only `M5Evil Cardputer` is supported in the automated M5Evil flow for now
- only `Admin WebUI` transport is implemented for that profile
- additional M5 / Evil-M5 devices are planned as a later expansion once web-path and transport compatibility are validated

## Related Integrations

- [Pwnagotchi](../04-INTEGRATIONS/pwnagotchi.md)
- [M5Evil Cardputer](../04-INTEGRATIONS/m5evil-cardputer.md)
- [Manual Import Layout](../00-GETTING_STARTED/manual-import-layout.md)
- [SSH & SFTP Remote](../04-INTEGRATIONS/ssh-sftp-remote.md)
- [Remote Sync How-To](../07-OPERATIONS/remote-sync-howto.md)
