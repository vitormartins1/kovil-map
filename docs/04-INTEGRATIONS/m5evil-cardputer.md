# M5Evil Cardputer

This page documents the current automated integration between KOVIL MAP and `M5Evil Cardputer`.

## Scope

The current version supports:

- `Admin WebUI`-based sync
- `HS_*.pcap` handshake import
- `RawSniff_*.pcap` import from `/evil/sniffer`
- `masterSniffer_*.pcap` import from `/evil/handshakes`
- WiGLE-style Wardrive CSV import

The current version does **not** support:

- `SSH Shell` as a desktop import path
- USB / mounted SD-card transport
- non-Cardputer M5Evil devices

## Current Transport

KOVIL MAP uses the shared `Sync` button, but the M5Evil profile is web-based.

Transport:

- `HTTP`
- `Admin WebUI` at `/evil-menu`
- `Browse SD` navigation plus direct file download
- HTTP Basic Auth with the configured username and password

`SSH Shell` is not used by KOVIL MAP for this feature.

## Default Form Values

Current preset values:

| Field | Value |
| --- | --- |
| Host | `192.168.4.1` |
| Port | `80` |
| Username | `evil` |
| Password | `test` |
| Handshake path | internal fixed default: `evil/handshakes` |
| Wardrive path | internal fixed default: `evil/wardriving` |
| Raw Sniffer path | internal fixed default: `evil/sniffer` |

The current Settings modal exposes host, port, username, password, enable/force flags, and `TEST CONNECTION`. The Cardputer SD paths remain fixed internally for now.

The defaults are best understood as a starting point. In day-to-day use, the most practical setup is replacing `Host` with the IP shown by the Cardputer after it joins the same network as the desktop running KOVIL MAP.

## Reachability Modes

### Same-network WebUI

- recommended workflow
- set `wifi_ssid=` and `wifi_password=` in the device `config.txt`
- let the Cardputer join the same Wi-Fi/network as the desktop
- use the IP shown by the Cardputer in `m5_host`
- then run `Start Captive Portal`

### Remote exposure

- `UPnP NAT` can expose internal port `80` on a different reachable port such as `50080`
- `Reverse TCP Tunnel` depends on `tcp_host=` and `tcp_port=` in the device `config.txt`
- if the device shows `Error check TCP host in config file`, configure `tcp_host=` first

KOVIL MAP does not configure either of these modes. It only consumes the final reachable `Admin WebUI` endpoint.

## Imported Data

### Handshakes

Remote files matching:

```text
HS_*.pcap
```

are downloaded into:

```text
backend/data/m5evil/handshakes/
```

### RAW Sniffer

Remote files matching:

```text
RawSniff_*.pcap
```

from `/evil/sniffer` are downloaded into:

```text
backend/data/m5evil/rawsniffer/
```

### Master Sniffer

Remote files matching:

```text
masterSniffer_*.pcap
```

from `/evil/handshakes` are downloaded into:

```text
backend/data/m5evil/mastersniffer/
```

These files are treated as RAW captures, not as normal handshake captures.

### Wardrive

Remote files matching:

```text
*.csv
```

from the configured Wardrive path are downloaded into:

```text
backend/data/wardrive/
```

using this naming rule:

```text
m5evil__<remote_filename>.csv
```

That keeps multiple devices from colliding on the same local filename.

## Downstream Behavior

After an M5Evil sync succeeds:

- new handshake captures are included in the normal M5Evil fingerprint planning flow
- new `RawSniff_*.pcap` and `masterSniffer_*.pcap` are included in the unified RAW pipeline
- new Wardrive CSVs are picked up by the standard Wardrive loader and manifest sync
- the frontend receives the usual `data_update` refresh behavior

## Operator Notes

To use this flow:

1. enable `Admin WebUI` on the Cardputer
2. choose one reachability mode:
   - same-network WebUI, using the IP shown by the Cardputer on the current network and then running `Start Captive Portal`
   - remote exposure with the final NAT/tunnel endpoint
3. make sure the desktop app can reach the same `Admin WebUI` endpoint the Cardputer is exposing on that network path
4. configure host, port, and auth in Settings
5. click `Sync`

## Config Ownership

Device `config.txt` owns:

- `wifi_ssid`
- `wifi_password`
- `tcp_host`
- `tcp_port`
- `webpassword`

KOVIL MAP owns:

- `m5_host`
- `m5_port`
- `m5_web_protocol`
- `m5_admin_base_path`
- `m5_web_user`
- `m5_web_password`
- the internal Cardputer path defaults used for handshake, Wardrive, RAW Sniffer, and Master Sniffer discovery

Use `webpassword=...` on the device as the source of truth for the WebUI password. The app preset keeps `test` as the current operator default, but firmware docs/builds may differ.

## Related Docs

- [`../02-FEATURES/sync-remote.md`](../02-FEATURES/sync-remote.md)
- [`../07-OPERATIONS/remote-sync-howto.md`](../07-OPERATIONS/remote-sync-howto.md)
- [`../00-GETTING_STARTED/manual-import-layout.md`](../00-GETTING_STARTED/manual-import-layout.md)
