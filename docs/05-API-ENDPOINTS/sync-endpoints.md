# Sync Endpoints

These endpoints cover remote ingestion plus local sync configuration.

Base path:

```text
/api
```

## `POST /api/sync`

Starts a remote sync run.

What it does:

- runs the enabled remote sync targets sequentially
- currently supports `Pwnagotchi`, `M5Evil Cardputer`, and `Bruce`
- downloads new files for each target
- triggers downstream processing such as fingerprint planning, dataset reload, and RAW extraction when needed

Body:

```json
{
  "force": false,
  "pwn_force_sync": false,
  "m5_force_sync": false,
  "bruce_force_sync": false,
  "pwn_handshakes_process_id": "sync::pwnagotchi::...::handshakes",
  "m5_handshakes_process_id": "sync::m5::...::handshakes",
  "m5_rawsniffer_process_id": "sync::m5::...::rawsniffer",
  "m5_mastersniffer_process_id": "sync::m5::...::mastersniffer",
  "m5_wardrive_process_id": "sync::m5::...::wardrive",
  "bruce_handshakes_process_id": "sync::bruce::...::handshakes",
  "bruce_rawsniffer_process_id": "sync::bruce::...::rawsniffer",
  "bruce_wardrive_process_id": "sync::bruce::...::wardrive"
}
```

Field summary:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `force` | boolean | no | global force flag used as fallback when per-target force is not set |
| `pwn_force_sync` | boolean | no | per-target force for Pwnagotchi |
| `m5_force_sync` | boolean | no | per-target force for M5Evil |
| `bruce_force_sync` | boolean | no | per-target force for Bruce |
| `pwn_handshakes_process_id` | string | no | process ID used to stream Pwnagotchi sync progress into the Process panel |
| `m5_*_process_id` | string | no | process IDs used to stream M5Evil progress into the Process panel |
| `bruce_*_process_id` | string | no | process IDs used to stream Bruce progress into the Process panel |

Typical success shape:

```json
{
  "status": "success",
  "data": {
    "status": "success",
    "message": "Sync completed (Pwnagotchi + M5Evil + Bruce)",
    "details": {
      "sync_stages": {
        "remote_sync": {
          "status": "success"
        },
        "pwnagotchi_remote_sync": {
          "status": "success",
          "downloaded_handshakes": 4,
          "downloaded_wardrive_csvs": 0
        },
        "m5evil_remote_sync": {
          "status": "success",
          "downloaded_handshakes": 2,
          "downloaded_rawsniffer_pcaps": 3,
          "downloaded_mastersniffer_pcaps": 1,
          "downloaded_wardrive_csvs": 1
        },
        "bruce_remote_sync": {
          "status": "success",
          "downloaded_handshakes": 1,
          "downloaded_rawsniffer_pcaps": 2,
          "downloaded_wardrive_csvs": 1
        }
      }
    }
  }
}
```

Notes:

- `Pwnagotchi` uses `SSH/SFTP`
- `M5Evil` uses `Admin WebUI`
- `Bruce` uses `WebUI`
- `m5evil_remote_sync` refers to the Admin WebUI import stage, not an SSH transfer
- `bruce_remote_sync` refers to the Bruce WebUI import stage

## `GET /api/config`

Returns the current local configuration in a client-safe format.

Example:

```json
{
  "status": "success",
  "data": {
    "pwn_host": "10.0.0.2",
    "pwn_user": "pi",
    "pwn_pass_configured": true,
    "remote_path": "/home/pi/handshakes",
    "m5_sync_enabled": true,
    "m5_host": "192.168.0.6",
    "m5_port": 80,
    "m5_web_protocol": "http",
    "m5_admin_base_path": "/evil-menu",
    "m5_web_user": "evil",
    "m5_web_password_configured": true,
    "m5_handshake_remote_path": "evil/handshakes",
    "m5_wardrive_remote_path": "evil/wardriving",
    "bruce_sync_enabled": true,
    "bruce_force_sync": false,
    "bruce_host": "bruce.local",
    "bruce_port": 80,
    "bruce_web_protocol": "http",
    "bruce_web_user": "admin",
    "bruce_web_password_configured": true,
    "ssh_known_hosts_path": "/Users/user/.ssh/known_hosts"
  }
}
```

Important notes:

- `pwn_pass` is not returned by the API
- `m5_web_password` is not returned by the API
- `bruce_web_password` is not returned by the API
- `m5_web_password_configured` indicates whether an Admin WebUI password is already stored locally
- `bruce_web_password_configured` indicates whether a Bruce WebUI password is already stored locally

## `PUT /api/config`

Updates local sync and tool configuration.

Typical body:

```json
{
  "pwn_host": "10.0.0.2",
  "pwn_user": "pi",
  "pwn_pass": "new_password",
  "remote_path": "/root/handshakes",
  "m5_sync_enabled": true,
  "m5_host": "192.168.0.6",
  "m5_port": 80,
  "m5_web_protocol": "http",
  "m5_admin_base_path": "/evil-menu",
  "m5_web_user": "evil",
  "m5_web_password": "test",
  "m5_handshake_remote_path": "evil/handshakes",
  "m5_wardrive_remote_path": "evil/wardriving",
  "bruce_sync_enabled": true,
  "bruce_force_sync": false,
  "bruce_host": "bruce.local",
  "bruce_port": 80,
  "bruce_web_protocol": "http",
  "bruce_web_user": "admin",
  "bruce_web_password": "bruce"
}
```

Notes:

- the backend validates and normalizes supported config fields
- the sync service reloads the new configuration immediately
- the response is sanitized in the same way as `GET /api/config`

## `POST /api/sync/trust-host-key`

Trusts or replaces an SSH host key for the Pwnagotchi SSH profile.

Body:

```json
{
  "host": "10.0.0.2",
  "port": 22,
  "replace": false
}
```

Field summary:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `host` | string | no | override host; if omitted, the backend resolves it from the SSH profile |
| `port` | integer | no | override port; if omitted, the backend resolves it from the SSH profile |
| `replace` | boolean | no | when `true`, replaces a mismatched key already stored in `known_hosts` |

Notes:

- this endpoint is for the `Pwnagotchi` SSH flow
- `M5Evil` does not use host-key trust in the current web-based transport

## `POST /api/sync/pwnagotchi/probe`

Validates the configured `Pwnagotchi SSH` endpoint without downloading files.

Typical body:

```json
{
  "pwn_host": "10.0.0.2",
  "pwn_port": 22,
  "pwn_user": "pi",
  "pwn_pass": "raspberry",
  "remote_path": "/home/pi/handshakes"
}
```

What it checks:

- SSH reachability
- authentication
- host-key trust state
- remote path accessibility

Important notes:

- this is the endpoint behind the `TEST CONNECTION` button in `PWNAGOTCHI SSH SYNC`
- the recommended setup is SSH over the USB-mapped network interface exposed by the device
- error details may distinguish between `auth_failed`, `ssh_host_key_not_trusted`, `ssh_host_key_mismatch`, `path_not_found`, and generic reachability failures

## `POST /api/sync/m5evil/probe`

Validates the configured `M5Evil Admin WebUI` endpoint without importing files.

Typical body:

```json
{
  "m5_host": "192.168.0.6",
  "m5_port": 80,
  "m5_web_protocol": "http",
  "m5_admin_base_path": "/evil-menu",
  "m5_web_user": "evil",
  "m5_web_password": "test",
  "m5_handshake_remote_path": "evil/handshakes",
  "m5_wardrive_remote_path": "evil/wardriving"
}
```

What it checks:

- endpoint reachability
- HTTP Basic Auth
- `Browse SD` parseability
- handshake, RAW Sniffer, and Wardrive path availability

Important notes:

- the normal workflow is using the IP shown by the Cardputer after it joins the same network as the desktop
- the inline success feedback in the Settings modal reports handshake, RAW Sniffer, Master Sniffer, and Wardrive counts
- error details may include probe phases such as `connection`, `auth`, `browse_root`, or `path`

## `POST /api/sync/bruce/probe`

Validates the configured `Bruce WebUI` endpoint without importing files.

Typical body:

```json
{
  "bruce_host": "bruce.local",
  "bruce_port": 80,
  "bruce_web_protocol": "http",
  "bruce_web_user": "admin",
  "bruce_web_password": "bruce"
}
```

What it checks:

- endpoint reachability
- HTTP Basic Auth
- fixed handshake path availability (`/BrucePCAP/handshakes`)
- fixed RAW path availability (`/BrucePCAP`)
- fixed Wardrive path availability (`/BruceWardriving`)

Important notes:

- this is the endpoint behind the `TEST CONNECTION` button in `BRUCE WEBUI`
- Bruce remote paths are fixed in backend code and not configurable in Settings

## Related WebSocket Events

During or after sync, the backend may emit:

### `data_update`

Signals that new files were processed and the dataset should be refreshed.

### `job_progress`

If sync starts RAW extraction jobs, they are reported through the normal job stream.
