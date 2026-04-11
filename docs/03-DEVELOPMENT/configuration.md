# Configuration & Environment

KOVIL MAP is configured through environment variables and a persistent JSON file for tool paths and user preferences.

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `KOVIL_API_TOKEN` | API and WebSocket token used by the desktop shell and any external client. | unset |
| `KOVIL_REQUIRE_API_TOKEN` | Forces token auth in development when set to `1/true/on`. | unset |
| `KOVIL_ALLOW_INSECURE_NO_AUTH` | Explicitly disables auth even if packaged runtime or require-token mode would enable it. Dev-only escape hatch. | unset |
| `KOVIL_ALLOW_LOCALHOST_CORS` | Re-enables localhost browser CORS in packaged runtime for debugging scenarios. | unset |
| `PORT` | Uvicorn listen port | `8000` |
| `HOST` | bind host | `127.0.0.1` |

### Protected Mode

```bash
# Linux/macOS
export KOVIL_API_TOKEN="your-secret-token"
python main.py

# Windows PowerShell
$env:KOVIL_API_TOKEN="your-secret-token"
python main.py
```

---

## `config.json`

Persistent settings live in `backend/config.json`. The repository keeps a sanitized starter version, and local edits may introduce sensitive values on your machine.

Example:

```json
{
  "pwn_host": "",
  "pwn_port": 22,
  "pwn_user": "pi",
  "pwn_pass": "",
  "remote_path": "/home/pi/handshakes",
  "m5_sync_enabled": false,
  "m5_host": "",
  "m5_port": 80,
  "m5_web_protocol": "http",
  "m5_admin_base_path": "/evil-menu",
  "m5_web_user": "evil",
  "m5_web_password": "",
  "m5_handshake_remote_path": "evil/handshakes",
  "m5_wardrive_remote_path": "evil/wardriving",
  "hashcat_path": "hashcat",
  "hcxpcapngtool_path": "hcxpcapngtool",
  "aircrack_path": "aircrack-ng",
  "tshark_path": "tshark",
  "custom_wordlists_path": "",
  "custom_rules_path": "",
  "custom_masks_path": "",
  "ssh_known_hosts_path": "",
  "use_wsl": false,
  "hashcat_optimized": true,
  "hashcat_potfile": true,
  "hashcat_slow": false,
  "hashcat_device_default": "all",
  "ui_visual_theme": "professional",
  "ui_theme": "slate",
  "ui_icon_pwned": "fa-skull",
  "ui_icon_locked": "fa-shield-halved",
  "ui_icon_wardrive": "fa-tower-broadcast",
  "ui_wardrive_color": "teal",
  "ui_wardrive_style": "icon",
  "ui_cracking_accordion_mode": "multi",
  "ui_wardrive_replay_speed_default": "1",
  "ui_wardrive_replay_follow_camera_default": false,
  "ui_wardrive_replay_follow_zoom_default": "current",
  "ui_wardrive_replay_timing_mode_default": "real_time"
}
```

### Key fields

- remote sync (Pwnagotchi): `pwn_host`, `pwn_user`, `pwn_pass`, `remote_path`
- remote sync (M5Evil Cardputer): `m5_sync_enabled`, `m5_host`, `m5_port`, `m5_web_protocol`, `m5_admin_base_path`, `m5_web_user`, `m5_web_password`, `m5_handshake_remote_path`, `m5_wardrive_remote_path`
- shared sync trust: `ssh_known_hosts_path`
- external tools: `hashcat_path`, `tshark_path`, `use_wsl`
- custom resources: `custom_wordlists_path`, `custom_rules_path`, `custom_masks_path`
- Hashcat tuning: `hashcat_optimized`, `hashcat_potfile`, `hashcat_slow`, `hashcat_device_default`
- UI theme: `ui_visual_theme`, `ui_theme`, `ui_icon_*`, `ui_wardrive_color`, `ui_wardrive_style`
- cracking workspace behavior: `ui_cracking_accordion_mode`
- WDrive replay defaults: `ui_wardrive_replay_speed_default`, `ui_wardrive_replay_follow_camera_default`, `ui_wardrive_replay_follow_zoom_default`, `ui_wardrive_replay_timing_mode_default`

### Config API behavior

`GET /api/config` returns a sanitized client payload:

- `pwn_pass` is never returned to the renderer
- `pwn_pass_configured` indicates whether a password is already stored locally
- `m5_web_password` is never returned to the renderer
- `m5_web_password_configured` indicates whether an Admin WebUI password is already stored locally
- `PUT /api/config` still accepts `pwn_pass` updates when you want to replace the stored value
- the current renderer keeps the Cardputer base path and SD paths as fixed defaults even though the backend config schema still accepts them

---

## Security Notes

1. `config.json` may contain sensitive credentials after local edits, so restrict file access.
2. Avoid running the app as Administrator or root.
3. In packaged runtime, token auth is expected by default. In development, set `KOVIL_API_TOKEN` or `KOVIL_REQUIRE_API_TOKEN=1` when exposing the API beyond localhost.
