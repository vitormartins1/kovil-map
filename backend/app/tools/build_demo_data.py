from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import shutil
import struct
from pathlib import Path

from app.utils.handshake_artifacts import create_combined_build_id

PROFILE_ID = "showcase-core-v1"
PROFILE_LABEL = "Showcase Core v1"
PROFILE_DESCRIPTION = (
    "Synthetic Rio de Janeiro showcase dataset for onboarding, screenshots, "
    "WarDrive replay, handshake workflows, Batch, Raw Sniffer, and demo cracking."
)
PROFILE_VERSION = 1
BUILD_STAMP = "2026-04-12T00:00:00Z"

BACKEND_ROOT = Path(__file__).resolve().parents[2]
PACK_ROOT = BACKEND_ROOT / "demo_data" / PROFILE_ID
RUNTIME_ROOT = PACK_ROOT / "runtime"

PCAP_LINKTYPE_IEEE80211 = 105
PCAP_MAGIC_LE = 0xA1B2C3D4
PCAP_SNAPLEN = 65535

WIGLE_COLUMNS = [
    "MAC",
    "SSID",
    "AuthMode",
    "FirstSeen",
    "LastSeen",
    "Channel",
    "Frequency",
    "RSSI",
    "CurrentLatitude",
    "CurrentLongitude",
    "AltitudeMeters",
    "AccuracyMeters",
    "Type",
]


NETWORKS = {
    "rio_cafe_loop": {
        "ssid": "RIO_CAFE_LOOP",
        "bssid": "02:11:22:33:44:50",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "cafeloop2026",
        "category": "easy_dictionary",
        "vendor": "RioSignals Labs",
        "channel": 6,
        "frequency": 2437,
        "lat": -22.91342,
        "lng": -43.18215,
        "altitude": 11.5,
        "accuracy": 6.2,
        "device_type": "router",
        "device_confidence": 0.94,
    },
    "lapa_event_guest": {
        "ssid": "LAPA_EVENT_GUEST",
        "bssid": "06:11:22:33:44:51",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "carioca2026",
        "category": "already_cracked",
        "vendor": "Festival Mesh",
        "channel": 11,
        "frequency": 2462,
        "lat": -22.91389,
        "lng": -43.18284,
        "altitude": 13.2,
        "accuracy": 5.9,
        "device_type": "router",
        "device_confidence": 0.91,
    },
    "metro_line_4": {
        "ssid": "METRO_LINE_4",
        "bssid": "0A:11:22:33:44:52",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "20262026",
        "category": "digits_mask",
        "vendor": "Transit Systems",
        "channel": 1,
        "frequency": 2412,
        "lat": -22.90811,
        "lng": -43.19688,
        "altitude": 9.4,
        "accuracy": 8.8,
        "device_type": "router",
        "device_confidence": 0.9,
    },
    "ops_truck_alpha": {
        "ssid": "OPS-TRUCK-ALPHA",
        "bssid": "0E:11:22:33:44:53",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "ops-truck-alpha",
        "category": "association_hint",
        "vendor": "FieldOps Devices",
        "channel": 36,
        "frequency": 5180,
        "lat": -22.90081,
        "lng": -43.29358,
        "altitude": 16.1,
        "accuracy": 7.4,
        "device_type": "vehicular_hotspot",
        "device_confidence": 0.88,
    },
    "nogps_lab_01": {
        "ssid": "NOGPS_LAB_01",
        "bssid": "02:AA:11:22:33:54",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "lab-3301",
        "category": "no_gps_only",
        "vendor": "LabNet",
        "channel": 44,
        "frequency": 5220,
        "lat": -22.90255,
        "lng": -43.30112,
        "altitude": 18.0,
        "accuracy": 7.8,
        "device_type": "router",
        "device_confidence": 0.85,
    },
    "hidden_relay_07": {
        "ssid": "",
        "bssid": "06:AA:11:22:33:55",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "relay-hidden-07",
        "category": "not_ready",
        "vendor": "Relay Nodes",
        "channel": 149,
        "frequency": 5745,
        "lat": -22.90212,
        "lng": -43.29784,
        "altitude": 18.4,
        "accuracy": 8.4,
        "device_type": "bridge",
        "device_confidence": 0.83,
    },
    "open_sensor_mesh": {
        "ssid": "OPEN_SENSOR_MESH",
        "bssid": "0A:AA:11:22:33:56",
        "auth_mode": "[ESS]",
        "encryption": "OPEN",
        "password": "",
        "category": "open",
        "vendor": "Municipal Sensors",
        "channel": 3,
        "frequency": 2422,
        "lat": -22.91471,
        "lng": -43.17598,
        "altitude": 12.0,
        "accuracy": 6.7,
        "device_type": "iot_gateway",
        "device_confidence": 0.8,
    },
    "copa_media_node": {
        "ssid": "COPA_MEDIA_NODE",
        "bssid": "0E:AA:11:22:33:57",
        "auth_mode": "[WPA3-SAE-CCMP][ESS]",
        "encryption": "WPA3",
        "password": "media-node-rio",
        "category": "wardrive_only",
        "vendor": "MediaCast",
        "channel": 149,
        "frequency": 5745,
        "lat": -22.97164,
        "lng": -43.18247,
        "altitude": 14.2,
        "accuracy": 5.2,
        "device_type": "router",
        "device_confidence": 0.82,
    },
    "rj_city_iot": {
        "ssid": "RJ_CITY_IOT",
        "bssid": "02:BB:11:22:33:58",
        "auth_mode": "[WEP][ESS]",
        "encryption": "WEP",
        "password": "cityiot58",
        "category": "wardrive_only",
        "vendor": "City Infrastructure",
        "channel": 9,
        "frequency": 2452,
        "lat": -22.91735,
        "lng": -43.17012,
        "altitude": 8.8,
        "accuracy": 9.1,
        "device_type": "iot_gateway",
        "device_confidence": 0.76,
    },
    "porto_link_backhaul": {
        "ssid": "PORTO_LINK_BACKHAUL",
        "bssid": "06:BB:11:22:33:59",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "backhaul-porto",
        "category": "wardrive_only",
        "vendor": "PortLink",
        "channel": 157,
        "frequency": 5785,
        "lat": -22.89761,
        "lng": -43.17926,
        "altitude": 10.8,
        "accuracy": 8.3,
        "device_type": "bridge",
        "device_confidence": 0.79,
    },
}

HANDSHAKE_CAPTURES = [
    {
        "id": "pwn_rio_cafe",
        "network_id": "rio_cafe_loop",
        "source": "pwnagotchi",
        "role": "handshakes",
        "root": "handshakes",
        "filename": "RIO_CAFE_LOOP_021122334450.pcap",
        "gps": True,
        "legacy_sidecars": True,
    },
    {
        "id": "bruce_rio_cafe",
        "network_id": "rio_cafe_loop",
        "source": "brucegotchi",
        "role": "bruce_handshakes",
        "root": "BrucePCAP/handshakes",
        "filename": "HS_021122334450_rio_cafe_loop_bruce.pcap",
        "gps": False,
        "legacy_sidecars": False,
    },
    {
        "id": "m5_rio_cafe",
        "network_id": "rio_cafe_loop",
        "source": "m5evil",
        "role": "m5evil_handshakes",
        "root": "m5evil/handshakes",
        "filename": "HS_021122334450_rio_cafe_loop_m5evil.pcap",
        "gps": False,
        "legacy_sidecars": False,
    },
    {
        "id": "pwn_lapa_event",
        "network_id": "lapa_event_guest",
        "source": "pwnagotchi",
        "role": "handshakes",
        "root": "handshakes",
        "filename": "LAPA_EVENT_GUEST_061122334451.pcap",
        "gps": True,
        "legacy_sidecars": True,
        "cracked": True,
    },
    {
        "id": "bruce_metro",
        "network_id": "metro_line_4",
        "source": "brucegotchi",
        "role": "bruce_handshakes",
        "root": "BrucePCAP/handshakes",
        "filename": "HS_0A1122334452_metro_line_4_bruce.pcap",
        "gps": False,
        "legacy_sidecars": False,
    },
    {
        "id": "m5_ops_truck",
        "network_id": "ops_truck_alpha",
        "source": "m5evil",
        "role": "m5evil_handshakes",
        "root": "m5evil/handshakes",
        "filename": "HS_0E1122334453_ops_truck_alpha_m5evil.pcap",
        "gps": False,
        "legacy_sidecars": False,
    },
    {
        "id": "m5_nogps_lab",
        "network_id": "nogps_lab_01",
        "source": "m5evil",
        "role": "m5evil_handshakes",
        "root": "m5evil/handshakes",
        "filename": "HS_02AA11223354_nogps_lab_01_m5evil.pcap",
        "gps": False,
        "legacy_sidecars": False,
    },
    {
        "id": "pwn_hidden_relay",
        "network_id": "hidden_relay_07",
        "source": "pwnagotchi",
        "role": "handshakes",
        "root": "handshakes",
        "filename": "hidden_06AA11223355.pcap",
        "gps": False,
        "legacy_sidecars": True,
        "hash_ready": False,
    },
]

RAW_CAPTURES = [
    {
        "id": "bruce_raw_rio",
        "source": "brucegotchi",
        "device_label": "Bruce",
        "source_path_role": "rawsniffer",
        "root": "BrucePCAP/rawsniffer",
        "filename": "rio_bruce_patrol.pcap",
        "networks": ["rio_cafe_loop", "lapa_event_guest"],
        "clients": ["1A:2B:3C:4D:5E:60", "1A:2B:3C:4D:5E:61"],
    },
    {
        "id": "m5_raw_rio",
        "source": "m5evil",
        "device_label": "M5Evil",
        "source_path_role": "rawsniffer",
        "root": "m5evil/rawsniffer",
        "filename": "rio_m5_raw_patrol.pcap",
        "networks": ["metro_line_4", "ops_truck_alpha"],
        "clients": ["2A:3B:4C:5D:6E:70", "2A:3B:4C:5D:6E:71"],
    },
    {
        "id": "m5_master_rio",
        "source": "m5evil",
        "device_label": "M5Evil",
        "source_path_role": "master_sniffer",
        "root": "m5evil/mastersniffer",
        "filename": "rio_master_patrol.pcap",
        "networks": ["nogps_lab_01", "hidden_relay_07"],
        "clients": ["3A:4B:5C:6D:7E:80", "3A:4B:5C:6D:7E:81"],
    },
]

WARDRIVE_SESSIONS = [
    {
        "filename": "20260411_001500_wardriving.csv",
        "header": "WigleWifi-1.4,appRelease=1.0,brand=Bruce",
        "points": [
            ("rio_cafe_loop", "2026-04-11T00:15:00", "2026-04-11T00:15:08", -67, -22.91342, -43.18215),
            ("lapa_event_guest", "2026-04-11T00:17:10", "2026-04-11T00:17:18", -61, -22.91389, -43.18284),
            ("open_sensor_mesh", "2026-04-11T00:19:35", "2026-04-11T00:19:42", -72, -22.91471, -43.17598),
            ("rj_city_iot", "2026-04-11T00:21:12", "2026-04-11T00:21:18", -74, -22.91735, -43.17012),
            ("porto_link_backhaul", "2026-04-11T00:23:44", "2026-04-11T00:23:53", -68, -22.89761, -43.17926),
        ],
    },
    {
        "filename": "m5evil__20260411_003000_wardriving.csv",
        "header": "WigleWifi-1.4,appRelease=1.0,device=Evil-Cardputer,model=cardputer",
        "points": [
            ("metro_line_4", "2026-04-11T00:30:00", "2026-04-11T00:30:12", -65, -22.90811, -43.19688),
            ("ops_truck_alpha", "2026-04-11T00:33:18", "2026-04-11T00:33:24", -58, -22.90081, -43.29358),
            ("nogps_lab_01", "2026-04-11T00:36:05", "2026-04-11T00:36:11", -64, -22.90255, -43.30112),
            ("hidden_relay_07", "2026-04-11T00:38:51", "2026-04-11T00:38:56", -69, -22.90212, -43.29784),
        ],
    },
    {
        "filename": "20260411_010500_wardriving.csv",
        "header": "WigleWifi-1.4,appRelease=1.0,brand=Bruce",
        "points": [
            ("copa_media_node", "2026-04-11T01:05:00", "2026-04-11T01:05:10", -59, -22.97164, -43.18247),
            ("rio_cafe_loop", "2026-04-11T01:11:12", "2026-04-11T01:11:20", -66, -22.91340, -43.18209),
            ("metro_line_4", "2026-04-11T01:14:34", "2026-04-11T01:14:41", -63, -22.90816, -43.19690),
            ("porto_link_backhaul", "2026-04-11T01:20:55", "2026-04-11T01:21:03", -70, -22.89758, -43.17922),
        ],
    },
]

UI_SEED = {
    "lists": {
        "targets": [
            NETWORKS["rio_cafe_loop"]["bssid"],
            NETWORKS["metro_line_4"]["bssid"],
            NETWORKS["ops_truck_alpha"]["bssid"],
        ],
        "favs": [
            NETWORKS["lapa_event_guest"]["bssid"],
            NETWORKS["copa_media_node"]["bssid"],
        ],
    },
    "modes": {
        "zones": True,
        "conquered": True,
        "toConquer": False,
        "discovered": False,
        "intelligence": False,
        "targets": True,
        "favs": True,
        "process": True,
        "logs": True,
    },
}


def _json_dump(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _mac_clean(mac: str) -> str:
    return str(mac or "").replace(":", "").lower()


def _mac_bytes(mac: str) -> bytes:
    return bytes.fromhex(_mac_clean(mac))


def _ssid_hex(ssid: str) -> str:
    return str(ssid or "").encode("utf-8").hex()


def _safe_stem(value: str) -> str:
    stem = Path(value).stem
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", stem).strip("._") or "capture"


def _capture_id(source: str, role: str, filename: str) -> str:
    digest = hashlib.sha1(
        f"{source}|{role}|{Path(filename).name}".encode("utf-8")
    ).hexdigest()[:16]
    return f"{source}-{role}-{digest}"


def _raw_item_id(
    artifact_type: str,
    source: str,
    source_path_role: str,
    filename: str,
    *,
    source_raw_file: str | None = None,
) -> str:
    digest = hashlib.sha1(
        "|".join(
            [
                str(artifact_type or "").strip().lower(),
                str(source or "").strip().lower(),
                str(source_path_role or "").strip().lower(),
                Path(filename).name.lower(),
                Path(str(source_raw_file or filename)).name.lower(),
            ]
        ).encode("utf-8")
    ).hexdigest()[:16]
    return f"raw::{str(artifact_type or '').strip().lower()}::{digest}"


def _pcap_global_header(linktype: int = PCAP_LINKTYPE_IEEE80211) -> bytes:
    return struct.pack(
        "<IHHIIII",
        PCAP_MAGIC_LE,
        2,
        4,
        0,
        0,
        PCAP_SNAPLEN,
        linktype,
    )


def _pcap_packet(ts_sec: int, ts_usec: int, payload: bytes) -> bytes:
    return struct.pack("<IIII", ts_sec, ts_usec, len(payload), len(payload)) + payload


def _mgmt_header(fc: bytes, addr1: str, addr2: str, addr3: str, seq: int) -> bytes:
    seq_ctrl = struct.pack("<H", (seq & 0xFFF) << 4)
    return (
        fc
        + b"\x00\x00"
        + _mac_bytes(addr1)
        + _mac_bytes(addr2)
        + _mac_bytes(addr3)
        + seq_ctrl
    )


def _beacon_frame(bssid: str, ssid: str, channel: int, seq: int) -> bytes:
    header = _mgmt_header(
        b"\x80\x00",
        "ff:ff:ff:ff:ff:ff",
        bssid,
        bssid,
        seq,
    )
    fixed = b"\x00" * 8 + b"\x64\x00" + b"\x31\x04"
    ssid_bytes = str(ssid or "").encode("utf-8")
    tags = (
        b"\x00" + bytes([len(ssid_bytes)]) + ssid_bytes
        + b"\x01\x04\x82\x84\x8b\x96"
        + b"\x03\x01" + bytes([int(channel or 1) & 0xFF])
    )
    return header + fixed + tags


def _probe_request_frame(client_mac: str, ssid: str, seq: int) -> bytes:
    header = _mgmt_header(
        b"\x40\x00",
        "ff:ff:ff:ff:ff:ff",
        client_mac,
        "ff:ff:ff:ff:ff:ff",
        seq,
    )
    ssid_bytes = str(ssid or "").encode("utf-8")
    tags = (
        b"\x00" + bytes([len(ssid_bytes)]) + ssid_bytes
        + b"\x01\x04\x82\x84\x8b\x96"
    )
    return header + tags


def _deauth_frame(bssid: str, client_mac: str, seq: int, reason: int = 7) -> bytes:
    header = _mgmt_header(b"\xc0\x00", client_mac, bssid, bssid, seq)
    return header + struct.pack("<H", int(reason))


def _disassoc_frame(
    bssid: str, client_mac: str, seq: int, reason: int = 8
) -> bytes:
    header = _mgmt_header(b"\xa0\x00", client_mac, bssid, bssid, seq)
    return header + struct.pack("<H", int(reason))


def _write_pcap(path: Path, frames: list[tuple[int, int, bytes]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(_pcap_global_header())
        for ts_sec, ts_usec, payload in frames:
            handle.write(_pcap_packet(ts_sec, ts_usec, payload))


def _build_demo_frames(network_ids: list[str], clients: list[str]) -> list[tuple[int, int, bytes]]:
    frames: list[tuple[int, int, bytes]] = []
    ts_base = 1_744_328_400
    seq = 1
    for idx, network_id in enumerate(network_ids):
        network = NETWORKS[network_id]
        bssid = network["bssid"]
        channel = int(network["channel"])
        ssid = network["ssid"]
        client = clients[idx % len(clients)]
        frames.append((ts_base + idx * 7, 0, _beacon_frame(bssid, ssid, channel, seq)))
        seq += 1
        frames.append(
            (ts_base + idx * 7 + 1, 0, _probe_request_frame(client, ssid, seq))
        )
        seq += 1
        frames.append((ts_base + idx * 7 + 2, 0, _deauth_frame(bssid, client, seq)))
        seq += 1
        frames.append((ts_base + idx * 7 + 3, 0, _disassoc_frame(bssid, client, seq)))
        seq += 1
    return frames


def _details_payload(network_id: str, *, source: str) -> dict:
    network = NETWORKS[network_id]
    ssid = network["ssid"]
    return {
        "ssid": ssid,
        "bssid": network["bssid"],
        "vendor": network["vendor"],
        "security": {
            "wpa_version": network["encryption"],
            "auth_mode": network["auth_mode"],
            "handshake_available": network["category"] != "not_ready",
            "pmkid_available": False,
        },
        "classification": {
            "type": network["device_type"],
            "confidence": network["device_confidence"],
        },
        "radio": {
            "channel": network["channel"],
            "band": "5GHz" if int(network["frequency"]) >= 5000 else "2.4GHz",
            "frequency_mhz": network["frequency"],
        },
        "wps": {"present": False},
        "demo": {
            "profile_id": PROFILE_ID,
            "source": source,
            "category": network["category"],
        },
    }


def _gps_payload(network_id: str, *, capture_filename: str) -> dict:
    network = NETWORKS[network_id]
    return {
        "SSID": network["ssid"],
        "BSSID": network["bssid"],
        "Latitude": network["lat"],
        "Longitude": network["lng"],
        "Accuracy": network["accuracy"],
        "Updated": "2026-04-11T00:00:00+00:00",
        "source_file": capture_filename,
        "demo_profile": PROFILE_ID,
    }


def _hash_line(network_id: str, *, suffix: str) -> str:
    network = NETWORKS[network_id]
    digest = hashlib.sha1(f"{PROFILE_ID}|{network_id}|{suffix}".encode("utf-8")).hexdigest()[
        :32
    ]
    client_mac = hashlib.sha1(f"{network_id}|client".encode("utf-8")).hexdigest()[:12]
    return (
        f"WPA*02*{digest}*{_mac_clean(network['bssid'])}*{client_mac}"
        f"*{_ssid_hex(network['ssid']) or '00'}*00"
    )


def _write_wardrive_csv(path: Path, header: str, points: list[tuple[str, str, str, int, float, float]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(f"{header}\n")
        writer = csv.DictWriter(handle, fieldnames=WIGLE_COLUMNS)
        writer.writeheader()
        for network_id, first_seen, last_seen, rssi, lat, lng in points:
            network = NETWORKS[network_id]
            writer.writerow(
                {
                    "MAC": network["bssid"],
                    "SSID": network["ssid"],
                    "AuthMode": network["auth_mode"],
                    "FirstSeen": first_seen,
                    "LastSeen": last_seen,
                    "Channel": network["channel"],
                    "Frequency": network["frequency"],
                    "RSSI": rssi,
                    "CurrentLatitude": lat,
                    "CurrentLongitude": lng,
                    "AltitudeMeters": network["altitude"],
                    "AccuracyMeters": network["accuracy"],
                    "Type": "WIFI",
                }
            )


def _build_capture_assets(runtime_root: Path) -> dict:
    captures = []
    combined_capture_ids = []
    combined_lines = []

    for spec in HANDSHAKE_CAPTURES:
        network_id = spec["network_id"]
        network = NETWORKS[network_id]
        filename = spec["filename"]
        source = spec["source"]
        role = spec["role"]
        capture_id = _capture_id(source, role, filename)
        capture_root = runtime_root / spec["root"]
        pcap_path = capture_root / filename
        frames = _build_demo_frames([network_id], ["6A:7B:8C:9D:AE:10"])
        _write_pcap(pcap_path, frames)

        line = _hash_line(network_id, suffix=filename)
        captures_dir = runtime_root / "handshakes" / "captures" / capture_id
        captures_dir.mkdir(parents=True, exist_ok=True)
        _json_dump(
            captures_dir / "manifest.json",
            {
                "artifact_scope": "capture",
                "capture_id": capture_id,
                "demo_profile": PROFILE_ID,
                "mac": network["bssid"],
                "network_id": network_id,
                "source": source,
                "source_filename": filename,
                "source_path_role": role,
                "ssid": network["ssid"],
                "version": 1,
            },
        )
        _json_dump(captures_dir / "capture.details", _details_payload(network_id, source=source))
        if spec.get("hash_ready", True):
            (captures_dir / "capture.22000").write_text(f"{line}\n", encoding="utf-8")
        if spec.get("cracked"):
            (captures_dir / "capture.cracked").write_text(
                f"{network['password']}\n", encoding="utf-8"
            )
        (captures_dir / "capture.try").write_text(
            f"demo::{network_id}::{source}\n", encoding="utf-8"
        )

        if spec.get("legacy_sidecars"):
            base_name = Path(filename).stem
            _json_dump(runtime_root / "handshakes" / f"{base_name}.details", _details_payload(network_id, source=source))
            if spec.get("gps"):
                _json_dump(runtime_root / "handshakes" / f"{base_name}.paw-gps.json", _gps_payload(network_id, capture_filename=filename))
            if spec.get("hash_ready", True):
                (runtime_root / "handshakes" / f"{base_name}.22000").write_text(
                    f"{line}\n", encoding="utf-8"
                )
            if spec.get("cracked"):
                (runtime_root / "handshakes" / f"{base_name}.pcap.cracked").write_text(
                    f"{network['password']}\n", encoding="utf-8"
                )
            (runtime_root / "handshakes" / f"{base_name}.try").write_text(
                f"demo::{network_id}::{source}\n", encoding="utf-8"
            )

        capture_record = {
            "capture_id": capture_id,
            "network_id": network_id,
            "source": source,
            "role": role,
            "filename": filename,
            "pcap_path": str(pcap_path.relative_to(runtime_root)),
            "hash_ready": bool(spec.get("hash_ready", True)),
            "cracked": bool(spec.get("cracked", False)),
        }
        captures.append(capture_record)

        if network_id == "rio_cafe_loop" and spec.get("hash_ready", True):
            combined_capture_ids.append(capture_id)
            combined_lines.append(line)

    build_id = create_combined_build_id(combined_capture_ids)
    combined_dir = (
        runtime_root
        / "handshakes"
        / "combined"
        / _mac_clean(NETWORKS["rio_cafe_loop"]["bssid"])
        / build_id
    )
    combined_dir.mkdir(parents=True, exist_ok=True)
    unique_lines = []
    seen = set()
    for line in combined_lines:
        if line in seen:
            continue
        seen.add(line)
        unique_lines.append(line)
    (combined_dir / "combined.22000").write_text(
        "\n".join(unique_lines) + "\n", encoding="utf-8"
    )
    _json_dump(
        combined_dir / "manifest.json",
        {
            "build_id": build_id,
            "created_at": BUILD_STAMP,
            "demo_profile": PROFILE_ID,
            "included_capture_ids": combined_capture_ids,
            "included_captures": [
                {
                    "capture_id": item["capture_id"],
                    "source": item["source"],
                    "source_filename": item["filename"],
                }
                for item in captures
                if item["capture_id"] in combined_capture_ids
            ],
            "mac": NETWORKS["rio_cafe_loop"]["bssid"],
        },
    )

    batch_name = "batch_showcase_core_v1.22000"
    batch_items = [
        next(item for item in captures if item["network_id"] == "lapa_event_guest"),
        next(item for item in captures if item["network_id"] == "rio_cafe_loop"),
        next(item for item in captures if item["network_id"] == "metro_line_4"),
    ]
    batch_lines = [
        _hash_line(item["network_id"], suffix=item["filename"]) for item in batch_items
    ]
    (runtime_root / "handshakes" / batch_name).write_text(
        "\n".join(batch_lines) + "\n", encoding="utf-8"
    )
    _json_dump(
        runtime_root / "handshakes" / f"{batch_name}.batch.json",
        {
            "demo_profile": PROFILE_ID,
            "items": [
                {
                    "capture_id": item["capture_id"],
                    "filename": item["filename"],
                    "mac": NETWORKS[item["network_id"]]["bssid"],
                    "network_id": item["network_id"],
                    "original_filename": item["filename"],
                    "source": item["source"],
                    "ssid": NETWORKS[item["network_id"]]["ssid"],
                }
                for item in batch_items
            ],
        },
    )

    return {
        "captures": captures,
        "combined_build_id": build_id,
        "batch_name": batch_name,
    }


def _build_raw_assets(runtime_root: Path) -> dict:
    raw_records = []
    raw_hash_index = 1

    for spec in RAW_CAPTURES:
        root = runtime_root / spec["root"]
        filename = spec["filename"]
        pcap_path = root / filename
        frames = _build_demo_frames(spec["networks"], spec["clients"])
        _write_pcap(pcap_path, frames)
        stat = pcap_path.stat()
        raw_item_id = _raw_item_id(
            "pcap",
            spec["source"],
            spec["source_path_role"],
            filename,
            source_raw_file=filename,
        )

        safe_stem = _safe_stem(filename)
        digest = raw_item_id.rsplit("::", 1)[-1]
        metadata_dir = (
            runtime_root / "m5evil" / ".metadata"
            if spec["source"] == "m5evil"
            else runtime_root / "BrucePCAP" / ".metadata"
        )
        metadata_path = metadata_dir / (
            f"{spec['source']}__{spec['source_path_role']}__{filename}.json"
        )
        analysis_path = metadata_dir / f"analysis__{safe_stem}_{digest}.json"

        networks_payload = []
        top_clients = []
        handshake_candidates = []
        for idx, network_id in enumerate(spec["networks"]):
            network = NETWORKS[network_id]
            networks_payload.append(
                {
                    "bssid": network["bssid"],
                    "ssid": network["ssid"],
                    "ssid_raw_hex": _ssid_hex(network["ssid"]) or None,
                    "channel": network["channel"],
                    "frequency_mhz": network["frequency"],
                    "beacon_count": 12 + idx * 4,
                    "eapol_count": 2 if network["category"] != "not_ready" else 0,
                    "probe_client_count": 1 + idx,
                    "last_seen_offset_s": float(18 + idx * 11),
                }
            )
            handshake_candidates.append(
                {
                    "bssid": network["bssid"],
                    "ssid": network["ssid"],
                    "eapol_count": 2 if network["category"] != "not_ready" else 0,
                    "tier": "ready" if network["category"] != "not_ready" else "watch",
                }
            )
            top_clients.append(
                {
                    "mac": spec["clients"][idx % len(spec["clients"])],
                    "total_frames": 18 + idx * 7,
                    "network_count": 1,
                    "eapol_count": 2 if network["category"] != "not_ready" else 0,
                }
            )

            hash_name = f"raw_{raw_hash_index}.22000"
            raw_hash_index += 1
            (runtime_root / "handshakes" / hash_name).write_text(
                _hash_line(network_id, suffix=hash_name) + "\n", encoding="utf-8"
            )

        metadata_payload = {
            "schema_version": 1,
            "demo_profile": PROFILE_ID,
            "raw_item_id": raw_item_id,
            "source": spec["source"],
            "device_label": spec["device_label"],
            "source_path_role": spec["source_path_role"],
            "source_file": filename,
            "source_size": stat.st_size,
            "source_mtime": stat.st_mtime,
            "processed_at": BUILD_STAMP,
            "warnings": [],
            "stats": {
                "networks_count": len(networks_payload),
                "beacon_frames": sum(int(item["beacon_count"]) for item in networks_payload),
                "eapol_frames": sum(int(item["eapol_count"]) for item in networks_payload),
            },
            "networks": networks_payload,
        }
        _json_dump(metadata_path, metadata_payload)
        _json_dump(
            analysis_path,
            {
                "schema_version": 1,
                "demo_profile": PROFILE_ID,
                "raw_item_id": raw_item_id,
                "source": spec["source"],
                "device_label": spec["device_label"],
                "source_path_role": spec["source_path_role"],
                "source_file": filename,
                "source_size": stat.st_size,
                "source_mtime": stat.st_mtime,
                "processed_at": BUILD_STAMP,
                "capture": {
                    "duration_s": 72.0,
                    "networks_count": len(networks_payload),
                    "clients_count": len(top_clients),
                    "frame_totals": {
                        "beacons": sum(int(item["beacon_count"]) for item in networks_payload),
                        "eapol": sum(int(item["eapol_count"]) for item in networks_payload),
                        "probe_requests": len(top_clients) * 3,
                    },
                    "warnings": [],
                },
                "highlights": {
                    "handshake_candidate_count": len(handshake_candidates),
                    "handshake_candidates": handshake_candidates,
                    "top_networks": [
                        {
                            "bssid": item["bssid"],
                            "ssid": item["ssid"],
                            "beacon_count": item["beacon_count"],
                            "client_count": item["probe_client_count"],
                        }
                        for item in networks_payload
                    ],
                    "top_clients": top_clients,
                    "hidden_network_count": 1
                    if any(not NETWORKS[net]["ssid"] for net in spec["networks"])
                    else 0,
                    "revealed_hidden_count": 0,
                    "noisy_capture": False,
                },
            },
        )
        raw_records.append(
            {
                "raw_item_id": raw_item_id,
                "filename": filename,
                "source": spec["source"],
                "source_path_role": spec["source_path_role"],
                "networks": list(spec["networks"]),
            }
        )

    return {"raw_records": raw_records}


def _build_wardrive_assets(runtime_root: Path) -> dict:
    session_ids = []
    for session in WARDRIVE_SESSIONS:
        _write_wardrive_csv(
            runtime_root / "wardrive" / session["filename"],
            session["header"],
            session["points"],
        )
        session_ids.append(Path(session["filename"]).stem)
    return {"session_ids": session_ids}


def _build_wordlists(runtime_root: Path) -> dict:
    wordlists_dir = runtime_root / "demo_wordlists"
    wordlists_dir.mkdir(parents=True, exist_ok=True)

    easy_words = [
        "cafeloop2026",
        "carioca2026",
        "rio-cafe-loop",
        "ops-truck-alpha",
        "lab-3301",
    ]
    digits_words = [
        "20262026",
        "12345678",
        "01042026",
        "33013301",
    ]
    association_words = [
        "ops truck alpha",
        "ops-truck-alpha",
        "opstruckalpha",
        "metro line 4",
        "metro-line-4",
    ]

    (wordlists_dir / "demo_easy.txt").write_text(
        "\n".join(easy_words) + "\n", encoding="utf-8"
    )
    (wordlists_dir / "demo_digits.txt").write_text(
        "\n".join(digits_words) + "\n", encoding="utf-8"
    )
    (wordlists_dir / "demo_association.txt").write_text(
        "\n".join(association_words) + "\n", encoding="utf-8"
    )
    return {
        "files": [
            "demo_easy.txt",
            "demo_digits.txt",
            "demo_association.txt",
        ]
    }


def _build_manifest(runtime_root: Path, capture_meta: dict, raw_meta: dict, wardrive_meta: dict, wordlist_meta: dict) -> dict:
    runtime_files = sorted(
        str(path.relative_to(runtime_root))
        for path in runtime_root.rglob("*")
        if path.is_file()
    )
    summary = {
        "networks_total": len(NETWORKS),
        "wardrive_sessions": len(wardrive_meta["session_ids"]),
        "handshake_captures": len(capture_meta["captures"]),
        "raw_files": len(raw_meta["raw_records"]),
        "batch_files": 1,
        "demo_wordlists": len(wordlist_meta["files"]),
        "cross_source_capture_networks": 1,
    }
    return {
        "profile_id": PROFILE_ID,
        "label": PROFILE_LABEL,
        "description": PROFILE_DESCRIPTION,
        "version": PROFILE_VERSION,
        "build_stamp": BUILD_STAMP,
        "runtime_roots": [
            "handshakes",
            "BrucePCAP",
            "m5evil",
            "wardrive",
            "demo_wordlists",
        ],
        "ui_seed": UI_SEED,
        "summary": summary,
        "network_catalog": {
            network_id: {
                "ssid": data["ssid"],
                "bssid": data["bssid"],
                "category": data["category"],
                "encryption": data["encryption"],
            }
            for network_id, data in sorted(NETWORKS.items())
        },
        "handshake_captures": capture_meta["captures"],
        "raw_captures": raw_meta["raw_records"],
        "batch_file": capture_meta["batch_name"],
        "combined_build_id": capture_meta["combined_build_id"],
        "files": runtime_files,
    }


def build_pack(validate: bool = False) -> int:
    if PACK_ROOT.exists():
        shutil.rmtree(PACK_ROOT)

    runtime_root = RUNTIME_ROOT
    runtime_root.mkdir(parents=True, exist_ok=True)

    capture_meta = _build_capture_assets(runtime_root)
    raw_meta = _build_raw_assets(runtime_root)
    wardrive_meta = _build_wardrive_assets(runtime_root)
    wordlist_meta = _build_wordlists(runtime_root)

    manifest = _build_manifest(
        runtime_root,
        capture_meta=capture_meta,
        raw_meta=raw_meta,
        wardrive_meta=wardrive_meta,
        wordlist_meta=wordlist_meta,
    )
    _json_dump(PACK_ROOT / "manifest.json", manifest)
    (PACK_ROOT / "README.md").write_text(
        "# Showcase Core v1\n\n"
        "Synthetic, public-safe demo dataset for KOVIL MAP.\n",
        encoding="utf-8",
    )

    if validate:
        assert (PACK_ROOT / "manifest.json").exists()
        assert (RUNTIME_ROOT / "handshakes").exists()
        assert (RUNTIME_ROOT / "wardrive").exists()
        assert (RUNTIME_ROOT / "BrucePCAP").exists()
        assert (RUNTIME_ROOT / "m5evil").exists()
        assert (RUNTIME_ROOT / "demo_wordlists").exists()
        assert manifest["summary"]["networks_total"] >= 8
        assert manifest["summary"]["wardrive_sessions"] == 3
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Build public demo data pack.")
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Run basic assertions after regenerating the pack.",
    )
    args = parser.parse_args()
    return build_pack(validate=bool(args.validate))


if __name__ == "__main__":
    raise SystemExit(main())
