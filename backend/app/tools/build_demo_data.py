from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import shutil
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.utils.handshake_artifacts import create_combined_build_id

PROFILE_ID = "showcase-core-v5"
PROFILE_LABEL = "Showcase Core v5"
PROFILE_DESCRIPTION = (
    "Synthetic Rio de Janeiro showcase dataset with expanded WarDrive "
    "coverage, transport-tagged sessions, artifact-consistent locked "
    "networks, richer RAW crossover, and public-safe cross-surface demo data."
)
PROFILE_VERSION = 5
BUILD_STAMP = "2026-04-15T00:00:00Z"
DEMO_SOURCE_MTIME = datetime.fromisoformat(
    BUILD_STAMP.replace("Z", "+00:00")
).timestamp()

BACKEND_ROOT = Path(__file__).resolve().parents[2]
PACK_ROOT = BACKEND_ROOT / "demo_data" / PROFILE_ID
RUNTIME_ROOT = PACK_ROOT / "runtime"
ROUTE_SOURCE_ROOT = BACKEND_ROOT / "demo_data_sources" / PROFILE_ID / "routes"
DENSITY_PROFILE_PATH = (
    BACKEND_ROOT / "demo_data_sources" / PROFILE_ID / "density_profile.json"
)

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

ROUTE_COLUMNS = (
    "timestamp",
    "lat",
    "lng",
    "altitude_m",
    "speed_kmh",
    "accuracy_m",
)
ROUTE_FORBIDDEN_COLUMNS = {"ssid", "bssid", "mac", "vendor", "channel", "frequency"}
RJ_BBOX = {
    "lat_min": -23.10,
    "lat_max": -22.80,
    "lng_min": -43.40,
    "lng_max": -43.10,
}
DENSITY_CHANNEL_PROFILES = [
    {"channel": 1, "frequency": 2412},
    {"channel": 6, "frequency": 2437},
    {"channel": 11, "frequency": 2462},
    {"channel": 36, "frequency": 5180},
    {"channel": 44, "frequency": 5220},
    {"channel": 149, "frequency": 5745},
    {"channel": 157, "frequency": 5785},
]
DENSITY_SSID_SUFFIXES = [
    "GUEST",
    "KIOSK",
    "TERRACE",
    "PASS",
    "STUDIO",
    "HUB",
    "LOUNGE",
    "LINK",
    "VIEW",
    "MESH",
]
DENSITY_DEVICE_TYPES = [
    "router_ap",
    "kiosk_hotspot",
    "bridge",
    "mobile_router",
]
WARDRIVE_MIN_VISIBLE_PER_POINT = 12
WARDRIVE_MAX_VISIBLE_PER_POINT = 48
PWNAGOTCHI_MASS_PROMOTION_ID = "pwnagotchi_mass_v5"
PWNAGOTCHI_MASS_PROMOTION_TOTAL = 240
PWNAGOTCHI_MASS_PROMOTION_CRACKED = 32
PWNAGOTCHI_MASS_PROMOTION_CONVERTIBLE = 24
PWNAGOTCHI_MASS_PROMOTION_CORRIDOR_QUOTAS = {
    "Centro + Lapa + Santa Teresa": 60,
    "Aterro do Flamengo + Botafogo + Urca": 60,
    "Copacabana + Arpoador + Ipanema + Lagoa": 60,
    "Lapa + Gloria + Praca Maua Motorcycle": 60,
}

NETWORKS = {
    "rio_cafe_loop": {
        "ssid": "RIO_CAFE_LOOP",
        "bssid": "02:11:22:33:44:60",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "cafeloop2026",
        "category": "easy_dictionary",
        "vendor": "RioSignals Labs",
        "channel": 6,
        "frequency": 2437,
        "lat": -22.91355,
        "lng": -43.18175,
        "altitude": 12.5,
        "accuracy": 5.4,
        "device_type": "router_ap",
        "device_confidence": 0.95,
        "wardrive_anchors": [
            {"lat": -22.91355, "lng": -43.18175, "radius_m": 165.0, "peak_rssi": -46},
        ],
    },
    "lapa_event_guest": {
        "ssid": "LAPA_EVENT_GUEST",
        "bssid": "06:11:22:33:44:61",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "carioca2026",
        "category": "already_cracked",
        "vendor": "Festival Mesh",
        "channel": 11,
        "frequency": 2462,
        "lat": -22.91425,
        "lng": -43.18325,
        "altitude": 13.4,
        "accuracy": 5.7,
        "device_type": "router_ap",
        "device_confidence": 0.92,
        "wardrive_anchors": [
            {"lat": -22.91425, "lng": -43.18325, "radius_m": 150.0, "peak_rssi": -47},
        ],
    },
    "santa_teresa_bonde": {
        "ssid": "SANTA_TERESA_BONDE",
        "bssid": "0A:11:22:33:44:62",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "bondesantateresa",
        "category": "association_hint",
        "vendor": "Heritage Transit",
        "channel": 1,
        "frequency": 2412,
        "lat": -22.91895,
        "lng": -43.19285,
        "altitude": 35.8,
        "accuracy": 6.0,
        "device_type": "router_ap",
        "device_confidence": 0.9,
        "wardrive_anchors": [
            {"lat": -22.91895, "lng": -43.19285, "radius_m": 185.0, "peak_rssi": -48},
        ],
    },
    "gloria_press_hub": {
        "ssid": "GLORIA_PRESS_HUB",
        "bssid": "0E:11:22:33:44:63",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "presshub2026",
        "category": "already_cracked",
        "vendor": "PressLink Mobile",
        "channel": 44,
        "frequency": 5220,
        "lat": -22.92560,
        "lng": -43.17340,
        "altitude": 7.4,
        "accuracy": 5.1,
        "device_type": "mobile_router",
        "device_confidence": 0.88,
        "wardrive_anchors": [
            {"lat": -22.92560, "lng": -43.17340, "radius_m": 220.0, "peak_rssi": -45},
        ],
    },
    "ops_truck_alpha": {
        "ssid": "OPS-TRUCK-ALPHA",
        "bssid": "02:AA:11:22:33:44",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "ops-truck-alpha",
        "category": "association_hint",
        "vendor": "FieldOps Devices",
        "channel": 36,
        "frequency": 5180,
        "lat": -22.93890,
        "lng": -43.18170,
        "altitude": 9.8,
        "accuracy": 6.2,
        "device_type": "vehicular_hotspot",
        "device_confidence": 0.89,
        "wardrive_anchors": [
            {"lat": -22.91305, "lng": -43.18110, "radius_m": 95.0, "peak_rssi": -49},
            {"lat": -22.93890, "lng": -43.18170, "radius_m": 180.0, "peak_rssi": -46},
        ],
    },
    "botafogo_kiosk_net": {
        "ssid": "BOTAFOGO_KIOSK_NET",
        "bssid": "06:AA:11:22:33:45",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "20262026",
        "category": "digits_mask",
        "vendor": "Beachside Retail",
        "channel": 149,
        "frequency": 5745,
        "lat": -22.94510,
        "lng": -43.18420,
        "altitude": 9.0,
        "accuracy": 5.5,
        "device_type": "router_ap",
        "device_confidence": 0.87,
        "wardrive_anchors": [
            {"lat": -22.94510, "lng": -43.18420, "radius_m": 225.0, "peak_rssi": -47},
        ],
    },
    "urca_field_uplink": {
        "ssid": "URCA_FIELD_UPLINK",
        "bssid": "0A:AA:11:22:33:46",
        "auth_mode": "[WPA3-SAE-CCMP][ESS]",
        "encryption": "WPA3",
        "password": "uplink-urca-26",
        "category": "wardrive_extra",
        "vendor": "Field Research Network",
        "channel": 149,
        "frequency": 5745,
        "lat": -22.95340,
        "lng": -43.16890,
        "altitude": 19.2,
        "accuracy": 5.4,
        "device_type": "bridge",
        "device_confidence": 0.84,
        "wardrive_anchors": [
            {"lat": -22.95340, "lng": -43.16890, "radius_m": 235.0, "peak_rssi": -48},
            {"lat": -22.95120, "lng": -43.17640, "radius_m": 145.0, "peak_rssi": -53},
        ],
    },
    "copa_media_node": {
        "ssid": "COPA_MEDIA_NODE",
        "bssid": "0E:AA:11:22:33:47",
        "auth_mode": "[WPA3-SAE-CCMP][ESS]",
        "encryption": "WPA3",
        "password": "media-node-rio",
        "category": "wardrive_extra",
        "vendor": "MediaCast",
        "channel": 157,
        "frequency": 5785,
        "lat": -22.97150,
        "lng": -43.18350,
        "altitude": 8.3,
        "accuracy": 4.9,
        "device_type": "router_ap",
        "device_confidence": 0.89,
        "wardrive_anchors": [
            {"lat": -22.97150, "lng": -43.18350, "radius_m": 250.0, "peak_rssi": -45},
            {"lat": -22.97480, "lng": -43.18670, "radius_m": 220.0, "peak_rssi": -49},
            {"lat": -22.98230, "lng": -43.19340, "radius_m": 190.0, "peak_rssi": -51},
        ],
    },
    "metro_line_4": {
        "ssid": "METRO_LINE_4",
        "bssid": "02:BB:11:22:33:48",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "04042026",
        "category": "digits_mask",
        "vendor": "Transit Systems",
        "channel": 1,
        "frequency": 2412,
        "lat": -22.98565,
        "lng": -43.19390,
        "altitude": 9.6,
        "accuracy": 6.1,
        "device_type": "router_ap",
        "device_confidence": 0.86,
        "wardrive_anchors": [
            {"lat": -22.98565, "lng": -43.19390, "radius_m": 255.0, "peak_rssi": -47},
            {"lat": -22.98510, "lng": -43.19920, "radius_m": 210.0, "peak_rssi": -50},
        ],
    },
    "ipanema_boardwalk": {
        "ssid": "IPANEMA_BOARDWALK",
        "bssid": "06:BB:11:22:33:49",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "boardwalk2026",
        "category": "easy_dictionary",
        "vendor": "Beachfront Guest",
        "channel": 11,
        "frequency": 2462,
        "lat": -22.98800,
        "lng": -43.18910,
        "altitude": 8.0,
        "accuracy": 5.0,
        "device_type": "router_ap",
        "device_confidence": 0.9,
        "wardrive_anchors": [
            {"lat": -22.98800, "lng": -43.18910, "radius_m": 320.0, "peak_rssi": -46},
            {"lat": -22.98360, "lng": -43.20340, "radius_m": 230.0, "peak_rssi": -52},
            {"lat": -22.98240, "lng": -43.19560, "radius_m": 180.0, "peak_rssi": -49},
            {"lat": -22.97220, "lng": -43.19180, "radius_m": 190.0, "peak_rssi": -50},
        ],
    },
    "nogps_lab_01": {
        "ssid": "NOGPS_LAB_01",
        "bssid": "0A:BB:11:22:33:4A",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "lab-3301",
        "category": "no_gps_only",
        "vendor": "LabNet",
        "channel": 44,
        "frequency": 5220,
        "lat": -22.97710,
        "lng": -43.21380,
        "altitude": 11.0,
        "accuracy": 7.3,
        "device_type": "router_ap",
        "device_confidence": 0.85,
        "wardrive_anchors": [],
    },
    "hidden_relay_07": {
        "ssid": "",
        "bssid": "0E:BB:11:22:33:4B",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "relay-hidden-07",
        "category": "not_ready",
        "vendor": "Relay Nodes",
        "channel": 149,
        "frequency": 5745,
        "lat": -22.95230,
        "lng": -43.17110,
        "altitude": 17.2,
        "accuracy": 7.0,
        "device_type": "bridge",
        "device_confidence": 0.82,
        "wardrive_anchors": [
            {"lat": -22.95230, "lng": -43.17110, "radius_m": 125.0, "peak_rssi": -58},
        ],
    },
    "open_sensor_mesh": {
        "ssid": "OPEN_SENSOR_MESH",
        "bssid": "02:CC:11:22:33:4C",
        "auth_mode": "[ESS]",
        "encryption": "OPEN",
        "password": "",
        "category": "open",
        "vendor": "Municipal Sensors",
        "channel": 3,
        "frequency": 2422,
        "lat": -22.91140,
        "lng": -43.17860,
        "altitude": 10.5,
        "accuracy": 6.8,
        "device_type": "iot_gateway",
        "device_confidence": 0.81,
        "wardrive_anchors": [
            {"lat": -22.91140, "lng": -43.17860, "radius_m": 160.0, "peak_rssi": -53},
            {"lat": -22.93600, "lng": -43.17880, "radius_m": 205.0, "peak_rssi": -56},
            {"lat": -22.97050, "lng": -43.20550, "radius_m": 230.0, "peak_rssi": -59},
            {"lat": -22.98080, "lng": -43.20980, "radius_m": 180.0, "peak_rssi": -61},
            {"lat": -22.97810, "lng": -43.20660, "radius_m": 170.0, "peak_rssi": -58},
        ],
    },
    "rj_city_iot": {
        "ssid": "RJ_CITY_IOT",
        "bssid": "06:CC:11:22:33:4D",
        "auth_mode": "[WEP][ESS]",
        "encryption": "WEP",
        "password": "cityiot58",
        "category": "wardrive_extra",
        "vendor": "City Infrastructure",
        "channel": 9,
        "frequency": 2452,
        "lat": -22.90480,
        "lng": -43.17550,
        "altitude": 8.8,
        "accuracy": 7.4,
        "device_type": "iot_gateway",
        "device_confidence": 0.76,
        "wardrive_anchors": [
            {"lat": -22.90480, "lng": -43.17550, "radius_m": 135.0, "peak_rssi": -57},
            {"lat": -22.97320, "lng": -43.21870, "radius_m": 220.0, "peak_rssi": -60},
        ],
    },
    "porto_link_backhaul": {
        "ssid": "PORTO_LINK_BACKHAUL",
        "bssid": "0A:CC:11:22:33:4E",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "backhaul-porto",
        "category": "wardrive_extra",
        "vendor": "PortLink",
        "channel": 157,
        "frequency": 5785,
        "lat": -22.90410,
        "lng": -43.17440,
        "altitude": 9.1,
        "accuracy": 7.1,
        "device_type": "bridge",
        "device_confidence": 0.79,
        "wardrive_anchors": [
            {"lat": -22.90410, "lng": -43.17440, "radius_m": 120.0, "peak_rssi": -55},
        ],
    },
    "museu_amanha_secure": {
        "ssid": "MUSEU_AMANHA_SECURE",
        "bssid": "0E:CC:11:22:33:4F",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "amanha-secure-26",
        "category": "locked_showcase",
        "vendor": "Porto Maravilha Fiber",
        "channel": 36,
        "frequency": 5180,
        "lat": -22.89385,
        "lng": -43.18090,
        "altitude": 6.5,
        "accuracy": 5.4,
        "device_type": "router_ap",
        "device_confidence": 0.9,
        "wardrive_anchors": [
            {"lat": -22.89385, "lng": -43.18090, "radius_m": 165.0, "peak_rssi": -46},
            {"lat": -22.90120, "lng": -43.17520, "radius_m": 185.0, "peak_rssi": -50},
        ],
    },
    "praca_maua_press_van": {
        "ssid": "PRACA_MAUA_PRESS_VAN",
        "bssid": "02:DD:11:22:33:50",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "press-van-maua",
        "category": "already_cracked",
        "vendor": "PressFleet",
        "channel": 44,
        "frequency": 5220,
        "lat": -22.89740,
        "lng": -43.17910,
        "altitude": 5.8,
        "accuracy": 5.0,
        "device_type": "mobile_router",
        "device_confidence": 0.88,
        "wardrive_anchors": [
            {"lat": -22.89740, "lng": -43.17910, "radius_m": 175.0, "peak_rssi": -45},
            {"lat": -22.90480, "lng": -43.17650, "radius_m": 145.0, "peak_rssi": -52},
        ],
    },
    "maracana_media_bus": {
        "ssid": "MARACANA_MEDIA_BUS",
        "bssid": "06:DD:11:22:33:51",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "maracana-media-26",
        "category": "locked_showcase",
        "vendor": "Arena Transit",
        "channel": 11,
        "frequency": 2462,
        "lat": -22.91210,
        "lng": -43.23070,
        "altitude": 17.5,
        "accuracy": 5.8,
        "device_type": "vehicular_hotspot",
        "device_confidence": 0.86,
        "wardrive_anchors": [
            {"lat": -22.91210, "lng": -43.23070, "radius_m": 165.0, "peak_rssi": -48},
            {"lat": -22.90520, "lng": -43.21050, "radius_m": 180.0, "peak_rssi": -51},
        ],
    },
    "engenhao_ops_mesh": {
        "ssid": "ENGENHAO_OPS_MESH",
        "bssid": "0A:DD:11:22:33:52",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "engenhao-ops-26",
        "category": "locked_showcase",
        "vendor": "NorthRail Mesh",
        "channel": 149,
        "frequency": 5745,
        "lat": -22.89490,
        "lng": -43.29220,
        "altitude": 22.0,
        "accuracy": 6.2,
        "device_type": "bridge",
        "device_confidence": 0.84,
        "wardrive_anchors": [
            {"lat": -22.89490, "lng": -43.29220, "radius_m": 170.0, "peak_rssi": -47},
            {"lat": -22.90010, "lng": -43.29840, "radius_m": 150.0, "peak_rssi": -53},
        ],
    },
    "aterro_marina_ops": {
        "ssid": "ATERRO_MARINA_OPS",
        "bssid": "0E:DD:11:22:33:53",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "marina-ops-26",
        "category": "locked_showcase",
        "vendor": "Marina South Link",
        "channel": 6,
        "frequency": 2437,
        "lat": -22.93120,
        "lng": -43.17390,
        "altitude": 5.4,
        "accuracy": 5.0,
        "device_type": "router_ap",
        "device_confidence": 0.87,
        "wardrive_anchors": [
            {"lat": -22.93120, "lng": -43.17390, "radius_m": 195.0, "peak_rssi": -46},
            {"lat": -22.93620, "lng": -43.18030, "radius_m": 165.0, "peak_rssi": -51},
        ],
    },
    "praia_vermelha_research": {
        "ssid": "PRAIA_VERMELHA_RESEARCH",
        "bssid": "02:EE:11:22:33:54",
        "auth_mode": "[WPA3-SAE-CCMP][ESS]",
        "encryption": "WPA3",
        "password": "praiavermelha26",
        "category": "locked_showcase",
        "vendor": "Coastal Research Net",
        "channel": 157,
        "frequency": 5785,
        "lat": -22.95560,
        "lng": -43.16520,
        "altitude": 14.3,
        "accuracy": 5.7,
        "device_type": "router_ap",
        "device_confidence": 0.89,
        "wardrive_anchors": [
            {"lat": -22.95560, "lng": -43.16520, "radius_m": 160.0, "peak_rssi": -47},
            {"lat": -22.95340, "lng": -43.16890, "radius_m": 145.0, "peak_rssi": -50},
        ],
    },
    "jardim_botanico_cycle_lab": {
        "ssid": "JARDIM_BOTANICO_CYCLE_LAB",
        "bssid": "06:EE:11:22:33:55",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "cycle-lab-rio",
        "category": "locked_showcase",
        "vendor": "Botanical Research Guest",
        "channel": 1,
        "frequency": 2412,
        "lat": -22.96690,
        "lng": -43.21520,
        "altitude": 10.8,
        "accuracy": 5.8,
        "device_type": "router_ap",
        "device_confidence": 0.85,
        "wardrive_anchors": [
            {"lat": -22.96690, "lng": -43.21520, "radius_m": 185.0, "peak_rssi": -47},
            {"lat": -22.97140, "lng": -43.21410, "radius_m": 175.0, "peak_rssi": -52},
        ],
    },
    "arpoador_staff_mesh": {
        "ssid": "ARPOADOR_STAFF_MESH",
        "bssid": "0A:EE:11:22:33:56",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "staff-arpoador",
        "category": "already_cracked",
        "vendor": "Beach Ops Staff",
        "channel": 36,
        "frequency": 5180,
        "lat": -22.98890,
        "lng": -43.19180,
        "altitude": 6.4,
        "accuracy": 4.8,
        "device_type": "router_ap",
        "device_confidence": 0.91,
        "wardrive_anchors": [
            {"lat": -22.98890, "lng": -43.19180, "radius_m": 170.0, "peak_rssi": -45},
            {"lat": -22.98590, "lng": -43.19320, "radius_m": 145.0, "peak_rssi": -50},
        ],
    },
    "nogps_lab_02": {
        "ssid": "NOGPS_LAB_02",
        "bssid": "0E:EE:11:22:33:57",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "lab-3302",
        "category": "no_gps_locked",
        "vendor": "LabNet",
        "channel": 149,
        "frequency": 5745,
        "lat": -23.00220,
        "lng": -43.32720,
        "altitude": 11.4,
        "accuracy": 7.6,
        "device_type": "router_ap",
        "device_confidence": 0.84,
        "wardrive_anchors": [],
    },
    "nogps_lab_03": {
        "ssid": "NOGPS_LAB_03",
        "bssid": "02:EF:11:22:33:58",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "lab-3303",
        "category": "no_gps_locked",
        "vendor": "LabNet",
        "channel": 44,
        "frequency": 5220,
        "lat": -22.99940,
        "lng": -43.31120,
        "altitude": 12.0,
        "accuracy": 7.4,
        "device_type": "router_ap",
        "device_confidence": 0.82,
        "wardrive_anchors": [],
    },
    "nogps_lab_04": {
        "ssid": "NOGPS_LAB_04",
        "bssid": "06:EF:11:22:33:59",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "lab-3304",
        "category": "no_gps_locked",
        "vendor": "LabNet",
        "channel": 6,
        "frequency": 2437,
        "lat": -22.99530,
        "lng": -43.29880,
        "altitude": 10.5,
        "accuracy": 7.1,
        "device_type": "router_ap",
        "device_confidence": 0.83,
        "wardrive_anchors": [],
    },
    "nogps_lab_05": {
        "ssid": "NOGPS_LAB_05",
        "bssid": "0A:EF:11:22:33:5A",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "lab-3305",
        "category": "no_gps_locked",
        "vendor": "LabNet",
        "channel": 11,
        "frequency": 2462,
        "lat": -22.99210,
        "lng": -43.30550,
        "altitude": 11.8,
        "accuracy": 7.5,
        "device_type": "router_ap",
        "device_confidence": 0.81,
        "wardrive_anchors": [],
    },
    "hidden_lapa_mesh": {
        "ssid": "",
        "bssid": "0E:EF:11:22:33:5B",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "hidden-lapa-26",
        "category": "not_ready",
        "vendor": "Historic Mesh",
        "channel": 1,
        "frequency": 2412,
        "lat": -22.91380,
        "lng": -43.18210,
        "altitude": 11.5,
        "accuracy": 6.0,
        "device_type": "bridge",
        "device_confidence": 0.8,
        "wardrive_anchors": [
            {"lat": -22.91380, "lng": -43.18210, "radius_m": 135.0, "peak_rssi": -57},
        ],
    },
    "hidden_engenhao_link": {
        "ssid": "",
        "bssid": "02:F0:11:22:33:5C",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "hidden-engenhao",
        "category": "not_ready",
        "vendor": "Trackside Mesh",
        "channel": 149,
        "frequency": 5745,
        "lat": -22.89570,
        "lng": -43.29030,
        "altitude": 19.7,
        "accuracy": 6.4,
        "device_type": "bridge",
        "device_confidence": 0.79,
        "wardrive_anchors": [
            {"lat": -22.89570, "lng": -43.29030, "radius_m": 125.0, "peak_rssi": -58},
        ],
    },
    "maua_rooftop_probe": {
        "ssid": "MAUA_ROOFTOP_PROBE",
        "bssid": "06:F0:11:22:33:5D",
        "auth_mode": "[WPA2-PSK-CCMP][ESS]",
        "encryption": "WPA2",
        "password": "maua-rooftop-26",
        "category": "raw_only_candidate",
        "vendor": "Porto Sensor Mesh",
        "channel": 36,
        "frequency": 5180,
        "lat": -22.89710,
        "lng": -43.17680,
        "altitude": 8.2,
        "accuracy": 5.3,
        "device_type": "bridge",
        "device_confidence": 0.8,
        "wardrive_anchors": [
            {"lat": -22.89710, "lng": -43.17680, "radius_m": 150.0, "peak_rssi": -54},
        ],
    },
}

HANDSHAKE_CAPTURES = [
    {
        "id": "pwn_rio_cafe",
        "network_id": "rio_cafe_loop",
        "source": "pwnagotchi",
        "role": "handshakes",
        "root": "handshakes",
        "filename": "RIO_CAFE_LOOP_021122334460.pcap",
        "gps": True,
        "legacy_sidecars": True,
        "scenario": "pcap_plus_22000",
        "pcap_profile": "full",
    },
    {
        "id": "bruce_rio_cafe",
        "network_id": "rio_cafe_loop",
        "source": "brucegotchi",
        "role": "bruce_handshakes",
        "root": "BrucePCAP/handshakes",
        "filename": "HS_021122334460_rio_cafe_loop_bruce.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "scenario": "pcap_plus_22000",
        "pcap_profile": "full",
    },
    {
        "id": "m5_rio_cafe",
        "network_id": "rio_cafe_loop",
        "source": "m5evil",
        "role": "m5evil_handshakes",
        "root": "m5evil/handshakes",
        "filename": "HS_021122334460_rio_cafe_loop_m5evil.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "scenario": "pcap_plus_22000",
        "pcap_profile": "full",
    },
    {
        "id": "pwn_lapa_event",
        "network_id": "lapa_event_guest",
        "source": "pwnagotchi",
        "role": "handshakes",
        "root": "handshakes",
        "filename": "LAPA_EVENT_GUEST_061122334461.pcap",
        "gps": True,
        "legacy_sidecars": True,
        "cracked": True,
        "scenario": "pcap_plus_22000_plus_cracked",
        "pcap_profile": "full",
    },
    {
        "id": "bruce_santa_teresa",
        "network_id": "santa_teresa_bonde",
        "source": "brucegotchi",
        "role": "bruce_handshakes",
        "root": "BrucePCAP/handshakes",
        "filename": "HS_0A1122334462_santa_teresa_bonde_bruce.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "hash_ready": False,
        "scenario": "pcap_only_convertible",
        "pcap_profile": "full",
    },
    {
        "id": "bruce_gloria_press",
        "network_id": "gloria_press_hub",
        "source": "brucegotchi",
        "role": "bruce_handshakes",
        "root": "BrucePCAP/handshakes",
        "filename": "HS_0E1122334463_gloria_press_hub_bruce.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "cracked": True,
        "scenario": "pcap_plus_22000_plus_cracked",
        "pcap_profile": "full",
    },
    {
        "id": "m5_ops_truck",
        "network_id": "ops_truck_alpha",
        "source": "m5evil",
        "role": "m5evil_handshakes",
        "root": "m5evil/handshakes",
        "filename": "HS_02AA11223344_ops_truck_alpha_m5evil.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "hash_ready": False,
        "scenario": "pcap_only_convertible",
        "pcap_profile": "full",
    },
    {
        "id": "bruce_botafogo_kiosk",
        "network_id": "botafogo_kiosk_net",
        "source": "brucegotchi",
        "role": "bruce_handshakes",
        "root": "BrucePCAP/handshakes",
        "filename": "HS_06AA11223345_botafogo_kiosk_net_bruce.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "scenario": "pcap_plus_22000",
        "pcap_profile": "full",
    },
    {
        "id": "pwn_urca_field",
        "network_id": "urca_field_uplink",
        "source": "pwnagotchi",
        "role": "handshakes",
        "root": "handshakes",
        "filename": "URCA_FIELD_UPLINK_0AAA11223346.pcap",
        "gps": True,
        "legacy_sidecars": True,
        "scenario": "pcap_plus_22000",
        "pcap_profile": "full",
    },
    {
        "id": "pwn_copa_media",
        "network_id": "copa_media_node",
        "source": "pwnagotchi",
        "role": "handshakes",
        "root": "handshakes",
        "filename": "COPA_MEDIA_NODE_0EAA11223347.pcap",
        "gps": True,
        "legacy_sidecars": True,
        "scenario": "pcap_plus_22000",
        "pcap_profile": "full",
    },
    {
        "id": "bruce_copa_media",
        "network_id": "copa_media_node",
        "source": "brucegotchi",
        "role": "bruce_handshakes",
        "root": "BrucePCAP/handshakes",
        "filename": "HS_0EAA11223347_copa_media_node_bruce.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "scenario": "pcap_plus_22000",
        "pcap_profile": "full",
    },
    {
        "id": "m5_copa_media",
        "network_id": "copa_media_node",
        "source": "m5evil",
        "role": "m5evil_handshakes",
        "root": "m5evil/handshakes",
        "filename": "HS_0EAA11223347_copa_media_node_m5evil.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "scenario": "pcap_plus_22000",
        "pcap_profile": "full",
    },
    {
        "id": "bruce_metro",
        "network_id": "metro_line_4",
        "source": "brucegotchi",
        "role": "bruce_handshakes",
        "root": "BrucePCAP/handshakes",
        "filename": "HS_02BB11223348_metro_line_4_bruce.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "scenario": "pcap_plus_22000",
        "pcap_profile": "full",
    },
    {
        "id": "pwn_ipanema_boardwalk",
        "network_id": "ipanema_boardwalk",
        "source": "pwnagotchi",
        "role": "handshakes",
        "root": "handshakes",
        "filename": "IPANEMA_BOARDWALK_06BB11223349.pcap",
        "gps": True,
        "legacy_sidecars": True,
        "hash_ready": False,
        "scenario": "pcap_only_convertible",
        "pcap_profile": "full",
    },
    {
        "id": "m5_nogps_lab",
        "network_id": "nogps_lab_01",
        "source": "m5evil",
        "role": "m5evil_handshakes",
        "root": "m5evil/handshakes",
        "filename": "HS_0ABB1122334A_nogps_lab_01_m5evil.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "scenario": "no_gps_locked",
        "pcap_profile": "full",
    },
    {
        "id": "pwn_hidden_relay",
        "network_id": "hidden_relay_07",
        "source": "pwnagotchi",
        "role": "handshakes",
        "root": "handshakes",
        "filename": "hidden_0EBB1122334B.pcap",
        "gps": False,
        "legacy_sidecars": True,
        "hash_ready": False,
        "scenario": "pcap_present_but_not_ready",
        "pcap_profile": "minimal",
    },
    {
        "id": "pwn_museu_amanha",
        "network_id": "museu_amanha_secure",
        "source": "pwnagotchi",
        "role": "handshakes",
        "root": "handshakes",
        "filename": "MUSEU_AMANHA_SECURE_0ECC1122334F.pcap",
        "gps": True,
        "legacy_sidecars": True,
        "scenario": "pcap_plus_22000",
        "pcap_profile": "full",
    },
    {
        "id": "bruce_praca_maua_press_van",
        "network_id": "praca_maua_press_van",
        "source": "brucegotchi",
        "role": "bruce_handshakes",
        "root": "BrucePCAP/handshakes",
        "filename": "HS_02DD11223350_praca_maua_press_van_bruce.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "cracked": True,
        "scenario": "pcap_plus_22000_plus_cracked",
        "pcap_profile": "full",
    },
    {
        "id": "pwn_maracana_media_bus",
        "network_id": "maracana_media_bus",
        "source": "pwnagotchi",
        "role": "handshakes",
        "root": "handshakes",
        "filename": "MARACANA_MEDIA_BUS_06DD11223351.pcap",
        "gps": True,
        "legacy_sidecars": True,
        "hash_ready": False,
        "scenario": "pcap_only_convertible",
        "pcap_profile": "full",
    },
    {
        "id": "m5_engenhao_ops_mesh",
        "network_id": "engenhao_ops_mesh",
        "source": "m5evil",
        "role": "m5evil_handshakes",
        "root": "m5evil/handshakes",
        "filename": "HS_0ADD11223352_engenhao_ops_mesh_m5evil.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "scenario": "pcap_plus_22000",
        "pcap_profile": "full",
    },
    {
        "id": "pwn_aterro_marina_ops",
        "network_id": "aterro_marina_ops",
        "source": "pwnagotchi",
        "role": "handshakes",
        "root": "handshakes",
        "filename": "ATERRO_MARINA_OPS_0EDD11223353.pcap",
        "gps": True,
        "legacy_sidecars": True,
        "hash_ready": False,
        "scenario": "pcap_only_convertible",
        "pcap_profile": "full",
    },
    {
        "id": "bruce_praia_vermelha_research",
        "network_id": "praia_vermelha_research",
        "source": "brucegotchi",
        "role": "bruce_handshakes",
        "root": "BrucePCAP/handshakes",
        "filename": "HS_02EE11223354_praia_vermelha_research_bruce.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "scenario": "pcap_plus_22000",
        "pcap_profile": "full",
    },
    {
        "id": "bruce_jardim_botanico_cycle_lab",
        "network_id": "jardim_botanico_cycle_lab",
        "source": "brucegotchi",
        "role": "bruce_handshakes",
        "root": "BrucePCAP/handshakes",
        "filename": "HS_06EE11223355_jardim_botanico_cycle_lab_bruce.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "hash_ready": False,
        "scenario": "pcap_only_convertible",
        "pcap_profile": "full",
    },
    {
        "id": "pwn_arpoador_staff_mesh",
        "network_id": "arpoador_staff_mesh",
        "source": "pwnagotchi",
        "role": "handshakes",
        "root": "handshakes",
        "filename": "ARPOADOR_STAFF_MESH_0AEE11223356.pcap",
        "gps": True,
        "legacy_sidecars": True,
        "cracked": True,
        "scenario": "pcap_plus_22000_plus_cracked",
        "pcap_profile": "full",
    },
    {
        "id": "m5_nogps_lab_02",
        "network_id": "nogps_lab_02",
        "source": "m5evil",
        "role": "m5evil_handshakes",
        "root": "m5evil/handshakes",
        "filename": "HS_0EEE11223357_nogps_lab_02_m5evil.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "scenario": "no_gps_locked",
        "pcap_profile": "full",
    },
    {
        "id": "m5_nogps_lab_03",
        "network_id": "nogps_lab_03",
        "source": "m5evil",
        "role": "m5evil_handshakes",
        "root": "m5evil/handshakes",
        "filename": "HS_02EF11223358_nogps_lab_03_m5evil.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "hash_ready": False,
        "scenario": "no_gps_locked",
        "pcap_profile": "full",
    },
    {
        "id": "bruce_nogps_lab_04",
        "network_id": "nogps_lab_04",
        "source": "brucegotchi",
        "role": "bruce_handshakes",
        "root": "BrucePCAP/handshakes",
        "filename": "HS_06EF11223359_nogps_lab_04_bruce.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "scenario": "no_gps_locked",
        "pcap_profile": "full",
    },
    {
        "id": "bruce_nogps_lab_05",
        "network_id": "nogps_lab_05",
        "source": "brucegotchi",
        "role": "bruce_handshakes",
        "root": "BrucePCAP/handshakes",
        "filename": "HS_0AEF1122335A_nogps_lab_05_bruce.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "hash_ready": False,
        "scenario": "no_gps_locked",
        "pcap_profile": "full",
    },
    {
        "id": "pwn_hidden_lapa_mesh",
        "network_id": "hidden_lapa_mesh",
        "source": "pwnagotchi",
        "role": "handshakes",
        "root": "handshakes",
        "filename": "hidden_0EEF1122335B.pcap",
        "gps": True,
        "legacy_sidecars": True,
        "hash_ready": False,
        "scenario": "pcap_present_but_not_ready",
        "pcap_profile": "minimal",
    },
    {
        "id": "m5_hidden_engenhao_link",
        "network_id": "hidden_engenhao_link",
        "source": "m5evil",
        "role": "m5evil_handshakes",
        "root": "m5evil/handshakes",
        "filename": "HS_02F01122335C_hidden_engenhao_link_m5evil.pcap",
        "gps": False,
        "legacy_sidecars": False,
        "hash_ready": False,
        "scenario": "pcap_present_but_not_ready",
        "pcap_profile": "minimal",
    },
]

COMBINED_CAPTURE_GROUPS = {
    "rio_cafe_loop": ["pwn_rio_cafe", "bruce_rio_cafe", "m5_rio_cafe"],
    "copa_media_node": ["pwn_copa_media", "bruce_copa_media", "m5_copa_media"],
}

RAW_CAPTURES = [
    {
        "id": "bruce_raw_centro",
        "source": "brucegotchi",
        "device_label": "Bruce",
        "source_path_role": "rawsniffer",
        "root": "BrucePCAP/rawsniffer",
        "filename": "rio_bruce_centro_patrol.pcap",
        "networks": [
            "rio_cafe_loop",
            "lapa_event_guest",
            "santa_teresa_bonde",
            "open_sensor_mesh",
            "museu_amanha_secure",
            "praca_maua_press_van",
        ],
        "clients": ["1A:2B:3C:4D:5E:60", "1A:2B:3C:4D:5E:61", "1A:2B:3C:4D:5E:62"],
    },
    {
        "id": "m5_raw_aterro",
        "source": "m5evil",
        "device_label": "M5Evil",
        "source_path_role": "rawsniffer",
        "root": "m5evil/rawsniffer",
        "filename": "rio_m5_aterro_patrol.pcap",
        "networks": [
            "gloria_press_hub",
            "ops_truck_alpha",
            "botafogo_kiosk_net",
            "open_sensor_mesh",
            "aterro_marina_ops",
            "praia_vermelha_research",
        ],
        "clients": ["2A:3B:4C:5D:6E:70", "2A:3B:4C:5D:6E:71", "2A:3B:4C:5D:6E:72"],
    },
    {
        "id": "m5_master_urca",
        "source": "m5evil",
        "device_label": "M5Evil",
        "source_path_role": "master_sniffer",
        "root": "m5evil/mastersniffer",
        "filename": "rio_m5_urca_master_patrol.pcap",
        "networks": [
            "urca_field_uplink",
            "hidden_relay_07",
            "nogps_lab_01",
            "praia_vermelha_research",
        ],
        "clients": ["3A:4B:5C:6D:7E:80", "3A:4B:5C:6D:7E:81", "3A:4B:5C:6D:7E:82"],
    },
    {
        "id": "bruce_raw_south",
        "source": "brucegotchi",
        "device_label": "Bruce",
        "source_path_role": "rawsniffer",
        "root": "BrucePCAP/rawsniffer",
        "filename": "rio_bruce_south_patrol.pcap",
        "networks": [
            "copa_media_node",
            "metro_line_4",
            "ipanema_boardwalk",
            "arpoador_staff_mesh",
            "jardim_botanico_cycle_lab",
        ],
        "clients": ["4A:5B:6C:7D:8E:90", "4A:5B:6C:7D:8E:91", "4A:5B:6C:7D:8E:92"],
    },
    {
        "id": "m5_raw_centro_revisit",
        "source": "m5evil",
        "device_label": "M5Evil",
        "source_path_role": "rawsniffer",
        "root": "m5evil/rawsniffer",
        "filename": "rio_m5_centro_revisit.pcap",
        "networks": [
            "rio_cafe_loop",
            "gloria_press_hub",
            "porto_link_backhaul",
            "hidden_lapa_mesh",
        ],
        "clients": ["5A:6B:7C:8D:9E:A0", "5A:6B:7C:8D:9E:A1", "5A:6B:7C:8D:9E:A2"],
    },
    {
        "id": "bruce_raw_porto_locked",
        "source": "brucegotchi",
        "device_label": "Bruce",
        "source_path_role": "rawsniffer",
        "root": "BrucePCAP/rawsniffer",
        "filename": "rio_bruce_porto_locked_demo.pcap",
        "networks": [
            "museu_amanha_secure",
            "praca_maua_press_van",
            "maua_rooftop_probe",
            "hidden_lapa_mesh",
        ],
        "clients": ["6A:7B:8C:9D:AE:B0", "6A:7B:8C:9D:AE:B1", "6A:7B:8C:9D:AE:B2"],
    },
    {
        "id": "m5_raw_north_corridor",
        "source": "m5evil",
        "device_label": "M5Evil",
        "source_path_role": "rawsniffer",
        "root": "m5evil/rawsniffer",
        "filename": "rio_m5_north_corridor_demo.pcap",
        "networks": [
            "maracana_media_bus",
            "engenhao_ops_mesh",
            "hidden_engenhao_link",
        ],
        "clients": ["7A:8B:9C:AD:BE:C0", "7A:8B:9C:AD:BE:C1", "7A:8B:9C:AD:BE:C2"],
    },
]

WARDRIVE_SESSIONS = [
    {
        "filename": "20260411_001500_wardriving.csv",
        "header": "WigleWifi-1.4,appRelease=1.0,brand=Bruce",
        "route_asset": "centro_lapa_santa_teresa.csv",
        "corridor": "Centro + Lapa + Santa Teresa",
        "transport_mode": "car",
        "density_multiplier": 1.0,
        "route_family": "road",
    },
    {
        "filename": "m5evil__20260411_011000_wardriving.csv",
        "header": "WigleWifi-1.4,appRelease=1.0,device=Evil-Cardputer,model=cardputer",
        "route_asset": "flamengo_botafogo_urca.csv",
        "corridor": "Aterro do Flamengo + Botafogo + Urca",
        "transport_mode": "car",
        "density_multiplier": 1.0,
        "route_family": "road",
    },
    {
        "filename": "20260411_020500_wardriving.csv",
        "header": "WigleWifi-1.4,appRelease=1.0,brand=Bruce",
        "route_asset": "copacabana_arpoador_ipanema_lagoa.csv",
        "corridor": "Copacabana + Arpoador + Ipanema + Lagoa",
        "transport_mode": "car",
        "density_multiplier": 1.0,
        "route_family": "road",
    },
    {
        "filename": "20260411_041000_lapa_gloria_praca_maua_motorcycle.csv",
        "header": "WigleWifi-1.4,appRelease=1.0,device=Evil-Cardputer,model=cardputer",
        "route_asset": "lapa_gloria_praca_maua_motorcycle.csv",
        "corridor": "Lapa + Gloria + Praca Maua Motorcycle",
        "transport_mode": "motorcycle",
        "density_multiplier": 0.82,
        "route_family": "road",
    },
]

WORDLISTS = {
    "demo_easy.txt": [
        "cafeloop2026",
        "boardwalk2026",
        "carioca2026",
        "presshub2026",
        "media-node-rio",
    ],
    "demo_digits.txt": [
        "20262026",
        "04042026",
        "11022026",
        "01042026",
        "33013301",
    ],
    "demo_association.txt": [
        "ops truck alpha",
        "ops-truck-alpha",
        "bondesantateresa",
        "santa teresa bonde",
        "urca field uplink",
        "copa media node",
    ],
}

UI_SEED = {
    "lists": {
        "targets": [
            NETWORKS["rio_cafe_loop"]["bssid"],
            NETWORKS["copa_media_node"]["bssid"],
            NETWORKS["metro_line_4"]["bssid"],
            NETWORKS["ops_truck_alpha"]["bssid"],
        ],
        "favs": [
            NETWORKS["lapa_event_guest"]["bssid"],
            NETWORKS["gloria_press_hub"]["bssid"],
            NETWORKS["ipanema_boardwalk"]["bssid"],
        ],
    },
    "modes": {
        "zones": True,
        "conquered": True,
        "toConquer": True,
        "discovered": False,
        "intelligence": False,
        "targets": True,
        "favs": True,
        "process": True,
        "logs": True,
    },
}

CORRIDOR_DENSITY_PLAN = {
    "Centro + Lapa + Santa Teresa": {
        "count": 28,
        "scan_points_target": 92,
        "themes": ["LAPA", "CARIOCA", "BONDE", "ARCOS", "CINELANDIA"],
        "vendors": [
            "Carioca Hospitality",
            "Centro Fiber",
            "Historic Mesh",
            "Rua do Lavradio Net",
        ],
    },
    "Aterro do Flamengo + Botafogo + Urca": {
        "count": 28,
        "scan_points_target": 98,
        "themes": ["ATERRO", "BOTAFOGO", "URCA", "PRAIA", "ENSEADA"],
        "vendors": [
            "Flamengo Promenade",
            "Botafogo Retail",
            "Urca Wireless",
            "Bayfront Services",
        ],
    },
    "Copacabana + Arpoador + Ipanema + Lagoa": {
        "count": 34,
        "scan_points_target": 84,
        "themes": ["COPA", "ARPOADOR", "IPANEMA", "LAGOA", "ORLA"],
        "vendors": [
            "South Zone Guest",
            "Orla Telecom",
            "Lagoa Wi-Fi",
            "Beachside Fiber",
        ],
    },
    "Lapa + Gloria + Praca Maua Motorcycle": {
        "count": 26,
        "scan_points_target": 110,
        "themes": ["LAPA", "GLORIA", "PORTO", "MAUA", "CENTRO"],
        "vendors": [
            "Centro Mobility",
            "Porto Retail Mesh",
            "Gloria Guest Fiber",
            "Boulevard Link",
        ],
    },
}


def _json_dump(path: Path, payload: dict[str, Any]) -> None:
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


def _data_header(fc: bytes, addr1: str, addr2: str, addr3: str, seq: int) -> bytes:
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
        b"\x00"
        + bytes([len(ssid_bytes)])
        + ssid_bytes
        + b"\x01\x04\x82\x84\x8b\x96"
        + b"\x03\x01"
        + bytes([int(channel or 1) & 0xFF])
        + b"\x30\x14"
        + bytes.fromhex("0100000fac040100000fac040100000fac020000")
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
    tags = b"\x00" + bytes([len(ssid_bytes)]) + ssid_bytes + b"\x01\x04\x82\x84\x8b\x96"
    return header + tags


def _broadcast_probe_request_frame(client_mac: str, seq: int) -> bytes:
    return _probe_request_frame(client_mac, "", seq)


def _deauth_frame(bssid: str, client_mac: str, seq: int, reason: int = 7) -> bytes:
    header = _mgmt_header(b"\xc0\x00", client_mac, bssid, bssid, seq)
    return header + struct.pack("<H", int(reason))


def _disassoc_frame(bssid: str, client_mac: str, seq: int, reason: int = 8) -> bytes:
    header = _mgmt_header(b"\xa0\x00", client_mac, bssid, bssid, seq)
    return header + struct.pack("<H", int(reason))


def _eapol_payload(network_id: str, client_mac: str, message: int) -> bytes:
    seed = hashlib.sha1(
        f"{PROFILE_ID}|{network_id}|{client_mac}|eapol|{message}".encode("utf-8")
    ).digest()
    nonce = (seed * 3)[:32]
    mic = hashlib.sha1(seed + b"mic").digest()[:16]
    iv = hashlib.sha1(seed + b"iv").digest()[:16]
    rsc = hashlib.sha1(seed + b"rsc").digest()[:8]
    key_id = hashlib.sha1(seed + b"keyid").digest()[:8]
    replay_counter = struct.pack(">Q", 100 + message)
    key_length = struct.pack(">H", 16)
    key_info_map = {
        1: 0x008A,
        2: 0x010A,
        3: 0x13CA,
        4: 0x030A,
    }
    key_info = struct.pack(">H", key_info_map.get(int(message), 0x008A))
    key_data_len = struct.pack(">H", 0)
    key_body = (
        b"\x02"
        + key_info
        + key_length
        + replay_counter
        + nonce
        + iv
        + rsc
        + key_id
        + mic
        + key_data_len
    )
    return b"\x02\x03" + struct.pack(">H", len(key_body)) + key_body


def _eapol_frame(
    network_id: str, bssid: str, client_mac: str, seq: int, message: int
) -> bytes:
    if int(message) in {1, 3}:
        header = _data_header(b"\x08\x02", client_mac, bssid, bssid, seq)
    else:
        header = _data_header(b"\x08\x01", bssid, client_mac, bssid, seq)
    llc_snap = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"
    return header + llc_snap + _eapol_payload(network_id, client_mac, int(message))


def _write_pcap(path: Path, frames: list[tuple[int, int, bytes]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.write(_pcap_global_header())
        for ts_sec, ts_usec, payload in frames:
            handle.write(_pcap_packet(ts_sec, ts_usec, payload))
    os.utime(path, (DEMO_SOURCE_MTIME, DEMO_SOURCE_MTIME))


def _build_demo_frames(
    network_ids: list[str], clients: list[str]
) -> list[tuple[int, int, bytes]]:
    frames: list[tuple[int, int, bytes]] = []
    ts_base = 1_744_328_400
    seq = 1
    for idx, network_id in enumerate(network_ids):
        network = NETWORKS[network_id]
        bssid = network["bssid"]
        channel = int(network["channel"])
        ssid = network["ssid"]
        client = clients[idx % len(clients)]
        step = idx * 19
        frames.append((ts_base + step, 0, _beacon_frame(bssid, ssid, channel, seq)))
        seq += 1
        frames.append((ts_base + step + 1, 0, _probe_request_frame(client, ssid, seq)))
        seq += 1
        frames.append(
            (ts_base + step + 2, 0, _broadcast_probe_request_frame(client, seq))
        )
        seq += 1
        if (
            network["encryption"] not in {"OPEN", "WEP"}
            and network["category"] != "not_ready"
        ):
            for message in range(1, 5):
                frames.append(
                    (
                        ts_base + step + 2 + message,
                        0,
                        _eapol_frame(network_id, bssid, client, seq, message),
                    )
                )
                seq += 1
        frames.append((ts_base + step + 8, 0, _deauth_frame(bssid, client, seq)))
        seq += 1
        frames.append((ts_base + step + 9, 0, _disassoc_frame(bssid, client, seq)))
        seq += 1
    return frames


def _build_minimal_demo_frames(
    network_ids: list[str], clients: list[str]
) -> list[tuple[int, int, bytes]]:
    frames: list[tuple[int, int, bytes]] = []
    ts_base = 1_744_328_400
    seq = 1
    for idx, network_id in enumerate(network_ids):
        network = NETWORKS[network_id]
        bssid = network["bssid"]
        channel = int(network["channel"])
        ssid = network["ssid"]
        client = clients[idx % len(clients)]
        step = idx * 11
        frames.append((ts_base + step, 0, _beacon_frame(bssid, ssid, channel, seq)))
        seq += 1
        frames.append((ts_base + step + 1, 0, _probe_request_frame(client, ssid, seq)))
        seq += 1
    return frames


def _capture_frames_for_spec(spec: dict[str, Any]) -> list[tuple[int, int, bytes]]:
    network_id = str(spec["network_id"])
    clients = list(spec.get("clients") or ["6A:7B:8C:9D:AE:10"])
    if str(spec.get("pcap_profile") or "").strip().lower() == "minimal":
        return _build_minimal_demo_frames([network_id], clients)
    return _build_demo_frames([network_id], clients)


def _details_payload(network_id: str, *, source: str) -> dict[str, Any]:
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
            "pmkid_available": network["encryption"] in {"WPA2", "WPA3"}
            and network["category"] != "not_ready",
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


def _gps_payload(network_id: str, *, capture_filename: str) -> dict[str, Any]:
    network = NETWORKS[network_id]
    return {
        "SSID": network["ssid"],
        "BSSID": network["bssid"],
        "Latitude": network["lat"],
        "Longitude": network["lng"],
        "Accuracy": network["accuracy"],
        "Updated": BUILD_STAMP,
        "source_file": capture_filename,
        "demo_profile": PROFILE_ID,
    }


def _hash_line(network_id: str, *, suffix: str) -> str:
    network = NETWORKS[network_id]
    digest = hashlib.sha1(
        f"{PROFILE_ID}|{network_id}|{suffix}".encode("utf-8")
    ).hexdigest()[:32]
    client_mac = hashlib.sha1(f"{network_id}|client".encode("utf-8")).hexdigest()[:12]
    return (
        f"WPA*02*{digest}*{_mac_clean(network['bssid'])}*{client_mac}"
        f"*{_ssid_hex(network['ssid']) or '00'}*00"
    )


def _iso_to_epoch(value: str) -> float:
    normalized = str(value or "").strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _epoch_to_iso(epoch: float) -> str:
    return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _deterministic_unit(*parts: object) -> float:
    raw = "|".join(str(part) for part in parts).encode("utf-8")
    digest = hashlib.sha1(raw).digest()
    return int.from_bytes(digest[:8], "big") / float(2**64 - 1)


def _slug_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")


def _local_admin_mac(*parts: object) -> str:
    digest = hashlib.sha1(
        "|".join(str(part) for part in parts).encode("utf-8")
    ).digest()
    octets = list(digest[:6])
    octets[0] = (octets[0] | 0x02) & 0xFE
    return ":".join(f"{octet:02X}" for octet in octets)


def _clamp_bbox(lat: float, lng: float) -> tuple[float, float]:
    lat = min(
        max(float(lat), RJ_BBOX["lat_min"] + 0.000001), RJ_BBOX["lat_max"] - 0.000001
    )
    lng = min(
        max(float(lng), RJ_BBOX["lng_min"] + 0.000001), RJ_BBOX["lng_max"] - 0.000001
    )
    return lat, lng


def _offset_lat_lng(
    lat: float, lng: float, *, north_m: float = 0.0, east_m: float = 0.0
) -> tuple[float, float]:
    lat_delta = float(north_m) / 111_320.0
    lng_scale = max(0.25, math.cos(math.radians(float(lat))))
    lng_delta = float(east_m) / (111_320.0 * lng_scale)
    return _clamp_bbox(float(lat) + lat_delta, float(lng) + lng_delta)


def _install_zone_showcase_expansion() -> None:
    """Add dense locked/cracked demo clusters for zone-oriented UI examples."""

    hotspots = [
        {
            "slug": "lapa_arcos",
            "ssid_prefix": "LAPA_ARCOS",
            "vendor": "Historic District Mesh",
            "lat": -22.91405,
            "lng": -43.18240,
            "locked": 8,
            "cracked": 3,
            "channel_base": 1,
        },
        {
            "slug": "porto_maua",
            "ssid_prefix": "PORTO_MAUA",
            "vendor": "Port District Fiber",
            "lat": -22.89730,
            "lng": -43.17880,
            "locked": 8,
            "cracked": 3,
            "channel_base": 36,
        },
        {
            "slug": "maracana_ring",
            "ssid_prefix": "MARACANA_RING",
            "vendor": "Arena Ops Network",
            "lat": -22.91220,
            "lng": -43.23060,
            "locked": 7,
            "cracked": 3,
            "channel_base": 6,
        },
        {
            "slug": "arpoador_ops",
            "ssid_prefix": "ARPOADOR_OPS",
            "vendor": "Beachfront Ops",
            "lat": -22.98880,
            "lng": -43.19160,
            "locked": 8,
            "cracked": 3,
            "channel_base": 44,
        },
        {
            "slug": "engenhao_track",
            "ssid_prefix": "ENGENHAO_TRACK",
            "vendor": "North Rail Services",
            "lat": -22.89515,
            "lng": -43.29235,
            "locked": 7,
            "cracked": 2,
            "channel_base": 149,
        },
    ]
    channels = [
        {"channel": 1, "frequency": 2412},
        {"channel": 6, "frequency": 2437},
        {"channel": 11, "frequency": 2462},
        {"channel": 36, "frequency": 5180},
        {"channel": 44, "frequency": 5220},
        {"channel": 149, "frequency": 5745},
    ]
    offsets_m = [
        (0.0, 0.0),
        (5.0, 4.0),
        (-4.0, 6.0),
        (7.0, -3.0),
        (-6.0, -5.0),
        (11.0, 2.0),
        (-10.0, 3.0),
        (3.0, -11.0),
        (16.0, 9.0),
        (-14.0, 10.0),
        (12.0, -14.0),
    ]
    scenario_cycle = ("pcap_plus_22000", "pcap_only_convertible", "pcap_plus_22000")

    for hotspot in hotspots:
        slug = str(hotspot["slug"])
        total = int(hotspot["locked"]) + int(hotspot["cracked"])
        for index in range(total):
            cracked = index >= int(hotspot["locked"])
            local_index = index - int(hotspot["locked"]) if cracked else index
            north_m, east_m = offsets_m[index % len(offsets_m)]
            if cracked:
                north_m += 72.0
                east_m += 64.0
            lat, lng = _offset_lat_lng(
                float(hotspot["lat"]),
                float(hotspot["lng"]),
                north_m=north_m,
                east_m=east_m,
            )
            channel_seed = int(hotspot["channel_base"])
            channel_profile = channels[(index + channel_seed) % len(channels)]
            suffix = "CRACKED" if cracked else "LOCKED"
            network_id = f"{slug}_{suffix.lower()}_{local_index + 1:02d}"
            ssid = f"{hotspot['ssid_prefix']}_{suffix}_{local_index + 1:02d}"
            NETWORKS[network_id] = {
                "ssid": ssid,
                "bssid": _local_admin_mac(
                    PROFILE_ID, "zone", slug, suffix, local_index
                ),
                "auth_mode": "[WPA2-PSK-CCMP][ESS]",
                "encryption": "WPA2",
                "password": f"{_slug_token(ssid)}-demo",
                "category": "already_cracked" if cracked else "locked_showcase",
                "vendor": str(hotspot["vendor"]),
                "channel": int(channel_profile["channel"]),
                "frequency": int(channel_profile["frequency"]),
                "lat": lat,
                "lng": lng,
                "altitude": 9.0 + (index % 5) * 1.7,
                "accuracy": 13.0 if cracked else 14.5,
                "device_type": "router_ap" if index % 3 else "mobile_router",
                "device_confidence": 0.86 + (index % 5) * 0.02,
                "wardrive_anchors": [
                    {
                        "lat": lat,
                        "lng": lng,
                        "radius_m": 135.0 if cracked else 155.0,
                        "peak_rssi": -44 if cracked else -46,
                    }
                ],
            }
            safe_id = _slug_token(network_id)
            scenario = (
                "pcap_plus_22000_plus_cracked"
                if cracked
                else scenario_cycle[index % len(scenario_cycle)]
            )
            HANDSHAKE_CAPTURES.append(
                {
                    "id": f"pwn_zone_{safe_id}",
                    "network_id": network_id,
                    "source": "pwnagotchi",
                    "role": "handshakes",
                    "root": "handshakes",
                    "filename": f"{_slug_token(ssid).upper()}_{_mac_clean(NETWORKS[network_id]['bssid'])}.pcap",
                    "gps": True,
                    "legacy_sidecars": True,
                    "cracked": cracked,
                    "hash_ready": scenario != "pcap_only_convertible",
                    "scenario": scenario,
                    "pcap_profile": "full",
                }
            )

            if cracked:
                WORDLISTS["demo_easy.txt"].append(str(NETWORKS[network_id]["password"]))
            elif index % 2 == 0:
                WORDLISTS["demo_association.txt"].append(
                    str(NETWORKS[network_id]["password"])
                )


_install_zone_showcase_expansion()


def _density_auth_profile(corridor: str, index: int) -> tuple[str, str, str, str]:
    open_selector = int(_deterministic_unit(corridor, index, "open") * 10)
    wpa3_selector = int(_deterministic_unit(corridor, index, "wpa3") * 8)
    if open_selector == 0:
        return "[OPEN]", "OPEN", "", "wardrive_density_open"
    if wpa3_selector in {0, 1}:
        return (
            "[WPA3-SAE-CCMP][ESS]",
            "WPA3",
            f"{_slug_token(corridor)}-{index + 1:02d}-sae",
            "wardrive_density",
        )
    return (
        "[WPA2-PSK-CCMP][ESS]",
        "WPA2",
        f"{_slug_token(corridor)}-{index + 1:02d}-psk",
        "wardrive_density",
    )


def _build_corridor_density_networks(
    session: dict[str, Any],
    route_points: list[dict[str, float | str]],
) -> dict[str, dict[str, Any]]:
    corridor = str(session["corridor"])
    plan = CORRIDOR_DENSITY_PLAN[corridor]
    route_count = len(route_points)
    count = int(plan["count"])
    stride = max(10, route_count // max(count, 1))
    corridor_slug = _slug_token(corridor)
    networks: dict[str, dict[str, Any]] = {}
    hub_count = max(4, min(7, count // 4))
    hub_indices = [
        int(round(((hub_number + 1) / float(hub_count + 1)) * (route_count - 1)))
        for hub_number in range(hub_count)
    ]

    for index in range(count):
        theme = str(plan["themes"][index % len(plan["themes"])])
        vendor = str(plan["vendors"][index % len(plan["vendors"])])
        suffix = str(DENSITY_SSID_SUFFIXES[index % len(DENSITY_SSID_SUFFIXES)])
        network_id = f"{corridor_slug}__{index + 1:02d}"
        primary_hub_index = hub_indices[index % len(hub_indices)]
        hub_jitter = int(
            round(
                (_deterministic_unit(corridor, index, "hub_jitter") - 0.5)
                * max(6, stride)
            )
        )
        base_point_index = min(
            route_count - 1,
            max(0, primary_hub_index + hub_jitter),
        )
        channel_profile = DENSITY_CHANNEL_PROFILES[
            int(
                _deterministic_unit(corridor, index, "channel")
                * len(DENSITY_CHANNEL_PROFILES)
            )
            % len(DENSITY_CHANNEL_PROFILES)
        ]
        auth_mode, encryption, password, category = _density_auth_profile(
            corridor, index
        )
        anchor_indices = {
            base_point_index,
            primary_hub_index,
            min(route_count - 1, max(0, primary_hub_index + max(6, stride // 3))),
        }
        if _deterministic_unit(corridor, index, "backtrack") > 0.35:
            anchor_indices.add(max(0, primary_hub_index - max(6, stride // 3)))
        if _deterministic_unit(corridor, index, "repeat") > 0.72:
            secondary_hub_index = hub_indices[(index + 1) % len(hub_indices)]
            anchor_indices.add(secondary_hub_index)
        if _deterministic_unit(corridor, index, "repeat_far") > 0.84:
            tertiary_hub_index = hub_indices[(index + 2) % len(hub_indices)]
            anchor_indices.add(tertiary_hub_index)

        anchors = []
        for anchor_number, point_index in enumerate(sorted(anchor_indices)):
            base_point = route_points[point_index]
            north_m = (
                _deterministic_unit(corridor, index, anchor_number, "north") - 0.5
            ) * 60.0
            east_m = (
                _deterministic_unit(corridor, index, anchor_number, "east") - 0.5
            ) * 60.0
            lat, lng = _offset_lat_lng(
                float(base_point["lat"]),
                float(base_point["lng"]),
                north_m=north_m,
                east_m=east_m,
            )
            anchors.append(
                {
                    "lat": lat,
                    "lng": lng,
                    "radius_m": round(
                        135.0
                        + _deterministic_unit(corridor, index, anchor_number, "radius")
                        * 120.0,
                        1,
                    ),
                    "peak_rssi": round(
                        -43.0
                        - _deterministic_unit(corridor, index, anchor_number, "peak")
                        * 21.0,
                        1,
                    ),
                }
            )

        primary_lat = float(anchors[0]["lat"])
        primary_lng = float(anchors[0]["lng"])
        networks[network_id] = {
            "ssid": f"{theme}_{suffix}_{index + 1:02d}",
            "bssid": _local_admin_mac(PROFILE_ID, corridor_slug, index),
            "auth_mode": auth_mode,
            "encryption": encryption,
            "password": password,
            "category": category,
            "vendor": vendor,
            "channel": int(channel_profile["channel"]),
            "frequency": int(channel_profile["frequency"]),
            "lat": primary_lat,
            "lng": primary_lng,
            "altitude": round(float(route_points[base_point_index]["altitude_m"]), 1),
            "accuracy": round(
                float(route_points[base_point_index]["accuracy_m"]) + 0.6, 1
            ),
            "device_type": DENSITY_DEVICE_TYPES[index % len(DENSITY_DEVICE_TYPES)],
            "device_confidence": round(
                0.74 + _deterministic_unit(corridor, index, "confidence") * 0.18, 2
            ),
            "wardrive_anchors": anchors,
        }
    return networks


def _lerp(start: float, end: float, ratio: float) -> float:
    return float(start) + (float(end) - float(start)) * float(ratio)


def _haversine_m(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    radius_m = 6_371_000.0
    phi1 = math.radians(float(lat1))
    phi2 = math.radians(float(lat2))
    d_phi = math.radians(float(lat2) - float(lat1))
    d_lambda = math.radians(float(lng2) - float(lng1))
    a = (
        math.sin(d_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2.0) ** 2
    )
    return 2.0 * radius_m * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))


def _route_asset_path(source_root: Path, asset_name: str) -> Path:
    return source_root / asset_name


def _load_route_waypoints(route_path: Path) -> list[dict[str, float | str]]:
    with route_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = tuple(reader.fieldnames or [])
        if fieldnames != ROUTE_COLUMNS:
            raise AssertionError(
                f"Route source {route_path.name} must use columns {ROUTE_COLUMNS}, got {fieldnames}"
            )
        if set(fieldnames) & ROUTE_FORBIDDEN_COLUMNS:
            raise AssertionError(
                f"Route source {route_path.name} contains forbidden Wi-Fi columns."
            )
        rows: list[dict[str, float | str]] = []
        previous_ts: float | None = None
        for row in reader:
            ts = _iso_to_epoch(str(row["timestamp"]))
            lat = float(row["lat"])
            lng = float(row["lng"])
            if not (
                RJ_BBOX["lat_min"] <= lat <= RJ_BBOX["lat_max"]
                and RJ_BBOX["lng_min"] <= lng <= RJ_BBOX["lng_max"]
            ):
                raise AssertionError(
                    f"Route point {lat},{lng} in {route_path.name} is outside the RJ bbox."
                )
            if previous_ts is not None and ts <= previous_ts:
                raise AssertionError(
                    f"Route source {route_path.name} must have strictly increasing timestamps."
                )
            previous_ts = ts
            rows.append(
                {
                    "timestamp": _epoch_to_iso(ts),
                    "epoch": ts,
                    "lat": lat,
                    "lng": lng,
                    "altitude_m": float(row["altitude_m"]),
                    "speed_kmh": float(row["speed_kmh"]),
                    "accuracy_m": float(row["accuracy_m"]),
                }
            )
    if len(rows) < 2:
        raise AssertionError(
            f"Route source {route_path.name} must contain at least 2 rows."
        )
    return rows


def _densify_route_waypoints(
    waypoints: list[dict[str, float | str]], *, step_seconds: int = 15
) -> list[dict[str, float | str]]:
    if len(waypoints) >= 150:
        return [dict(item) for item in waypoints]
    dense_points = [dict(waypoints[0])]
    for idx in range(len(waypoints) - 1):
        start = waypoints[idx]
        end = waypoints[idx + 1]
        start_epoch = float(start["epoch"])
        end_epoch = float(end["epoch"])
        duration = max(1.0, end_epoch - start_epoch)
        steps = max(1, int(duration // float(step_seconds)))
        for step in range(1, steps + 1):
            ratio = step / float(steps)
            epoch = _lerp(start_epoch, end_epoch, ratio)
            dense_points.append(
                {
                    "timestamp": _epoch_to_iso(epoch),
                    "epoch": epoch,
                    "lat": _lerp(float(start["lat"]), float(end["lat"]), ratio),
                    "lng": _lerp(float(start["lng"]), float(end["lng"]), ratio),
                    "altitude_m": _lerp(
                        float(start["altitude_m"]), float(end["altitude_m"]), ratio
                    ),
                    "speed_kmh": _lerp(
                        float(start["speed_kmh"]), float(end["speed_kmh"]), ratio
                    ),
                    "accuracy_m": _lerp(
                        float(start["accuracy_m"]), float(end["accuracy_m"]), ratio
                    ),
                }
            )
    return dense_points


def _network_anchors(network: dict[str, Any]) -> list[dict[str, float]]:
    anchors = list(network.get("wardrive_anchors") or [])
    if anchors:
        return anchors
    return [
        {
            "lat": float(network["lat"]),
            "lng": float(network["lng"]),
            "radius_m": 150.0,
            "peak_rssi": -50.0,
        }
    ]


def _wardrive_row_for_visibility(
    *,
    network_id: str,
    network: dict[str, Any],
    point: dict[str, float | str],
    session_key: str,
    point_index: int,
    distance_m: float,
    radius_m: float,
    peak_rssi: float,
) -> dict[str, Any]:
    visibility_ratio = max(0.0, 1.0 - (distance_m / max(radius_m, 1.0)))
    jitter = (
        _deterministic_unit(session_key, network_id, point_index, "rssi") - 0.5
    ) * 6.0
    rssi_floor = -87.0
    rssi = int(
        round(max(rssi_floor, peak_rssi - (1.0 - visibility_ratio) * 29.0 + jitter))
    )
    linger_seconds = min(12.0, 4.0 + float(point["speed_kmh"]) / 10.0)
    first_seen = _epoch_to_iso(float(point["epoch"]) - linger_seconds)
    accuracy = max(
        3.5,
        min(
            9.8,
            float(point["accuracy_m"]) + (distance_m / max(radius_m, 1.0)) * 1.7,
        ),
    )
    return {
        "MAC": network["bssid"],
        "SSID": network["ssid"],
        "AuthMode": network["auth_mode"],
        "FirstSeen": first_seen,
        "LastSeen": str(point["timestamp"]),
        "Channel": network["channel"],
        "Frequency": network["frequency"],
        "RSSI": rssi,
        "CurrentLatitude": round(float(point["lat"]), 6),
        "CurrentLongitude": round(float(point["lng"]), 6),
        "AltitudeMeters": round(float(point["altitude_m"]), 1),
        "AccuracyMeters": round(accuracy, 1),
        "Type": "WIFI",
    }


def _generate_wardrive_rows(
    session: dict[str, Any],
    route_points: list[dict[str, float | str]],
    *,
    network_catalog: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], set[str]]:
    rows: list[dict[str, Any]] = []
    observed_network_ids: set[str] = set()
    session_key = Path(str(session["filename"])).stem

    for point_index, point in enumerate(route_points):
        visible: list[tuple[float, str, dict[str, Any]]] = []
        for network_id, network in network_catalog.items():
            for anchor_index, anchor in enumerate(_network_anchors(network)):
                distance_m = _haversine_m(
                    float(point["lat"]),
                    float(point["lng"]),
                    float(anchor["lat"]),
                    float(anchor["lng"]),
                )
                radius_m = float(anchor.get("radius_m", 150.0))
                if distance_m > radius_m:
                    continue
                row = _wardrive_row_for_visibility(
                    network_id=network_id,
                    network=network,
                    point=point,
                    session_key=f"{session_key}:{anchor_index}",
                    point_index=point_index,
                    distance_m=distance_m,
                    radius_m=radius_m,
                    peak_rssi=float(anchor.get("peak_rssi", -50.0)),
                )
                visible.append((distance_m, network_id, row))
        visible.sort(key=lambda item: (item[0], item[1]))
        visible_cap = WARDRIVE_MIN_VISIBLE_PER_POINT + int(
            round(
                _deterministic_unit(session_key, point_index, "visible_cap")
                * (WARDRIVE_MAX_VISIBLE_PER_POINT - WARDRIVE_MIN_VISIBLE_PER_POINT)
            )
        )
        for _, network_id, row in visible[:visible_cap]:
            rows.append(row)
            observed_network_ids.add(network_id)

    return rows, observed_network_ids


def _write_wardrive_csv(path: Path, header: str, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        handle.write(f"{header}\n")
        writer = csv.DictWriter(handle, fieldnames=WIGLE_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _build_capture_assets(runtime_root: Path) -> dict[str, Any]:
    captures = []
    capture_id_index: dict[str, str] = {}
    line_index: dict[str, str] = {}

    for spec in HANDSHAKE_CAPTURES:
        network_id = str(spec["network_id"])
        network = NETWORKS[network_id]
        filename = str(spec["filename"])
        source = str(spec["source"])
        role = str(spec["role"])
        scenario = str(spec.get("scenario") or "pcap_plus_22000")
        capture_id = _capture_id(source, role, filename)
        capture_id_index[str(spec["id"])] = capture_id
        capture_root = runtime_root / str(spec["root"])
        pcap_path = capture_root / filename
        frames = _capture_frames_for_spec(spec)
        _write_pcap(pcap_path, frames)

        line = _hash_line(network_id, suffix=filename)
        line_index[capture_id] = line
        base_name = Path(filename).stem
        _json_dump(
            capture_root / f"{base_name}.details",
            _details_payload(network_id, source=source),
        )
        if spec.get("hash_ready", True):
            (capture_root / f"{base_name}.22000").write_text(
                f"{line}\n", encoding="utf-8"
            )
        if spec.get("cracked"):
            (capture_root / f"{base_name}.cracked").write_text(
                f"{network['password']}\n", encoding="utf-8"
            )
        (capture_root / f"{base_name}.try").write_text(
            f"demo::{network_id}::{source}\n", encoding="utf-8"
        )

        if spec.get("legacy_sidecars"):
            if spec.get("gps"):
                _json_dump(
                    runtime_root / "handshakes" / f"{base_name}.paw-gps.json",
                    _gps_payload(network_id, capture_filename=filename),
                )

        capture_record = {
            "capture_id": capture_id,
            "network_id": network_id,
            "source": source,
            "role": role,
            "filename": filename,
            "scenario": scenario,
            "pcap_profile": str(spec.get("pcap_profile") or "full"),
            "pcap_path": str(pcap_path.relative_to(runtime_root)),
            "gps": bool(spec.get("gps", False)),
            "hash_ready": bool(spec.get("hash_ready", True)),
            "cracked": bool(spec.get("cracked", False)),
            "promotion": str(spec.get("demo_promotion") or ""),
        }
        captures.append(capture_record)

    combined_records: list[dict[str, Any]] = []
    for network_id, capture_keys in COMBINED_CAPTURE_GROUPS.items():
        capture_ids = [
            capture_id_index[key]
            for key in capture_keys
            if key in capture_id_index and line_index.get(capture_id_index[key])
        ]
        build_id = create_combined_build_id(capture_ids)
        combined_dir = (
            runtime_root
            / "handshakes"
            / "combined"
            / _mac_clean(NETWORKS[network_id]["bssid"])
            / build_id
        )
        combined_dir.mkdir(parents=True, exist_ok=True)
        unique_lines = []
        seen_lines = set()
        for capture_id in capture_ids:
            line = line_index[capture_id]
            if line in seen_lines:
                continue
            seen_lines.add(line)
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
                "included_capture_ids": capture_ids,
                "included_captures": [
                    {
                        "capture_id": item["capture_id"],
                        "source": item["source"],
                        "source_filename": item["filename"],
                    }
                    for item in captures
                    if item["capture_id"] in capture_ids
                ],
                "mac": NETWORKS[network_id]["bssid"],
                "network_id": network_id,
            },
        )
        combined_records.append(
            {
                "network_id": network_id,
                "mac": NETWORKS[network_id]["bssid"],
                "build_id": build_id,
                "included_capture_ids": capture_ids,
            }
        )

    batch_name = "batch_showcase_core_v5.22000"
    batch_network_ids = [
        "lapa_event_guest",
        "rio_cafe_loop",
        "botafogo_kiosk_net",
        "copa_media_node",
        "metro_line_4",
    ]
    batch_items = [
        next(
            item
            for item in captures
            if item["network_id"] == network_id and item["hash_ready"]
        )
        for network_id in batch_network_ids
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
        "combined_records": combined_records,
        "batch_name": batch_name,
    }


def _build_raw_assets(runtime_root: Path) -> dict[str, Any]:
    raw_records = []
    raw_hash_index = 1

    for spec in RAW_CAPTURES:
        root = runtime_root / str(spec["root"])
        filename = str(spec["filename"])
        pcap_path = root / filename
        frames = _build_demo_frames(list(spec["networks"]), list(spec["clients"]))
        _write_pcap(pcap_path, frames)
        stat = pcap_path.stat()
        raw_item_id = _raw_item_id(
            "pcap",
            str(spec["source"]),
            str(spec["source_path_role"]),
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
            network = NETWORKS[str(network_id)]
            eapol_count = 4 if network["category"] not in {"not_ready", "open"} else 0
            networks_payload.append(
                {
                    "bssid": network["bssid"],
                    "ssid": network["ssid"],
                    "ssid_raw_hex": _ssid_hex(network["ssid"]) or None,
                    "channel": network["channel"],
                    "frequency_mhz": network["frequency"],
                    "beacon_count": 18 + idx * 6,
                    "eapol_count": eapol_count,
                    "probe_client_count": 1 + idx,
                    "last_seen_offset_s": float(18 + idx * 11),
                }
            )
            handshake_candidates.append(
                {
                    "bssid": network["bssid"],
                    "ssid": network["ssid"],
                    "eapol_count": eapol_count,
                    "tier": (
                        "ready"
                        if network["category"] not in {"not_ready", "open"}
                        else "watch"
                    ),
                }
            )
            top_clients.append(
                {
                    "mac": spec["clients"][idx % len(spec["clients"])],
                    "total_frames": 20 + idx * 7,
                    "network_count": 1,
                    "eapol_count": eapol_count,
                }
            )

            if network["category"] not in {"not_ready", "open", "raw_only_candidate"}:
                hash_name = f"raw_{raw_hash_index}.22000"
                raw_hash_index += 1
                (runtime_root / "handshakes" / hash_name).write_text(
                    _hash_line(str(network_id), suffix=hash_name) + "\n",
                    encoding="utf-8",
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
                "beacon_frames": sum(
                    int(item["beacon_count"]) for item in networks_payload
                ),
                "eapol_frames": sum(
                    int(item["eapol_count"]) for item in networks_payload
                ),
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
                    "duration_s": 95.0,
                    "networks_count": len(networks_payload),
                    "clients_count": len(top_clients),
                    "frame_totals": {
                        "beacons": sum(
                            int(item["beacon_count"]) for item in networks_payload
                        ),
                        "eapol": sum(
                            int(item["eapol_count"]) for item in networks_payload
                        ),
                        "probe_requests": len(top_clients) * 4,
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
                    "hidden_network_count": (
                        1
                        if any(
                            not NETWORKS[str(net)]["ssid"] for net in spec["networks"]
                        )
                        else 0
                    ),
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


def _load_density_profile(path: Path | None = None) -> dict[str, Any]:
    density_path = Path(path or DENSITY_PROFILE_PATH)
    payload = json.loads(density_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise AssertionError(f"Invalid density profile payload: {density_path}")
    return payload


def _route_distance_km(route_points: list[dict[str, float | str]]) -> float:
    total_m = sum(
        _haversine_m(
            float(current["lat"]),
            float(current["lng"]),
            float(nxt["lat"]),
            float(nxt["lng"]),
        )
        for current, nxt in zip(route_points, route_points[1:])
    )
    return total_m / 1000.0


def _profile_batch_sequence(
    density_profile: dict[str, Any],
    *,
    total_points: int,
    session_key: str,
    density_multiplier: float = 1.0,
) -> list[int]:
    histogram = density_profile.get("point_batch_histogram") or {}
    weighted: list[int] = []
    for batch_size, count in sorted(
        ((int(size), int(count)) for size, count in histogram.items()),
        key=lambda item: item[0],
    ):
        weighted.extend([batch_size] * max(1, count))
    if not weighted:
        weighted = [int(round(float(density_profile.get("rows_per_point") or 32.0)))]

    min_batch = min(weighted)
    max_batch = int(density_profile.get("max_same_gps") or max(weighted))
    target_rows_per_point = float(density_profile.get("rows_per_point") or 32.0) * max(
        0.35, float(density_multiplier)
    )
    base_sequence = [
        weighted[
            min(
                len(weighted) - 1,
                int(_deterministic_unit(session_key, index, "batch") * len(weighted)),
            )
        ]
        for index in range(total_points)
    ]
    current_avg = sum(base_sequence) / float(max(1, len(base_sequence)))
    scale = target_rows_per_point / max(current_avg, 1.0)
    return [
        max(min_batch, min(max_batch, int(round(batch_size * scale))))
        for batch_size in base_sequence
    ]


def _channel_profile_pool(density_profile: dict[str, Any]) -> list[dict[str, int]]:
    channel_hist = density_profile.get("channels") or {}
    if not channel_hist:
        return list(DENSITY_CHANNEL_PROFILES)

    total = float(sum(int(count) for count in channel_hist.values()) or 1)
    pool: list[dict[str, int]] = []
    for channel, count in sorted(
        ((int(channel), int(count)) for channel, count in channel_hist.items()),
        key=lambda item: item[0],
    ):
        repeats = max(1, int(round((count / total) * 240.0)))
        if channel <= 14:
            frequency = 2484 if channel == 14 else 2407 + (channel * 5)
        else:
            frequency = 5000 + (channel * 5)
        pool.extend([{"channel": int(channel), "frequency": int(frequency)}] * repeats)
    return pool or list(DENSITY_CHANNEL_PROFILES)


def _session_key(session: dict[str, Any]) -> str:
    return Path(str(session["filename"])).stem


def _visible_hero_rows_for_point(
    *,
    point: dict[str, float | str],
    point_index: int,
    session: dict[str, Any],
) -> tuple[list[tuple[str, dict[str, Any]]], set[str]]:
    rows: list[tuple[str, dict[str, Any]]] = []
    observed: set[str] = set()
    session_key = _session_key(session)
    for network_id, network in NETWORKS.items():
        anchors = list(network.get("wardrive_anchors") or [])
        for anchor_index, anchor in enumerate(anchors):
            distance_m = _haversine_m(
                float(point["lat"]),
                float(point["lng"]),
                float(anchor["lat"]),
                float(anchor["lng"]),
            )
            radius_m = float(anchor.get("radius_m", 150.0))
            if distance_m > radius_m:
                continue
            rows.append(
                (
                    network_id,
                    _wardrive_row_for_visibility(
                        network_id=network_id,
                        network=network,
                        point=point,
                        session_key=f"{session_key}:hero:{anchor_index}",
                        point_index=point_index,
                        distance_m=distance_m,
                        radius_m=radius_m,
                        peak_rssi=float(anchor.get("peak_rssi", -50.0)),
                    ),
                )
            )
            observed.add(network_id)
    rows.sort(key=lambda item: (item[1]["RSSI"] * -1, item[0]))
    return rows, observed


def _density_span_points(
    *,
    corridor: str,
    network_index: int,
    avg_span_points: float,
) -> int:
    selector = _deterministic_unit(corridor, network_index, "span_mode")
    base = avg_span_points
    if selector < 0.16:
        span = base * (
            0.45 + _deterministic_unit(corridor, network_index, "short") * 0.30
        )
    elif selector > 0.84:
        span = base * (
            1.20 + _deterministic_unit(corridor, network_index, "long") * 0.75
        )
    else:
        span = base * (
            0.80 + _deterministic_unit(corridor, network_index, "normal") * 0.60
        )
    return max(6, int(round(span)))


def _build_density_network(
    *,
    session: dict[str, Any],
    corridor: str,
    session_key: str,
    point: dict[str, float | str],
    point_index: int,
    route_points: list[dict[str, float | str]],
    network_index: int,
    span_points: int,
    channel_pool: list[dict[str, int]],
    rssi_profile: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    corridor_slug = _slug_token(corridor)
    plan = CORRIDOR_DENSITY_PLAN[corridor]
    theme = str(plan["themes"][network_index % len(plan["themes"])])
    vendor = str(plan["vendors"][network_index % len(plan["vendors"])])
    suffix = str(DENSITY_SSID_SUFFIXES[network_index % len(DENSITY_SSID_SUFFIXES)])
    channel_profile = channel_pool[
        int(_deterministic_unit(corridor, network_index, "channel") * len(channel_pool))
        % len(channel_pool)
    ]
    auth_mode, encryption, password, category = _density_auth_profile(
        corridor, network_index
    )
    start_index = point_index
    end_index = min(len(route_points) - 1, point_index + span_points - 1)
    peak_offset = int(
        round(
            _deterministic_unit(corridor, network_index, "peak_offset")
            * max(2, span_points - 1)
        )
    )
    peak_index = min(end_index, start_index + peak_offset)
    anchor_lat, anchor_lng = _offset_lat_lng(
        float(point["lat"]),
        float(point["lng"]),
        north_m=(
            (_deterministic_unit(corridor, network_index, "north") - 0.5) * 36.0
            + float(session.get("anchor_bias_north_m") or 0.0)
        ),
        east_m=(
            (_deterministic_unit(corridor, network_index, "east") - 0.5) * 36.0
            + float(session.get("anchor_bias_east_m") or 0.0)
        ),
    )
    peak_floor = float(rssi_profile.get("p90") or -72)
    peak_ceiling = max(-44.0, float(rssi_profile.get("median") or -82) + 18.0)
    peak_rssi = peak_ceiling - (
        _deterministic_unit(corridor, network_index, "peak_rssi")
        * max(4.0, peak_ceiling - peak_floor)
    )
    edge_penalty = (
        16.0 + _deterministic_unit(corridor, network_index, "edge_penalty") * 20.0
    )
    network_id = f"{corridor_slug}__wd_{network_index + 1:04d}"
    return network_id, {
        "ssid": f"{theme}_{suffix}_{network_index + 1:04d}",
        "bssid": _local_admin_mac(PROFILE_ID, corridor_slug, "v5", network_index),
        "auth_mode": auth_mode,
        "encryption": encryption,
        "password": password,
        "category": category,
        "vendor": vendor,
        "channel": int(channel_profile["channel"]),
        "frequency": int(channel_profile["frequency"]),
        "lat": anchor_lat,
        "lng": anchor_lng,
        "altitude": round(float(point["altitude_m"]), 1),
        "accuracy": round(float(point["accuracy_m"]) + 0.4, 1),
        "device_type": DENSITY_DEVICE_TYPES[network_index % len(DENSITY_DEVICE_TYPES)],
        "device_confidence": round(
            0.72 + _deterministic_unit(corridor, network_index, "confidence") * 0.19,
            2,
        ),
        "wardrive_anchors": [
            {
                "lat": anchor_lat,
                "lng": anchor_lng,
                "radius_m": round(90.0 + span_points * 3.2, 1),
                "peak_rssi": round(peak_rssi, 1),
            }
        ],
        "_session_key": session_key,
        "_corridor": corridor,
        "_start_index": start_index,
        "_end_index": end_index,
        "_peak_index": peak_index,
        "_peak_rssi": round(peak_rssi, 1),
        "_edge_penalty": round(edge_penalty, 1),
    }


def _density_row_for_point(
    *,
    network_id: str,
    network: dict[str, Any],
    point: dict[str, float | str],
    point_index: int,
) -> dict[str, Any]:
    start_index = int(network["_start_index"])
    end_index = int(network["_end_index"])
    peak_index = int(network["_peak_index"])
    if point_index <= peak_index:
        denominator = max(1, peak_index - start_index)
        visibility_ratio = 0.30 + 0.70 * (
            (point_index - start_index) / float(denominator)
        )
    else:
        denominator = max(1, end_index - peak_index)
        visibility_ratio = 0.30 + 0.70 * (
            (end_index - point_index) / float(denominator)
        )
    visibility_ratio = max(0.05, min(1.0, visibility_ratio))
    jitter = (_deterministic_unit(network_id, point_index, "rssi_jitter") - 0.5) * 6.0
    peak_rssi = float(network["_peak_rssi"])
    edge_penalty = float(network["_edge_penalty"])
    rssi = int(
        round(
            max(
                -100.0,
                min(
                    -32.0,
                    peak_rssi - ((1.0 - visibility_ratio) * edge_penalty) + jitter,
                ),
            )
        )
    )
    linger_seconds = min(12.0, 3.0 + float(point["speed_kmh"]) / 9.0)
    first_seen = _epoch_to_iso(float(point["epoch"]) - linger_seconds)
    return {
        "MAC": network["bssid"],
        "SSID": network["ssid"],
        "AuthMode": network["auth_mode"],
        "FirstSeen": first_seen,
        "LastSeen": str(point["timestamp"]),
        "Channel": network["channel"],
        "Frequency": network["frequency"],
        "RSSI": rssi,
        "CurrentLatitude": round(float(point["lat"]), 6),
        "CurrentLongitude": round(float(point["lng"]), 6),
        "AltitudeMeters": round(float(point["altitude_m"]), 1),
        "AccuracyMeters": round(float(point["accuracy_m"]), 1),
        "Type": "WIFI",
    }


def _generate_wardrive_rows(
    session: dict[str, Any],
    route_points: list[dict[str, float | str]],
    *,
    density_profile: dict[str, Any],
) -> tuple[list[dict[str, Any]], set[str], dict[str, dict[str, Any]], dict[str, Any]]:
    session_key = _session_key(session)
    corridor = str(session["corridor"])
    density_multiplier = float(session.get("density_multiplier") or 1.0)
    route_distance_km = _route_distance_km(route_points)
    batch_targets = _profile_batch_sequence(
        density_profile,
        total_points=len(route_points),
        session_key=session_key,
        density_multiplier=density_multiplier,
    )

    hero_rows_by_point: list[list[tuple[str, dict[str, Any]]]] = []
    observed_hero_ids: set[str] = set()
    for point_index, point in enumerate(route_points):
        hero_rows, observed_here = _visible_hero_rows_for_point(
            point=point,
            point_index=point_index,
            session=session,
        )
        hero_rows_by_point.append(hero_rows)
        observed_hero_ids.update(observed_here)

    rows_per_km = float(density_profile.get("rows_per_km") or 10000.0)
    unique_bssids_per_km = float(density_profile.get("unique_bssids_per_km") or 550.0)
    target_total_rows = int(round(rows_per_km * route_distance_km * density_multiplier))
    hero_row_total = sum(len(item) for item in hero_rows_by_point)
    target_unique_networks = int(
        round(unique_bssids_per_km * route_distance_km * max(0.42, density_multiplier))
    )
    target_density_rows = max(
        0,
        target_total_rows - hero_row_total,
    )
    target_density_unique = max(
        220,
        target_unique_networks - len(observed_hero_ids),
    )
    avg_span_points = max(
        12.0,
        min(
            42.0,
            (target_density_rows / float(max(1, target_density_unique))) * 1.2,
        ),
    )
    channel_pool = _channel_profile_pool(density_profile)
    rssi_profile = dict(density_profile.get("rssi") or {})

    density_targets = [
        max(0, batch_target - len(hero_rows_by_point[index]))
        for index, batch_target in enumerate(batch_targets)
    ]

    density_catalog: dict[str, dict[str, Any]] = {}
    active_density_ids: list[str] = []
    rows: list[dict[str, Any]] = []
    observed_network_ids: set[str] = set()
    density_network_index = 0

    for point_index, point in enumerate(route_points):
        active_density_ids = [
            network_id
            for network_id in active_density_ids
            if int(density_catalog[network_id]["_end_index"]) >= point_index
        ]

        desired_density = density_targets[point_index]
        while len(active_density_ids) < desired_density:
            span_points = _density_span_points(
                corridor=corridor,
                network_index=density_network_index,
                avg_span_points=avg_span_points,
            )
            network_id, network = _build_density_network(
                session=session,
                corridor=corridor,
                session_key=session_key,
                point=point,
                point_index=point_index,
                route_points=route_points,
                network_index=density_network_index,
                span_points=span_points,
                channel_pool=channel_pool,
                rssi_profile=rssi_profile,
            )
            density_catalog[network_id] = network
            active_density_ids.append(network_id)
            density_network_index += 1

        def _density_rank(network_id: str) -> tuple[float, float]:
            network = density_catalog[network_id]
            span = max(
                1,
                int(network["_end_index"]) - int(network["_start_index"]) + 1,
            )
            distance_ratio = abs(point_index - int(network["_peak_index"])) / float(
                span
            )
            tie_break = _deterministic_unit(
                session_key, network_id, point_index, "rank"
            )
            return (distance_ratio, tie_break)

        selected_density_ids = sorted(active_density_ids, key=_density_rank)[
            :desired_density
        ]

        for network_id, row in hero_rows_by_point[point_index]:
            rows.append(row)
            observed_network_ids.add(network_id)

        for network_id in selected_density_ids:
            rows.append(
                _density_row_for_point(
                    network_id=network_id,
                    network=density_catalog[network_id],
                    point=point,
                    point_index=point_index,
                )
            )
            observed_network_ids.add(network_id)

    point_batch_sizes = [0] * len(route_points)
    for point_index, point in enumerate(route_points):
        point_batch_sizes[point_index] = batch_targets[point_index]

    session_stats = {
        "route_distance_km": round(route_distance_km, 3),
        "rows_per_km": round(len(rows) / max(route_distance_km, 0.001), 2),
        "rows_per_point": round(len(rows) / float(max(1, len(route_points))), 2),
        "unique_bssids_per_km": round(
            len(observed_network_ids) / max(route_distance_km, 0.001),
            2,
        ),
        "max_same_gps": max(point_batch_sizes) if point_batch_sizes else 0,
        "target_total_rows": target_total_rows,
        "target_unique_networks": target_unique_networks,
    }
    return rows, observed_network_ids, density_catalog, session_stats


def _write_wardrive_session_tags(runtime_root: Path) -> dict[str, str]:
    tags = {
        Path(str(session["filename"])).stem: str(session["transport_mode"])
        for session in WARDRIVE_SESSIONS
        if str(session.get("transport_mode") or "").strip()
    }
    tags_path = runtime_root / "wardrive" / "session_tags.json"
    tags_path.parent.mkdir(parents=True, exist_ok=True)
    tags_path.write_text(
        json.dumps(tags, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return tags


def _build_wardrive_assets(runtime_root: Path, *, source_root: Path) -> dict[str, Any]:
    density_profile = _load_density_profile()
    network_catalog: dict[str, dict[str, Any]] = dict(NETWORKS)
    session_ids = []
    session_stats = []
    observed_network_ids: set[str] = set()

    for session in WARDRIVE_SESSIONS:
        route_path = _route_asset_path(source_root, str(session["route_asset"]))
        route_points = _load_route_waypoints(route_path)
        rows, session_network_ids, density_catalog, stats = _generate_wardrive_rows(
            session,
            route_points,
            density_profile=density_profile,
        )
        network_catalog.update(density_catalog)
        _write_wardrive_csv(
            runtime_root / "wardrive" / str(session["filename"]),
            str(session["header"]),
            rows,
        )
        session_id = Path(str(session["filename"])).stem
        session_ids.append(session_id)
        observed_network_ids.update(session_network_ids)
        session_stats.append(
            {
                "session_id": session_id,
                "source_file": str(session["filename"]),
                "route_asset": str(session["route_asset"]),
                "corridor": str(session["corridor"]),
                "transport_mode": str(session.get("transport_mode") or ""),
                "route_family": str(session.get("route_family") or ""),
                "density_multiplier": float(session.get("density_multiplier") or 1.0),
                "route_points": len(route_points),
                "scan_points": len(route_points),
                "csv_rows": len(rows),
                "networks_observed": len(session_network_ids),
                "route_distance_km": stats["route_distance_km"],
                "rows_per_km": stats["rows_per_km"],
                "rows_per_point": stats["rows_per_point"],
                "unique_bssids_per_km": stats["unique_bssids_per_km"],
                "max_same_gps": stats["max_same_gps"],
                "target_total_rows": stats["target_total_rows"],
                "target_unique_networks": stats["target_unique_networks"],
            }
        )

    _validate_catalog(network_catalog)
    session_tags = _write_wardrive_session_tags(runtime_root)

    return {
        "session_ids": session_ids,
        "session_stats": session_stats,
        "observed_network_ids": sorted(observed_network_ids),
        "corridors": [str(session["corridor"]) for session in WARDRIVE_SESSIONS],
        "route_assets": [str(session["route_asset"]) for session in WARDRIVE_SESSIONS],
        "network_catalog": network_catalog,
        "session_tags": session_tags,
        "density_profile": {
            "rows_per_km": density_profile.get("rows_per_km"),
            "points_per_km": density_profile.get("points_per_km"),
            "rows_per_point": density_profile.get("rows_per_point"),
            "unique_bssids_per_km": density_profile.get("unique_bssids_per_km"),
            "max_same_gps": density_profile.get("max_same_gps"),
        },
    }


def _append_wordlist_once(filename: str, value: str) -> None:
    entries = WORDLISTS.setdefault(filename, [])
    text = str(value or "").strip()
    if text and text not in entries:
        entries.append(text)


def _balanced_slot(index: int, total: int, count: int) -> bool:
    if count <= 0 or total <= 0:
        return False
    return ((index + 1) * count) // total > (index * count) // total


def _spread_select(
    candidates: list[tuple[str, dict[str, Any]]],
    limit: int,
) -> list[tuple[str, dict[str, Any]]]:
    if len(candidates) <= limit:
        return list(candidates)

    ordered = sorted(
        candidates,
        key=lambda item: (
            int(item[1].get("_peak_index") or 0),
            _deterministic_unit(PWNAGOTCHI_MASS_PROMOTION_ID, item[0]),
            item[0],
        ),
    )
    selected: list[tuple[str, dict[str, Any]]] = []
    used: set[str] = set()
    step = len(ordered) / float(limit)
    for idx in range(limit):
        pick_index = min(len(ordered) - 1, int(round((idx + 0.5) * step - 0.5)))
        network_id, network = ordered[pick_index]
        if network_id in used:
            continue
        selected.append((network_id, network))
        used.add(network_id)

    if len(selected) < limit:
        for network_id, network in ordered:
            if network_id in used:
                continue
            selected.append((network_id, network))
            used.add(network_id)
            if len(selected) >= limit:
                break
    return selected


def _reset_pwnagotchi_mass_promotions() -> None:
    HANDSHAKE_CAPTURES[:] = [
        spec
        for spec in HANDSHAKE_CAPTURES
        if spec.get("demo_promotion") != PWNAGOTCHI_MASS_PROMOTION_ID
    ]
    for network_id in list(NETWORKS):
        if (
            NETWORKS[network_id].get("_demo_promoted_by")
            == PWNAGOTCHI_MASS_PROMOTION_ID
        ):
            del NETWORKS[network_id]


def _install_pwnagotchi_mass_promotions(
    wardrive_meta: dict[str, Any],
) -> dict[str, Any]:
    _reset_pwnagotchi_mass_promotions()

    existing_handshake_network_ids = {
        str(spec["network_id"])
        for spec in HANDSHAKE_CAPTURES
        if spec.get("demo_promotion") != PWNAGOTCHI_MASS_PROMOTION_ID
    }
    observed_network_ids = set(wardrive_meta["observed_network_ids"])
    network_catalog = wardrive_meta["network_catalog"]
    encrypted_candidates_by_corridor: dict[str, list[tuple[str, dict[str, Any]]]] = {
        corridor: [] for corridor in PWNAGOTCHI_MASS_PROMOTION_CORRIDOR_QUOTAS
    }

    for network_id in sorted(observed_network_ids):
        if network_id in existing_handshake_network_ids:
            continue
        network = network_catalog.get(network_id)
        if not network:
            continue
        if str(network.get("category") or "") != "wardrive_density":
            continue
        if str(network.get("encryption") or "").upper() in {"OPEN", "WEP"}:
            continue
        corridor = str(network.get("_corridor") or "")
        if corridor not in encrypted_candidates_by_corridor:
            continue
        encrypted_candidates_by_corridor[corridor].append((network_id, network))

    selected: list[tuple[str, dict[str, Any]]] = []
    for corridor, quota in PWNAGOTCHI_MASS_PROMOTION_CORRIDOR_QUOTAS.items():
        selected.extend(
            _spread_select(encrypted_candidates_by_corridor.get(corridor, []), quota)
        )

    selected_by_id: dict[str, dict[str, Any]] = {}
    for network_id, network in selected:
        selected_by_id.setdefault(network_id, network)
    if len(selected_by_id) < PWNAGOTCHI_MASS_PROMOTION_TOTAL:
        selected_ids = set(selected_by_id)
        fallback_candidates = [
            (network_id, network)
            for items in encrypted_candidates_by_corridor.values()
            for network_id, network in items
            if network_id not in selected_ids
        ]
        for network_id, network in _spread_select(
            fallback_candidates,
            PWNAGOTCHI_MASS_PROMOTION_TOTAL - len(selected_by_id),
        ):
            selected_by_id.setdefault(network_id, network)

    selected = sorted(
        selected_by_id.items(),
        key=lambda item: (
            str(item[1].get("_corridor") or ""),
            int(item[1].get("_peak_index") or 0),
            _deterministic_unit(PWNAGOTCHI_MASS_PROMOTION_ID, item[0]),
            item[0],
        ),
    )[:PWNAGOTCHI_MASS_PROMOTION_TOTAL]
    if len(selected) != PWNAGOTCHI_MASS_PROMOTION_TOTAL:
        raise AssertionError(
            f"Expected {PWNAGOTCHI_MASS_PROMOTION_TOTAL} Pwnagotchi promotions, got {len(selected)}."
        )

    cracked_indexes = {
        index
        for index in range(len(selected))
        if _balanced_slot(index, len(selected), PWNAGOTCHI_MASS_PROMOTION_CRACKED)
    }
    remaining_indexes = [
        index for index in range(len(selected)) if index not in cracked_indexes
    ]
    convertible_indexes = {
        remaining_indexes[index]
        for index in range(len(remaining_indexes))
        if _balanced_slot(
            index, len(remaining_indexes), PWNAGOTCHI_MASS_PROMOTION_CONVERTIBLE
        )
    }

    summary = {
        "total": 0,
        "locked": 0,
        "cracked": 0,
        "convertible": 0,
        "by_corridor": {},
    }
    for index, (network_id, network) in enumerate(selected):
        cracked = index in cracked_indexes
        convertible = index in convertible_indexes
        scenario = (
            "pcap_plus_22000_plus_cracked"
            if cracked
            else ("pcap_only_convertible" if convertible else "pcap_plus_22000")
        )
        promoted_network = dict(network)
        promoted_network["category"] = (
            "already_cracked" if cracked else "locked_showcase"
        )
        promoted_network["_demo_promoted_by"] = PWNAGOTCHI_MASS_PROMOTION_ID
        network_catalog[network_id] = promoted_network
        NETWORKS[network_id] = promoted_network

        safe_id = _slug_token(network_id)
        safe_ssid = _slug_token(str(promoted_network["ssid"])).upper()
        HANDSHAKE_CAPTURES.append(
            {
                "id": f"pwn_mass_{safe_id}",
                "network_id": network_id,
                "source": "pwnagotchi",
                "role": "handshakes",
                "root": "handshakes",
                "filename": f"PWN_MASS_{index + 1:04d}_{safe_ssid}_{_mac_clean(promoted_network['bssid'])}.pcap",
                "gps": False,
                "legacy_sidecars": False,
                "cracked": cracked,
                "hash_ready": not convertible,
                "scenario": scenario,
                "pcap_profile": "full",
                "demo_promotion": PWNAGOTCHI_MASS_PROMOTION_ID,
                "clients": [
                    _local_admin_mac(
                        PROFILE_ID, PWNAGOTCHI_MASS_PROMOTION_ID, network_id, "client"
                    )
                ],
            }
        )

        if cracked:
            _append_wordlist_once("demo_easy.txt", str(promoted_network["password"]))
            summary["cracked"] += 1
        elif convertible:
            _append_wordlist_once(
                "demo_association.txt", str(promoted_network["password"])
            )
            summary["convertible"] += 1
            summary["locked"] += 1
        else:
            if index % 11 == 0:
                _append_wordlist_once(
                    "demo_association.txt", str(promoted_network["password"])
                )
            summary["locked"] += 1

        corridor = str(promoted_network.get("_corridor") or "unknown")
        summary["by_corridor"][corridor] = (
            int(summary["by_corridor"].get(corridor, 0)) + 1
        )
        summary["total"] += 1

    wardrive_meta["pwnagotchi_promotions"] = summary
    return summary


def _build_wordlists(runtime_root: Path) -> dict[str, Any]:
    wordlists_dir = runtime_root / "demo_wordlists"
    wordlists_dir.mkdir(parents=True, exist_ok=True)
    for filename, lines in WORDLISTS.items():
        (wordlists_dir / filename).write_text(
            "\n".join(str(line) for line in lines) + "\n", encoding="utf-8"
        )
    return {"files": sorted(WORDLISTS)}


def _manifest_network_state(
    *,
    network: dict[str, Any],
    gps_backed: bool,
    capture_scenarios: set[str],
    raw_present: bool,
) -> str:
    encryption = str(network.get("encryption") or "").strip().upper()
    if encryption in {"OPEN", "WEP"}:
        return "open"
    if "pcap_plus_22000_plus_cracked" in capture_scenarios:
        return "cracked"
    if capture_scenarios & {
        "pcap_only_convertible",
        "pcap_plus_22000",
        "pcap_plus_22000_plus_cracked",
        "no_gps_locked",
    }:
        return "locked" if gps_backed else "no_gps_locked"
    if capture_scenarios & {"pcap_present_but_not_ready"}:
        return "not_ready"
    if raw_present:
        return "not_ready"
    return "gps_only" if gps_backed else "no_gps_only"


def _build_manifest(
    runtime_root: Path,
    *,
    capture_meta: dict[str, Any],
    raw_meta: dict[str, Any],
    wardrive_meta: dict[str, Any],
    wordlist_meta: dict[str, Any],
) -> dict[str, Any]:
    runtime_files = sorted(
        str(path.relative_to(runtime_root))
        for path in runtime_root.rglob("*")
        if path.is_file()
    )
    handshake_sources: dict[str, set[str]] = {}
    for capture in capture_meta["captures"]:
        handshake_sources.setdefault(str(capture["network_id"]), set()).add(
            str(capture["source"])
        )
    handshake_network_ids = {
        str(capture["network_id"]) for capture in capture_meta["captures"]
    }
    handshake_scenarios: dict[str, set[str]] = {}
    for capture in capture_meta["captures"]:
        network_id = str(capture["network_id"])
        handshake_scenarios.setdefault(network_id, set()).add(
            str(capture.get("scenario") or "pcap_plus_22000")
        )
    raw_network_ids = {
        str(network_id)
        for record in raw_meta["raw_records"]
        for network_id in record["networks"]
    }
    wardrive_network_ids = set(wardrive_meta["observed_network_ids"])
    gps_capture_network_ids = {
        str(capture["network_id"])
        for capture in capture_meta["captures"]
        if bool(capture.get("gps", False))
    }
    network_surfaces = {}
    all_networks = dict(wardrive_meta["network_catalog"])
    for network_id, data in sorted(all_networks.items()):
        surfaces = []
        gps_backed = (
            network_id in wardrive_network_ids or network_id in gps_capture_network_ids
        )
        if network_id in wardrive_network_ids:
            surfaces.append("wardrive")
        if network_id in handshake_network_ids:
            surfaces.append("handshake")
        if network_id in raw_network_ids:
            surfaces.append("raw")
        network_state = _manifest_network_state(
            network=data,
            gps_backed=gps_backed,
            capture_scenarios=handshake_scenarios.get(network_id, set()),
            raw_present=network_id in raw_network_ids,
        )
        network_surfaces[network_id] = {
            "ssid": data["ssid"],
            "bssid": data["bssid"],
            "category": data["category"],
            "encryption": data["encryption"],
            "surfaces": surfaces,
            "network_state": network_state,
        }

    gps_backed_locked = sum(
        1 for item in network_surfaces.values() if item["network_state"] == "locked"
    )
    no_gps_locked = sum(
        1
        for item in network_surfaces.values()
        if item["network_state"] == "no_gps_locked"
    )
    cracked_networks = sum(
        1 for item in network_surfaces.values() if item["network_state"] == "cracked"
    )
    not_ready_networks = sum(
        1 for item in network_surfaces.values() if item["network_state"] == "not_ready"
    )
    pwnagotchi_promoted_captures = [
        capture
        for capture in capture_meta["captures"]
        if capture.get("promotion") == PWNAGOTCHI_MASS_PROMOTION_ID
    ]
    pwnagotchi_promoted_network_ids = {
        str(capture["network_id"]) for capture in pwnagotchi_promoted_captures
    }
    pwnagotchi_promoted_cracked = {
        str(capture["network_id"])
        for capture in pwnagotchi_promoted_captures
        if str(capture.get("scenario") or "") == "pcap_plus_22000_plus_cracked"
    }
    pwnagotchi_promoted_convertible = {
        str(capture["network_id"])
        for capture in pwnagotchi_promoted_captures
        if str(capture.get("scenario") or "") == "pcap_only_convertible"
    }
    summary = {
        "networks_total": len(all_networks),
        "wardrive_sessions": len(wardrive_meta["session_ids"]),
        "wardrive_networks_observed": len(wardrive_network_ids),
        "handshake_captures": len(capture_meta["captures"]),
        "raw_files": len(raw_meta["raw_records"]),
        "batch_files": 1,
        "demo_wordlists": len(wordlist_meta["files"]),
        "cross_source_capture_networks": sum(
            1 for sources in handshake_sources.values() if len(sources) > 1
        ),
        "combined_candidate_networks": len(capture_meta["combined_records"]),
        "wardrive_handshake_networks": len(
            wardrive_network_ids & handshake_network_ids
        ),
        "wardrive_handshake_raw_networks": len(
            wardrive_network_ids & handshake_network_ids & raw_network_ids
        ),
        "gps_backed_locked_networks": gps_backed_locked,
        "no_gps_locked_networks": no_gps_locked,
        "cracked_networks": cracked_networks,
        "not_ready_networks": not_ready_networks,
        "pwnagotchi_promoted_wardrive_networks": len(
            pwnagotchi_promoted_network_ids & wardrive_network_ids
        ),
        "pwnagotchi_promoted_locked_networks": len(
            pwnagotchi_promoted_network_ids - pwnagotchi_promoted_cracked
        ),
        "pwnagotchi_promoted_cracked_networks": len(pwnagotchi_promoted_cracked),
        "pwnagotchi_promoted_convertible_networks": len(
            pwnagotchi_promoted_convertible
        ),
        "regions": list(wardrive_meta["corridors"]),
        "density_profile": dict(wardrive_meta.get("density_profile") or {}),
        "pwnagotchi_promotion_profile": dict(
            wardrive_meta.get("pwnagotchi_promotions") or {}
        ),
        "session_count_by_transport_mode": {
            mode: sum(
                1
                for item in wardrive_meta["session_stats"]
                if str(item.get("transport_mode") or "") == mode
            )
            for mode in sorted(
                {
                    str(item.get("transport_mode") or "")
                    for item in wardrive_meta["session_stats"]
                    if str(item.get("transport_mode") or "").strip()
                }
            )
        },
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
        "network_catalog": network_surfaces,
        "handshake_captures": capture_meta["captures"],
        "combined_candidates": capture_meta["combined_records"],
        "raw_captures": raw_meta["raw_records"],
        "wardrive_sessions": wardrive_meta["session_stats"],
        "wardrive_session_tags": dict(wardrive_meta.get("session_tags") or {}),
        "route_sources": wardrive_meta["route_assets"],
        "batch_file": capture_meta["batch_name"],
        "files": runtime_files,
    }


def _assert_local_admin_mac(mac: str) -> None:
    first_octet = int(_mac_clean(mac)[:2], 16)
    assert first_octet & 0b10 == 0b10, f"{mac} is not locally administered"
    assert first_octet & 0b1 == 0, f"{mac} must remain unicast"


def _validate_catalog(catalog: dict[str, dict[str, Any]] | None = None) -> None:
    for network_id, network in (catalog or NETWORKS).items():
        _assert_local_admin_mac(str(network["bssid"]))
        lat = float(network["lat"])
        lng = float(network["lng"])
        assert RJ_BBOX["lat_min"] <= lat <= RJ_BBOX["lat_max"], network_id
        assert RJ_BBOX["lng_min"] <= lng <= RJ_BBOX["lng_max"], network_id
        assert isinstance(network["ssid"], str), network_id
        assert isinstance(network["password"], str), network_id
        for anchor in _network_anchors(network):
            assert (
                RJ_BBOX["lat_min"] <= float(anchor["lat"]) <= RJ_BBOX["lat_max"]
            ), network_id
            assert (
                RJ_BBOX["lng_min"] <= float(anchor["lng"]) <= RJ_BBOX["lng_max"]
            ), network_id


def _validate_build(
    manifest: dict[str, Any], *, pack_root: Path, source_root: Path
) -> None:
    assert (pack_root / "manifest.json").exists()
    assert manifest["summary"]["networks_total"] >= 2000
    assert manifest["summary"]["wardrive_sessions"] == 4
    assert manifest["summary"]["wardrive_networks_observed"] >= 2500
    assert manifest["summary"]["cross_source_capture_networks"] >= 2
    assert manifest["summary"]["combined_candidate_networks"] >= 2
    assert manifest["summary"]["wardrive_handshake_networks"] >= 260
    assert manifest["summary"]["wardrive_handshake_raw_networks"] >= 8
    assert manifest["summary"]["handshake_captures"] >= 320
    assert manifest["summary"]["gps_backed_locked_networks"] >= 250
    assert manifest["summary"]["cracked_networks"] >= 50
    assert manifest["summary"]["pwnagotchi_promoted_wardrive_networks"] == 240
    assert manifest["summary"]["pwnagotchi_promoted_locked_networks"] == 208
    assert manifest["summary"]["pwnagotchi_promoted_cracked_networks"] == 32
    assert manifest["summary"]["pwnagotchi_promoted_convertible_networks"] == 24
    session_tags = dict(manifest.get("wardrive_session_tags") or {})
    assert len(session_tags) == 4
    assert session_tags["20260411_001500_wardriving"] == "car"
    assert session_tags["m5evil__20260411_011000_wardriving"] == "car"
    assert session_tags["20260411_020500_wardriving"] == "car"
    counts = manifest["summary"]["session_count_by_transport_mode"]
    assert counts["car"] == 3
    assert counts["motorcycle"] == 1
    for asset_name in manifest["route_sources"]:
        assert (_route_asset_path(source_root, asset_name)).exists()
    for session in manifest["wardrive_sessions"]:
        multiplier = float(session["density_multiplier"])
        route_distance_km = float(session["route_distance_km"])
        route_points = int(session["route_points"])
        scan_points = int(session["scan_points"])
        csv_rows = int(session["csv_rows"])
        networks_observed = int(session["networks_observed"])
        rows_per_km = float(session["rows_per_km"])
        rows_per_point = float(session["rows_per_point"])
        unique_bssids_per_km = float(session["unique_bssids_per_km"])
        max_same_gps = int(session["max_same_gps"])

        assert 1.7 <= route_distance_km <= 5.8
        assert route_points >= 480
        assert scan_points == route_points
        assert csv_rows >= 9000
        assert networks_observed >= 700

        expected_rows_per_km = 12555.66 * multiplier
        assert expected_rows_per_km * 0.84 <= rows_per_km <= expected_rows_per_km * 1.12

        expected_rows_per_point = 44.46 * multiplier
        assert (
            expected_rows_per_point * 0.8
            <= rows_per_point
            <= expected_rows_per_point * 1.2
        )

        expected_unique_bssids_per_km = 658.11 * max(0.42, multiplier)
        assert (
            expected_unique_bssids_per_km * 0.8
            <= unique_bssids_per_km
            <= expected_unique_bssids_per_km * 1.25
        )

        expected_max_same_gps = int(round(82 * max(0.55, multiplier)))
        assert (
            max(16, expected_max_same_gps - 16)
            <= max_same_gps
            <= min(85, expected_max_same_gps + 8)
        )

        transport_mode = str(session["transport_mode"])
        if transport_mode == "car":
            assert 38.0 <= rows_per_point <= 50.0
            assert 550.0 <= unique_bssids_per_km <= 720.0
        elif transport_mode == "train":
            assert 40.0 <= rows_per_point <= 49.0
            assert 520.0 <= unique_bssids_per_km <= 710.0
        elif transport_mode == "metro":
            assert 34.0 <= rows_per_point <= 44.0
            assert 470.0 <= unique_bssids_per_km <= 650.0
        elif transport_mode == "boat":
            assert 24.0 <= rows_per_point <= 38.0
            assert 360.0 <= unique_bssids_per_km <= 620.0
        elif transport_mode == "motorcycle":
            assert 30.0 <= rows_per_point <= 42.0
            assert 430.0 <= unique_bssids_per_km <= 650.0
        elif transport_mode == "bike":
            assert 22.0 <= rows_per_point <= 32.0
            assert 330.0 <= unique_bssids_per_km <= 520.0
        elif transport_mode == "walk":
            assert 18.0 <= rows_per_point <= 28.0
            assert 280.0 <= unique_bssids_per_km <= 470.0


def build_pack(
    validate: bool = False,
    *,
    pack_root: Path | None = None,
    source_root: Path | None = None,
) -> int:
    pack_root = Path(pack_root or PACK_ROOT)
    runtime_root = pack_root / "runtime"
    source_root = Path(source_root or ROUTE_SOURCE_ROOT)
    assert source_root.exists(), f"Route source root not found: {source_root}"

    _validate_catalog()

    if pack_root.exists():
        shutil.rmtree(pack_root)
    runtime_root.mkdir(parents=True, exist_ok=True)

    wardrive_meta = _build_wardrive_assets(runtime_root, source_root=source_root)
    _install_pwnagotchi_mass_promotions(wardrive_meta)
    capture_meta = _build_capture_assets(runtime_root)
    raw_meta = _build_raw_assets(runtime_root)
    wordlist_meta = _build_wordlists(runtime_root)

    manifest = _build_manifest(
        runtime_root,
        capture_meta=capture_meta,
        raw_meta=raw_meta,
        wardrive_meta=wardrive_meta,
        wordlist_meta=wordlist_meta,
    )
    _json_dump(pack_root / "manifest.json", manifest)
    (pack_root / "README.md").write_text(
        "# Showcase Core v5\n\n"
        "Synthetic, public-safe demo dataset for KOVIL MAP with expanded WarDrive coverage, transport-tagged sessions, artifact-consistent locked networks, and richer RAW crossover.\n",
        encoding="utf-8",
    )

    if validate:
        assert (pack_root / "manifest.json").exists()
        assert (runtime_root / "handshakes").exists()
        assert (runtime_root / "wardrive").exists()
        assert (runtime_root / "BrucePCAP").exists()
        assert (runtime_root / "m5evil").exists()
        assert (runtime_root / "demo_wordlists").exists()
        _validate_build(manifest, pack_root=pack_root, source_root=source_root)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Build public demo data pack.")
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Run assertions after regenerating the pack.",
    )
    args = parser.parse_args()
    return build_pack(validate=bool(args.validate))


if __name__ == "__main__":
    raise SystemExit(main())
