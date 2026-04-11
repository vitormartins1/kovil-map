import json
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime
from typing import Dict, List, Tuple
from string import hexdigits

from app.api import deps
from app.core.config import (
    HANDSHAKES_DIR,
    BRUCE_HANDSHAKES_DIR,
    BRUCE_PCAP_DIR,
    M5EVIL_HANDSHAKES_DIR,
    load_config,
)
from app.utils.pcap import (
    build_pcap_search_roots,
    resolve_pcap_reference,
)
from app.utils.handshake_artifacts import get_capture_artifact_path
from app.services.base_service import BaseService
from app.services.history_service import history_service
from app.services.data_loader import reload_data
from app.services.rawsniffer_service import rawsniffer_service
from app.utils.rawsniffer_parser import normalize_mac

AKM_MAP = {
    "1": "802.1X",
    "2": "PSK",
    "3": "FT/802.1X",
    "4": "FT/PSK",
    "5": "802.1X-SHA256",
    "6": "PSK-SHA256",
    "7": "TDLS",
    "8": "SAE",
    "9": "FT/SAE",
    "11": "FT/802.1X-SHA384",
    "12": "OWE",
    "18": "DPP",
}

PAIRWISE_MAP = {
    "2": "TKIP",
    "4": "WRAP",
    "5": "CCMP",
    "6": "WEP104",
    "7": "BIP",
    "8": "GCMP",
    "9": "GCMP-256",
    "10": "CCMP-256",
}

GROUP_MAP = {
    "1": "WEP40",
    "2": "TKIP",
    "4": "WRAP",
    "5": "CCMP",
    "6": "WEP104",
    "8": "GCMP",
    "9": "GCMP-256",
    "10": "CCMP-256",
}


class FingerprintService(BaseService):
    def __init__(self):
        super().__init__()
        self.conf = load_config()

    def _pcap_search_roots(self):
        return build_pcap_search_roots(
            HANDSHAKES_DIR,
            BRUCE_HANDSHAKES_DIR,
            BRUCE_PCAP_DIR,
            M5EVIL_HANDSHAKES_DIR,
        )

    def _check_tshark(self):
        tshark_bin = self.conf.get("tshark_path", "tshark")
        if os.path.isabs(tshark_bin):
            exists = os.path.exists(tshark_bin)
        else:
            exists = shutil.which(tshark_bin) is not None
        return tshark_bin if exists else None

    def _build_command(self, base_cmd: List[str]) -> Tuple[List[str], str]:
        tshark_bin = self.conf.get("tshark_path", "tshark")
        use_wsl = self._should_use_wsl(tshark_bin)

        if use_wsl:
            cmd = ["wsl", tshark_bin] + base_cmd
        else:
            cmd = [tshark_bin] + base_cmd
        return cmd, " ".join(cmd)

    def _run_tshark(self, base_cmd: List[str]) -> Tuple[str, List[str]]:
        cmd, cmd_str = self._build_command(base_cmd)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                cwd=None,
            )
            stdout = proc.stdout or ""
            stderr = proc.stderr or ""
            if proc.returncode != 0 and not stdout.strip():
                raise RuntimeError(stderr.strip() or f"tshark exit {proc.returncode}")
            warnings = []
            if stderr.strip():
                warnings.append(stderr.strip())
            return stdout, warnings
        except FileNotFoundError:
            raise RuntimeError("tshark not found")

    def _parse_rows(self, raw: str, expected_cols: int) -> List[List[str]]:
        rows = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            # pad to expected cols
            if len(parts) < expected_cols:
                parts += [""] * (expected_cols - len(parts))
            rows.append(parts[:expected_cols])
        return rows

    def _rows_for_bssid(
        self, rows: List[List[str]], bssid: str, allow_fallback: bool = True
    ) -> List[List[str]]:
        if not rows:
            return []
        if not bssid:
            return rows
        target = bssid.upper()
        matched = [r for r in rows if (r[0] or "").upper() == target]
        if matched:
            return matched
        return rows if allow_fallback else []

    def _first_non_empty(self, rows: List[List[str]], idx: int) -> str:
        for r in rows:
            if idx >= len(r):
                continue
            val = (r[idx] or "").strip()
            if val:
                return val
        return ""

    def _parse_number_list(self, value: str) -> List[float]:
        if not value:
            return []
        nums = re.findall(r"-?\d+(?:\.\d+)?", value)
        out: List[float] = []
        for n in nums:
            try:
                out.append(float(n))
            except Exception:
                continue
        return out

    def _collect_numbers(self, rows: List[List[str]], idx: int) -> List[float]:
        values: List[float] = []
        for r in rows:
            if idx >= len(r):
                continue
            values += self._parse_number_list(r[idx])
        return values

    def _normalize_oui(self, value: str) -> str | None:
        if not value:
            return None
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", str(value))
        if len(cleaned) < 6:
            return None
        return cleaned[:6].upper()

    def _collect_ouis(self, rows: List[List[str]], idx: int) -> List[str]:
        out: List[str] = []
        seen = set()
        for r in rows:
            if idx >= len(r):
                continue
            raw = r[idx] or ""
            if not raw:
                continue
            parts = re.split(r"[,\s;]+", raw)
            for part in parts:
                oui = self._normalize_oui(part)
                if not oui or oui in seen:
                    continue
                seen.add(oui)
                out.append(oui)
        return out

    def _unique_numbers(self, values: List[float]) -> List[float]:
        seen = set()
        out: List[float] = []
        for v in values:
            key = round(v, 6)
            if key in seen:
                continue
            seen.add(key)
            out.append(v)
        return out

    def _any_flag(self, rows: List[List[str]], idx: int) -> bool:
        for r in rows:
            if idx >= len(r):
                continue
            val = (r[idx] or "").strip().lower()
            if val in ("1", "true", "yes", "y"):
                return True
        return False

    def _to_int(self, value: str) -> int | None:
        if value is None or value == "":
            return None
        try:
            return int(float(value))
        except Exception:
            return None

    def _clamp(self, value: float, min_value: float, max_value: float) -> float:
        return max(min_value, min(max_value, value))

    def _stats(self, values: List[float], include_min: bool = True) -> Dict[str, float]:
        if not values:
            return {}
        avg = sum(values) / len(values)
        stats = {"avg": round(avg, 2), "max": max(values)}
        if include_min:
            stats["min"] = min(values)
        return stats

    def _derive_band(
        self, frequency_mhz: int | None, channel: int | None
    ) -> str | None:
        if frequency_mhz:
            if 2400 <= frequency_mhz <= 2500:
                return "2.4"
            if 4900 <= frequency_mhz <= 5900:
                return "5"
            if 5925 <= frequency_mhz <= 7125:
                return "6"
        if channel:
            if 1 <= channel <= 14:
                return "2.4"
            if channel >= 32:
                return "5"
        return None

    def _decode_ssid(self, ssid: str) -> Tuple[str, str | None]:
        """Returns (decoded, raw_hex_if_decoded)."""
        if not ssid:
            return "", None
        s = ssid.strip()
        if all(c in hexdigits for c in s) and len(s) % 2 == 0:
            try:
                decoded = bytes.fromhex(s).decode("utf-8", errors="ignore")
                if decoded.strip():
                    return decoded, s
            except Exception:
                pass
        return ssid, None

    def _first_network(self, rows: List[List[str]]) -> Tuple[str, str, str | None]:
        for r in rows:
            bssid = (r[0] or "").upper()
            ssid = r[1] or ""
            if bssid or ssid:
                decoded, raw_hex = self._decode_ssid(ssid)
                return bssid, decoded, raw_hex
        return "", "", None

    def _label_list(self, codes: List[str], mapping: Dict[str, str]) -> List[str]:
        labels = []
        for c in codes:
            if not c:
                continue
            labels.append(mapping.get(c, c))
        # unique preserving order
        seen = set()
        ordered = []
        for label in labels:
            if label not in seen:
                seen.add(label)
                ordered.append(label)
        return ordered

    def _derive_wpa_version(
        self, akm_labels: List[str], pairwise_labels: List[str]
    ) -> str:
        has_wpa3 = any(a in ("SAE", "FT/SAE", "OWE", "DPP") for a in akm_labels)
        if has_wpa3:
            return "WPA3"
        if akm_labels or pairwise_labels:
            return "WPA2"
        return "Unknown"

    def _derive_pmf(self, mfpr: str, mfpc: str) -> str:
        if mfpr == "1":
            return "Required"
        if mfpc == "1":
            return "Capable"
        if mfpr == "" and mfpc == "":
            return "Unknown"
        return "None"

    def _classify(self, details: Dict) -> Dict:
        """
        Classificação assistiva v2 (offline), multi-classe e baseada em score.
        A UI trata confidence < 0.6 como baixa confiança.
        """
        classes = [
            "router_ap",
            "phone_hotspot",
            "camera_ap",
            "printer_ap",
            "iot_ap",
        ]
        scores = {name: 0.0 for name in classes}
        evidence: List[str] = []
        signals = {
            "wps": False,
            "ssid_pattern": False,
            "vendor": False,
            "vendor_ie": False,
            "security": False,
        }

        wps = details.get("wps", {}) if isinstance(details.get("wps"), dict) else {}
        security = (
            details.get("security", {})
            if isinstance(details.get("security"), dict)
            else {}
        )
        caps = (
            details.get("capabilities", {})
            if isinstance(details.get("capabilities"), dict)
            else {}
        )
        vendor_ies = (
            details.get("vendor_ies", {})
            if isinstance(details.get("vendor_ies"), dict)
            else {}
        )

        vendor = str(details.get("vendor") or "").strip().lower()
        ssid = str(details.get("ssid") or "").strip().lower()

        def contains_any(text: str, keywords: List[str]) -> bool:
            t = str(text or "").lower()
            return any(k in t for k in keywords)

        def add_score(class_name: str, value: float, reason: str):
            if class_name not in scores or value <= 0:
                return
            scores[class_name] += float(value)
            if reason and reason not in evidence:
                evidence.append(reason)

        router_tokens = [
            "router",
            "access point",
            "wireless ap",
            "wifi 6",
            "mesh",
        ]
        router_brands = {
            "tp-link",
            "tplink",
            "tp link",
            "d-link",
            "dlink",
            "asus",
            "netgear",
            "linksys",
            "cisco",
            "ubiquiti",
            "mikrotik",
            "mercusys",
            "zyxel",
            "arris",
            "intelbras",
            "hpe",
            "comcast",
            "sagemcom",
            "technicolor",
            "fiberhome",
            "arcadyan",
            "zte",
        }
        phone_vendors = {
            "apple",
            "samsung",
            "google",
            "motorola",
            "xiaomi",
            "redmi",
            "huawei",
            "honor",
            "oneplus",
            "oppo",
            "vivo",
            "realme",
            "nokia",
        }
        camera_tokens = [
            "camera",
            "cam",
            "ipcam",
            "ipc",
            "hik",
            "hikvision",
            "ezviz",
            "arlo",
            "dahua",
            "wyze",
            "imou",
            "reolink",
            "yi home",
        ]
        printer_tokens = [
            "printer",
            "print",
            "epson",
            "canon",
            "brother",
            "lexmark",
            "ricoh",
            "kyocera",
            "okidata",
            "oki",
        ]
        printer_brands = {
            "hp",
            "epson",
            "canon",
            "brother",
            "lexmark",
            "ricoh",
            "kyocera",
            "oki",
        }
        hotspot_tokens = [
            "iphone",
            "android",
            "galaxy",
            "pixel",
            "oneplus",
            "mobile hotspot",
            "hotspot",
            "mifi",
            "phone",
        ]
        iot_tokens = [
            "iot",
            "smart",
            "plug",
            "bulb",
            "switch",
            "sensor",
            "thermostat",
            "tuya",
            "tapo",
            "sonoff",
            "espressif",
            "esp",
            "ring",
            "nest",
            "alexa",
            "roku",
            "chromecast",
        ]
        iot_vendors = {
            "tuya",
            "espressif",
            "sonoff",
            "ring",
            "nest",
            "arlo",
            "wyze",
            "hikvision",
            "dahua",
            "tp-link",
            "xiaomi",
        }
        camera_vendors = {
            "hikvision",
            "dahua",
            "ezviz",
            "arlo",
            "wyze",
            "axis",
            "reolink",
            "foscam",
            "imou",
        }

        wps_text = " ".join(
            [
                str(wps.get("device_name") or ""),
                str(wps.get("model_name") or ""),
                str(wps.get("manufacturer") or ""),
                str(wps.get("model_number") or ""),
            ]
        ).strip()
        primary_device_type = str(wps.get("primary_device_type") or "").strip()

        if wps.get("present"):
            signals["wps"] = True
            if wps_text:
                if contains_any(wps_text, camera_tokens):
                    add_score("camera_ap", 0.75, "WPS strings indicate camera profile.")
                if contains_any(wps_text, printer_tokens):
                    add_score(
                        "printer_ap", 0.75, "WPS strings indicate printer profile."
                    )
                if contains_any(wps_text, hotspot_tokens):
                    add_score(
                        "phone_hotspot",
                        0.7,
                        "WPS strings indicate mobile hotspot profile.",
                    )
                if contains_any(wps_text, iot_tokens):
                    add_score("iot_ap", 0.6, "WPS strings indicate IoT profile.")
                if contains_any(wps_text, router_tokens):
                    add_score(
                        "router_ap", 0.55, "WPS strings indicate router/AP profile."
                    )

            wps_type_map = {
                "3": ("printer_ap", 0.7, "WPS primary device type indicates printer."),
                "4": ("camera_ap", 0.7, "WPS primary device type indicates camera."),
                "6": (
                    "router_ap",
                    0.62,
                    "WPS primary device type indicates network infrastructure.",
                ),
                "10": (
                    "phone_hotspot",
                    0.7,
                    "WPS primary device type indicates phone device.",
                ),
            }
            if primary_device_type in wps_type_map:
                class_name, points, reason = wps_type_map[primary_device_type]
                add_score(class_name, points, reason)

        if ssid:
            if (
                contains_any(ssid, printer_tokens)
                or ssid.startswith("direct-")
                or ssid.startswith("direct ")
            ):
                signals["ssid_pattern"] = True
                add_score("printer_ap", 0.58, "SSID pattern suggests printer network.")
            if contains_any(ssid, camera_tokens):
                signals["ssid_pattern"] = True
                add_score("camera_ap", 0.58, "SSID pattern suggests camera network.")
            if contains_any(ssid, hotspot_tokens):
                signals["ssid_pattern"] = True
                add_score(
                    "phone_hotspot",
                    0.62,
                    "SSID pattern suggests mobile hotspot network.",
                )
            if contains_any(ssid, iot_tokens):
                signals["ssid_pattern"] = True
                add_score("iot_ap", 0.52, "SSID pattern suggests IoT network.")

        if vendor and vendor != "unknown":
            signals["vendor"] = True
            if contains_any(vendor, list(router_brands)):
                add_score(
                    "router_ap", 0.48, "Vendor family is common in router/AP devices."
                )
            if contains_any(vendor, list(phone_vendors)):
                add_score("phone_hotspot", 0.5, "Vendor family matches smartphone OEM.")
            if contains_any(vendor, list(camera_vendors)):
                add_score("camera_ap", 0.48, "Vendor family matches camera OEM.")
            if contains_any(vendor, list(printer_brands)):
                add_score("printer_ap", 0.52, "Vendor family matches printer OEM.")
            if contains_any(vendor, list(iot_vendors)):
                add_score("iot_ap", 0.45, "Vendor family matches IoT OEM.")

        vendor_ouis = (
            vendor_ies.get("ouis") if isinstance(vendor_ies.get("ouis"), list) else []
        )
        if vendor_ies.get("present") or vendor_ouis:
            signals["vendor_ie"] = True
            add_score(
                "router_ap", 0.08, "Vendor-specific IEs observed in management frames."
            )
            add_score(
                "iot_ap", 0.08, "Vendor-specific IEs may indicate embedded Wi-Fi stack."
            )

        pmf = str(security.get("pmf") or "")
        if pmf:
            signals["security"] = True
            if pmf == "Required":
                add_score(
                    "router_ap",
                    0.08,
                    "PMF required suggests infrastructure AP posture.",
                )

        if caps.get("qos") and caps.get("spectrum_mgmt"):
            signals["security"] = True
            add_score(
                "router_ap",
                0.06,
                "QoS + spectrum management suggests infrastructure AP.",
            )

        if str(security.get("wpa_version") or "") == "WPA3":
            signals["security"] = True
            add_score(
                "router_ap", 0.05, "WPA3 profile is more typical on modern AP routers."
            )

        # clamp per class
        for key in list(scores.keys()):
            scores[key] = round(float(self._clamp(scores[key], 0.0, 0.99)), 2)

        top_type = "unknown"
        top_score = 0.0
        if scores:
            ranked = sorted(
                scores.items(), key=lambda item: (item[1], item[0]), reverse=True
            )
            top_type, top_score = ranked[0]

        confidence = float(top_score)
        if confidence < 0.6:
            top_type = "unknown"
            if (
                vendor
                and "Only vendor known; classification uncertain." not in evidence
            ):
                evidence.append("Only vendor known; classification uncertain.")

        if confidence >= 0.75:
            tier = "high"
        elif confidence >= 0.6:
            tier = "medium"
        else:
            tier = "low"

        return {
            "type": top_type,
            "confidence": round(confidence, 2),
            "tier": tier,
            "version": "v2",
            "scores": scores,
            "signals": signals,
            "evidence": evidence,
        }

    def extract(
        self,
        filename: str,
        force: bool = False,
        capture_id: str | None = None,
        raw_item_id: str | None = None,
        bssid: str | None = None,
    ):
        tshark_bin = self._check_tshark()
        if not tshark_bin:
            return {"status": "error", "message": "tshark not configured or not found"}

        raw_record = (
            rawsniffer_service.resolve_raw_pcap_item(raw_item_id)
            if raw_item_id
            else None
        )

        if raw_record:
            resolved = {
                "path": raw_record.get("path"),
                "filename": raw_record.get("filename"),
                "capture_id": str(capture_id or ""),
                "basename": os.path.basename(
                    str(raw_record.get("filename") or filename or "")
                ).rsplit(".", 1)[0],
            }
        else:
            resolved = resolve_pcap_reference(
                filename,
                capture_id=capture_id,
                search_roots=self._pcap_search_roots(),
            )
        pcap_path = resolved.get("path") if resolved else None
        if not pcap_path or not os.path.exists(pcap_path):
            return {"status": "error", "message": "PCAP not found"}

        display_filename = resolved.get("filename") if resolved else filename
        target_raw_bssid = normalize_mac(bssid) if raw_record else None
        if raw_record:
            details_filename = (
                rawsniffer_service._resolve_existing_raw_details_filename(
                    str(raw_record.get("raw_item_id") or raw_item_id or ""),
                    str(raw_record.get("filename") or display_filename or filename),
                    target_raw_bssid,
                )
                or rawsniffer_service._raw_details_filename(
                    str(raw_record.get("raw_item_id") or raw_item_id or ""),
                    str(raw_record.get("filename") or display_filename or filename),
                    target_raw_bssid,
                )
            )
            details_path = os.path.join(HANDSHAKES_DIR, details_filename)
        else:
            base_name = (resolved or {}).get("basename") or str(filename).rsplit(
                ".", 1
            )[0]
            details_path = (
                get_capture_artifact_path(
                    capture_id,
                    "details",
                    handshakes_dir=HANDSHAKES_DIR,
                    ensure_parent=True,
                )
                if capture_id
                else os.path.join(HANDSHAKES_DIR, f"{base_name}.details")
            )

        if os.path.exists(details_path) and not force:
            try:
                with open(details_path, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                    return {
                        "status": "success",
                        "cached": True,
                        "saved_path": details_path,
                        "details": cached,
                        "timestamp": cached.get("meta", {}).get("timestamp"),
                    }
            except Exception:
                pass

        entry_id = history_service.add_entry(
            display_filename,
            "fingerprint",
            f"{tshark_bin} (passive beacon/probe)",
            {"force": force},
            capture_id=capture_id if not raw_record else None,
        )

        warnings = []
        try:
            # 1) SSID/BSSID
            ssid_out, warn = self._run_tshark(
                [
                    "-r",
                    (
                        self._to_wsl_path(pcap_path)
                        if self._should_use_wsl(tshark_bin)
                        else pcap_path
                    ),
                    "-Y",
                    "wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05",
                    "-T",
                    "fields",
                    "-E",
                    "separator=\t",
                    "-e",
                    "wlan.bssid",
                    "-e",
                    "wlan.ssid",
                ]
            )
            warnings += warn
            ssid_rows = self._parse_rows(ssid_out, 2)
            if target_raw_bssid:
                ssid_rows = self._rows_for_bssid(
                    ssid_rows, target_raw_bssid, allow_fallback=False
                )

            # 2) RSN/WPA
            rsn_out, warn = self._run_tshark(
                [
                    "-r",
                    (
                        self._to_wsl_path(pcap_path)
                        if self._should_use_wsl(tshark_bin)
                        else pcap_path
                    ),
                    "-Y",
                    "wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05",
                    "-T",
                    "fields",
                    "-E",
                    "separator=\t",
                    "-e",
                    "wlan.bssid",
                    "-e",
                    "wlan.ssid",
                    "-e",
                    "wlan.rsn.akms.type",
                    "-e",
                    "wlan.rsn.pcs.type",
                    "-e",
                    "wlan.rsn.gcs.type",
                    "-e",
                    "wlan.rsn.capabilities.mfpr",
                    "-e",
                    "wlan.rsn.capabilities.mfpc",
                ]
            )
            warnings += warn
            rsn_rows = self._parse_rows(rsn_out, 7)
            if target_raw_bssid:
                rsn_rows = self._rows_for_bssid(
                    rsn_rows, target_raw_bssid, allow_fallback=False
                )

            # 3) WPS
            wps_out, warn = self._run_tshark(
                [
                    "-r",
                    (
                        self._to_wsl_path(pcap_path)
                        if self._should_use_wsl(tshark_bin)
                        else pcap_path
                    ),
                    "-Y",
                    "wps",
                    "-T",
                    "fields",
                    "-E",
                    "separator=\t",
                    "-e",
                    "wlan.bssid",
                    "-e",
                    "wlan.ssid",
                    "-e",
                    "wps.manufacturer",
                    "-e",
                    "wps.model_name",
                    "-e",
                    "wps.model_number",
                    "-e",
                    "wps.device_name",
                    "-e",
                    "wps.primary_device_type",
                ]
            )
            warnings += warn
            wps_rows = self._parse_rows(wps_out, 7)
            if target_raw_bssid:
                wps_rows = self._rows_for_bssid(
                    wps_rows, target_raw_bssid, allow_fallback=False
                )

            bssid, ssid, ssid_raw_hex = self._first_network(
                ssid_rows or rsn_rows or wps_rows
            )
            if target_raw_bssid and not bssid:
                return {
                    "status": "error",
                    "message": f"BSSID not found in RAW capture: {target_raw_bssid}",
                }

            akm_codes = [r[2] for r in rsn_rows if r[0].upper() == bssid] or [
                r[2] for r in rsn_rows
            ]
            pairwise_codes = [r[3] for r in rsn_rows if r[0].upper() == bssid] or [
                r[3] for r in rsn_rows
            ]
            group_codes = [r[4] for r in rsn_rows if r[0].upper() == bssid] or [
                r[4] for r in rsn_rows
            ]
            mfpr = ""
            mfpc = ""
            for r in rsn_rows:
                if r[0].upper() == bssid:
                    mfpr = r[5] or mfpr
                    mfpc = r[6] or mfpc

            akm_labels = self._label_list(akm_codes, AKM_MAP)
            pairwise_labels = self._label_list(pairwise_codes, PAIRWISE_MAP)
            group_label = self._label_list(group_codes, GROUP_MAP)
            group_label = group_label[0] if group_label else "Unknown"

            wpa_version = self._derive_wpa_version(akm_labels, pairwise_labels)
            pmf = self._derive_pmf(mfpr, mfpc)

            wps_present = len(wps_rows) > 0
            wps_info = {
                "present": wps_present,
                "manufacturer": "",
                "model_name": "",
                "model_number": "",
                "device_name": "",
                "primary_device_type": "",
            }
            if wps_present:
                wr = wps_rows[0]
                wps_info.update(
                    {
                        "manufacturer": wr[2] or "",
                        "model_name": wr[3] or "",
                        "model_number": wr[4] or "",
                        "device_name": wr[5] or "",
                        "primary_device_type": wr[6] or "",
                    }
                )

            vendor = "Unknown"
            try:
                if deps.manuf_parser:
                    vendor = deps.manuf_parser.get_manuf(bssid) or "Unknown"
                else:
                    vendor = deps.mac_lookup.lookup(bssid) or "Unknown"
            except Exception:
                pass

            extras_rows: List[List[str]] = []
            try:
                extras_out, warn = self._run_tshark(
                    [
                        "-r",
                        (
                            self._to_wsl_path(pcap_path)
                            if self._should_use_wsl(tshark_bin)
                            else pcap_path
                        ),
                        "-Y",
                        "wlan.fc.type_subtype==0x08 || wlan.fc.type_subtype==0x05",
                        "-T",
                        "fields",
                        "-E",
                        "separator=\t",
                        "-e",
                        "wlan.bssid",
                        "-e",
                        "wlan.ssid",
                        "-e",
                        "wlan.ds.current_channel",
                        "-e",
                        "wlan.supported_rates",
                        "-e",
                        "wlan.extended_supported_rates",
                        "-e",
                        "wlan.fixed.capabilities.privacy",
                        "-e",
                        "wlan.fixed.capabilities.short_preamble",
                        "-e",
                        "wlan.fixed.capabilities.short_slot_time",
                        "-e",
                        "wlan.fixed.capabilities.qos",
                        "-e",
                        "wlan.fixed.capabilities.spectrum_mgmt",
                        "-e",
                        "wlan.ht.capabilities",
                        "-e",
                        "wlan.ht.capabilities.width",
                        "-e",
                        "wlan.vht.capabilities.supportedchanwidthset",
                        "-e",
                        "wlan.vht.op.channelwidth",
                        "-e",
                        "wlan.qbss.scount",
                        "-e",
                        "wlan.qbss.cu",
                        "-e",
                        "wlan.qbss.adc",
                        "-e",
                        "radiotap.dbm_antsignal",
                        "-e",
                        "radiotap.datarate",
                        "-e",
                        "radiotap.channel.freq",
                        "-e",
                        "wlan.tag.vendor.oui",
                    ]
                )
                warnings += warn
                extras_rows = self._parse_rows(extras_out, 21)
                if target_raw_bssid:
                    extras_rows = self._rows_for_bssid(
                        extras_rows, target_raw_bssid, allow_fallback=False
                    )
            except Exception as exc:
                warnings.append(f"tshark extra fields failed: {exc}")

            extras_target_rows = self._rows_for_bssid(extras_rows, bssid)
            channel = self._to_int(self._first_non_empty(extras_target_rows, 2))
            frequency_mhz = self._to_int(self._first_non_empty(extras_target_rows, 19))
            band = self._derive_band(frequency_mhz, channel)

            supported_rates = self._unique_numbers(
                self._collect_numbers(extras_target_rows, 3)
            )
            extended_rates = self._unique_numbers(
                self._collect_numbers(extras_target_rows, 4)
            )
            all_rates = self._unique_numbers(supported_rates + extended_rates)
            max_rate = max(all_rates) if all_rates else None

            signal_stats = self._stats(self._collect_numbers(extras_target_rows, 17))
            datarate_stats = self._stats(
                self._collect_numbers(extras_target_rows, 18), include_min=False
            )

            capabilities_flags = []
            privacy = self._any_flag(extras_target_rows, 5)
            short_preamble = self._any_flag(extras_target_rows, 6)
            short_slot = self._any_flag(extras_target_rows, 7)
            qos = self._any_flag(extras_target_rows, 8)
            spectrum_mgmt = self._any_flag(extras_target_rows, 9)
            if privacy:
                capabilities_flags.append("PRIVACY")
            if short_preamble:
                capabilities_flags.append("SHORT_PREAMBLE")
            if short_slot:
                capabilities_flags.append("SHORT_SLOT")
            if qos:
                capabilities_flags.append("QOS")
            if spectrum_mgmt:
                capabilities_flags.append("SPECTRUM_MGMT")

            ht_present = bool(
                self._first_non_empty(extras_target_rows, 10)
                or self._first_non_empty(extras_target_rows, 11)
            )
            vht_present = bool(
                self._first_non_empty(extras_target_rows, 12)
                or self._first_non_empty(extras_target_rows, 13)
            )

            ht_width_code = self._first_non_empty(extras_target_rows, 11)
            vht_width_code = self._first_non_empty(
                extras_target_rows, 13
            ) or self._first_non_empty(extras_target_rows, 12)

            qbss_station_count = self._to_int(
                self._first_non_empty(extras_target_rows, 14)
            )
            qbss_channel_utilization = self._to_int(
                self._first_non_empty(extras_target_rows, 15)
            )
            qbss_available_capacity = self._to_int(
                self._first_non_empty(extras_target_rows, 16)
            )
            vendor_ouis = self._collect_ouis(extras_target_rows, 20)

            details = {
                "bssid": bssid,
                "ssid": ssid,
                "vendor": vendor,
                "security": {
                    "wpa_version": wpa_version,
                    "akm": akm_labels,
                    "pairwise_ciphers": pairwise_labels,
                    "group_cipher": group_label,
                    "pmf": pmf,
                },
                "wps": wps_info,
                "radio": {
                    "channel": channel,
                    "frequency_mhz": frequency_mhz,
                    "band": band,
                    "signal_dbm_min": signal_stats.get("min"),
                    "signal_dbm_avg": signal_stats.get("avg"),
                    "signal_dbm_max": signal_stats.get("max"),
                    "datarate_mbps_avg": datarate_stats.get("avg"),
                    "datarate_mbps_max": datarate_stats.get("max"),
                },
                "rates": {
                    "supported": supported_rates,
                    "extended": extended_rates,
                    "all": all_rates,
                    "max_rate_mbps": max_rate,
                },
                "phy": {
                    "ht_present": ht_present,
                    "vht_present": vht_present,
                    "ht_width_code": ht_width_code,
                    "vht_width_code": vht_width_code,
                },
                "capabilities": {
                    "privacy": privacy,
                    "short_preamble": short_preamble,
                    "short_slot_time": short_slot,
                    "qos": qos,
                    "spectrum_mgmt": spectrum_mgmt,
                    "flags": capabilities_flags,
                },
                "qbss": {
                    "station_count": qbss_station_count,
                    "channel_utilization": qbss_channel_utilization,
                    "available_capacity": qbss_available_capacity,
                },
                "vendor_ies": {"present": bool(vendor_ouis), "ouis": vendor_ouis},
                "classification": {},  # filled below
                "meta": {
                    "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                    "source": "tshark",
                    "warnings": warnings,
                },
            }
            if raw_record:
                details["meta"]["raw_item_id"] = str(
                    raw_record.get("raw_item_id") or raw_item_id or ""
                )
                details["meta"]["raw_source"] = str(raw_record.get("source") or "")
                details["meta"]["raw_device_label"] = str(
                    raw_record.get("device_label") or ""
                )
                details["meta"]["raw_filename"] = str(
                    raw_record.get("filename") or display_filename or ""
                )
                if target_raw_bssid:
                    details["meta"]["raw_target_bssid"] = target_raw_bssid
            if ssid_raw_hex:
                details["meta"]["ssid_raw_hex"] = ssid_raw_hex
                details["meta"]["warnings"].append(
                    "SSID was hex-encoded and decoded to UTF-8"
                )

            details["classification"] = self._classify(details)

            with open(details_path, "w", encoding="utf-8") as f:
                json.dump(details, f, indent=2, ensure_ascii=False)

            history_service.update_entry(
                display_filename,
                entry_id,
                "SUCCESS",
                "Fingerprint extracted",
                capture_id=capture_id if not raw_record else None,
            )
            reload_data()

            return {
                "status": "success",
                "cached": False,
                "saved_path": details_path,
                "details": details,
                "timestamp": details["meta"]["timestamp"],
            }
        except Exception as e:
            history_service.update_entry(
                display_filename,
                entry_id,
                "FAILED",
                str(e),
                capture_id=capture_id if not raw_record else None,
            )
            return {"status": "error", "message": str(e)}


fingerprint_service = FingerprintService()
