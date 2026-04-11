import glob
import json
import os
from datetime import datetime


def _is_supported_gps_json(filename):
    return (
        filename.endswith(".gps.json")
        or filename.endswith(".geo.json")
        or filename.endswith(".paw-gps.json")
    )


def _extract_mac_ssid_from_filename_or_content(filename, content):
    parts = filename.split("_")
    if len(parts) >= 2:
        ssid = parts[0]
        mac_part = parts[-1].split(".")[0]
        if len(mac_part) == 12 and ":" not in mac_part:
            mac = ":".join(mac_part[i : i + 2] for i in range(0, 12, 2))
        else:
            mac = mac_part
    else:
        mac = content.get("BSSID", "Unknown")
        ssid = content.get("SSID", "Unknown")

    if mac:
        mac = str(mac).upper()
    return mac, ssid


def _extract_accuracy(content):
    acc = content.get("Accuracy")
    if acc is None:
        acc = content.get("accuracy")
    if acc is None:
        acc = content.get("acc")

    if acc is None:
        hdop = content.get("HDOP") or content.get("hdop")
        if hdop:
            try:
                acc = float(hdop) * 5
            except Exception:
                acc = 50
        else:
            acc = 50
    return acc


def _extract_timestamp(content, file_path):
    ts = content.get("ts")
    if ts is None:
        updated_str = content.get("Updated")
        if updated_str:
            try:
                if str(updated_str).endswith("Z"):
                    updated_str = str(updated_str).replace("Z", "+00:00")
                dt = datetime.fromisoformat(updated_str)
                ts = dt.timestamp()
            except Exception:
                pass
    if ts is None:
        ts = os.path.getmtime(file_path)
    return ts


def _collect_related_files(handshakes_dir, base_name):
    related_files = []
    pattern = os.path.join(handshakes_dir, f"{base_name}*")
    for file_path in glob.glob(pattern):
        if os.path.getsize(file_path) > 0:
            related_files.append(os.path.basename(file_path))
    return related_files


def _read_cracked_password(handshakes_dir, base_name):
    pcap_cracked_file = os.path.join(handshakes_dir, f"{base_name}.pcap.cracked")
    if not os.path.exists(pcap_cracked_file):
        return False, None
    try:
        with open(pcap_cracked_file, "r") as cracked_file:
            return True, cracked_file.read().strip()
    except Exception:
        return True, None


def _load_gps_handshake_entries(
    handshakes_dir,
    *,
    load_details_for_base,
    infer_encryption_from_details,
    extract_device_classification,
    logger,
):
    data = {}
    gps_files = glob.glob(os.path.join(handshakes_dir, "*.json"))

    for file_path in gps_files:
        filename = os.path.basename(file_path)
        if not _is_supported_gps_json(filename):
            continue

        try:
            with open(file_path, "r") as file_handle:
                content = json.load(file_handle)

            mac, ssid = _extract_mac_ssid_from_filename_or_content(filename, content)

            lat = content.get("Latitude")
            if lat is None:
                lat = content.get("lat")
            lng = content.get("Longitude")
            if lng is None:
                lng = content.get("lng")

            ts = _extract_timestamp(content, file_path)
            acc = _extract_accuracy(content)

            if lat is not None and lng is not None:
                base_name = filename.split(".")[0]
                is_cracked, password = _read_cracked_password(handshakes_dir, base_name)
                related_files = _collect_related_files(handshakes_dir, base_name)
                details = load_details_for_base(base_name)
                device_type, device_confidence = extract_device_classification(details)
                encryption = (
                    infer_encryption_from_details(details) if details else "WPA2"
                )

                data[mac] = {
                    "mac": mac,
                    "ssid": ssid,
                    "lat": lat,
                    "lng": lng,
                    "acc": acc,
                    "ts_last": ts,
                    "type": "ap",
                    "encryption": encryption,
                    "pass": password if is_cracked else None,
                    "handshake": True,
                    "handshake_files": related_files,
                    "sources": ["pwnagotchi"],
                    "device_type": device_type,
                    "device_confidence": device_confidence,
                }
        except Exception as exc:
            logger.warning("Erro ao ler %s: %s", filename, exc)

    return data


def _merge_no_gps_pcap_entries(
    data,
    handshakes_dir,
    *,
    load_details_for_base,
    infer_encryption_from_details,
    extract_device_classification,
):
    all_pcaps = glob.glob(os.path.join(handshakes_dir, "*.pcap"))

    for pcap_path in all_pcaps:
        filename = os.path.basename(pcap_path)
        parts = filename.rsplit(".", 1)[0].split("_")
        if len(parts) < 2:
            continue

        mac_part = parts[-1]
        if len(mac_part) != 12:
            continue

        mac = ":".join(mac_part[i : i + 2] for i in range(0, 12, 2)).upper()
        if mac in data:
            continue

        ssid = parts[0]
        base_name = filename.rsplit(".", 1)[0]
        _is_cracked, password = _read_cracked_password(handshakes_dir, base_name)
        related_files = _collect_related_files(handshakes_dir, base_name)
        details = load_details_for_base(base_name)
        device_type, device_confidence = extract_device_classification(details)
        encryption = infer_encryption_from_details(details) if details else "WPA2"
        ts = os.path.getmtime(pcap_path)

        data[mac] = {
            "mac": mac,
            "ssid": ssid,
            "lat": None,
            "lng": None,
            "acc": 0,
            "ts_last": ts,
            "type": "no-gps",
            "encryption": encryption,
            "pass": password,
            "handshake": True,
            "handshake_files": related_files,
            "sources": ["pwnagotchi"],
            "device_type": device_type,
            "device_confidence": device_confidence,
        }

    return data
