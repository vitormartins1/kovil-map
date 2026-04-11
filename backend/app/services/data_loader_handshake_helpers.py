import glob
import json
import os


def _load_details_for_base(base_name, handshakes_dir):
    details_path = os.path.join(handshakes_dir, f"{base_name}.details")
    if not os.path.exists(details_path):
        return None
    try:
        with open(details_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _load_prefixed_handshake_entries(
    candidates,
    roots,
    source_name,
    *,
    handshakes_dir,
    load_details_for_base,
    infer_encryption_from_details,
    extract_device_classification,
):
    entries = {}
    for mac, filename in candidates.items():
        base_name = filename.rsplit(".", 1)[0]
        related_files = []
        pattern = os.path.join(handshakes_dir, f"{base_name}*")
        for file_path in glob.glob(pattern):
            if os.path.getsize(file_path) > 0:
                related_files.append(os.path.basename(file_path))

        if filename not in related_files:
            related_files.append(filename)

        details = load_details_for_base(base_name)
        ssid = ""
        encryption = "UNK"
        device_type = "unknown"
        device_confidence = 0.0
        if details:
            ssid = details.get("ssid") or ""
            encryption = infer_encryption_from_details(details)
            device_type, device_confidence = extract_device_classification(details)

        path = None
        for root in roots:
            candidate = os.path.join(root, filename)
            if os.path.exists(candidate):
                path = candidate
                break

        ts = os.path.getmtime(path) if path else None
        if ts is None:
            continue

        entries[mac] = {
            "mac": mac,
            "ssid": ssid,
            "lat": None,
            "lng": None,
            "acc": 0,
            "ts_last": ts,
            "type": "no-gps",
            "encryption": encryption,
            "pass": None,
            "handshake": True,
            "handshake_files": related_files,
            "sources": [source_name],
            "device_type": device_type,
            "device_confidence": device_confidence,
        }

    return entries


def _merge_external_handshake_entries(data, entries, source_name):
    for mac, entry in entries.items():
        if mac in data:
            item = data[mac]
            sources = list(item.get("sources") or [])
            if not sources:
                sources.append("pwnagotchi")
            if source_name not in sources:
                sources.append(source_name)
            item["sources"] = sources
        else:
            data[mac] = entry
