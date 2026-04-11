def _merge_wardrive_entries(data, wardrive_entries):
    for mac, entry in wardrive_entries.items():
        if mac in data:
            item = data[mac]
            sources = list(item.get("sources") or [])
            if not sources:
                sources.append("pwnagotchi")
            if "wardrive" not in sources:
                sources.append("wardrive")
            item["sources"] = sources
            wardrive_sessions = list(entry.get("wardrive_sessions") or [])
            if wardrive_sessions:
                item["wardrive_sessions"] = wardrive_sessions

            lat_missing = (
                item.get("type") == "no-gps"
                or item.get("lat") is None
                or item.get("lng") is None
            )
            if lat_missing:
                item["lat"] = entry.get("lat")
                item["lng"] = entry.get("lng")
                item["acc"] = entry.get("acc")
                item["sourceAccuracyMeters"] = entry.get("sourceAccuracyMeters")
                if item.get("type") == "no-gps":
                    item["type"] = "ap"

            for field in ["channel", "frequency", "rssi", "altitude", "ts_first"]:
                if entry.get(field) is not None and item.get(field) is None:
                    item[field] = entry.get(field)

            entry_ts = entry.get("ts_last")
            item_ts = item.get("ts_last")
            if entry_ts is not None and (item_ts is None or entry_ts > item_ts):
                item["ts_last"] = entry_ts

            current_enc = item.get("encryption")
            if not current_enc or str(current_enc).upper() == "UNK":
                if entry.get("encryption"):
                    item["encryption"] = entry.get("encryption")
        else:
            data[mac] = {
                "mac": mac,
                "ssid": entry.get("ssid") or "",
                "lat": entry.get("lat"),
                "lng": entry.get("lng"),
                "acc": entry.get("acc"),
                "sourceAccuracyMeters": entry.get("sourceAccuracyMeters"),
                "ts_last": entry.get("ts_last"),
                "ts_first": entry.get("ts_first"),
                "channel": entry.get("channel"),
                "frequency": entry.get("frequency"),
                "rssi": entry.get("rssi"),
                "altitude": entry.get("altitude"),
                "type": "ap",
                "encryption": entry.get("encryption") or "UNK",
                "pass": None,
                "handshake": False,
                "handshake_files": [],
                "sources": ["wardrive"],
                "device_type": "unknown",
                "device_confidence": 0.0,
                "sessionId": entry.get("sessionId"),
                "sessionSourceFile": entry.get("sessionSourceFile"),
                "wardrive_sessions": list(entry.get("wardrive_sessions") or []),
            }
    return data


def _finalize_loaded_data(
    data,
    *,
    merge_raw_metadata,
    normalize_network_positions,
    apply_handshake_set_summaries,
):
    merge_raw_metadata(data)

    for item in data.values():
        if not isinstance(item, dict):
            continue
        if not item.get("device_type"):
            item["device_type"] = "unknown"
        if item.get("device_confidence") is None:
            item["device_confidence"] = 0.0

    data = normalize_network_positions(data, apply_jitter=True)
    apply_handshake_set_summaries(data)
    return data
