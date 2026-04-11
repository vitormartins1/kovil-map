from __future__ import annotations

import os
import re
from datetime import datetime

from app.services.spatial_normalizer import generate_deterministic_accuracy

_WARDRIVE_OPERATIONAL_MIN_ACCURACY = 3.0
_WARDRIVE_OPERATIONAL_MAX_ACCURACY = 25.0
_WARDRIVE_LOW_ACCURACY_FLOOR = 5.0
_WARDRIVE_IMPORTED_SOURCE_PREFIXES = ("m5evil__",)

_RE_BRUCE_WARDRIVE_FILENAME = re.compile(
    r"^\d{8}_\d{6}_wardriving\.csv$", re.IGNORECASE
)


def _parse_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _normalize_wardrive_source_basename(value):
    normalized = str(value or "").strip()
    if not normalized:
        return ""
    lowered = normalized.lower()
    for prefix in _WARDRIVE_IMPORTED_SOURCE_PREFIXES:
        if lowered.startswith(prefix):
            return normalized[len(prefix) :]
    return normalized


def _wardrive_session_base_name_from_filename(filename):
    base_name = os.path.splitext(os.path.basename(str(filename or "").strip()))[0]
    return _normalize_wardrive_source_basename(base_name)


def _is_m5evil_wardrive_source(source_file=None, wigle_header=None):
    source_name = str(source_file or "").strip().lower()
    header = str(wigle_header or "").strip().lower()
    if source_name.startswith(_WARDRIVE_IMPORTED_SOURCE_PREFIXES):
        return True
    return any(
        token in header
        for token in (
            "evil-cardputer",
            "evil-m5project",
            "device=evil-",
            "model=cardputer",
        )
    )


def _is_bruce_wardrive_source(source_file=None, wigle_header=None):
    header = str(wigle_header or "").strip().lower()
    if any(token in header for token in ("brand=bruce", "device=esp32 m5stack")):
        return True
    source_name = str(source_file or "").strip()
    if _RE_BRUCE_WARDRIVE_FILENAME.match(source_name):
        return True
    return False


def _classify_wardrive_device(source_file=None, wigle_header=None):
    if _is_m5evil_wardrive_source(source_file=source_file, wigle_header=wigle_header):
        return "m5evil"
    if _is_bruce_wardrive_source(source_file=source_file, wigle_header=wigle_header):
        return "bruce"
    return "uncategorized"


def _normalize_wardrive_accuracy(mac, accuracy, *, source_file=None, wigle_header=None):
    raw_accuracy = _parse_float(accuracy)
    if _is_m5evil_wardrive_source(source_file=source_file, wigle_header=wigle_header):
        raw_accuracy = None if raw_accuracy is None else raw_accuracy / 100.0
    if raw_accuracy is None or raw_accuracy < _WARDRIVE_LOW_ACCURACY_FLOOR:
        return generate_deterministic_accuracy(
            mac,
            min_accuracy=_WARDRIVE_OPERATIONAL_MIN_ACCURACY,
            max_accuracy=15.0,
        )

    return max(
        _WARDRIVE_LOW_ACCURACY_FLOOR,
        min(raw_accuracy, _WARDRIVE_OPERATIONAL_MAX_ACCURACY),
    )


def _wardrive_session_id_from_path(file_path):
    return _wardrive_session_base_name_from_filename(file_path)


def _merge_wardrive_session_observation(observations, observation):
    if not isinstance(observations, list):
        return [dict(observation)]

    session_id = observation.get("session_id")
    for idx, current in enumerate(observations):
        if str(current.get("session_id") or "") != str(session_id or ""):
            continue

        current_ts = _parse_float(current.get("ts_last")) or 0
        next_ts = _parse_float(observation.get("ts_last")) or 0
        current_acc = _parse_float(current.get("acc"))
        next_acc = _parse_float(observation.get("acc"))

        should_replace = False
        if next_ts > current_ts:
            should_replace = True
        elif next_ts == current_ts:
            if next_acc is not None and (current_acc is None or next_acc < current_acc):
                should_replace = True

        if should_replace:
            merged = dict(current)
            merged.update(observation)
        else:
            merged = dict(current)
            for key, value in observation.items():
                if merged.get(key) in (None, "", []):
                    merged[key] = value
                if key == "ts_first":
                    current_first = _parse_float(merged.get("ts_first"))
                    next_first = _parse_float(value)
                    if next_first is not None and (
                        current_first is None or next_first < current_first
                    ):
                        merged["ts_first"] = next_first

        observations[idx] = merged
        return observations

    observations.append(dict(observation))
    return observations


def _normalize_mac(raw):
    if not raw:
        return None
    value = str(raw).strip().upper()
    if not value:
        return None
    cleaned = re.sub(r"[^0-9A-F]", "", value)
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


def _parse_wigle_timestamp(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
        return dt.timestamp()
    except Exception:
        pass
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
    ):
        try:
            dt = datetime.strptime(text, fmt)
            return dt.timestamp()
        except Exception:
            continue
    return None


def _infer_encryption(auth_mode):
    text = str(auth_mode or "").upper()
    if "WEP" in text:
        return "WEP"
    if "WPA3" in text:
        return "WPA3"
    if "WPA2" in text:
        return "WPA2"
    if "WPA" in text:
        return "WPA"
    if "OPEN" in text or "OPN" in text or "NONE" in text:
        return "OPEN"
    return "UNK"


def _infer_encryption_from_details(details):
    security = details.get("security", {}) if isinstance(details, dict) else {}
    wpa_version = security.get("wpa_version")
    if wpa_version and wpa_version != "Unknown":
        return str(wpa_version)
    return "UNK"


def _extract_device_classification(details):
    if not isinstance(details, dict):
        return "unknown", 0.0
    cls = details.get("classification")
    if not isinstance(cls, dict):
        return "unknown", 0.0

    device_type = str(cls.get("type") or "unknown").strip().lower() or "unknown"
    confidence = _parse_float(cls.get("confidence"))
    if confidence is None:
        confidence = 0.0
    confidence = max(0.0, min(1.0, float(confidence)))
    return device_type, confidence
