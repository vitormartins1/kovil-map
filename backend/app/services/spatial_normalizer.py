"""
Spatial normalization for Wi-Fi networks imported from Bruce Wardriving CSV.

Handles:
- Preserving raw GPS coordinates from CSV
- Detecting clusters (multiple networks at same exact location)
- Applying deterministic jitter to separate overlapping pins
- Managing source priority (Pwnagotchi > Bruce)
- Computing display coordinates vs. raw coordinates
"""

import hashlib
import logging
import math
from typing import Any, Dict, List, Tuple, Optional
from enum import Enum

logger = logging.getLogger(__name__)

# Earth's radius in meters
EARTH_RADIUS_METERS = 6371000

# Source priority (lower value = higher priority)
SOURCE_PRIORITY = {
    "pwnagotchi-handshake-gps": (1, "high"),  # Most reliable
    "pwnagotchi-wardrive": (2, "medium"),  # Pwnagotchi device
    "bruce-wardriving-csv": (3, "low"),  # External CSV with jitter
}

# Default sources from existing code
SOURCE_ALIASES = {
    "pwnagotchi": "pwnagotchi-handshake-gps",
    "brucegotchi": "pwnagotchi-wardrive",
    "wardrive": "bruce-wardriving-csv",
}


class PositionMode(Enum):
    """Enum for position mode types"""

    RAW = "raw"  # Original CSV position
    DERIVED_JITTER = "derived_jitter"  # Position with jitter applied
    PREFERRED_EXTERNAL = "preferred_external"  # Position from preferred source


def _hash_to_offset(hash_value: str, max_offset: float) -> Tuple[float, float]:
    """
    Convert a hash string to deterministic x,y offsets in range [-max_offset, +max_offset].

    Args:
        hash_value: Hash string (hex)
        max_offset: Maximum offset in meters

    Returns:
        Tuple of (offset_x, offset_y) in meters
    """
    # Use the hash to generate consistent random-like values
    int_val = int(hash_value[:16], 16)

    # Generate angle (0 to 2*pi) from first part of hash
    angle = (int_val % 1000) / 1000.0 * 2 * math.pi

    # Generate radius (0 to max_offset) from second part of hash
    radius = ((int_val // 1000) % 1000) / 1000.0 * max_offset

    # Convert polar to cartesian
    offset_x = radius * math.cos(angle)
    offset_y = radius * math.sin(angle)

    return offset_x, offset_y


def _meters_to_lat_lng_delta(
    meters_east: float, meters_north: float, latitude: float
) -> Tuple[float, float]:
    """
    Convert meters (east/north) to latitude/longitude deltas.

    Args:
        meters_east: Offset in meters (longitude direction)
        meters_north: Offset in meters (latitude direction)
        latitude: Reference latitude for calculation

    Returns:
        Tuple of (delta_lat, delta_lng)
    """
    # 1 degree of latitude = ~111,320 meters (constant)
    meters_per_degree_lat = 111320.0

    # 1 degree of longitude varies by latitude
    # degrees_per_meter_lon = 1 / (111320 * cos(lat_radians))
    lat_radians = math.radians(latitude)
    meters_per_degree_lng = 111320.0 * math.cos(lat_radians)

    delta_lat = meters_north / meters_per_degree_lat
    delta_lng = meters_east / meters_per_degree_lng if meters_per_degree_lng != 0 else 0

    return delta_lat, delta_lng


def generate_deterministic_accuracy(
    mac_address: str,
    min_accuracy: float = 3.0,
    max_accuracy: float = 35.0,
) -> float:
    """
    Generate deterministic but pseudo-random accuracy value based on MAC address.

    Simulates realistic GPS accuracy variation:
    - Same MAC always produces same accuracy
    - Different MACs get different values
    - Range: 3-35 meters (typical consumer GPS)

    Args:
        mac_address: MAC address string (BSSID)
        min_accuracy: Minimum accuracy in meters
        max_accuracy: Maximum accuracy in meters

    Returns:
        Accuracy value in meters
    """
    # Hash the MAC address
    hash_input = mac_address.encode("utf-8")
    hash_hex = hashlib.sha256(hash_input).hexdigest()

    # Convert first 8 hex chars to integer (0 to 4,294,967,295)
    int_val = int(hash_hex[:8], 16)

    # Normalize to 0-1 range
    normalized = (int_val % 10000) / 10000.0

    # Map to min-max range
    accuracy = min_accuracy + (normalized * (max_accuracy - min_accuracy))

    return accuracy


def calculate_deterministic_jitter(
    bssid: str,
    session_id: str,
    raw_accuracy: float,
    rssi: Optional[float] = None,
    cluster_index: int = 0,
    cluster_size: int = 1,
) -> Tuple[float, float]:
    """
    Calculate deterministic jitter offsets in meters.

    The jitter is:
    - Deterministic (same BSSID + session always produces same offset)
    - Based on accuracy, signal strength, and cluster position
    - Bounded to reasonable proximity

    Args:
        bssid: MAC address string
        session_id: Session identifier (ensures separation across sessions)
        raw_accuracy: Raw accuracy from GPS in meters
        rssi: Signal strength (lower = weaker, optional)
        cluster_index: Index of this network within its cluster (0-based)
        cluster_size: Total number of networks in this cluster

    Returns:
        Tuple of (offset_x_meters, offset_y_meters)
    """
    # Calculate base radius in meters:
    # - Minimum 8m (even with perfect accuracy)
    # - Maximum 25m (for very poor accuracy)
    # - Based on raw accuracy
    try:
        base_radius = max(5, min(raw_accuracy, 25))
    except (TypeError, ValueError):
        base_radius = 5  # Default middle ground

    # Adjust radius based on signal strength (if available)
    # Stronger signals (closer to 0) use smaller offsets
    # Weaker signals use larger offsets
    if rssi is not None:
        try:
            rssi_val = float(rssi)
            if rssi_val >= -50:
                # Very strong signal, reduce offset
                base_radius = base_radius * 0.4
            elif rssi_val >= -70:
                # Medium signal, use base
                pass  # Keep base_radius as is
            else:
                # Weak signal, increase offset
                base_radius = base_radius * 1.2
        except (TypeError, ValueError):
            pass

    # For clusters with multiple networks, vary radius based on position
    # This spreads networks out more when RSSI data is unavailable (CSV imports)
    # First network: 1.0x, second: 1.3x, third: 1.6x, etc.
    if cluster_size > 1 and cluster_index >= 0:
        radius_multiplier = 1.0 + (cluster_index * 0.3)
        base_radius = base_radius * radius_multiplier

    # Create hash: BSSID:sessionId (deterministic per network per session)
    hash_input = f"{bssid}:{session_id}".encode("utf-8")
    hash_hex = hashlib.sha256(hash_input).hexdigest()

    # Convert hash to x,y offsets
    offset_x, offset_y = _hash_to_offset(hash_hex, base_radius)

    return offset_x, offset_y


def apply_jitter_to_position(
    latitude: float,
    longitude: float,
    bssid: str,
    session_id: str,
    raw_accuracy: float,
    rssi: Optional[float] = None,
    cluster_index: int = 0,
    cluster_size: int = 1,
) -> Tuple[float, float]:
    """
    Apply jitter to a position and return display coordinates.

    Args:
        latitude: Raw latitude
        longitude: Raw longitude
        bssid: MAC address
        session_id: Session ID
        raw_accuracy: Raw accuracy in meters
        rssi: Signal strength (optional)
        cluster_index: Index of this network within its cluster (0-based)
        cluster_size: Total number of networks in this cluster

    Returns:
        Tuple of (display_lat, display_lng)
    """
    offset_x, offset_y = calculate_deterministic_jitter(
        bssid, session_id, raw_accuracy, rssi, cluster_index, cluster_size
    )

    # Convert meter offsets to lat/lng deltas
    delta_lat, delta_lng = _meters_to_lat_lng_delta(offset_x, offset_y, latitude)

    display_lat = latitude + delta_lat
    display_lng = longitude + delta_lng

    return display_lat, display_lng


def detect_position_clusters(networks: Dict[str, Dict]) -> Dict[Tuple, List[str]]:
    """
    Detect clusters of networks at the same raw position.

    Groups networks by:
    - sessionId (if present)
    - raw latitude
    - raw longitude

    Networks without valid positions are ignored.

    Args:
        networks: Dictionary of {mac: network_data}

    Returns:
        Dictionary of {(session_id, lat, lng): [mac1, mac2, ...]}
    """
    clusters: Dict[Tuple, List[str]] = {}

    for mac, network in networks.items():
        if not isinstance(network, dict):
            continue

        # Get raw position (or display if raw not available yet)
        lat = network.get("rawLatitude") or network.get("lat")
        lng = network.get("rawLongitude") or network.get("lng")

        # Skip networks without valid position (e.g., no-gps networks)
        if lat is None or lng is None:
            continue

        session_id = network.get("sessionId") or "default"

        # Round coordinates to detect exact duplicates
        # (accounting for floating point precision)
        key = (session_id, round(lat, 6), round(lng, 6))

        if key not in clusters:
            clusters[key] = []
        clusters[key].append(mac)

    return clusters


def _normalize_wardrive_session_observations(
    networks: Dict[str, Dict],
    apply_jitter: bool = True,
) -> None:
    """
    Propagate raw/display position metadata to nested wardrive observations.

    Nested observations intentionally keep raw ``lat``/``lng`` untouched so
    replay and distance calculations still track the original capture path.
    """
    observation_records: Dict[str, Dict[str, Any]] = {}
    observation_refs: Dict[str, Dict[str, Any]] = {}

    for network_key, network in networks.items():
        if not isinstance(network, dict):
            continue

        mac = str(network.get("mac") or network_key or "").strip()
        if not mac:
            continue

        observations = network.get("wardrive_sessions") or []
        if not isinstance(observations, list):
            continue

        for index, observation in enumerate(observations):
            if not isinstance(observation, dict):
                continue

            lat = observation.get("lat")
            lng = observation.get("lng")
            if lat is None or lng is None:
                continue

            raw_lat = observation.get("rawLatitude", lat)
            raw_lng = observation.get("rawLongitude", lng)
            raw_acc = observation.get("rawAccuracy", observation.get("acc"))
            raw_alt = observation.get("rawAltitude", observation.get("altitude"))
            session_id = (
                str(observation.get("session_id") or "default").strip() or "default"
            )
            synthetic_key = f"{mac}::{session_id}::{index}"

            observation_records[synthetic_key] = {
                "mac": mac,
                "lat": raw_lat,
                "lng": raw_lng,
                "acc": raw_acc,
                "altitude": raw_alt,
                "rawLatitude": raw_lat,
                "rawLongitude": raw_lng,
                "rawAccuracy": raw_acc,
                "rawAltitude": raw_alt,
                "displayLatitude": observation.get("displayLatitude", raw_lat),
                "displayLongitude": observation.get("displayLongitude", raw_lng),
                "displayAltitude": observation.get("displayAltitude", raw_alt),
                "rssi": observation.get("rssi"),
                "sources": ["wardrive"],
                "sessionId": session_id,
            }
            observation_refs[synthetic_key] = observation

    if not observation_records:
        return

    normalized = normalize_network_positions(
        observation_records,
        apply_jitter=apply_jitter,
    )
    for synthetic_key, normalized_observation in normalized.items():
        original = observation_refs.get(synthetic_key)
        if not isinstance(original, dict):
            continue

        original["rawLatitude"] = normalized_observation.get("rawLatitude")
        original["rawLongitude"] = normalized_observation.get("rawLongitude")
        original["rawAccuracy"] = normalized_observation.get("rawAccuracy")
        original["rawAltitude"] = normalized_observation.get("rawAltitude")
        original["displayLatitude"] = normalized_observation.get("displayLatitude")
        original["displayLongitude"] = normalized_observation.get("displayLongitude")
        original["displayAltitude"] = normalized_observation.get("displayAltitude")
        if normalized_observation.get("positionMode") is not None:
            original["positionMode"] = normalized_observation.get("positionMode")
        if normalized_observation.get("positionConfidence") is not None:
            original["positionConfidence"] = normalized_observation.get(
                "positionConfidence"
            )


def get_source_priority(source_name: str) -> Tuple[int, str]:
    """
    Get priority and confidence for a source.

    Args:
        source_name: Source identifier

    Returns:
        Tuple of (priority_level, confidence_level)
        - Lower priority number = higher priority
        - confidence_level: "high", "medium", or "low"
    """
    # Map legacy source names to new names
    normalized = SOURCE_ALIASES.get(source_name, source_name)

    # Return priority and confidence
    return SOURCE_PRIORITY.get(normalized, (999, "low"))


def resolve_source_priority(sources: List[str]) -> Tuple[str, int, str]:
    """
    From a list of sources, return the preferred one.

    Args:
        sources: List of source identifiers

    Returns:
        Tuple of (preferred_source, priority_level, confidence_level)
    """
    if not sources:
        return "unknown", 999, "low"

    best_source = sources[0]
    best_priority, best_confidence = get_source_priority(best_source)

    for source in sources[1:]:
        priority, confidence = get_source_priority(source)
        if priority < best_priority:
            best_source = source
            best_priority = priority
            best_confidence = confidence

    return best_source, best_priority, best_confidence


def normalize_network_positions(
    networks: Dict[str, Dict],
    apply_jitter: bool = True,
) -> Dict[str, Dict]:
    """
    Normalize positions for all networks.

    Handles:
    - Preserving raw coordinates
    - Detecting clusters
    - Applying jitter for display
    - Source priority resolution
    - Position mode assignment

    Networks without valid positions (e.g., no-gps) are not modified.

    Args:
        networks: Dictionary of {mac: network_data}
        apply_jitter: Whether to apply jitter to clustered networks

    Returns:
        Updated networks dictionary with normalized positions
    """
    # Ensure raw position fields exist for networks with valid positions
    for mac, network in networks.items():
        if not isinstance(network, dict):
            continue

        # Skip networks without position
        if network.get("lat") is None or network.get("lng") is None:
            continue

        # Preserve raw coordinates if not already set
        if "rawLatitude" not in network:
            network["rawLatitude"] = network.get("lat")
        if "rawLongitude" not in network:
            network["rawLongitude"] = network.get("lng")
        if "rawAltitude" not in network:
            network["rawAltitude"] = network.get("altitude")
        if "rawAccuracy" not in network:
            network["rawAccuracy"] = network.get("acc")

        # Initialize display fields if not set
        if "displayLatitude" not in network:
            network["displayLatitude"] = network.get("lat")
        if "displayLongitude" not in network:
            network["displayLongitude"] = network.get("lng")
        if "displayAltitude" not in network:
            network["displayAltitude"] = network.get("altitude")

    if not apply_jitter:
        # Still set position mode but don't apply jitter
        for mac, network in networks.items():
            if not isinstance(network, dict):
                continue
            sources = network.get("sources", ["unknown"])
            preferred_source, priority, confidence = resolve_source_priority(sources)
            network["sourceType"] = preferred_source
            network["sourcePriority"] = priority
            network["positionMode"] = PositionMode.RAW.value
            network["positionConfidence"] = confidence
        _normalize_wardrive_session_observations(networks, apply_jitter=False)
        return networks

    # Detect clusters
    clusters = detect_position_clusters(networks)

    # For each cluster with >1 network, apply jitter
    for (session_id, lat, lng), macs in clusters.items():
        if len(macs) <= 1:
            continue  # No clustering needed

        # Sort MAC addresses for deterministic ordering within clusters
        sorted_macs = sorted(macs)
        cluster_size = len(sorted_macs)

        for cluster_index, mac in enumerate(sorted_macs):
            network = networks.get(mac)
            if not isinstance(network, dict):
                continue

            bssid = str(network.get("mac") or mac or "").strip() or str(mac)

            raw_lat = network.get("rawLatitude", lat)
            raw_lng = network.get("rawLongitude", lng)
            raw_acc = network.get("rawAccuracy") or 5
            rssi = network.get("rssi")

            # Apply jitter with cluster position info
            display_lat, display_lng = apply_jitter_to_position(
                raw_lat,
                raw_lng,
                bssid,
                session_id,
                raw_acc,
                rssi,
                cluster_index=cluster_index,
                cluster_size=cluster_size,
            )

            network["displayLatitude"] = display_lat
            network["displayLongitude"] = display_lng
            network["positionMode"] = PositionMode.DERIVED_JITTER.value

    # Set source metadata for all networks
    for mac, network in networks.items():
        if not isinstance(network, dict):
            continue

        sources = network.get("sources", ["unknown"])
        preferred_source, priority, confidence = resolve_source_priority(sources)

        network["sourceType"] = preferred_source
        network["sourcePriority"] = priority
        network["positionConfidence"] = confidence

        # Override position mode if it wasn't already set to DERIVED_JITTER
        if network.get("positionMode") != PositionMode.DERIVED_JITTER.value:
            network["positionMode"] = PositionMode.RAW.value

        # Update lat/lng to use display coordinates for frontend rendering
        # while preserving raw values for audit trail
        if network.get("displayLatitude") is not None:
            network["lat"] = network["displayLatitude"]
        if network.get("displayLongitude") is not None:
            network["lng"] = network["displayLongitude"]

    _normalize_wardrive_session_observations(networks, apply_jitter=apply_jitter)

    return networks


def prepare_network_for_display(network: Dict) -> Dict:
    """
    Prepare a network record for frontend display.

    Ensures all necessary fields are present and display coordinates are used.

    Args:
        network: Network data dictionary

    Returns:
        Dictionary ready for frontend consumption
    """
    if not isinstance(network, dict):
        return network

    # Use display coordinates for map rendering
    output = dict(network)

    # For frontend compatibility, also set lat/lng to display values
    # but preserve the raw values separately
    if output.get("displayLatitude") is not None:
        output["lat"] = output["displayLatitude"]
    if output.get("displayLongitude") is not None:
        output["lng"] = output["displayLongitude"]

    return output
