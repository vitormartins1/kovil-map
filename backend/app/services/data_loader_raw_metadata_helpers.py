import glob
import json
import os


def _raw_metadata_dirs(bruce_pcap_dir, m5evil_dir):
    dirs = []
    for base_dir in (bruce_pcap_dir, m5evil_dir):
        metadata_dir = os.path.join(base_dir, ".metadata")
        if os.path.exists(metadata_dir):
            dirs.append(metadata_dir)
    return dirs


def _normalize_raw_metadata_source(metadata, metadata_dir, m5evil_dir):
    metadata_dir_abs = os.path.abspath(str(metadata_dir or ""))
    m5_metadata_dir = os.path.abspath(os.path.join(m5evil_dir, ".metadata"))

    source = str(metadata.get("source") or "").strip().lower()
    if not source:
        source = "m5evil" if metadata_dir_abs == m5_metadata_dir else "brucegotchi"

    source_path_role = str(metadata.get("source_path_role") or "").strip().lower()
    if not source_path_role:
        source_path_role = "rawsniffer"

    return source, source_path_role


def _raw_metadata_source_id(source, source_path_role):
    normalized_source = str(source or "").strip().lower()
    normalized_role = str(source_path_role or "").strip().lower()

    if normalized_source == "m5evil":
        if normalized_role == "master_sniffer":
            return "m5evil_master_raw_sniffing"
        return "m5evil_raw_sniffing"
    if normalized_source == "brucegotchi":
        return "bruce_raw_sniffing"
    return "rawsniffer"


def _merge_raw_metadata(
    data,
    *,
    bruce_pcap_dir,
    m5evil_dir,
    normalize_mac,
    logger,
):
    """
    Mescla metadados extraídos dos PCAPs RAW (Bruce / M5Evil / Master Sniffer)
    com os dados existentes.
    """
    metadata_files = []
    for metadata_dir in _raw_metadata_dirs(bruce_pcap_dir, m5evil_dir):
        metadata_files.extend(glob.glob(os.path.join(metadata_dir, "*.json")))

    for metadata_file in metadata_files:
        try:
            if os.path.basename(metadata_file).startswith("analysis__"):
                continue

            with open(metadata_file, "r", encoding="utf-8") as f:
                metadata = json.load(f)

            metadata_dir = os.path.dirname(metadata_file)
            source, source_path_role = _normalize_raw_metadata_source(
                metadata, metadata_dir, m5evil_dir
            )
            raw_source_id = _raw_metadata_source_id(source, source_path_role)
            networks = metadata.get("networks", [])
            for network in networks:
                bssid = normalize_mac(network.get("bssid"))
                if not bssid or bssid not in data:
                    continue

                item = data[bssid]

                channel = network.get("channel")
                frequency = network.get("frequency_mhz")
                if channel is not None and item.get("channel") is None:
                    item["channel"] = channel
                if frequency is not None and item.get("frequency") is None:
                    item["frequency"] = frequency

                beacon_count = int(network.get("beacon_count") or 0)
                eapol_count = int(network.get("eapol_count") or 0)
                probe_peak_count = int(network.get("probe_client_count") or 0)
                item["raw_beacon_count"] = max(
                    int(item.get("raw_beacon_count") or 0), beacon_count
                )
                item["raw_eapol_count"] = max(
                    int(item.get("raw_eapol_count") or 0), eapol_count
                )
                item["raw_probe_peak_count"] = max(
                    int(item.get("raw_probe_peak_count") or 0), probe_peak_count
                )

                if beacon_count > 0 or eapol_count > 0 or probe_peak_count > 0:
                    sources = list(item.get("sources") or [])
                    if raw_source_id not in sources:
                        sources.append(raw_source_id)
                    item["sources"] = sources

        except Exception as exc:
            logger.warning("Erro ao carregar metadados %s: %s", metadata_file, exc)
