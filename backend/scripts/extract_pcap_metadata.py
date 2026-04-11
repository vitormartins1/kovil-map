#!/usr/bin/env python3
"""
Utility script to extract Bruce RawSniffer metadata from a PCAP using tshark.

By default, stdout contains only JSON output so this script can be piped/parsed.
Use --verbose for progress logs in stderr.
"""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Tuple

BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

from app.utils.rawsniffer_parser import parse_output  # noqa: E402


def build_tshark_command(tshark_bin: str, pcap_path: str) -> List[str]:
    fields = [
        "frame.time_epoch",
        "wlan.fc.type_subtype",
        "wlan.bssid",
        "wlan.sa",
        "wlan.da",
        "wlan.ssid",
        "wlan.ds.current_channel",
        "wlan_rsna_eapol.keydes.msgnr",
        "eapol.type",
    ]

    cmd = [
        tshark_bin,
        "-r",
        pcap_path,
        "-Y",
        "(wlan.fc.type_subtype==0x08) or (wlan.fc.type_subtype==0x04) or eapol",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
    ]
    for field in fields:
        cmd.extend(["-e", field])
    return cmd


def run_tshark(cmd: List[str]) -> Tuple[str, List[str], int]:
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    warnings: List[str] = []
    if stderr.strip():
        warnings.extend([line.strip() for line in stderr.splitlines() if line.strip()])

    if proc.returncode != 0 and stdout.strip():
        warnings.append(
            f"tshark exited with code {proc.returncode} but returned partial output"
        )

    return stdout, warnings, proc.returncode


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract metadata from Bruce RawSniffer PCAP files using tshark"
    )
    parser.add_argument("pcap_file", help="Path to raw_*.pcap")
    parser.add_argument("--tshark", default="tshark", help="Tshark binary path")
    parser.add_argument(
        "--output", "-o", default="", help="Optional output file. Defaults to stdout"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty print JSON output (indented)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print progress logs to stderr",
    )

    args = parser.parse_args()

    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists() or not pcap_path.is_file():
        print(
            json.dumps(
                {"status": "error", "message": f"PCAP file not found: {pcap_path}"}
            ),
            file=sys.stdout,
        )
        return 1

    tshark_bin = args.tshark
    if not Path(tshark_bin).is_absolute() and shutil.which(tshark_bin) is None:
        print(
            json.dumps(
                {"status": "error", "message": f"tshark not found: {tshark_bin}"}
            ),
            file=sys.stdout,
        )
        return 2

    cmd = build_tshark_command(tshark_bin, str(pcap_path))
    if args.verbose:
        print(f"Running: {' '.join(cmd)}", file=sys.stderr)

    stdout, warnings, return_code = run_tshark(cmd)
    if return_code != 0 and not stdout.strip():
        payload = {
            "status": "error",
            "message": "tshark failed without partial output",
            "warnings": warnings,
        }
    else:
        stat = pcap_path.stat()
        parsed = parse_output(stdout, warnings, pcap_path.name, stat)
        payload = {
            "status": "success",
            "cached": False,
            "data": parsed,
        }

    json_text = json.dumps(
        payload, indent=2 if args.pretty else None, ensure_ascii=False
    )

    if args.output:
        out_path = Path(args.output)
        out_path.write_text(json_text + "\n", encoding="utf-8")
        if args.verbose:
            print(f"Saved JSON to: {out_path}", file=sys.stderr)
    else:
        print(json_text)

    return 0 if payload.get("status") == "success" else 3


if __name__ == "__main__":
    raise SystemExit(main())
