import argparse
import json

from app.services.wardrive_regions_service import wardrive_regions_service


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate canonical WarDrive map packs"
    )
    parser.add_argument(
        "--pretty", action="store_true", help="Pretty-print JSON output"
    )
    args = parser.parse_args()

    payload = wardrive_regions_service.get_maps_inventory()
    if args.pretty:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
