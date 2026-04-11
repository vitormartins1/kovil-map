import json
import sys

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


def load_spec(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def collect_methods(spec: dict) -> dict:
    paths = spec.get("paths", {})
    result = {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        methods = {m for m in item.keys() if m.lower() in HTTP_METHODS}
        result[path] = {m.lower(): item[m] for m in methods}
    return result


def compare(base: dict, current: dict) -> list:
    breaking = []
    base_paths = collect_methods(base)
    current_paths = collect_methods(current)

    for path, base_methods in base_paths.items():
        if path not in current_paths:
            breaking.append(f"Removed path: {path}")
            continue
        current_methods = current_paths[path]
        for method, base_def in base_methods.items():
            if method not in current_methods:
                breaking.append(f"Removed method: {method.upper()} {path}")
                continue

            base_responses = (base_def or {}).get("responses", {}) or {}
            current_responses = (current_methods[method] or {}).get("responses", {}) or {}
            for status_code in base_responses.keys():
                if status_code not in current_responses:
                    breaking.append(
                        f"Removed response {status_code} from {method.upper()} {path}"
                    )

    return breaking


def main():
    if len(sys.argv) < 3:
        print("Usage: check_openapi_breaking.py <base_spec> <current_spec>")
        sys.exit(1)

    base = load_spec(sys.argv[1])
    current = load_spec(sys.argv[2])

    breaking = compare(base, current)
    if breaking:
        print("Breaking API changes detected:")
        for item in breaking:
            print(f"- {item}")
        sys.exit(1)

    print("No breaking API changes detected.")


if __name__ == "__main__":
    main()
