import json
import re
import sys

VALID_PATH_RE = re.compile(r"^/[-a-zA-Z0-9_/{}/.]+$")


def load_spec(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def lint(spec: dict) -> list:
    warnings = []
    paths = spec.get("paths", {})
    for path in paths.keys():
        if not path.startswith("/"):
            warnings.append(f"Path should start with '/': {path}")
        if path != "/" and path.endswith("/"):
            warnings.append(f"Path should not have trailing slash: {path}")
        if any(ch.isupper() for ch in path):
            warnings.append(f"Path contains uppercase characters: {path}")
        if " " in path:
            warnings.append(f"Path contains spaces: {path}")
        if not VALID_PATH_RE.match(path):
            warnings.append(f"Path contains unusual characters: {path}")
    return warnings


def main():
    if len(sys.argv) < 2:
        print("Usage: openapi_lint.py <spec_path>")
        sys.exit(1)

    spec = load_spec(sys.argv[1])
    warnings = lint(spec)
    if warnings:
        print("OpenAPI lint warnings:")
        for item in warnings:
            print(f"- {item}")
    else:
        print("OpenAPI lint passed with no warnings.")


if __name__ == "__main__":
    main()
