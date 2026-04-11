import json
import sys


def load_spec(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize(spec: dict) -> dict:
    # Keep schemas resolvable but remove volatile ValidationError fields that
    # can change across FastAPI/Pydantic versions without affecting API
    # contract compatibility for our endpoints.
    components = spec.get("components") or {}
    schemas = components.get("schemas") or {}

    validation_error = schemas.get("ValidationError")
    if isinstance(validation_error, dict):
        props = validation_error.get("properties")
        if isinstance(props, dict):
            props.pop("input", None)
            props.pop("ctx", None)
        required = validation_error.get("required")
        if isinstance(required, list):
            validation_error["required"] = [
                item for item in required if item not in {"input", "ctx"}
            ]

    return spec


def main():
    if len(sys.argv) < 3:
        print("Usage: openapi_normalize.py <input> <output>")
        sys.exit(1)

    spec = load_spec(sys.argv[1])
    spec = normalize(spec)
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(spec, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
