import json
import os
import sys


def _load_app():
    backend_dir = os.path.dirname(os.path.dirname(__file__))
    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)
    from main import app  # noqa: E402

    return app


def main():
    if len(sys.argv) < 2:
        print("Usage: export_openapi.py <output_path>")
        sys.exit(1)

    output_path = sys.argv[1]
    app = _load_app()
    spec = app.openapi()

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    ext = os.path.splitext(output_path)[1].lower()
    with open(output_path, "w", encoding="utf-8") as f:
        if ext in {".yaml", ".yml"}:
            try:
                import yaml  # type: ignore
            except ModuleNotFoundError as exc:
                raise SystemExit(
                    "PyYAML is required to export YAML. Install it with: pip install pyyaml"
                ) from exc
            yaml.safe_dump(spec, f, sort_keys=False, allow_unicode=True)
        else:
            json.dump(spec, f, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    main()
