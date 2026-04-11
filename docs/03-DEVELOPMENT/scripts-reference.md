# Scripts and Utilities Reference

This page documents the current script layout and how the repository groups operational helpers.

## Docs Utilities

### `docs/scripts/check_docs_links.py`
Validates Markdown links inside `docs/`.

```bash
python3 docs/scripts/check_docs_links.py
```

## Backend Operational Scripts

The maintained backend CLI tools live in `backend/scripts/`.

### OpenAPI and contract helpers

- `backend/scripts/export_openapi.py`
- `backend/scripts/openapi_normalize.py`
- `backend/scripts/openapi_lint.py`
- `backend/scripts/check_openapi_breaking.py`

### Platform and install helpers

- `backend/scripts/install_tools.py`
- `backend/scripts/verify_install.py`
- `backend/scripts/check_wsl.py`
- `backend/scripts/setup_wsl.py`

### RAW and metadata helpers

- `backend/scripts/extract_pcap_metadata.py`

## Manual and Legacy Helpers

These scripts are kept under `backend/scripts/manual/` for ad-hoc debugging and historical hashcat experiments. They are not part of the maintained workflow.

- `backend/scripts/manual/debug_hashcat.py`
- `backend/scripts/manual/debug_job.py`
- `backend/scripts/manual/test_hashcat_command_builder.py`
- `backend/scripts/manual/test_hashcat_devices.py`
- `backend/scripts/manual/test_hashcat_dict_feedback.py`
- `backend/scripts/manual/test_hashcat_folder.py`
- `backend/scripts/manual/test_hashcat_folder_real.py`
- `backend/scripts/manual/test_hashcat_increment.py`
- `backend/scripts/manual/test_hashcat_parsing.py`

## Notes

- The repository no longer uses a root-level `scripts/` bucket for mixed concerns.
- If you need packaged builds or runtime features, use the backend/frontend workflows documented in the project READMEs instead of looking for a deprecated one-shot script.
