BRUCE_WEB_TEXT_TIMEOUT = 30


def _format_bytes(value):
    try:
        size = float(value or 0)
    except (TypeError, ValueError):
        return "0 B"
    units = ["B", "KB", "MB", "GB"]
    unit_index = 0
    while size >= 1024 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    return f"{size:.1f} {units[unit_index]}"


def _format_bruce_download_label(filename, downloaded_bytes, total_bytes, speed_bps):
    name = str(filename or "").strip() or "download"
    downloaded_label = _format_bytes(downloaded_bytes)
    total_label = _format_bytes(total_bytes) if total_bytes else "unknown size"
    if speed_bps:
        speed_label = f"{_format_bytes(speed_bps)}/s"
        return f"{name} [{downloaded_label} / {total_label} @ {speed_label}]"
    return f"{name} [{downloaded_label} / {total_label}]"


def _bruce_phase_details(
    *,
    connection_ok=False,
    auth_ok=False,
    sd_browser_ok=False,
    handshake_path_ok=False,
    rawsniffer_path_ok=False,
    wardrive_path_ok=False,
    failure_phase=None,
    url_used=None,
):
    return {
        "target": "bruce",
        "connection_ok": bool(connection_ok),
        "auth_ok": bool(auth_ok),
        "sd_browser_ok": bool(sd_browser_ok),
        "handshake_path_ok": bool(handshake_path_ok),
        "rawsniffer_path_ok": bool(rawsniffer_path_ok),
        "wardrive_path_ok": bool(wardrive_path_ok),
        "failure_phase": failure_phase,
        "url_used": str(url_used or "").strip(),
    }


def _looks_like_bruce_sd_browser_page(body):
    haystack = str(body or "").lower()
    return (
        (
            "bruce firmware" in haystack
            and "listfilesbutton('/', 'sd', true)" in haystack
        )
        or (
            "sd files" in haystack
            and "littlefs" in haystack
            and "actualfolder" in haystack
        )
        or ("sd files" in haystack and "listfilesbutton(" in haystack)
        or (
            "please select the storage you want to manage" in haystack
            and "listfilesbutton(" in haystack
        )
        or ("sd files" in haystack and "folder actions" in haystack)
        or ("downloaddeletebutton" in haystack and "littlefs" in haystack)
        or ("sd files" in haystack and "name" in haystack and "size" in haystack)
    )


def _looks_like_bruce_directory_listing_page(body):
    haystack = str(body or "").lower()
    return (
        "folder actions" in haystack
        or "downloaddeletebutton" in haystack
        or ("<table" in haystack and "listfilesbutton(" in haystack)
        or ("<table" in haystack and "gg-arrow-down-r" in haystack)
        or ("name" in haystack and "size" in haystack and "sd files" in haystack)
    )


def emit_bruce_progress(
    progress_callback,
    mode,
    processed,
    total,
    downloaded,
    failed,
    *,
    current_file="",
    stage="RUNNING",
):
    if not callable(progress_callback):
        return
    safe_total = max(int(total or 0), 0)
    safe_processed = max(int(processed or 0), 0)
    safe_downloaded = max(int(downloaded or 0), 0)
    safe_failed = max(int(failed or 0), 0)

    upper_stage = str(stage).upper()
    if safe_total <= 0:
        percentage = (
            100
            if upper_stage in {"UP TO DATE", "COMPLETED", "PARTIAL", "ERROR"}
            else 15
        )
    elif upper_stage in {"COMPLETED", "PARTIAL", "ERROR"}:
        percentage = 100
    else:
        percentage = min(95, max(10, round((safe_processed / safe_total) * 100)))

    progress_bits = []
    if safe_total > 0:
        progress_bits.append(f"{safe_downloaded}/{safe_total}")
    if safe_failed > 0:
        progress_bits.append(f"{safe_failed} failed")
    if current_file:
        progress_bits.append(current_file)
    extra = " | ".join(progress_bits)

    progress_callback(
        mode,
        {
            "percentage": percentage,
            "stage": stage,
            "extra": extra,
            "current_step": safe_processed,
            "total_steps": safe_total,
            "downloaded": safe_downloaded,
            "failed": safe_failed,
            "current_file": current_file,
        },
    )


def list_bruce_webui_directory(
    profile,
    remote_path,
    *,
    build_bruce_listfiles_url,
    fetch_web_text,
    parse_bruce_listfiles_payload,
    urllib_error_module,
):
    list_url = build_bruce_listfiles_url(profile, remote_path)
    try:
        page = fetch_web_text(
            list_url,
            username=profile.get("web_user"),
            password=profile.get("web_password"),
            timeout=BRUCE_WEB_TEXT_TIMEOUT,
        )
    except urllib_error_module.HTTPError as exc:
        if exc.code == 401:
            return {
                "status": "error",
                "code": "auth_failed",
                "message": "Bruce WebUI authentication failed (401 Unauthorized)",
                "url": list_url,
                "details": _bruce_phase_details(
                    connection_ok=True,
                    auth_ok=False,
                    failure_phase="auth",
                    url_used=list_url,
                ),
            }
        return {
            "status": "error",
            "code": "http_error",
            "message": f"Bruce WebUI returned HTTP {exc.code}",
            "url": list_url,
            "details": _bruce_phase_details(
                connection_ok=True,
                auth_ok=exc.code != 401,
                sd_browser_ok=True,
                failure_phase="path",
                url_used=list_url,
            ),
        }
    except urllib_error_module.URLError as exc:
        return {
            "status": "error",
            "code": "unreachable",
            "message": f"Failed to reach Bruce WebUI: {exc.reason}",
            "url": list_url,
            "details": _bruce_phase_details(
                connection_ok=False,
                auth_ok=False,
                failure_phase="connection",
                url_used=list_url,
            ),
        }
    except Exception as exc:
        return {
            "status": "error",
            "code": "path_open_failed",
            "message": f"Failed to list Bruce WebUI path: {exc}",
            "url": list_url,
            "details": _bruce_phase_details(
                connection_ok=False,
                auth_ok=False,
                failure_phase="path",
                url_used=list_url,
            ),
        }

    entries = parse_bruce_listfiles_payload(page.get("body") or "")
    if not entries and not _looks_like_bruce_directory_listing_page(
        page.get("body") or ""
    ):
        return {
            "status": "error",
            "code": "path_not_parseable",
            "message": "Bruce WebUI path returned no parseable file entries",
            "url": page.get("url") or list_url,
            "details": _bruce_phase_details(
                connection_ok=True,
                auth_ok=True,
                sd_browser_ok=True,
                failure_phase="path",
                url_used=page.get("url") or list_url,
            ),
        }
    return {
        "status": "success",
        "entries": entries,
        "url": page.get("url") or list_url,
        "details": _bruce_phase_details(
            connection_ok=True,
            auth_ok=True,
            sd_browser_ok=True,
            failure_phase=None,
            url_used=page.get("url") or list_url,
        ),
    }


def probe_bruce_webui(
    profile,
    *,
    handshake_remote_path,
    rawsniffer_remote_path,
    wardrive_remote_path,
    build_bruce_base_url,
    fetch_web_text,
    list_bruce_webui_directory_fn,
    urllib_parse_module,
    urllib_error_module,
):
    host = profile.get("host")
    if not host:
        return {
            "status": "error",
            "code": "host_missing",
            "message": "Bruce WebUI host missing",
        }
    if not str(profile.get("web_user") or "").strip():
        return {
            "status": "error",
            "code": "auth_missing",
            "message": "Bruce WebUI username missing",
        }

    base_url = build_bruce_base_url(profile)
    try:
        root_page = fetch_web_text(
            base_url,
            username=profile.get("web_user"),
            password=profile.get("web_password"),
            timeout=BRUCE_WEB_TEXT_TIMEOUT,
        )
    except Exception as exc:
        if isinstance(exc, urllib_error_module.HTTPError) and exc.code == 401:
            return {
                "status": "error",
                "code": "auth_failed",
                "message": "Bruce WebUI authentication failed (401 Unauthorized)",
                "details": _bruce_phase_details(
                    connection_ok=True,
                    auth_ok=False,
                    failure_phase="auth",
                    url_used=base_url,
                ),
            }
        return {
            "status": "error",
            "code": "unreachable",
            "message": f"Failed to reach Bruce WebUI: {exc}",
            "details": _bruce_phase_details(
                connection_ok=False,
                auth_ok=False,
                failure_phase="connection",
                url_used=base_url,
            ),
        }

    if not _looks_like_bruce_sd_browser_page(root_page.get("body") or ""):
        return {
            "status": "error",
            "code": "sd_browser_unavailable",
            "message": "Connected and authenticated, but the Bruce SD Files browser was not detected.",
            "details": _bruce_phase_details(
                connection_ok=True,
                auth_ok=True,
                sd_browser_ok=False,
                failure_phase="sd_browser",
                url_used=root_page.get("url") or base_url,
            ),
        }

    raw_listing = list_bruce_webui_directory_fn(profile, rawsniffer_remote_path)
    if raw_listing.get("status") != "success":
        listing_details = raw_listing.get("details") or {}
        return {
            "status": "error",
            "code": raw_listing.get("code"),
            "message": f"RAW sniffer path could not be opened: {raw_listing.get('message')}",
            "details": {
                **listing_details,
                "target": "bruce",
                "sd_browser_ok": True,
                "handshake_path_ok": True,
                "rawsniffer_path_ok": False,
            },
        }

    handshake_dir_name = (
        str(handshake_remote_path or "").strip().rstrip("/").split("/")[-1]
    )
    raw_entries = raw_listing.get("entries") or []
    handshake_listing_url = ""
    handshake_dir_visible = any(
        entry.get("type") == "dir"
        and (
            str(entry.get("raw_name") or "").strip().rstrip("/")
            == str(handshake_remote_path or "").strip().rstrip("/")
            or str(entry.get("filename") or "").strip() == handshake_dir_name
        )
        for entry in raw_entries
    )

    handshake_files_found = 0
    handshake_file_count_skipped = False
    if handshake_dir_visible:
        handshake_file_count_skipped = True
    else:
        handshake_listing = list_bruce_webui_directory_fn(
            profile, handshake_remote_path
        )
        if handshake_listing.get("status") != "success":
            listing_details = handshake_listing.get("details") or {}
            return {
                "status": "error",
                "code": handshake_listing.get("code"),
                "message": f"Handshake path could not be opened: {handshake_listing.get('message')}",
                "details": {
                    **listing_details,
                    "target": "bruce",
                    "sd_browser_ok": True,
                    "handshake_path_ok": False,
                    "rawsniffer_path_ok": True,
                },
            }
        handshake_listing_url = handshake_listing.get("url") or ""
        handshake_files_found = len(
            [
                entry["filename"]
                for entry in (handshake_listing.get("entries") or [])
                if entry.get("type") == "file"
                and str(entry.get("filename") or "").startswith("HS_")
                and str(entry.get("filename") or "").lower().endswith(".pcap")
            ]
        )

    rawsniffer_files = [
        entry["filename"]
        for entry in raw_entries
        if entry.get("type") == "file"
        and str(entry.get("filename") or "").lower().endswith(".pcap")
    ]
    wardrive_listing = list_bruce_webui_directory_fn(profile, wardrive_remote_path)
    wardrive_files = (
        [
            entry["filename"]
            for entry in (wardrive_listing.get("entries") or [])
            if entry.get("type") == "file"
            and str(entry.get("filename") or "").lower().endswith(".csv")
        ]
        if wardrive_listing.get("status") == "success"
        else []
    )
    return {
        "status": "success",
        "message": "Bruce WebUI connection successful",
        "details": {
            **_bruce_phase_details(
                connection_ok=True,
                auth_ok=True,
                sd_browser_ok=True,
                handshake_path_ok=True,
                rawsniffer_path_ok=True,
                wardrive_path_ok=wardrive_listing.get("status") == "success",
                failure_phase=None,
                url_used=wardrive_listing.get("url")
                or raw_listing.get("url")
                or handshake_listing_url
                or root_page.get("url")
                or base_url,
            ),
            "handshake_path_ok": True,
            "rawsniffer_path_ok": True,
            "probe_mode": "quick",
            "handshake_file_count_skipped": handshake_file_count_skipped,
            "handshake_files_found": handshake_files_found,
            "rawsniffer_files_found": len(rawsniffer_files),
            "wardrive_files_found": len(wardrive_files),
            "base_url": base_url,
        },
    }


def perform_bruce_sync(
    profile,
    *,
    force,
    progress_callback,
    handshake_remote_path,
    rawsniffer_remote_path,
    wardrive_remote_path,
    list_bruce_webui_directory_fn,
    emit_bruce_progress_fn,
    build_bruce_download_url,
    download_web_file,
    build_bruce_base_url,
    os_module,
    time_module,
):
    if not profile.get("enabled"):
        return {
            "status": "skipped",
            "message": "Bruce auto-sync disabled",
            "details": {
                "target": "bruce",
                "handshakes": [],
                "rawsniffer_pcaps": [],
                "wardrive_csvs": [],
                "errors": [],
                "sync_ms": 0,
            },
        }

    host = str(profile.get("host") or "").strip()
    if not host:
        return {
            "status": "error",
            "message": "Bruce WebUI host missing",
            "details": {"target": "bruce"},
        }

    downloaded_handshakes = []
    downloaded_rawsniffer = []
    downloaded_wardrive = []
    errors = []
    started_at = time_module.perf_counter()
    stats = {
        "handshakes": {
            "remote_files_found": 0,
            "files_to_download": 0,
            "downloaded": 0,
            "failed": 0,
        },
        "rawsniffer": {
            "remote_files_found": 0,
            "files_to_download": 0,
            "downloaded": 0,
            "failed": 0,
        },
        "wardrive": {
            "remote_files_found": 0,
            "files_to_download": 0,
            "downloaded": 0,
            "failed": 0,
        },
    }

    try:
        for remote_path, local_dir, collector, mode in (
            (
                handshake_remote_path,
                profile["local_handshakes_dir"],
                downloaded_handshakes,
                "handshakes",
            ),
            (
                rawsniffer_remote_path,
                profile["local_rawsniffer_dir"],
                downloaded_rawsniffer,
                "rawsniffer",
            ),
            (
                wardrive_remote_path,
                profile["local_wardrive_dir"],
                downloaded_wardrive,
                "wardrive",
            ),
        ):
            progress_mode = (
                "bruce_handshakes"
                if mode == "handshakes"
                else "bruce_rawsniffer" if mode == "rawsniffer" else "bruce_wardrive"
            )
            listing = list_bruce_webui_directory_fn(profile, remote_path)
            if listing.get("status") != "success":
                errors.append(
                    f"Failed to list {mode} in {remote_path}: {listing.get('message')}"
                )
                stats[mode]["failed"] += 1
                emit_bruce_progress_fn(
                    progress_callback,
                    progress_mode,
                    0,
                    0,
                    0,
                    stats[mode]["failed"],
                    current_file=str(listing.get("message") or "listing_failed"),
                    stage="ERROR",
                )
                continue

            candidate_entries = []
            for entry in listing.get("entries") or []:
                if entry.get("type") != "file":
                    continue
                filename = str(entry.get("filename") or "").strip()
                if mode == "handshakes":
                    if not (
                        filename.startswith("HS_")
                        and filename.lower().endswith(".pcap")
                    ):
                        continue
                elif mode == "rawsniffer":
                    if not filename.lower().endswith(".pcap"):
                        continue
                else:
                    if not filename.lower().endswith(".csv"):
                        continue

                local_file = os_module.path.join(local_dir, filename)
                if not force and os_module.path.exists(local_file):
                    continue
                candidate_entries.append(
                    {**entry, "filename": filename, "local_file": local_file}
                )

            stats[mode]["remote_files_found"] = len(
                [
                    entry
                    for entry in (listing.get("entries") or [])
                    if entry.get("type") == "file"
                    and (
                        (
                            mode == "handshakes"
                            and str(entry.get("filename") or "").startswith("HS_")
                            and str(entry.get("filename") or "")
                            .lower()
                            .endswith(".pcap")
                        )
                        or (
                            mode == "rawsniffer"
                            and str(entry.get("filename") or "")
                            .lower()
                            .endswith(".pcap")
                        )
                        or (
                            mode == "wardrive"
                            and str(entry.get("filename") or "")
                            .lower()
                            .endswith(".csv")
                        )
                    )
                ]
            )
            stats[mode]["files_to_download"] = len(candidate_entries)
            emit_bruce_progress_fn(
                progress_callback,
                progress_mode,
                0,
                len(candidate_entries),
                stats[mode]["downloaded"],
                stats[mode]["failed"],
                current_file="Preparing download queue",
                stage="RUNNING" if candidate_entries else "UP TO DATE",
            )

            processed_count = 0
            for entry in candidate_entries:
                filename = str(entry.get("filename") or "").strip()
                try:
                    download_url = build_bruce_download_url(
                        profile, remote_path, filename
                    )
                    emit_bruce_progress_fn(
                        progress_callback,
                        progress_mode,
                        processed_count,
                        len(candidate_entries),
                        stats[mode]["downloaded"],
                        stats[mode]["failed"],
                        current_file=f"Starting {filename}",
                        stage="RUNNING",
                    )
                    download_web_file(
                        download_url,
                        entry["local_file"],
                        username=profile.get("web_user"),
                        password=profile.get("web_password"),
                        progress_hook=lambda downloaded_bytes, total_bytes, speed_bps, done, _filename=filename: emit_bruce_progress_fn(
                            progress_callback,
                            progress_mode,
                            processed_count,
                            len(candidate_entries),
                            stats[mode]["downloaded"],
                            stats[mode]["failed"],
                            current_file=_format_bruce_download_label(
                                _filename,
                                (
                                    downloaded_bytes
                                    if not done
                                    else (total_bytes or downloaded_bytes)
                                ),
                                total_bytes,
                                speed_bps,
                            ),
                            stage="RUNNING",
                        ),
                    )
                    collector.append(filename)
                    stats[mode]["downloaded"] += 1
                except Exception as exc:
                    stats[mode]["failed"] += 1
                    errors.append(f"Failed to download {filename}: {exc}")
                finally:
                    processed_count += 1
                    emit_bruce_progress_fn(
                        progress_callback,
                        progress_mode,
                        processed_count,
                        len(candidate_entries),
                        stats[mode]["downloaded"],
                        stats[mode]["failed"],
                        current_file=filename,
                        stage="RUNNING",
                    )

            mode_total = stats[mode]["files_to_download"]
            mode_downloaded = stats[mode]["downloaded"]
            mode_failed = stats[mode]["failed"]
            if mode_total <= 0 and mode_failed > 0:
                final_stage = "ERROR"
                final_file = "Listing failed"
            elif mode_total <= 0:
                final_stage = "UP TO DATE"
                final_file = "No new files"
            elif mode_failed > 0:
                final_stage = "PARTIAL"
                final_file = ""
            else:
                final_stage = "COMPLETED"
                final_file = ""
            emit_bruce_progress_fn(
                progress_callback,
                progress_mode,
                mode_total,
                mode_total,
                mode_downloaded,
                mode_failed,
                current_file=final_file,
                stage=final_stage,
            )

        status = "partial" if errors else "success"
        message = (
            "Bruce WebUI sync completed with errors"
            if errors
            else "Bruce WebUI sync completed"
        )
        if (
            not downloaded_handshakes
            and not downloaded_rawsniffer
            and not downloaded_wardrive
            and errors
        ):
            status = "error"

        for mode in ("handshakes", "rawsniffer", "wardrive"):
            mode_total = stats[mode]["files_to_download"]
            mode_downloaded = stats[mode]["downloaded"]
            mode_failed = stats[mode]["failed"]
            progress_mode = (
                "bruce_handshakes"
                if mode == "handshakes"
                else "bruce_rawsniffer" if mode == "rawsniffer" else "bruce_wardrive"
            )
            if mode_total <= 0 and mode_failed > 0:
                stage = "ERROR"
                current_file = "Listing failed"
            elif mode_total <= 0:
                stage = "UP TO DATE"
                current_file = "No new files"
            elif mode_failed > 0:
                stage = "PARTIAL"
                current_file = ""
            else:
                stage = "COMPLETED"
                current_file = ""
            emit_bruce_progress_fn(
                progress_callback,
                progress_mode,
                mode_total,
                mode_total,
                mode_downloaded,
                mode_failed,
                current_file=current_file,
                stage=stage,
            )

        return {
            "status": status,
            "message": message,
            "details": {
                "target": "bruce",
                "handshakes": downloaded_handshakes,
                "rawsniffer_pcaps": downloaded_rawsniffer,
                "wardrive_csvs": downloaded_wardrive,
                "errors": errors,
                "handshake_remote_files_found": stats["handshakes"][
                    "remote_files_found"
                ],
                "handshake_files_to_download": stats["handshakes"]["files_to_download"],
                "handshake_files_failed": stats["handshakes"]["failed"],
                "rawsniffer_remote_files_found": stats["rawsniffer"][
                    "remote_files_found"
                ],
                "rawsniffer_files_to_download": stats["rawsniffer"][
                    "files_to_download"
                ],
                "rawsniffer_files_failed": stats["rawsniffer"]["failed"],
                "wardrive_remote_files_found": stats["wardrive"]["remote_files_found"],
                "wardrive_files_to_download": stats["wardrive"]["files_to_download"],
                "wardrive_files_failed": stats["wardrive"]["failed"],
                "connection_ok": True,
                "auth_ok": True,
                "handshake_path_ok": True,
                "rawsniffer_path_ok": True,
                "wardrive_path_ok": True,
                "failure_phase": None,
                "url_used": build_bruce_base_url(profile),
                "sync_ms": round((time_module.perf_counter() - started_at) * 1000, 2),
            },
        }
    except Exception as exc:
        for mode in ("handshakes", "rawsniffer", "wardrive"):
            progress_mode = (
                "bruce_handshakes"
                if mode == "handshakes"
                else "bruce_rawsniffer" if mode == "rawsniffer" else "bruce_wardrive"
            )
            emit_bruce_progress_fn(
                progress_callback,
                progress_mode,
                stats[mode]["downloaded"] + stats[mode]["failed"],
                stats[mode]["files_to_download"],
                stats[mode]["downloaded"],
                stats[mode]["failed"],
                stage="ERROR",
            )
        return {
            "status": "error",
            "message": str(exc),
            "details": {
                "target": "bruce",
                "connection_ok": False,
                "auth_ok": False,
                "handshake_path_ok": False,
                "rawsniffer_path_ok": False,
                "failure_phase": "connection",
            },
        }
