def m5evil_phase_details(
    profile,
    *,
    build_m5evil_base_url,
    connection_ok=False,
    auth_ok=False,
    browse_root_ok=False,
    handshake_path_ok=False,
    rawsniffer_path_ok=False,
    wardrive_path_ok=False,
    failure_phase=None,
    url_used=None,
):
    return {
        "target": profile.get("target", "m5evil"),
        "reachable": bool(connection_ok),
        "connection_ok": bool(connection_ok),
        "auth_ok": bool(auth_ok),
        "browse_ok": bool(browse_root_ok),
        "browse_root_ok": bool(browse_root_ok),
        "handshake_path_ok": bool(handshake_path_ok),
        "rawsniffer_path_ok": bool(rawsniffer_path_ok),
        "wardrive_path_ok": bool(wardrive_path_ok),
        "failure_phase": failure_phase,
        "url_used": str(url_used or "").strip() or build_m5evil_base_url(profile),
    }


def emit_m5evil_progress(
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
        percentage = 100 if upper_stage in {"UP TO DATE", "COMPLETED", "PARTIAL", "ERROR"} else 15
    elif upper_stage in {"COMPLETED", "PARTIAL", "ERROR"}:
        percentage = 100
    else:
        percentage = min(95, max(10, round((safe_processed / safe_total) * 100)))

    if mode == "handshakes":
        label = "handshake file(s)"
    elif mode == "rawsniffer":
        label = "RAW sniffer file(s)"
    elif mode == "mastersniffer":
        label = "Master Sniffer file(s)"
    else:
        label = "Wardrive CSV file(s)"
    progress_bits = [f"{safe_downloaded}/{safe_total} imported"]
    if safe_failed > 0:
        progress_bits.append(f"{safe_failed} failed")
    extra = f"{' | '.join(progress_bits)} {label}"
    if current_file:
        extra = f"{extra} | {current_file}"

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


def find_m5evil_browse_root(
    profile,
    *,
    build_m5evil_base_url,
    fetch_web_text,
    list_links,
    looks_like_m5evil_browse_link,
    m5evil_phase_details_fn,
    urllib_parse_module,
    urllib_error_module,
):
    base_url = build_m5evil_base_url(profile)
    try:
        page = fetch_web_text(
            base_url,
            username=profile.get("web_user"),
            password=profile.get("web_password"),
        )
    except urllib_error_module.HTTPError as exc:
        if exc.code == 401:
            return {
                "status": "error",
                "code": "auth_failed",
                "message": "Admin WebUI authentication failed (401 Unauthorized)",
                "url": base_url,
                "details": m5evil_phase_details_fn(
                    profile,
                    connection_ok=True,
                    auth_ok=False,
                    browse_root_ok=False,
                    failure_phase="auth",
                    url_used=base_url,
                ),
            }
        return {
            "status": "error",
            "code": "http_error",
            "message": f"Admin WebUI returned HTTP {exc.code}",
            "url": base_url,
            "details": m5evil_phase_details_fn(
                profile,
                connection_ok=True,
                auth_ok=exc.code != 401,
                browse_root_ok=False,
                failure_phase="connection",
                url_used=base_url,
            ),
        }
    except urllib_error_module.URLError as exc:
        return {
            "status": "error",
            "code": "unreachable",
            "message": f"Failed to reach Admin WebUI: {exc.reason}",
            "url": base_url,
            "details": m5evil_phase_details_fn(
                profile,
                connection_ok=False,
                auth_ok=False,
                browse_root_ok=False,
                failure_phase="connection",
                url_used=base_url,
            ),
        }
    except Exception as exc:
        return {
            "status": "error",
            "code": "endpoint_unavailable",
            "message": f"Failed to open Admin WebUI: {exc}",
            "url": base_url,
            "details": m5evil_phase_details_fn(
                profile,
                connection_ok=False,
                auth_ok=False,
                browse_root_ok=False,
                failure_phase="connection",
                url_used=base_url,
            ),
        }

    links = list_links(page["body"])
    browse_url = page["url"]
    for link in links:
        href = str(link.get("href") or "").strip()
        text = str(link.get("text") or "").strip()
        if not href:
            continue
        if looks_like_m5evil_browse_link(href, text):
            browse_url = urllib_parse_module.urljoin(page["url"], href)
            break

    if browse_url == page["url"] and links:
        return {
            "status": "success",
            "page": page,
            "details": m5evil_phase_details_fn(
                profile,
                connection_ok=True,
                auth_ok=True,
                browse_root_ok=True,
                failure_phase=None,
                url_used=page["url"],
            ),
        }

    try:
        browse_page = fetch_web_text(
            browse_url,
            username=profile.get("web_user"),
            password=profile.get("web_password"),
        )
    except urllib_error_module.HTTPError as exc:
        if exc.code == 401:
            return {
                "status": "error",
                "code": "auth_failed",
                "message": "Admin WebUI authentication failed (401 Unauthorized)",
                "url": browse_url,
                "details": m5evil_phase_details_fn(
                    profile,
                    connection_ok=True,
                    auth_ok=False,
                    browse_root_ok=False,
                    failure_phase="auth",
                    url_used=browse_url,
                ),
            }
        return {
            "status": "error",
            "code": "browse_unavailable",
            "message": f"Admin WebUI browse page returned HTTP {exc.code}",
            "url": browse_url,
            "details": m5evil_phase_details_fn(
                profile,
                connection_ok=True,
                auth_ok=exc.code != 401,
                browse_root_ok=False,
                failure_phase="browse_root",
                url_used=browse_url,
            ),
        }
    except urllib_error_module.URLError as exc:
        return {
            "status": "error",
            "code": "browse_unreachable",
            "message": f"Failed to open Admin WebUI browse page: {exc.reason}",
            "url": browse_url,
            "details": m5evil_phase_details_fn(
                profile,
                connection_ok=True,
                auth_ok=True,
                browse_root_ok=False,
                failure_phase="browse_root",
                url_used=browse_url,
            ),
        }
    except Exception as exc:
        return {
            "status": "error",
            "code": "browse_unavailable",
            "message": f"Failed to open Admin WebUI browse page: {exc}",
            "url": browse_url,
            "details": m5evil_phase_details_fn(
                profile,
                connection_ok=True,
                auth_ok=True,
                browse_root_ok=False,
                failure_phase="browse_root",
                url_used=browse_url,
            ),
        }

    if not list_links(browse_page["body"]):
        return {
            "status": "error",
            "code": "browse_not_parseable",
            "message": "Connected and authenticated, but the current firmware Browse SD page could not be parsed",
            "url": browse_page["url"],
            "details": m5evil_phase_details_fn(
                profile,
                connection_ok=True,
                auth_ok=True,
                browse_root_ok=False,
                failure_phase="browse_root",
                url_used=browse_page["url"],
            ),
        }
    return {
        "status": "success",
        "page": browse_page,
        "details": m5evil_phase_details_fn(
            profile,
            connection_ok=True,
            auth_ok=True,
            browse_root_ok=True,
            failure_phase=None,
            url_used=browse_page["url"],
        ),
    }


def navigate_m5evil_directory(
    profile,
    remote_path,
    *,
    find_m5evil_browse_root_fn,
    m5evil_phase_details_fn,
    normalize_m5evil_remote_path,
    list_links,
    link_name_tokens,
    fetch_web_text,
    urllib_parse_module,
    urllib_error_module,
):
    root = find_m5evil_browse_root_fn(profile)
    if root.get("status") != "success":
        return root

    current_page = root["page"]
    current_details = root.get("details") or m5evil_phase_details_fn(
        profile,
        connection_ok=True,
        auth_ok=True,
        browse_root_ok=True,
        failure_phase=None,
        url_used=current_page["url"],
    )
    segments = [
        segment for segment in normalize_m5evil_remote_path(remote_path).split("/") if segment
    ]
    traversed = []
    for segment in segments:
        links = list_links(current_page["body"])
        selected_href = None
        for link in links:
            href = str(link.get("href") or "").strip()
            if not href or href.startswith("#"):
                continue
            tokens = link_name_tokens(href, link.get("text"))
            if segment.lower() in tokens:
                selected_href = href
                break
        if not selected_href:
            return {
                "status": "error",
                "code": "path_not_found",
                "message": f"Configured SD path not found: {'/'.join(traversed + [segment])}",
                "url": current_page["url"],
                "details": {
                    **current_details,
                    "failure_phase": "path",
                    "url_used": current_page["url"],
                },
            }
        traversed.append(segment)
        next_url = urllib_parse_module.urljoin(current_page["url"], selected_href)
        try:
            current_page = fetch_web_text(
                next_url,
                username=profile.get("web_user"),
                password=profile.get("web_password"),
            )
        except urllib_error_module.HTTPError as exc:
            if exc.code == 401:
                return {
                    "status": "error",
                    "code": "auth_failed",
                    "message": "Admin WebUI authentication failed (401 Unauthorized)",
                    "url": next_url,
                    "details": {
                        **current_details,
                        "auth_ok": False,
                        "failure_phase": "auth",
                        "url_used": next_url,
                    },
                }
            return {
                "status": "error",
                "code": "path_open_failed",
                "message": f"Failed to open SD path {'/'.join(traversed)}: HTTP {exc.code}",
                "url": next_url,
                "details": {
                    **current_details,
                    "failure_phase": "path",
                    "url_used": next_url,
                },
            }
        except Exception as exc:
            return {
                "status": "error",
                "code": "path_open_failed",
                "message": f"Failed to open SD path {'/'.join(traversed)}: {exc}",
                "url": next_url,
                "details": {
                    **current_details,
                    "failure_phase": "path",
                    "url_used": next_url,
                },
            }
    return {
        "status": "success",
        "page": current_page,
        "details": {**current_details, "url_used": current_page["url"]},
    }


def list_m5evil_admin_directory(
    profile,
    remote_path,
    *,
    build_m5evil_direct_dir_url,
    fetch_web_text,
    list_links,
    extract_listing_filename,
    m5evil_phase_details_fn,
    navigate_m5evil_directory_fn,
    urllib_parse_module,
    urllib_error_module,
):
    direct_url = build_m5evil_direct_dir_url(profile, remote_path)
    try:
        direct_page = fetch_web_text(
            direct_url,
            username=profile.get("web_user"),
            password=profile.get("web_password"),
        )
        direct_entries = []
        for item in list_links(direct_page["body"]):
            href = str(item.get("href") or "").strip()
            if not href or href.startswith("#"):
                continue
            filename = extract_listing_filename(href, item.get("text"))
            if not filename or filename in {".", ".."}:
                continue
            direct_entries.append(
                {
                    "filename": filename,
                    "url": urllib_parse_module.urljoin(direct_page["url"], href),
                    "text": str(item.get("text") or "").strip(),
                }
            )
        if direct_entries:
            return {
                "status": "success",
                "entries": direct_entries,
                "url": direct_page["url"],
                "details": m5evil_phase_details_fn(
                    profile,
                    connection_ok=True,
                    auth_ok=True,
                    browse_root_ok=True,
                    failure_phase=None,
                    url_used=direct_page["url"],
                ),
            }
    except urllib_error_module.HTTPError as exc:
        if exc.code == 401:
            return {
                "status": "error",
                "code": "auth_failed",
                "message": "Admin WebUI authentication failed (401 Unauthorized)",
                "url": direct_url,
                "details": m5evil_phase_details_fn(
                    profile,
                    connection_ok=True,
                    auth_ok=False,
                    browse_root_ok=False,
                    failure_phase="auth",
                    url_used=direct_url,
                ),
            }
    except urllib_error_module.URLError:
        pass
    except Exception:
        pass

    navigation = navigate_m5evil_directory_fn(profile, remote_path)
    if navigation.get("status") != "success":
        return navigation

    current_page = navigation["page"]
    entries = []
    for item in list_links(current_page["body"]):
        href = str(item.get("href") or "").strip()
        if not href or href.startswith("#"):
            continue
        filename = extract_listing_filename(href, item.get("text"))
        if not filename or filename in {".", ".."}:
            continue
        entries.append(
            {
                "filename": filename,
                "url": urllib_parse_module.urljoin(current_page["url"], href),
                "text": str(item.get("text") or "").strip(),
            }
        )
    if not entries:
        return {
            "status": "error",
            "code": "browse_not_parseable",
            "message": "Admin WebUI directory page was parsed, but no files or folders were found",
            "url": current_page["url"],
            "details": {
                **(navigation.get("details") or {}),
                "failure_phase": "path",
                "url_used": current_page["url"],
            },
        }
    return {
        "status": "success",
        "entries": entries,
        "url": current_page["url"],
        "details": {
            **(navigation.get("details") or {}),
            "failure_phase": None,
            "url_used": current_page["url"],
        },
    }


def find_m5evil_download_url(
    profile,
    file_entry,
    *,
    build_m5evil_base_url,
    fetch_web_binary,
    m5evil_phase_details_fn,
    looks_like_html,
    list_links,
    link_name_tokens,
    urllib_parse_module,
    urllib_error_module,
):
    file_url = str(file_entry.get("url") or "").strip()
    filename = str(file_entry.get("filename") or "").strip()
    if not file_url:
        return {
            "status": "error",
            "code": "download_missing",
            "message": f"No Admin WebUI URL available for {filename}",
            "details": m5evil_phase_details_fn(
                profile,
                connection_ok=True,
                auth_ok=True,
                browse_root_ok=True,
                failure_phase="download",
                url_used=file_url or build_m5evil_base_url(profile),
            ),
        }
    try:
        fetched = fetch_web_binary(
            file_url,
            username=profile.get("web_user"),
            password=profile.get("web_password"),
        )
    except urllib_error_module.HTTPError as exc:
        if exc.code == 401:
            return {
                "status": "error",
                "code": "auth_failed",
                "message": "Admin WebUI authentication failed (401 Unauthorized)",
                "url": file_url,
                "details": m5evil_phase_details_fn(
                    profile,
                    connection_ok=True,
                    auth_ok=False,
                    browse_root_ok=True,
                    failure_phase="auth",
                    url_used=file_url,
                ),
            }
        return {
            "status": "error",
            "code": "download_failed",
            "message": f"Download page returned HTTP {exc.code} for {filename}",
            "url": file_url,
            "details": m5evil_phase_details_fn(
                profile,
                connection_ok=True,
                auth_ok=exc.code != 401,
                browse_root_ok=True,
                failure_phase="download",
                url_used=file_url,
            ),
        }
    except urllib_error_module.URLError as exc:
        return {
            "status": "error",
            "code": "download_failed",
            "message": f"Failed to reach download URL for {filename}: {exc.reason}",
            "url": file_url,
            "details": m5evil_phase_details_fn(
                profile,
                connection_ok=True,
                auth_ok=True,
                browse_root_ok=True,
                failure_phase="download",
                url_used=file_url,
            ),
        }
    except Exception as exc:
        return {
            "status": "error",
            "code": "download_failed",
            "message": f"Failed to inspect download URL for {filename}: {exc}",
            "url": file_url,
            "details": m5evil_phase_details_fn(
                profile,
                connection_ok=True,
                auth_ok=True,
                browse_root_ok=True,
                failure_phase="download",
                url_used=file_url,
            ),
        }

    if not looks_like_html(fetched.get("payload") or b"", fetched.get("content_type") or ""):
        return {"status": "success", "download_url": file_url}

    page = (fetched.get("payload") or b"").decode("utf-8", errors="replace")
    for link in list_links(page):
        href = str(link.get("href") or "").strip()
        if not href:
            continue
        haystack = f"{href} {link.get('text') or ''}".lower()
        if "download" not in haystack:
            continue
        tokens = link_name_tokens(href, link.get("text"))
        if not tokens or filename.lower() in tokens:
            return {
                "status": "success",
                "download_url": urllib_parse_module.urljoin(fetched.get("url") or file_url, href),
            }
    return {
        "status": "error",
        "code": "download_not_parseable",
        "message": f"Admin WebUI did not expose a downloadable link for {filename}",
        "url": fetched.get("url") or file_url,
        "details": m5evil_phase_details_fn(
            profile,
            connection_ok=True,
            auth_ok=True,
            browse_root_ok=True,
            failure_phase="download",
            url_used=fetched.get("url") or file_url,
        ),
    }


def probe_m5evil_admin_webui(
    profile,
    *,
    rawsniffer_default_path,
    list_m5evil_admin_directory_fn,
    build_m5evil_base_url,
):
    host = profile["host"]
    handshake_remote_path = str(profile["handshake_path"] or "").strip()
    wardrive_remote_path = str(profile["wardrive_path"] or "").strip()
    rawsniffer_remote_path = str(profile.get("rawsniffer_path") or rawsniffer_default_path).strip()
    if not host:
        return {
            "status": "error",
            "code": "host_missing",
            "message": "M5Evil Admin WebUI host missing",
        }
    if not handshake_remote_path or not wardrive_remote_path or not rawsniffer_remote_path:
        return {
            "status": "error",
            "code": "paths_missing",
            "message": "M5Evil Admin WebUI SD paths missing",
        }
    if not str(profile.get("web_user") or "").strip():
        return {
            "status": "error",
            "code": "auth_missing",
            "message": "M5Evil Admin WebUI username missing",
        }

    handshake_listing = list_m5evil_admin_directory_fn(profile, handshake_remote_path)
    if handshake_listing.get("status") != "success":
        listing_details = handshake_listing.get("details") or {}
        return {
            "status": "error",
            "code": handshake_listing.get("code"),
            "message": f"Handshake SD path could not be opened: {handshake_listing.get('message')}",
            "details": {
                **listing_details,
                "target": profile["target"],
                "handshake_path_ok": False,
                "rawsniffer_path_ok": False,
                "wardrive_path_ok": False,
            },
        }

    rawsniffer_listing = list_m5evil_admin_directory_fn(profile, rawsniffer_remote_path)
    if rawsniffer_listing.get("status") != "success":
        listing_details = rawsniffer_listing.get("details") or {}
        return {
            "status": "error",
            "code": rawsniffer_listing.get("code"),
            "message": f"RAW sniffer SD path could not be opened: {rawsniffer_listing.get('message')}",
            "details": {
                **listing_details,
                "target": profile["target"],
                "handshake_path_ok": True,
                "rawsniffer_path_ok": False,
                "wardrive_path_ok": False,
            },
        }

    wardrive_listing = list_m5evil_admin_directory_fn(profile, wardrive_remote_path)
    if wardrive_listing.get("status") != "success":
        listing_details = wardrive_listing.get("details") or {}
        return {
            "status": "error",
            "code": wardrive_listing.get("code"),
            "message": f"Wardrive SD path could not be opened: {wardrive_listing.get('message')}",
            "details": {
                **listing_details,
                "target": profile["target"],
                "handshake_path_ok": True,
                "rawsniffer_path_ok": True,
                "wardrive_path_ok": False,
            },
        }

    handshake_files = [
        entry["filename"]
        for entry in (handshake_listing.get("entries") or [])
        if str(entry.get("filename") or "").startswith("HS_")
        and str(entry.get("filename") or "").lower().endswith(".pcap")
    ]
    mastersniffer_files = [
        entry["filename"]
        for entry in (handshake_listing.get("entries") or [])
        if str(entry.get("filename") or "").lower().startswith("mastersniffer_")
        and str(entry.get("filename") or "").lower().endswith(".pcap")
    ]
    rawsniffer_files = [
        entry["filename"]
        for entry in (rawsniffer_listing.get("entries") or [])
        if str(entry.get("filename") or "").lower().startswith("rawsniff_")
        and str(entry.get("filename") or "").lower().endswith(".pcap")
    ]
    wardrive_files = [
        entry["filename"]
        for entry in (wardrive_listing.get("entries") or [])
        if str(entry.get("filename") or "").lower().endswith(".csv")
    ]
    return {
        "status": "success",
        "message": "M5Evil Admin WebUI connection successful",
        "details": {
            "target": profile["target"],
            "reachable": True,
            "connection_ok": True,
            "auth_ok": True,
            "browse_ok": True,
            "browse_root_ok": True,
            "handshake_path_ok": True,
            "rawsniffer_path_ok": True,
            "wardrive_path_ok": True,
            "failure_phase": None,
            "handshake_files_found": len(handshake_files),
            "mastersniffer_files_found": len(mastersniffer_files),
            "rawsniffer_files_found": len(rawsniffer_files),
            "wardrive_files_found": len(wardrive_files),
            "base_url": build_m5evil_base_url(profile),
            "url_used": (
                wardrive_listing.get("url")
                or rawsniffer_listing.get("url")
                or handshake_listing.get("url")
                or build_m5evil_base_url(profile)
            ),
        },
    }


def perform_m5evil_sync(
    profile,
    *,
    rawsniffer_default_path,
    force,
    progress_callback,
    m5evil_phase_details_fn,
    list_m5evil_admin_directory_fn,
    emit_m5evil_progress_fn,
    find_m5evil_download_url_fn,
    download_web_file,
    build_m5evil_base_url,
    os_module,
    time_module,
):
    if not profile["enabled"]:
        return {
            "status": "skipped",
            "message": "M5Evil auto-sync disabled",
            "details": {
                "target": profile["target"],
                "handshakes": [],
                "rawsniffer_pcaps": [],
                "mastersniffer_pcaps": [],
                "wardrive_csvs": [],
                "errors": [],
                "sync_ms": 0,
            },
        }

    host = profile["host"]
    handshake_remote_path = str(profile["handshake_path"] or "").strip()
    wardrive_remote_path = str(profile["wardrive_path"] or "").strip()
    rawsniffer_remote_path = str(profile.get("rawsniffer_path") or rawsniffer_default_path).strip()
    if not host:
        return {
            "status": "error",
            "message": "M5Evil Admin WebUI host missing",
            "details": {
                **m5evil_phase_details_fn(
                    profile,
                    connection_ok=False,
                    auth_ok=False,
                    browse_root_ok=False,
                    failure_phase="connection",
                ),
                "target": profile["target"],
            },
        }
    if not handshake_remote_path or not wardrive_remote_path or not rawsniffer_remote_path:
        return {
            "status": "error",
            "message": "M5Evil Admin WebUI SD paths missing",
            "details": {
                **m5evil_phase_details_fn(
                    profile,
                    connection_ok=False,
                    auth_ok=False,
                    browse_root_ok=False,
                    failure_phase="path",
                ),
                "target": profile["target"],
            },
        }

    downloaded_handshakes = []
    downloaded_rawsniffer = []
    downloaded_mastersniffer = []
    downloaded_wardrive = []
    errors = []
    had_listing_success = False
    last_failure_details = None
    started_at = time_module.perf_counter()
    stats = {
        "handshakes": {"remote_files_found": 0, "files_to_download": 0, "downloaded": 0, "failed": 0},
        "rawsniffer": {"remote_files_found": 0, "files_to_download": 0, "downloaded": 0, "failed": 0},
        "mastersniffer": {"remote_files_found": 0, "files_to_download": 0, "downloaded": 0, "failed": 0},
        "wardrive": {"remote_files_found": 0, "files_to_download": 0, "downloaded": 0, "failed": 0},
    }

    try:
        for remote_path, local_dir, collector, mode in (
            (handshake_remote_path, profile["local_handshakes_dir"], downloaded_handshakes, "handshakes"),
            (handshake_remote_path, profile["local_mastersniffer_dir"], downloaded_mastersniffer, "mastersniffer"),
            (rawsniffer_remote_path, profile["local_rawsniffer_dir"], downloaded_rawsniffer, "rawsniffer"),
            (wardrive_remote_path, profile["local_wardrive_dir"], downloaded_wardrive, "wardrive"),
        ):
            listing = list_m5evil_admin_directory_fn(profile, remote_path)
            if listing.get("status") != "success":
                errors.append(f"Failed to list {mode} in {remote_path}: {listing.get('message')}")
                last_failure_details = listing.get("details") or last_failure_details
                continue
            had_listing_success = True

            candidate_entries = []
            for entry in listing.get("entries") or []:
                filename = str(entry.get("filename") or "").strip()
                if mode == "handshakes":
                    if not (filename.startswith("HS_") and filename.lower().endswith(".pcap")):
                        continue
                    local_name = filename
                elif mode == "mastersniffer":
                    if not (filename.lower().startswith("mastersniffer_") and filename.lower().endswith(".pcap")):
                        continue
                    local_name = filename
                elif mode == "rawsniffer":
                    if not (filename.lower().startswith("rawsniff_") and filename.lower().endswith(".pcap")):
                        continue
                    local_name = filename
                else:
                    if not filename.lower().endswith(".csv"):
                        continue
                    local_name = f"m5evil__{filename}"

                local_file = os_module.path.join(local_dir, local_name)
                should_download = force or not os_module.path.exists(local_file)
                if not should_download:
                    continue
                candidate_entries.append({**entry, "filename": filename, "local_name": local_name, "local_file": local_file})

            stats[mode]["remote_files_found"] = len(
                [
                    entry
                    for entry in (listing.get("entries") or [])
                    if (
                        (
                            mode == "handshakes"
                            and str(entry.get("filename") or "").startswith("HS_")
                            and str(entry.get("filename") or "").lower().endswith(".pcap")
                        )
                        or (
                            mode == "mastersniffer"
                            and str(entry.get("filename") or "").lower().startswith("mastersniffer_")
                            and str(entry.get("filename") or "").lower().endswith(".pcap")
                        )
                        or (
                            mode == "rawsniffer"
                            and str(entry.get("filename") or "").lower().startswith("rawsniff_")
                            and str(entry.get("filename") or "").lower().endswith(".pcap")
                        )
                        or (
                            mode not in {"handshakes", "mastersniffer", "rawsniffer"}
                            and str(entry.get("filename") or "").lower().endswith(".csv")
                        )
                    )
                ]
            )
            stats[mode]["files_to_download"] = len(candidate_entries)
            emit_m5evil_progress_fn(
                progress_callback,
                mode,
                0,
                len(candidate_entries),
                0,
                0,
                current_file="Preparing download queue",
                stage="RUNNING" if candidate_entries else "UP TO DATE",
            )

            processed_count = 0
            for entry in candidate_entries:
                filename = str(entry.get("filename") or "").strip()
                try:
                    resolved_download = find_m5evil_download_url_fn(profile, entry)
                    if resolved_download.get("status") != "success":
                        errors.append(resolved_download.get("message"))
                        stats[mode]["failed"] += 1
                        last_failure_details = resolved_download.get("details") or last_failure_details
                        continue
                    download_web_file(
                        resolved_download.get("download_url"),
                        entry["local_file"],
                        username=profile.get("web_user"),
                        password=profile.get("web_password"),
                    )
                    collector.append(entry["local_name"])
                    stats[mode]["downloaded"] += 1
                except Exception as exc:
                    stats[mode]["failed"] += 1
                    errors.append(f"Failed to download {filename}: {exc}")
                finally:
                    processed_count += 1
                    emit_m5evil_progress_fn(
                        progress_callback,
                        mode,
                        processed_count,
                        len(candidate_entries),
                        stats[mode]["downloaded"],
                        stats[mode]["failed"],
                        current_file=filename,
                        stage="RUNNING",
                    )

        if not had_listing_success and errors:
            return {
                "status": "error",
                "message": errors[0],
                "details": {
                    **(
                        last_failure_details
                        or m5evil_phase_details_fn(
                            profile,
                            connection_ok=False,
                            auth_ok=False,
                            browse_root_ok=False,
                            failure_phase="connection",
                        )
                    ),
                    "target": profile["target"],
                    "handshakes": downloaded_handshakes,
                    "rawsniffer_pcaps": downloaded_rawsniffer,
                    "mastersniffer_pcaps": downloaded_mastersniffer,
                    "wardrive_csvs": downloaded_wardrive,
                    "errors": errors,
                    "handshake_remote_files_found": stats["handshakes"]["remote_files_found"],
                    "handshake_files_to_download": stats["handshakes"]["files_to_download"],
                    "handshake_files_failed": stats["handshakes"]["failed"],
                    "rawsniffer_remote_files_found": stats["rawsniffer"]["remote_files_found"],
                    "rawsniffer_files_to_download": stats["rawsniffer"]["files_to_download"],
                    "rawsniffer_files_failed": stats["rawsniffer"]["failed"],
                    "mastersniffer_remote_files_found": stats["mastersniffer"]["remote_files_found"],
                    "mastersniffer_files_to_download": stats["mastersniffer"]["files_to_download"],
                    "mastersniffer_files_failed": stats["mastersniffer"]["failed"],
                    "wardrive_remote_files_found": stats["wardrive"]["remote_files_found"],
                    "wardrive_files_to_download": stats["wardrive"]["files_to_download"],
                    "wardrive_files_failed": stats["wardrive"]["failed"],
                    "sync_ms": round((time_module.perf_counter() - started_at) * 1000, 2),
                },
            }

        final_status = "partial" if errors else "success"
        final_message = "M5Evil Admin WebUI sync completed with errors" if errors else "M5Evil Admin WebUI sync completed"
        for mode in ("handshakes", "rawsniffer", "mastersniffer", "wardrive"):
            mode_total = stats[mode]["files_to_download"]
            mode_downloaded = stats[mode]["downloaded"]
            mode_failed = stats[mode]["failed"]
            if mode_total <= 0:
                stage = "UP TO DATE"
                current_file = "No new files"
            elif mode_failed > 0:
                stage = "PARTIAL"
                current_file = ""
            else:
                stage = "COMPLETED"
                current_file = ""
            emit_m5evil_progress_fn(
                progress_callback,
                mode,
                mode_total,
                mode_total,
                mode_downloaded,
                mode_failed,
                current_file=current_file,
                stage=stage,
            )

        return {
            "status": final_status,
            "message": final_message,
            "details": {
                "target": profile["target"],
                "handshakes": downloaded_handshakes,
                "rawsniffer_pcaps": downloaded_rawsniffer,
                "mastersniffer_pcaps": downloaded_mastersniffer,
                "wardrive_csvs": downloaded_wardrive,
                "errors": errors,
                "handshake_remote_files_found": stats["handshakes"]["remote_files_found"],
                "handshake_files_to_download": stats["handshakes"]["files_to_download"],
                "handshake_files_failed": stats["handshakes"]["failed"],
                "rawsniffer_remote_files_found": stats["rawsniffer"]["remote_files_found"],
                "rawsniffer_files_to_download": stats["rawsniffer"]["files_to_download"],
                "rawsniffer_files_failed": stats["rawsniffer"]["failed"],
                "mastersniffer_remote_files_found": stats["mastersniffer"]["remote_files_found"],
                "mastersniffer_files_to_download": stats["mastersniffer"]["files_to_download"],
                "mastersniffer_files_failed": stats["mastersniffer"]["failed"],
                "wardrive_remote_files_found": stats["wardrive"]["remote_files_found"],
                "wardrive_files_to_download": stats["wardrive"]["files_to_download"],
                "wardrive_files_failed": stats["wardrive"]["failed"],
                "connection_ok": True,
                "auth_ok": True,
                "browse_root_ok": True,
                "handshake_path_ok": True,
                "rawsniffer_path_ok": True,
                "wardrive_path_ok": True,
                "failure_phase": None,
                "url_used": build_m5evil_base_url(profile),
                "sync_ms": round((time_module.perf_counter() - started_at) * 1000, 2),
            },
        }
    except Exception as exc:
        for mode in ("handshakes", "rawsniffer", "mastersniffer", "wardrive"):
            emit_m5evil_progress_fn(
                progress_callback,
                mode,
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
                **m5evil_phase_details_fn(
                    profile,
                    connection_ok=False,
                    auth_ok=False,
                    browse_root_ok=False,
                    failure_phase="connection",
                ),
                "target": profile["target"],
            },
        }
