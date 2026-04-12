import os


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


def _format_pwnagotchi_download_label(filename, downloaded_bytes, total_bytes):
    name = str(filename or "").strip() or "download"
    downloaded_label = _format_bytes(downloaded_bytes)
    total_label = _format_bytes(total_bytes) if total_bytes else "unknown size"
    return f"{name} [{downloaded_label} / {total_label}]"


def emit_pwnagotchi_progress(
    progress_callback,
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
        "pwnagotchi_handshakes",
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


def download_remote_file(
    sftp, remote_path, local_path, *, os_module=os, progress_hook=None
):
    directory = os.path.dirname(local_path)
    if directory:
        os_module.makedirs(directory, exist_ok=True)
    if callable(progress_hook):
        sftp.get(remote_path, local_path, callback=progress_hook)
        return
    sftp.get(remote_path, local_path)


def should_download_entry(
    local_file,
    remote_entry,
    force,
    errors,
    filename,
    *,
    os_module=os,
    logger,
):
    if force:
        return True
    if not os_module.path.exists(local_file):
        return True
    remote_size = (
        getattr(remote_entry, "st_size", None) if remote_entry is not None else None
    )
    if remote_size is None:
        msg = f"Error checking remote size for {filename}"
        logger.error(msg)
        errors.append(msg)
        return False
    local_size = os_module.path.getsize(local_file)
    return remote_size != local_size


def probe_pwnagotchi_ssh(
    profile,
    *,
    build_ssh_client,
    get_known_hosts_path,
    serialize_host_key,
    probe_remote_host_key_details,
    sha256_fingerprint,
    md5_fingerprint,
    stat_module,
    paramiko_module,
):
    host = profile["host"]
    port = profile["port"]
    user = profile["user"]
    password = profile["password"]
    remote_path = profile["handshake_path"]
    if not host:
        return {
            "status": "error",
            "code": "host_missing",
            "message": "Pwnagotchi SSH host missing",
        }
    if not user or not password:
        return {
            "status": "error",
            "code": "credentials_missing",
            "message": "Pwnagotchi SSH credentials missing",
        }
    if not remote_path:
        return {
            "status": "error",
            "code": "path_missing",
            "message": "Pwnagotchi remote path missing",
        }

    ssh = None
    sftp = None
    try:
        ssh = build_ssh_client()
        ssh.connect(host, port=port, username=user, password=password, timeout=10)
        sftp = ssh.open_sftp()
        entries = sftp.listdir_attr(remote_path)
        regular_files = 0
        for entry in entries:
            mode = getattr(entry, "st_mode", None)
            if mode is None or stat_module.S_ISREG(mode):
                regular_files += 1
        return {
            "status": "success",
            "message": "Pwnagotchi SSH connection successful",
            "details": {
                "target": profile["target"],
                "connection_ok": True,
                "auth_ok": True,
                "host_key_trusted": True,
                "remote_path_ok": True,
                "files_found": regular_files,
                "remote_path": remote_path,
                "host": host,
                "port": port,
            },
        }
    except paramiko_module.BadHostKeyException as exc:
        expected = getattr(exc, "expected_key", None)
        presented = getattr(exc, "key", None)
        details = {
            "target": profile["target"],
            "connection_ok": True,
            "auth_ok": False,
            "host_key_trusted": False,
            "remote_path_ok": False,
            "host": host,
            "port": port,
            "remote_path": remote_path,
            "known_hosts_path": get_known_hosts_path(),
            "host_key": (
                serialize_host_key(presented, host, port)
                if presented is not None
                else probe_remote_host_key_details(host, port)
            ),
        }
        if expected is not None:
            details["expected_host_key"] = {
                "key_type": expected.get_name(),
                "fingerprint_sha256": sha256_fingerprint(expected),
                "fingerprint_md5": md5_fingerprint(expected),
            }
        return {
            "status": "error",
            "code": "ssh_host_key_mismatch",
            "message": "SSH host key changed. Verify the fingerprint before replacing the trusted key.",
            "details": details,
        }
    except paramiko_module.AuthenticationException:
        return {
            "status": "error",
            "code": "auth_failed",
            "message": "Pwnagotchi SSH authentication failed",
            "details": {
                "target": profile["target"],
                "connection_ok": True,
                "auth_ok": False,
                "host_key_trusted": True,
                "remote_path_ok": False,
                "host": host,
                "port": port,
                "remote_path": remote_path,
            },
        }
    except paramiko_module.SSHException as exc:
        msg = str(exc)
        if "not found in known_hosts" in msg.lower():
            return {
                "status": "error",
                "code": "ssh_host_key_not_trusted",
                "message": "SSH host key not trusted. Confirm fingerprint before testing or syncing.",
                "details": {
                    "target": profile["target"],
                    "connection_ok": True,
                    "auth_ok": False,
                    "host_key_trusted": False,
                    "remote_path_ok": False,
                    "host": host,
                    "port": port,
                    "remote_path": remote_path,
                    "known_hosts_path": get_known_hosts_path(),
                    "host_key": probe_remote_host_key_details(host, port),
                },
            }
        return {
            "status": "error",
            "code": "ssh_error",
            "message": msg,
            "details": {
                "target": profile["target"],
                "connection_ok": False,
                "auth_ok": False,
                "host_key_trusted": False,
                "remote_path_ok": False,
                "host": host,
                "port": port,
                "remote_path": remote_path,
            },
        }
    except FileNotFoundError:
        return {
            "status": "error",
            "code": "path_not_found",
            "message": f"Pwnagotchi remote path not found: {remote_path}",
            "details": {
                "target": profile["target"],
                "connection_ok": True,
                "auth_ok": True,
                "host_key_trusted": True,
                "remote_path_ok": False,
                "host": host,
                "port": port,
                "remote_path": remote_path,
            },
        }
    except OSError as exc:
        return {
            "status": "error",
            "code": "unreachable",
            "message": f"Failed to reach Pwnagotchi SSH: {exc}",
            "details": {
                "target": profile["target"],
                "connection_ok": False,
                "auth_ok": False,
                "host_key_trusted": False,
                "remote_path_ok": False,
                "host": host,
                "port": port,
                "remote_path": remote_path,
            },
        }
    except Exception as exc:
        return {
            "status": "error",
            "code": "probe_failed",
            "message": f"Pwnagotchi SSH probe failed: {exc}",
            "details": {
                "target": profile["target"],
                "connection_ok": False,
                "auth_ok": False,
                "host_key_trusted": False,
                "remote_path_ok": False,
                "host": host,
                "port": port,
                "remote_path": remote_path,
            },
        }
    finally:
        if sftp is not None:
            try:
                sftp.close()
            except Exception:
                pass
        if ssh is not None:
            try:
                ssh.close()
            except Exception:
                pass


def perform_pwnagotchi_sync(
    profile,
    *,
    force,
    progress_callback,
    build_ssh_client,
    emit_progress,
    should_download_entry_fn,
    download_remote_file_fn,
    handshakes_dir,
    posixpath_module,
    stat_module,
    paramiko_module,
    get_known_hosts_path,
    serialize_host_key,
    probe_remote_host_key_details,
    sha256_fingerprint,
    md5_fingerprint,
    logger,
    time_module,
):
    if not profile["enabled"]:
        return {
            "status": "skipped",
            "message": "Pwnagotchi auto-sync disabled",
            "details": {
                "target": profile["target"],
                "handshakes": [],
                "wardrive_csvs": [],
                "errors": [],
                "sync_ms": 0,
            },
        }
    host = profile["host"]
    port = profile["port"]
    user = profile["user"]
    password = profile["password"]
    remote_path = profile["handshake_path"]
    if not any([host, user, password, remote_path]):
        return {
            "status": "skipped",
            "message": "Pwnagotchi sync not configured",
            "details": {
                "target": profile["target"],
                "handshakes": [],
                "wardrive_csvs": [],
                "errors": [],
                "sync_ms": 0,
            },
        }
    if not host or not user or not password:
        return {
            "status": "error",
            "message": "Pwnagotchi SSH credentials missing",
            "details": {"target": profile["target"]},
        }
    if not remote_path:
        return {
            "status": "error",
            "message": "Pwnagotchi remote path missing",
            "details": {"target": profile["target"]},
        }
    ssh = None
    sftp = None
    started_at = time_module.perf_counter()

    try:
        ssh = build_ssh_client()
        ssh.connect(host, port=port, username=user, password=password, timeout=10)
        sftp = ssh.open_sftp()

        remote_entries = {}
        for entry in sftp.listdir_attr(remote_path):
            mode = getattr(entry, "st_mode", None)
            if mode is not None and not stat_module.S_ISREG(mode):
                continue
            remote_entries[entry.filename] = entry

        candidate_files = [
            file
            for file in list(remote_entries.keys())
            if any(
                file.endswith(ext)
                for ext in [".pcap", ".gps.json", ".geo.json", ".paw-gps.json"]
            )
        ]
        download_queue = []
        downloaded = []
        errors = []

        for file in candidate_files:
            local_file = os.path.join(handshakes_dir, file)
            should_download = should_download_entry_fn(
                local_file, remote_entries.get(file), force, errors, file
            )
            if should_download:
                download_queue.append(
                    {
                        "filename": file,
                        "local_file": local_file,
                        "remote_size": getattr(remote_entries.get(file), "st_size", 0),
                    }
                )

        total_candidates = len(download_queue)

        emit_progress(
            progress_callback,
            0,
            total_candidates,
            0,
            0,
            current_file="Preparing download queue",
            stage="RUNNING" if total_candidates else "UP TO DATE",
        )

        processed = 0
        for item in download_queue:
            file = item["filename"]
            local_file = item["local_file"]
            remote_size = item["remote_size"]
            try:
                remote_file = posixpath_module.join(remote_path.rstrip("/"), file)
                emit_progress(
                    progress_callback,
                    processed,
                    total_candidates,
                    len(downloaded),
                    len(errors),
                    current_file=f"Starting {file}",
                    stage="RUNNING",
                )
                download_remote_file_fn(
                    sftp,
                    remote_file,
                    local_file,
                    progress_hook=lambda transferred, total, _filename=file, _processed=processed, _remote_size=remote_size: emit_progress(
                        progress_callback,
                        _processed,
                        total_candidates,
                        len(downloaded),
                        len(errors),
                        current_file=_format_pwnagotchi_download_label(
                            _filename,
                            transferred,
                            total or _remote_size,
                        ),
                        stage="RUNNING",
                    ),
                )
                downloaded.append(file)
            except Exception as exc:
                errors.append(f"Failed to download {file}: {str(exc)}")
            processed += 1
            emit_progress(
                progress_callback,
                processed,
                total_candidates,
                len(downloaded),
                len(errors),
                current_file=file,
                stage="RUNNING",
            )

        if total_candidates <= 0:
            final_stage = "UP TO DATE"
        elif errors and downloaded:
            final_stage = "PARTIAL"
        elif errors:
            final_stage = "ERROR"
        else:
            final_stage = "COMPLETED"

        emit_progress(
            progress_callback,
            total_candidates,
            total_candidates,
            len(downloaded),
            len(errors),
            current_file="No new files" if total_candidates <= 0 else "",
            stage=final_stage,
        )

        if errors and downloaded:
            status = "partial"
            message = "Pwnagotchi sync completed with errors"
        elif errors:
            status = "error"
            message = errors[0] if len(errors) == 1 else "Pwnagotchi sync failed"
        else:
            status = "success"
            message = "Pwnagotchi sync completed"

        return {
            "status": status,
            "message": message,
            "details": {
                "target": profile["target"],
                "handshakes": downloaded,
                "wardrive_csvs": [],
                "errors": errors,
                "handshake_remote_files_found": len(candidate_files),
                "handshake_files_to_download": total_candidates,
                "handshake_files_failed": len(errors),
                "sync_ms": round((time_module.perf_counter() - started_at) * 1000, 2),
            },
        }
    except paramiko_module.BadHostKeyException as exc:
        emit_progress(progress_callback, 0, 0, 0, 1, stage="ERROR")
        expected = getattr(exc, "expected_key", None)
        presented = getattr(exc, "key", None)
        details = {
            "target": profile["target"],
            "known_hosts_path": get_known_hosts_path(),
            "host": host,
            "port": port,
            "host_key": (
                serialize_host_key(presented, host, port)
                if presented is not None
                else probe_remote_host_key_details(host, port)
            ),
        }
        if expected is not None:
            details["expected_host_key"] = {
                "key_type": expected.get_name(),
                "fingerprint_sha256": sha256_fingerprint(expected),
                "fingerprint_md5": md5_fingerprint(expected),
            }
        msg = "SSH host key changed. Verify the fingerprint before replacing the trusted key."
        logger.error("Sync Error: %s", msg)
        return {
            "status": "error",
            "code": "ssh_host_key_mismatch",
            "message": msg,
            "details": details,
        }
    except paramiko_module.SSHException as exc:
        msg = str(exc)
        emit_progress(progress_callback, 0, 0, 0, 1, stage="ERROR")
        if "not found in known_hosts" in msg.lower():
            known_hosts_path = get_known_hosts_path()
            logger.error("Sync Error: %s", msg)
            return {
                "status": "error",
                "code": "ssh_host_key_not_trusted",
                "message": (
                    "SSH host key not trusted. Confirm fingerprint and trust the host key "
                    "before syncing."
                ),
                "details": {
                    "target": profile["target"],
                    "known_hosts_path": known_hosts_path,
                    "host": host,
                    "port": port,
                    "host_key": probe_remote_host_key_details(host, port),
                },
            }
        logger.error("Sync Error: %s", msg)
        return {
            "status": "error",
            "message": msg,
            "details": {"target": profile["target"]},
        }
    except Exception as exc:
        emit_progress(progress_callback, 0, 0, 0, 1, stage="ERROR")
        logger.error("Sync Error: %s", exc)
        return {
            "status": "error",
            "message": str(exc),
            "details": {"target": profile["target"]},
        }
    finally:
        if sftp is not None:
            try:
                sftp.close()
            except Exception:
                pass
        if ssh is not None:
            try:
                ssh.close()
            except Exception:
                pass
