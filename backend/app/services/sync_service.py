import logging
import os
import posixpath
import socket
import stat
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

import paramiko

from app.core.config import (
    BRUCE_HANDSHAKE_REMOTE_PATH,
    BRUCE_HANDSHAKES_DIR,
    BRUCE_RAWSNIFFER_REMOTE_PATH,
    BRUCE_RAWSNIFFER_DIR,
    BRUCE_WARDRIVE_REMOTE_PATH,
    HANDSHAKES_DIR,
    M5EVIL_HANDSHAKES_DIR,
    M5EVIL_MASTERSNIFFER_DIR,
    M5EVIL_RAWSNIFFER_DIR,
    WARDRIVE_DIR,
    load_config,
)
from app.services.sync_infra_helpers import (
    LinkListingParser,
    build_basic_auth_value as _build_basic_auth_value_helper,
    build_bruce_base_url as _build_bruce_base_url_helper,
    build_bruce_download_url as _build_bruce_download_url_helper,
    build_bruce_listfiles_url as _build_bruce_listfiles_url_helper,
    build_m5evil_base_url as _build_m5evil_base_url_helper,
    build_m5evil_direct_dir_url as _build_m5evil_direct_dir_url_helper,
    build_ssh_client as _build_ssh_client_helper,
    ensure_known_hosts_file as _ensure_known_hosts_file_helper,
    extract_listing_filename as _extract_listing_filename_helper,
    extract_path_from_link as _extract_path_from_link_helper,
    fetch_remote_host_key as _fetch_remote_host_key_helper,
    fetch_web_binary as _fetch_web_binary_helper,
    fetch_web_text as _fetch_web_text_helper,
    get_known_hosts_path as _get_known_hosts_path_helper,
    host_patterns as _host_patterns_helper,
    link_name_tokens as _link_name_tokens_helper,
    list_links as _list_links_helper,
    looks_like_html as _looks_like_html_helper,
    looks_like_m5evil_browse_link as _looks_like_m5evil_browse_link_helper,
    md5_fingerprint as _md5_fingerprint_helper,
    normalize_bruce_remote_path as _normalize_bruce_remote_path_helper,
    normalize_m5evil_remote_path as _normalize_m5evil_remote_path_helper,
    normalize_web_path as _normalize_web_path_helper,
    open_web_url as _open_web_url_helper,
    parse_bruce_listfiles_payload as _parse_bruce_listfiles_payload_helper,
    resolve_remote_path as _resolve_remote_path_helper,
    serialize_host_key as _serialize_host_key_helper,
    sha256_fingerprint as _sha256_fingerprint_helper,
)
from app.services.sync_bruce_helpers import (
    emit_bruce_progress as _emit_bruce_progress_helper,
    list_bruce_webui_directory as _list_bruce_webui_directory_helper,
    perform_bruce_sync as _perform_bruce_sync_helper,
    probe_bruce_webui as _probe_bruce_webui_helper,
)
from app.services.sync_m5evil_helpers import (
    emit_m5evil_progress as _emit_m5evil_progress_helper,
    find_m5evil_browse_root as _find_m5evil_browse_root_helper,
    find_m5evil_download_url as _find_m5evil_download_url_helper,
    list_m5evil_admin_directory as _list_m5evil_admin_directory_helper,
    m5evil_phase_details as _m5evil_phase_details_helper,
    navigate_m5evil_directory as _navigate_m5evil_directory_helper,
    perform_m5evil_sync as _perform_m5evil_sync_helper,
    probe_m5evil_admin_webui as _probe_m5evil_admin_webui_helper,
)
from app.services.sync_pwnagotchi_helpers import (
    download_remote_file as _download_remote_file_helper,
    emit_pwnagotchi_progress as _emit_pwnagotchi_progress_helper,
    perform_pwnagotchi_sync as _perform_pwnagotchi_sync_helper,
    probe_pwnagotchi_ssh as _probe_pwnagotchi_ssh_helper,
    should_download_entry as _should_download_entry_helper,
)

logger = logging.getLogger(__name__)
_M5_FILE_EXTENSIONS = {".pcap", ".csv", ".json", ".txt", ".details", ".22000"}
_M5EVIL_SNIFFER_REMOTE_PATH = "evil/sniffer"
_BRUCE_DRIVE = "SD"
_LinkListingParser = LinkListingParser


class SyncService:
    def __init__(self):
        self.config = load_config()

    def reload_config(self):
        self.config = load_config()

    def _get_known_hosts_path(self):
        return _get_known_hosts_path_helper(self.config)

    def _ensure_known_hosts_file(self, known_hosts_path):
        return _ensure_known_hosts_file_helper(known_hosts_path)

    def _host_patterns(self, host, port):
        return _host_patterns_helper(host, port)

    def _sha256_fingerprint(self, key):
        return _sha256_fingerprint_helper(key)

    def _md5_fingerprint(self, key):
        return _md5_fingerprint_helper(key)

    def _serialize_host_key(self, key, host, port):
        return _serialize_host_key_helper(key, host, port)

    def _fetch_remote_host_key(self, host, port, timeout=10):
        return _fetch_remote_host_key_helper(
            host,
            port,
            socket_module=socket,
            paramiko_module=paramiko,
            timeout=timeout,
        )

    def _probe_remote_host_key_details(self, host, port):
        try:
            key = self._fetch_remote_host_key(host, port)
            return self._serialize_host_key(key, host, port)
        except Exception as exc:
            logger.warning(
                "Unable to probe remote host key for %s:%s: %s", host, port, exc
            )
            return None

    def _build_ssh_client(self):
        return _build_ssh_client_helper(
            self.config,
            paramiko_module=paramiko,
            ensure_known_hosts_file_fn=self._ensure_known_hosts_file,
            get_known_hosts_path_fn=lambda config: self._get_known_hosts_path(),
            logger=logger,
        )

    def _get_target_profile(self, target="pwnagotchi"):
        normalized = str(target or "pwnagotchi").strip().lower()
        if normalized == "bruce":
            return {
                "target": "bruce",
                "label": "Bruce",
                "enabled": bool(self.config.get("bruce_sync_enabled")),
                "force_sync": bool(self.config.get("bruce_force_sync")),
                "host": str(self.config.get("bruce_host") or "").strip(),
                "port": int(self.config.get("bruce_port", 80) or 80),
                "transport": "webui",
                "protocol": str(self.config.get("bruce_web_protocol") or "http")
                .strip()
                .lower()
                or "http",
                "web_user": str(self.config.get("bruce_web_user") or "admin").strip()
                or "admin",
                "web_password": str(self.config.get("bruce_web_password") or ""),
                "handshake_path": BRUCE_HANDSHAKE_REMOTE_PATH,
                "rawsniffer_path": BRUCE_RAWSNIFFER_REMOTE_PATH,
                "wardrive_path": BRUCE_WARDRIVE_REMOTE_PATH,
                "drive": _BRUCE_DRIVE,
                "local_handshakes_dir": BRUCE_HANDSHAKES_DIR,
                "local_rawsniffer_dir": BRUCE_RAWSNIFFER_DIR,
                "local_wardrive_dir": WARDRIVE_DIR,
            }
        if normalized == "m5evil":
            return {
                "target": "m5evil",
                "label": "M5Evil",
                "enabled": bool(self.config.get("m5_sync_enabled")),
                "force_sync": bool(self.config.get("m5_force_sync")),
                "host": str(self.config.get("m5_host") or "").strip(),
                "port": int(self.config.get("m5_port", 80) or 80),
                "transport": "admin_webui",
                "protocol": str(self.config.get("m5_web_protocol") or "http")
                .strip()
                .lower()
                or "http",
                "admin_base_path": str(
                    self.config.get("m5_admin_base_path")
                    or self.config.get("m5_web_base_path")
                    or "/evil-menu"
                ).strip()
                or "/evil-menu",
                "web_user": str(self.config.get("m5_web_user") or "evil").strip()
                or "evil",
                "web_password": str(self.config.get("m5_web_password") or ""),
                "handshake_path": str(
                    self.config.get("m5_handshake_remote_path") or ""
                ).strip(),
                "wardrive_path": str(
                    self.config.get("m5_wardrive_remote_path") or ""
                ).strip(),
                "rawsniffer_path": _M5EVIL_SNIFFER_REMOTE_PATH,
                "local_handshakes_dir": M5EVIL_HANDSHAKES_DIR,
                "local_rawsniffer_dir": M5EVIL_RAWSNIFFER_DIR,
                "local_mastersniffer_dir": M5EVIL_MASTERSNIFFER_DIR,
                "local_wardrive_dir": WARDRIVE_DIR,
            }
        return {
            "target": "pwnagotchi",
            "label": "Pwnagotchi",
            "enabled": bool(self.config.get("pwn_sync_enabled", True)),
            "force_sync": bool(
                self.config.get("pwn_force_sync", self.config.get("force_sync"))
            ),
            "host": str(self.config.get("pwn_host") or "").strip(),
            "port": int(self.config.get("pwn_port", 22) or 22),
            "user": str(self.config.get("pwn_user") or "").strip(),
            "password": str(self.config.get("pwn_pass") or ""),
            "transport": "ssh",
            "remote_root": "",
            "handshake_path": str(self.config.get("remote_path") or "").strip(),
            "wardrive_path": "",
            "local_handshakes_dir": HANDSHAKES_DIR,
            "local_wardrive_dir": WARDRIVE_DIR,
        }

    def _get_pwnagotchi_profile(self, overrides=None):
        base = self._get_target_profile("pwnagotchi")
        incoming = overrides if isinstance(overrides, dict) else {}
        if "pwn_host" in incoming:
            base["host"] = str(incoming.get("pwn_host") or "").strip()
        if "pwn_port" in incoming:
            try:
                base["port"] = int(incoming.get("pwn_port") or base.get("port") or 22)
            except (TypeError, ValueError):
                pass
        if "pwn_user" in incoming:
            base["user"] = str(incoming.get("pwn_user") or "").strip()
        if "pwn_pass" in incoming:
            base["password"] = str(incoming.get("pwn_pass") or "")
        if "remote_path" in incoming:
            base["handshake_path"] = str(incoming.get("remote_path") or "").strip()
        return base

    def probe_pwnagotchi_ssh(self, overrides=None):
        profile = self._get_pwnagotchi_profile(overrides)
        return _probe_pwnagotchi_ssh_helper(
            profile,
            build_ssh_client=self._build_ssh_client,
            get_known_hosts_path=self._get_known_hosts_path,
            serialize_host_key=self._serialize_host_key,
            probe_remote_host_key_details=self._probe_remote_host_key_details,
            sha256_fingerprint=self._sha256_fingerprint,
            md5_fingerprint=self._md5_fingerprint,
            stat_module=stat,
            paramiko_module=paramiko,
        )

    def _resolve_remote_path(self, root, child):
        return _resolve_remote_path_helper(root, child)

    def _normalize_web_path(self, path):
        return _normalize_web_path_helper(path)

    def _normalize_m5evil_remote_path(self, path):
        return _normalize_m5evil_remote_path_helper(path)

    def _normalize_bruce_remote_path(self, path):
        return _normalize_bruce_remote_path_helper(path)

    def _build_m5evil_direct_dir_url(self, profile, remote_path):
        return _build_m5evil_direct_dir_url_helper(profile, remote_path)

    def _build_m5evil_base_url(self, profile):
        return _build_m5evil_base_url_helper(profile)

    def _build_bruce_base_url(self, profile):
        return _build_bruce_base_url_helper(profile)

    def _build_bruce_listfiles_url(self, profile, remote_path):
        return _build_bruce_listfiles_url_helper(
            profile, remote_path, bruce_drive=_BRUCE_DRIVE
        )

    def _build_bruce_download_url(self, profile, remote_path, filename):
        return _build_bruce_download_url_helper(
            profile, remote_path, filename, bruce_drive=_BRUCE_DRIVE
        )

    def _parse_bruce_listfiles_payload(self, payload):
        return _parse_bruce_listfiles_payload_helper(payload)

    def _list_bruce_webui_directory(self, profile, remote_path):
        return _list_bruce_webui_directory_helper(
            profile,
            remote_path,
            build_bruce_listfiles_url=self._build_bruce_listfiles_url,
            fetch_web_text=self._fetch_web_text,
            parse_bruce_listfiles_payload=self._parse_bruce_listfiles_payload,
            urllib_error_module=urllib_error,
        )

    def _build_basic_auth_value(self, username, password):
        return _build_basic_auth_value_helper(username, password)

    def _open_web_url(self, url, timeout=10, *, username=None, password=None):
        return _open_web_url_helper(
            url,
            urllib_request_module=urllib_request,
            timeout=timeout,
            username=username,
            password=password,
        )

    def _fetch_web_text(self, url, *, username=None, password=None, timeout=10):
        return _fetch_web_text_helper(
            url,
            urllib_request_module=urllib_request,
            username=username,
            password=password,
            timeout=timeout,
        )

    def _fetch_web_binary(self, url, *, username=None, password=None, timeout=15):
        return _fetch_web_binary_helper(
            url,
            urllib_request_module=urllib_request,
            username=username,
            password=password,
            timeout=timeout,
        )

    def _extract_listing_filename(self, href, text):
        return _extract_listing_filename_helper(href, text)

    def _looks_like_m5evil_browse_link(self, href, text):
        return _looks_like_m5evil_browse_link_helper(href, text)

    def _looks_like_html(self, payload, content_type=""):
        return _looks_like_html_helper(payload, content_type)

    def _list_links(self, body):
        return _list_links_helper(body)

    def _m5evil_phase_details(
        self,
        profile,
        *,
        connection_ok=False,
        auth_ok=False,
        browse_root_ok=False,
        handshake_path_ok=False,
        rawsniffer_path_ok=False,
        wardrive_path_ok=False,
        failure_phase=None,
        url_used=None,
    ):
        return _m5evil_phase_details_helper(
            profile,
            build_m5evil_base_url=self._build_m5evil_base_url,
            connection_ok=connection_ok,
            auth_ok=auth_ok,
            browse_root_ok=browse_root_ok,
            handshake_path_ok=handshake_path_ok,
            rawsniffer_path_ok=rawsniffer_path_ok,
            wardrive_path_ok=wardrive_path_ok,
            failure_phase=failure_phase,
            url_used=url_used,
        )

    def _extract_path_from_link(self, href):
        return _extract_path_from_link_helper(href)

    def _link_name_tokens(self, href, text):
        return _link_name_tokens_helper(href, text)

    def _find_m5evil_browse_root(self, profile):
        return _find_m5evil_browse_root_helper(
            profile,
            build_m5evil_base_url=self._build_m5evil_base_url,
            fetch_web_text=self._fetch_web_text,
            list_links=self._list_links,
            looks_like_m5evil_browse_link=self._looks_like_m5evil_browse_link,
            m5evil_phase_details_fn=self._m5evil_phase_details,
            urllib_parse_module=urllib_parse,
            urllib_error_module=urllib_error,
        )

    def _navigate_m5evil_directory(self, profile, remote_path):
        return _navigate_m5evil_directory_helper(
            profile,
            remote_path,
            find_m5evil_browse_root_fn=self._find_m5evil_browse_root,
            m5evil_phase_details_fn=self._m5evil_phase_details,
            normalize_m5evil_remote_path=self._normalize_m5evil_remote_path,
            list_links=self._list_links,
            link_name_tokens=self._link_name_tokens,
            fetch_web_text=self._fetch_web_text,
            urllib_parse_module=urllib_parse,
            urllib_error_module=urllib_error,
        )

    def _list_m5evil_admin_directory(self, profile, remote_path):
        return _list_m5evil_admin_directory_helper(
            profile,
            remote_path,
            build_m5evil_direct_dir_url=self._build_m5evil_direct_dir_url,
            fetch_web_text=self._fetch_web_text,
            list_links=self._list_links,
            extract_listing_filename=self._extract_listing_filename,
            m5evil_phase_details_fn=self._m5evil_phase_details,
            navigate_m5evil_directory_fn=self._navigate_m5evil_directory,
            urllib_parse_module=urllib_parse,
            urllib_error_module=urllib_error,
        )

    def _find_m5evil_download_url(self, profile, file_entry):
        return _find_m5evil_download_url_helper(
            profile,
            file_entry,
            build_m5evil_base_url=self._build_m5evil_base_url,
            fetch_web_binary=self._fetch_web_binary,
            m5evil_phase_details_fn=self._m5evil_phase_details,
            looks_like_html=self._looks_like_html,
            list_links=self._list_links,
            link_name_tokens=self._link_name_tokens,
            urllib_parse_module=urllib_parse,
            urllib_error_module=urllib_error,
        )

    def _download_web_file(
        self,
        file_url,
        local_path,
        *,
        username=None,
        password=None,
        timeout=60,
        progress_hook=None,
    ):
        directory = os.path.dirname(local_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        temp_path = None
        chunk_size = 256 * 1024
        started_at = time.perf_counter()
        last_emit_at = started_at
        downloaded_bytes = 0
        total_bytes = 0
        try:
            with self._open_web_url(
                file_url, timeout=timeout, username=username, password=password
            ) as response:
                headers = getattr(response, "headers", None)
                if headers is not None:
                    try:
                        total_bytes = int(headers.get("Content-Length") or 0)
                    except (TypeError, ValueError):
                        total_bytes = 0

                handle = tempfile.NamedTemporaryFile(
                    mode="wb",
                    delete=False,
                    dir=directory or None,
                    prefix=".sync-download-",
                    suffix=".part",
                )
                temp_path = handle.name
                with handle as output:
                    if callable(progress_hook):
                        progress_hook(0, total_bytes, 0.0, False)
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        output.write(chunk)
                        downloaded_bytes += len(chunk)
                        now = time.perf_counter()
                        if callable(progress_hook) and (
                            downloaded_bytes == len(chunk)
                            or downloaded_bytes >= total_bytes > 0
                            or (now - last_emit_at) >= 0.4
                        ):
                            elapsed = max(now - started_at, 0.001)
                            progress_hook(
                                downloaded_bytes,
                                total_bytes,
                                downloaded_bytes / elapsed,
                                False,
                            )
                            last_emit_at = now
                os.replace(temp_path, local_path)
                temp_path = None
                if callable(progress_hook):
                    elapsed = max(time.perf_counter() - started_at, 0.001)
                    progress_hook(
                        downloaded_bytes,
                        total_bytes,
                        downloaded_bytes / elapsed,
                        True,
                    )
        except Exception:
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass
            raise

    def _emit_m5evil_progress(
        self,
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
        return _emit_m5evil_progress_helper(
            progress_callback,
            mode,
            processed,
            total,
            downloaded,
            failed,
            current_file=current_file,
            stage=stage,
        )

    def _emit_bruce_progress(
        self,
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
        return _emit_bruce_progress_helper(
            progress_callback,
            mode,
            processed,
            total,
            downloaded,
            failed,
            current_file=current_file,
            stage=stage,
        )

    def _emit_pwnagotchi_progress(
        self,
        progress_callback,
        processed,
        total,
        downloaded,
        failed,
        *,
        current_file="",
        stage="RUNNING",
    ):
        return _emit_pwnagotchi_progress_helper(
            progress_callback,
            processed,
            total,
            downloaded,
            failed,
            current_file=current_file,
            stage=stage,
        )

    def trust_remote_host_key(
        self, host=None, port=None, replace=False, target="pwnagotchi"
    ):
        normalized_target = str(target or "pwnagotchi").strip().lower()
        if normalized_target == "m5evil":
            return {
                "status": "error",
                "code": "unsupported_target",
                "message": "M5Evil sync uses Admin WebUI and does not support SSH host-key trust.",
            }
        profile = self._get_target_profile(target)
        host = str(host or profile.get("host") or "").strip()
        port = int(port or profile.get("port", 22) or 22)
        known_hosts_path = self._get_known_hosts_path()

        if not host:
            return {"status": "error", "message": "SSH host missing"}

        try:
            self._ensure_known_hosts_file(known_hosts_path)
        except OSError as exc:
            return {
                "status": "error",
                "code": "known_hosts_unavailable",
                "message": f"Failed to prepare known_hosts file: {exc}",
            }

        try:
            remote_key = self._fetch_remote_host_key(host, port)
        except Exception as exc:
            logger.error(
                "Failed to fetch remote host key for %s:%s: %s", host, port, exc
            )
            return {
                "status": "error",
                "code": "ssh_host_key_probe_failed",
                "message": f"Failed to fetch remote host key: {exc}",
            }

        host_keys = paramiko.HostKeys()
        try:
            host_keys.load(known_hosts_path)
        except FileNotFoundError:
            pass
        except OSError as exc:
            return {
                "status": "error",
                "code": "known_hosts_unavailable",
                "message": f"Failed to read known_hosts: {exc}",
            }

        key_type = remote_key.get_name()
        mismatches = []
        already_trusted = False

        for pattern in self._host_patterns(host, port):
            known = host_keys.lookup(pattern) or {}
            existing = known.get(key_type)
            if existing is None:
                continue
            if existing == remote_key:
                already_trusted = True
                continue
            mismatches.append(
                {
                    "host": pattern,
                    "key_type": key_type,
                    "fingerprint_sha256": self._sha256_fingerprint(existing),
                    "fingerprint_md5": self._md5_fingerprint(existing),
                }
            )

        if mismatches and not replace:
            return {
                "status": "error",
                "code": "ssh_host_key_mismatch",
                "message": "SSH host key changed. Confirm replacement before trusting.",
                "details": {
                    "target": profile["target"],
                    "known_hosts_path": known_hosts_path,
                    "host_key": self._serialize_host_key(remote_key, host, port),
                    "known_host_keys": mismatches,
                },
            }

        for pattern in self._host_patterns(host, port):
            host_keys.add(pattern, key_type, remote_key)

        try:
            host_keys.save(known_hosts_path)
        except OSError as exc:
            return {
                "status": "error",
                "code": "known_hosts_unavailable",
                "message": f"Failed to write known_hosts: {exc}",
            }

        return {
            "status": "success",
            "message": (
                "SSH host key already trusted."
                if already_trusted and not mismatches
                else "SSH host key trusted successfully."
            ),
            "details": {
                "target": profile["target"],
                "known_hosts_path": known_hosts_path,
                "host_key": self._serialize_host_key(remote_key, host, port),
            },
        }

    def _download_remote_file(self, sftp, remote_path, local_path):
        return _download_remote_file_helper(sftp, remote_path, local_path)

    def _should_download_entry(self, local_file, remote_entry, force, errors, filename):
        return _should_download_entry_helper(
            local_file,
            remote_entry,
            force,
            errors,
            filename,
            logger=logger,
        )

    def _perform_pwnagotchi_sync(self, force=False, progress_callback=None):
        profile = self._get_target_profile("pwnagotchi")
        return _perform_pwnagotchi_sync_helper(
            profile,
            force=force,
            progress_callback=progress_callback,
            build_ssh_client=self._build_ssh_client,
            emit_progress=self._emit_pwnagotchi_progress,
            should_download_entry_fn=self._should_download_entry,
            download_remote_file_fn=self._download_remote_file,
            handshakes_dir=HANDSHAKES_DIR,
            posixpath_module=posixpath,
            stat_module=stat,
            paramiko_module=paramiko,
            get_known_hosts_path=self._get_known_hosts_path,
            serialize_host_key=self._serialize_host_key,
            probe_remote_host_key_details=self._probe_remote_host_key_details,
            sha256_fingerprint=self._sha256_fingerprint,
            md5_fingerprint=self._md5_fingerprint,
            logger=logger,
            time_module=time,
        )

    def _get_m5evil_profile(self, overrides=None):
        base = self._get_target_profile("m5evil")
        incoming = overrides if isinstance(overrides, dict) else {}
        if "m5_sync_enabled" in incoming:
            base["enabled"] = bool(incoming.get("m5_sync_enabled"))
        if "m5_host" in incoming:
            base["host"] = str(incoming.get("m5_host") or "").strip()
        if "m5_port" in incoming:
            try:
                base["port"] = int(incoming.get("m5_port") or base.get("port") or 80)
            except (TypeError, ValueError):
                pass
        if "m5_web_protocol" in incoming:
            protocol = str(incoming.get("m5_web_protocol") or "").strip().lower()
            if protocol in {"http", "https"}:
                base["protocol"] = protocol
        if "m5_admin_base_path" in incoming or "m5_web_base_path" in incoming:
            base["admin_base_path"] = str(
                incoming.get("m5_admin_base_path", incoming.get("m5_web_base_path"))
                or base.get("admin_base_path")
                or "/evil-menu"
            ).strip()
        if "m5_web_user" in incoming:
            base["web_user"] = str(incoming.get("m5_web_user") or "").strip()
        if "m5_web_password" in incoming:
            base["web_password"] = str(incoming.get("m5_web_password") or "")
        if "m5_handshake_remote_path" in incoming:
            base["handshake_path"] = str(
                incoming.get("m5_handshake_remote_path") or ""
            ).strip()
        if "m5_wardrive_remote_path" in incoming:
            base["wardrive_path"] = str(
                incoming.get("m5_wardrive_remote_path") or ""
            ).strip()
        return base

    def _get_bruce_profile(self, overrides=None):
        base = self._get_target_profile("bruce")
        incoming = overrides if isinstance(overrides, dict) else {}
        if "bruce_sync_enabled" in incoming:
            base["enabled"] = bool(incoming.get("bruce_sync_enabled"))
        if "bruce_host" in incoming:
            base["host"] = str(incoming.get("bruce_host") or "").strip()
        if "bruce_port" in incoming:
            try:
                base["port"] = int(incoming.get("bruce_port") or base.get("port") or 80)
            except (TypeError, ValueError):
                pass
        if "bruce_web_protocol" in incoming:
            protocol = str(incoming.get("bruce_web_protocol") or "").strip().lower()
            if protocol in {"http", "https"}:
                base["protocol"] = protocol
        if "bruce_web_user" in incoming:
            base["web_user"] = str(incoming.get("bruce_web_user") or "").strip()
        if "bruce_web_password" in incoming:
            base["web_password"] = str(incoming.get("bruce_web_password") or "")
        return base

    def probe_bruce_webui(self, overrides=None):
        profile = self._get_bruce_profile(overrides)
        return _probe_bruce_webui_helper(
            profile,
            handshake_remote_path=BRUCE_HANDSHAKE_REMOTE_PATH,
            rawsniffer_remote_path=BRUCE_RAWSNIFFER_REMOTE_PATH,
            wardrive_remote_path=BRUCE_WARDRIVE_REMOTE_PATH,
            build_bruce_base_url=self._build_bruce_base_url,
            fetch_web_text=self._fetch_web_text,
            list_bruce_webui_directory_fn=self._list_bruce_webui_directory,
            urllib_parse_module=urllib_parse,
            urllib_error_module=urllib_error,
        )

    def _perform_bruce_sync(self, force=False, progress_callback=None):
        profile = self._get_bruce_profile()
        return _perform_bruce_sync_helper(
            profile,
            force=force,
            progress_callback=progress_callback,
            handshake_remote_path=BRUCE_HANDSHAKE_REMOTE_PATH,
            rawsniffer_remote_path=BRUCE_RAWSNIFFER_REMOTE_PATH,
            wardrive_remote_path=BRUCE_WARDRIVE_REMOTE_PATH,
            list_bruce_webui_directory_fn=self._list_bruce_webui_directory,
            emit_bruce_progress_fn=self._emit_bruce_progress,
            build_bruce_download_url=self._build_bruce_download_url,
            download_web_file=self._download_web_file,
            build_bruce_base_url=self._build_bruce_base_url,
            os_module=os,
            time_module=time,
        )

    def probe_m5evil_admin_webui(self, overrides=None):
        profile = self._get_m5evil_profile(overrides)
        return _probe_m5evil_admin_webui_helper(
            profile,
            rawsniffer_default_path=_M5EVIL_SNIFFER_REMOTE_PATH,
            list_m5evil_admin_directory_fn=self._list_m5evil_admin_directory,
            build_m5evil_base_url=self._build_m5evil_base_url,
        )

    def _perform_m5evil_sync(self, force=False, progress_callback=None):
        profile = self._get_m5evil_profile()
        return _perform_m5evil_sync_helper(
            profile,
            rawsniffer_default_path=_M5EVIL_SNIFFER_REMOTE_PATH,
            force=force,
            progress_callback=progress_callback,
            m5evil_phase_details_fn=self._m5evil_phase_details,
            list_m5evil_admin_directory_fn=self._list_m5evil_admin_directory,
            emit_m5evil_progress_fn=self._emit_m5evil_progress,
            find_m5evil_download_url_fn=self._find_m5evil_download_url,
            download_web_file=self._download_web_file,
            build_m5evil_base_url=self._build_m5evil_base_url,
            os_module=os,
            time_module=time,
        )

    def perform_sync(self, force=False, progress_callback=None, target_force=None):
        target_force = target_force if isinstance(target_force, dict) else {}
        pwn_force = bool(target_force.get("pwnagotchi", force))
        m5_force = bool(target_force.get("m5evil", force))
        bruce_force = bool(target_force.get("bruce", force))
        target_results = {}
        target_workers = {
            "pwnagotchi": (
                self._perform_pwnagotchi_sync,
                {"force": pwn_force, "progress_callback": progress_callback},
            ),
            "m5evil": (
                self._perform_m5evil_sync,
                {"force": m5_force, "progress_callback": progress_callback},
            ),
            "bruce": (
                self._perform_bruce_sync,
                {"force": bruce_force, "progress_callback": progress_callback},
            ),
        }
        with ThreadPoolExecutor(max_workers=len(target_workers)) as executor:
            future_to_target = {
                executor.submit(worker, **kwargs): target_name
                for target_name, (worker, kwargs) in target_workers.items()
            }
            for future in as_completed(future_to_target):
                target_name = future_to_target[future]
                try:
                    target_results[target_name] = future.result()
                except Exception as exc:
                    logger.exception("Remote sync worker failed for %s", target_name)
                    target_results[target_name] = {
                        "status": "error",
                        "message": f"{target_name} sync failed: {exc}",
                        "details": {"target": target_name, "errors": [str(exc)]},
                    }

        downloaded_handshakes = []
        downloaded_wardrive = []
        downloaded_m5_rawsniffer = []
        downloaded_m5_mastersniffer = []
        downloaded_bruce_rawsniffer = []
        errors = []
        any_success = False
        blocking_error = None
        failed_results = []
        skipped_targets = []

        for target_name in ("pwnagotchi", "m5evil", "bruce"):
            result = target_results[target_name]
            status = result.get("status")
            details = (
                result.get("details") if isinstance(result.get("details"), dict) else {}
            )
            if status in {"success", "partial"}:
                any_success = True
                downloaded_handshakes.extend(details.get("handshakes") or [])
                downloaded_wardrive.extend(details.get("wardrive_csvs") or [])
                downloaded_m5_rawsniffer.extend(details.get("rawsniffer_pcaps") or [])
                downloaded_m5_mastersniffer.extend(
                    details.get("mastersniffer_pcaps") or []
                )
                downloaded_bruce_rawsniffer.extend(
                    details.get("rawsniffer_pcaps") or []
                )
                errors.extend(details.get("errors") or [])
                continue
            if status == "skipped":
                skipped_targets.append(target_name)
                continue
            if (
                result.get("code")
                in {"ssh_host_key_not_trusted", "ssh_host_key_mismatch"}
                and blocking_error is None
            ):
                blocking_error = result
                continue
            failed_results.append(result)
            message = str(result.get("message") or f"{target_name} sync failed")
            errors.append(f"{target_name}: {message}")

        def _merge_target_result(result: dict) -> dict:
            if not isinstance(result, dict):
                return {}
            merged = dict(result)
            nested = result.get("details")
            if isinstance(nested, dict):
                for key, value in nested.items():
                    merged.setdefault(key, value)
            return merged

        combined_details = {
            "handshakes": downloaded_handshakes,
            "wardrive_csvs": downloaded_wardrive,
            "rawsniffer_pcaps": downloaded_m5_rawsniffer,
            "mastersniffer_pcaps": downloaded_m5_mastersniffer,
            "bruce_rawsniffer_pcaps": downloaded_bruce_rawsniffer,
            "errors": errors,
            "targets": target_results,
            "pwnagotchi_remote_sync": _merge_target_result(
                target_results["pwnagotchi"]
            ),
            "m5evil_remote_sync": _merge_target_result(target_results["m5evil"]),
            "bruce_remote_sync": _merge_target_result(target_results["bruce"]),
            "any_remote_success": any_success,
        }

        if blocking_error is not None:
            error_details = dict(combined_details)
            blocking_details = (
                blocking_error.get("details")
                if isinstance(blocking_error.get("details"), dict)
                else {}
            )
            error_details.update(blocking_details)
            return {
                "status": "error",
                "code": blocking_error.get("code"),
                "message": blocking_error.get("message"),
                "details": error_details,
            }

        if any_success:
            message_bits = []
            if target_results["pwnagotchi"].get("status") in {"success", "partial"}:
                message_bits.append("Pwnagotchi")
            if target_results["m5evil"].get("status") in {"success", "partial"}:
                message_bits.append("M5Evil")
            if target_results["bruce"].get("status") in {"success", "partial"}:
                message_bits.append("Bruce")
            source_text = " + ".join(message_bits) if message_bits else "remote targets"
            return {
                "status": "success",
                "message": f"Sync completed ({source_text})",
                "details": combined_details,
            }

        if len(failed_results) == 1 and len(skipped_targets) == 1:
            return {
                "status": "error",
                "message": str(failed_results[0].get("message") or "Sync failed"),
                "details": combined_details,
            }

        if len(skipped_targets) == len(target_results):
            return {
                "status": "error",
                "message": "No sync targets configured",
                "details": combined_details,
            }

        return {
            "status": "error",
            "message": "No sync targets succeeded",
            "details": combined_details,
        }
