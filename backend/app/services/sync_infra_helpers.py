import base64
import hashlib
import os
import posixpath
import re
import socket
from html.parser import HTMLParser
from urllib import parse as urllib_parse


class LinkListingParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self._seen = set()
        self._current_href = None
        self._current_text = []
        self._current_script = []
        self._inside_script = False

    def _append_link(self, href, text=""):
        href_value = str(href or "").strip()
        text_value = str(text or "").strip()
        if not href_value:
            return
        key = (href_value, text_value)
        if key in self._seen:
            return
        self._seen.add(key)
        self.links.append({"href": href_value, "text": text_value})

    def _looks_like_url_value(self, value):
        candidate = str(value or "").strip()
        if not candidate:
            return False
        lowered = candidate.lower()
        return (
            lowered.startswith(("http://", "https://", "/", "./", "../"))
            or "evil-menu" in lowered
            or "browse" in lowered
            or "download" in lowered
        )

    def _extract_urls_from_value(self, raw):
        candidate = str(raw or "").strip()
        if not candidate:
            return []
        discovered = []
        if self._looks_like_url_value(candidate):
            discovered.append(candidate)
        for match in re.finditer(r"""['"`]([^'"`\s<>]+)['"`]""", candidate):
            quoted = str(match.group(1) or "").strip()
            if self._looks_like_url_value(quoted):
                discovered.append(quoted)
        return discovered

    def _handle_attr_links(self, attr_map):
        label = (
            attr_map.get("data-name")
            or attr_map.get("data-label")
            or attr_map.get("aria-label")
            or attr_map.get("title")
            or attr_map.get("value")
            or ""
        )
        for attr_name in (
            "href",
            "action",
            "formaction",
            "data-href",
            "data-url",
            "data-link",
            "data-download",
            "src",
            "onclick",
        ):
            for url in self._extract_urls_from_value(attr_map.get(attr_name)):
                self._append_link(url, label)

    def handle_starttag(self, tag, attrs):
        tag_name = tag.lower()
        attr_map = {
            str(name or "").strip().lower(): str(value or "").strip()
            for name, value in (attrs or [])
            if str(name or "").strip()
        }
        if tag_name == "a":
            href = str(attr_map.get("href") or "").strip()
            if not href:
                return
            self._current_href = href
            self._current_text = []
            return
        self._handle_attr_links(attr_map)
        if tag_name == "script":
            self._inside_script = True
            self._current_script = []

    def handle_data(self, data):
        if self._current_href is not None:
            self._current_text.append(data)
        if self._inside_script:
            self._current_script.append(data)

    def handle_endtag(self, tag):
        tag_name = tag.lower()
        if tag_name == "script":
            script_body = "".join(self._current_script).strip()
            if script_body:
                for url in self._extract_urls_from_value(script_body):
                    self._append_link(url, "script")
            self._inside_script = False
            self._current_script = []
            return
        if tag_name != "a" or self._current_href is None:
            return
        self._append_link(self._current_href, "".join(self._current_text).strip())
        self._current_href = None
        self._current_text = []


def get_known_hosts_path(config):
    configured_path = str(config.get("ssh_known_hosts_path", "") or "").strip()
    if configured_path:
        return os.path.expanduser(configured_path)
    return os.path.expanduser("~/.kovil/known_hosts")


def ensure_known_hosts_file(known_hosts_path):
    directory = os.path.dirname(known_hosts_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    if not os.path.exists(known_hosts_path):
        with open(known_hosts_path, "a", encoding="utf-8"):
            pass
    try:
        os.chmod(known_hosts_path, 0o600)
    except OSError:
        pass


def host_patterns(host, port):
    return [host, f"[{host}]:{port}"]


def sha256_fingerprint(key):
    digest = hashlib.sha256(key.asbytes()).digest()
    encoded = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{encoded}"


def md5_fingerprint(key):
    digest = hashlib.md5(key.asbytes()).hexdigest()  # nosec B324
    chunks = [digest[i : i + 2] for i in range(0, len(digest), 2)]
    return "MD5:" + ":".join(chunks)


def serialize_host_key(key, host, port):
    return {
        "host": host,
        "port": port,
        "key_type": key.get_name(),
        "fingerprint_sha256": sha256_fingerprint(key),
        "fingerprint_md5": md5_fingerprint(key),
        "key_base64": key.get_base64(),
    }


def fetch_remote_host_key(host, port, *, socket_module, paramiko_module, timeout=10):
    sock = socket_module.create_connection((host, port), timeout=timeout)
    transport = paramiko_module.Transport(sock)
    try:
        transport.start_client(timeout=timeout)
        return transport.get_remote_server_key()
    finally:
        try:
            transport.close()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass


def probe_remote_host_key_details(host, port, *, socket_module, paramiko_module, logger):
    try:
        key = fetch_remote_host_key(
            host,
            port,
            socket_module=socket_module,
            paramiko_module=paramiko_module,
        )
        return serialize_host_key(key, host, port)
    except Exception as exc:
        logger.warning(
            "Unable to probe remote host key for %s:%s: %s", host, port, exc
        )
        return None


def build_ssh_client(
    config, *, paramiko_module, ensure_known_hosts_file_fn, get_known_hosts_path_fn, logger
):
    ssh = paramiko_module.SSHClient()
    ssh.load_system_host_keys()

    known_hosts_path = get_known_hosts_path_fn(config)
    if known_hosts_path:
        try:
            ensure_known_hosts_file_fn(known_hosts_path)
            ssh.load_host_keys(known_hosts_path)
        except FileNotFoundError:
            logger.warning(
                "Known hosts file not found: %s (continuing with system host keys)",
                known_hosts_path,
            )
        except OSError as exc:
            logger.warning(
                "Failed to load known hosts file %s: %s",
                known_hosts_path,
                exc,
            )

    ssh.set_missing_host_key_policy(paramiko_module.RejectPolicy())
    return ssh


def resolve_remote_path(root, child):
    root_clean = str(root or "").strip()
    child_clean = str(child or "").strip()
    if child_clean.startswith("/"):
        return posixpath.normpath(child_clean)
    if root_clean and child_clean:
        return posixpath.normpath(posixpath.join(root_clean, child_clean))
    return posixpath.normpath(root_clean or child_clean or "")


def normalize_web_path(path):
    value = str(path or "").strip().replace("\\", "/")
    if not value:
        return "/"
    while "//" in value:
        value = value.replace("//", "/")
    if not value.startswith("/"):
        value = f"/{value}"
    return value


def normalize_m5evil_remote_path(path):
    value = str(path or "").strip().replace("\\", "/")
    value = value.strip("/")
    while "//" in value:
        value = value.replace("//", "/")
    return value


def normalize_bruce_remote_path(path):
    value = str(path or "").strip().replace("\\", "/")
    if not value:
        return "/"
    while "//" in value:
        value = value.replace("//", "/")
    if not value.startswith("/"):
        value = f"/{value}"
    if value != "/" and value.endswith("/"):
        value = value.rstrip("/")
    return value or "/"


def build_m5evil_direct_dir_url(profile, remote_path):
    protocol = str(profile.get("protocol") or "http").strip().lower() or "http"
    host = str(profile.get("host") or "").strip()
    port = int(profile.get("port", 80) or 80)
    origin_url = f"{protocol}://{host}:{port}/"
    normalized_path = normalize_m5evil_remote_path(remote_path)
    query = urllib_parse.urlencode({"dir": f"/{normalized_path}"})
    return urllib_parse.urljoin(origin_url, f"check-sd-file?{query}")


def build_m5evil_base_url(profile):
    protocol = str(profile.get("protocol") or "http").strip().lower() or "http"
    host = str(profile.get("host") or "").strip()
    port = int(profile.get("port", 80) or 80)
    base_path = normalize_web_path(profile.get("admin_base_path") or "/evil-menu")
    return f"{protocol}://{host}:{port}{base_path.rstrip('/') or ''}/"


def build_bruce_base_url(profile):
    protocol = str(profile.get("protocol") or "http").strip().lower() or "http"
    host = str(profile.get("host") or "").strip()
    port = int(profile.get("port", 80) or 80)
    return f"{protocol}://{host}:{port}/"


def build_bruce_listfiles_url(profile, remote_path, *, bruce_drive):
    base_url = build_bruce_base_url(profile)
    folder = normalize_bruce_remote_path(remote_path)
    query = urllib_parse.urlencode({"fs": bruce_drive, "folder": folder})
    return urllib_parse.urljoin(base_url, f"listfiles?{query}")


def build_bruce_download_url(profile, remote_path, filename, *, bruce_drive):
    base_url = build_bruce_base_url(profile)
    remote_file = posixpath.normpath(
        posixpath.join(
            normalize_bruce_remote_path(remote_path),
            str(filename or "").strip(),
        )
    )
    query = urllib_parse.urlencode(
        {"name": remote_file, "action": "download", "fs": bruce_drive}
    )
    return urllib_parse.urljoin(base_url, f"file?{query}")


def parse_bruce_listfiles_payload(payload):
    def _is_bruce_file_candidate(path_value, filename_value, href_value):
        path_lower = str(path_value or "").strip().lower()
        filename_lower = str(filename_value or "").strip().lower()
        href_lower = str(href_value or "").strip().lower()
        if "download-sd-file" in href_lower:
            return True
        return any(
            candidate.endswith(suffix)
            for candidate in (path_lower, filename_lower)
            for suffix in (
                ".pcap",
                ".cap",
                ".csv",
                ".txt",
                ".json",
                ".ini",
                ".conf",
                ".22000",
                ".pcapng",
            )
        )

    entries = []
    for raw_line in str(payload or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("pa:"):
            continue
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        entry_type, name, size = parts[0], parts[1], parts[2]
        entry_type = str(entry_type or "").strip()
        clean_name = str(name or "").strip()
        if entry_type not in {"Fi", "Fo"} or not clean_name:
            continue
        entries.append(
            {
                "type": "dir" if entry_type == "Fo" else "file",
                "filename": posixpath.basename(clean_name.rstrip("/")),
                "raw_name": clean_name,
                "size": str(size or "").strip(),
            }
        )
    if entries:
        return entries

    html_links = list_links(payload or "")
    html_entries = []
    seen = set()
    for link in html_links:
        href = str(link.get("href") or "").strip()
        text = str(link.get("text") or "").strip()
        if not href:
            continue
        path_value = extract_path_from_link(href)
        if not path_value and href.startswith("/"):
            path_value = urllib_parse.unquote(href)
        normalized_path = normalize_bruce_remote_path(path_value)
        if not normalized_path or normalized_path in {"/", "/.", "/.."}:
            continue
        filename = extract_listing_filename(href, text)
        if not filename:
            filename = posixpath.basename(normalized_path.rstrip("/"))
        if not filename or filename in {"..", "..."} or text in {"..", "..."}:
            continue
        entry_type = "file" if _is_bruce_file_candidate(normalized_path, filename, href) else "dir"
        dedupe_key = (entry_type, normalized_path.lower())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        html_entries.append(
            {
                "type": entry_type,
                "filename": filename,
                "raw_name": normalized_path,
                "size": "",
            }
        )
    return html_entries


def build_basic_auth_value(username, password):
    raw = f"{username}:{password}".encode("utf-8")
    return f"Basic {base64.b64encode(raw).decode('ascii')}"


def open_web_url(
    url,
    *,
    urllib_request_module,
    timeout=10,
    username=None,
    password=None,
):
    headers = {
        "User-Agent": "KOVIL MAP/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    if username:
        headers["Authorization"] = build_basic_auth_value(username, password or "")
    request = urllib_request_module.Request(url, headers=headers)
    return urllib_request_module.urlopen(request, timeout=timeout)


def fetch_web_text(
    url, *, urllib_request_module, username=None, password=None, timeout=10
):
    with open_web_url(
        url,
        urllib_request_module=urllib_request_module,
        timeout=timeout,
        username=username,
        password=password,
    ) as response:
        body = response.read().decode("utf-8", errors="replace")
        final_url = getattr(response, "url", url)
        headers = getattr(response, "headers", None)
        content_type = ""
        if headers is not None:
            content_type = str(headers.get("Content-Type") or "")
        return {
            "body": body,
            "url": final_url,
            "content_type": content_type,
        }


def fetch_web_binary(
    url, *, urllib_request_module, username=None, password=None, timeout=15
):
    with open_web_url(
        url,
        urllib_request_module=urllib_request_module,
        timeout=timeout,
        username=username,
        password=password,
    ) as response:
        payload = response.read()
        final_url = getattr(response, "url", url)
        headers = getattr(response, "headers", None)
        content_type = ""
        if headers is not None:
            content_type = str(headers.get("Content-Type") or "")
        return {
            "payload": payload,
            "url": final_url,
            "content_type": content_type,
        }


def extract_listing_filename(href, text):
    parsed = urllib_parse.urlparse(href or "")
    candidate = posixpath.basename(urllib_parse.unquote(parsed.path or "").rstrip("/"))
    if candidate and "." in candidate:
        return candidate
    query = urllib_parse.parse_qs(parsed.query or "", keep_blank_values=False)
    for key in ("file", "filename", "name", "path"):
        values = query.get(key) or []
        if not values:
            continue
        query_candidate = posixpath.basename(
            urllib_parse.unquote(str(values[0] or "").strip()).rstrip("/")
        )
        if query_candidate:
            return query_candidate
    text_candidate = posixpath.basename(str(text or "").strip().rstrip("/"))
    return text_candidate or ""


def looks_like_m5evil_browse_link(href, text):
    haystack = f"{href or ''} {text or ''}".strip().lower()
    return any(
        token in haystack
        for token in (
            "browse sd",
            "check sd file",
            "sd file",
            "browse",
            "files",
            "file manager",
        )
    )


def looks_like_html(payload, content_type=""):
    if "text/html" in str(content_type or "").lower():
        return True
    head = bytes(payload[:128] if isinstance(payload, (bytes, bytearray)) else b"")
    return head.lstrip().lower().startswith(
        b"<html"
    ) or head.lstrip().lower().startswith(b"<!doctype html")


def list_links(body):
    parser = LinkListingParser()
    parser.feed(body or "")
    parser.close()
    return parser.links


def extract_path_from_link(href):
    parsed = urllib_parse.urlparse(href or "")
    values = urllib_parse.parse_qs(parsed.query or "", keep_blank_values=False)
    for key in ("path", "file", "filename", "name", "dir", "folder"):
        if values.get(key):
            return str(values[key][0] or "")
    return urllib_parse.unquote(parsed.path or "")


def link_name_tokens(href, text):
    candidates = []
    extracted = extract_listing_filename(href, text)
    if extracted:
        candidates.append(extracted)
    path_value = extract_path_from_link(href)
    if path_value:
        candidates.append(posixpath.basename(path_value.rstrip("/")))
        candidates.append(path_value.rstrip("/"))
    if text:
        stripped = str(text).strip().strip("/")
        if stripped:
            candidates.append(stripped)
    return {
        str(item or "").strip().strip("/").lower()
        for item in candidates
        if str(item or "").strip().strip("/")
    }
