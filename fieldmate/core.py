"""Validation, scope matching, and best-effort secret minimization."""
import base64
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit

STATES = {"unobserved", "suggested", "attempted", "inconclusive", "confirmed", "dismissed"}
KINDS = {"terminal", "command", "http", "service", "note", "screenshot", "scanner_issue"}
SECRET = re.compile(r"^(authorization|proxy-authorization|cookie|set-cookie|password|passwd|pwd|secret|token|access_token|refresh_token|api[-_]?key|x-api-key|client_secret|session(?:id|_id)?)$", re.I)
ANSI = re.compile(r"\x1b(?:\][^\x07]*(?:\x07|\x1b\\)|\[[0-?]*[ -/]*[@-~])")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def text(value, limit=100_000):
    if not isinstance(value, str):
        raise ValueError("Expected text")
    if len(value) > limit:
        raise ValueError(f"Text exceeds {limit:,} characters")
    return value


def clean(value, header_lines=True):
    value = ANSI.sub("", value).replace("\r\n", "\n").replace("\r", "\n")
    if header_lines:
        value = re.sub(r"(?im)^((?:proxy-)?authorization|(?:set-)?cookie|x-api-key)(\s*:\s*)[^\n]*", r"\1\2[REDACTED]", value)
    value = re.sub(r"(?i)(\b(?:password|passwd|pwd|secret|access_token|refresh_token|api[-_]?key|client_secret|token|session(?:id|_id)?)\b[\"']?\s*[:=]\s*)(?:\"[^\"]*\"|'[^']*'|[^\s&,;}]+)", r"\1[REDACTED]", value)
    value = re.sub(r"(?i)(--(?:password|passwd|token|api-key|secret)\s+)(?:\"[^\"]*\"|'[^']*'|\S+)", r"\1[REDACTED]", value)
    value = re.sub(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "[REDACTED_JWT]", value)
    value = re.sub(r"\bsk-(?:unsloth-)?[A-Za-z0-9_-]{12,}\b", "[REDACTED_KEY]", value)
    value = re.sub(r"(?s)-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]", value)
    value = re.sub(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^\s/@]+(?::[^\s/@]*)?@", r"\1[REDACTED]@", value)
    return "".join(c for c in value if c in "\n\t" or ord(c) >= 32)


def redact(value, depth=0):
    if depth > 15:
        raise ValueError("Data nesting is too deep")
    if isinstance(value, dict):
        # HAR-style {name: Authorization, value: ...} needs pair-aware masking.
        if SECRET.fullmatch(str(value.get("name", ""))):
            return {str(k): "[REDACTED]" if k == "value" else redact(v, depth + 1) for k, v in value.items()}
        identifiers = {"identity", "source", "kind", "check_name", "subject", "endpoint", "protocol", "method", "service"}
        return {str(k): "[REDACTED]" if SECRET.fullmatch(str(k)) else clean(v, header_lines=False) if k in identifiers and isinstance(v, str) else redact(v, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, depth + 1) for v in value]
    if isinstance(value, str):
        return clean(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    raise ValueError("Unsupported data value")


def safe_url(value):
    parts = urlsplit(text(value, 16_000))
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("Expected an HTTP or HTTPS URL")
    host = parts.hostname.lower().rstrip(".")
    hostpart = f"[{host}]" if ":" in host else host
    if parts.port:
        hostpart += f":{parts.port}"
    query = urlencode([(k, "[REDACTED]" if SECRET.fullmatch(k) else clean(v)) for k, v in parse_qsl(parts.query, keep_blank_values=True)])
    return urlunsplit((parts.scheme, hostpart, parts.path or "/", query, ""))


def host_of(value):
    value = text(value, 16_000).strip()
    if not value:
        return ""
    if "://" in value:
        return (urlsplit(value).hostname or "").lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except ValueError:
        return (urlsplit("//" + value).hostname or "").lower().rstrip(".")


def validate_scope(entries):
    if isinstance(entries, str):
        entries = entries.splitlines()
    if not isinstance(entries, list) or not entries or len(entries) > 200:
        raise ValueError("Add 1–200 scope entries: hosts, URLs, CIDRs, or *.example.test")
    result = []
    for entry in entries:
        entry = text(entry, 500).strip().lower()
        if not entry:
            continue
        if "/" in entry and "://" not in entry:
            entry = str(ipaddress.ip_network(entry, strict=False))
        else:
            wildcard = entry.startswith("*.")
            entry = host_of(entry[2:] if wildcard else entry)
            if not entry or not re.fullmatch(r"[a-z0-9.:-]+", entry):
                raise ValueError("Invalid scope entry")
            entry = ("*." if wildcard else "") + entry
        result.append(entry)
    if not result:
        raise ValueError("At least one scope entry is required")
    return list(dict.fromkeys(result))


def in_scope(target, entries):
    host = host_of(target)
    if not host:
        return False
    for entry in entries:
        if host == entry or (entry.startswith("*.") and host.endswith(entry[1:]) and host != entry[2:]):
            return True
        if "/" in entry:
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(entry):
                    return True
            except ValueError:
                pass
    return False


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def image_bytes(encoded):
    value = text(encoded, 8_000_000)
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("Invalid image encoding") from exc
    if raw.startswith(b"\x89PNG\r\n\x1a\n"):
        mime = "image/png"
    elif raw.startswith(b"\xff\xd8\xff"):
        mime = "image/jpeg"
    else:
        raise ValueError("Only PNG and JPEG screenshots are supported")
    if len(raw) > 5_000_000:
        raise ValueError("Screenshot exceeds 5 MB")
    return raw, mime
