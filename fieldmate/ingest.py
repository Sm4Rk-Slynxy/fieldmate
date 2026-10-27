"""Offline parsers for Nmap XML, Burp XML, HAR, JSONL, and transcripts."""
import base64
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit
from .core import safe_url, host_of, text, clean, redact, fingerprint


def http_key(metadata):
    return fingerprint(redact({k: metadata.get(k, "" if k.endswith("body") else {}) for k in
        ("url", "method", "request_headers", "request_body", "response_headers", "response_body", "status")}))


def record(kind, content, source, target="", identity="unlabeled", metadata=None):
    return {"kind": kind, "content": content, "source": source, "target": target, "identity": identity, "metadata": metadata or {}}


def xml_root(content):
    # Allow Nmap's simple <!DOCTYPE nmaprun>; reject entity declarations and subsets.
    if re.search(r"<!ENTITY|<!DOCTYPE[^>]*\[|<!DOCTYPE[^>]*(?:SYSTEM|PUBLIC)", content, re.I):
        raise ValueError("XML entities and external declarations are not supported")
    try:
        return ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError("Invalid XML export") from exc


def parse_nmap(content, source):
    root = xml_root(content)
    if root.tag != "nmaprun":
        raise ValueError("Expected a Nmap XML export")
    records = []
    for host in root.findall("host"):
        addresses = host.findall("address")
        address = next((a.get("addr") for a in addresses if a.get("addrtype") in {"ipv4", "ipv6"}), None)
        if not address:
            continue
        names = [n.get("name", "") for n in host.findall("hostnames/hostname")]
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            service = port.find("service")
            attrs = service.attrib if service is not None else {}
            number = int(port.get("portid", "0"))
            if not 1 <= number <= 65535:
                raise ValueError("Invalid port in export")
            meta = {"port": number, "protocol": port.get("protocol", "tcp"), "service": attrs.get("name", "unknown"),
                    "product": attrs.get("product", ""), "version": attrs.get("version", ""), "hostnames": names,
                    "scripts": [{"id": s.get("id", ""), "output": s.get("output", "")[:16000]} for s in port.findall("script")]}
            records.append(record("service", f"{address}:{number}/{meta['protocol']} open · {meta['service']} · {meta['product']} {meta['version']}", source, address, metadata=meta))
    return records


def header_map(headers):
    if not isinstance(headers, list):
        return {}
    return {str(h.get("name", "")): str(h.get("value", ""))[:10000] for h in headers if isinstance(h, dict)}


def http_record(request, response, source, identity, timestamp=""):
    url = safe_url(request.get("url", ""))
    method = str(request.get("method", "GET")).upper()[:20]
    status = int(response.get("status", 0) or 0)
    if not 0 <= status <= 599 or not re.fullmatch(r"[A-Z-]+", method):
        raise ValueError("Invalid HTTP method or status")
    content = response.get("content", {}) or {}
    body = str(content.get("text", ""))
    if content.get("encoding") == "base64":
        try:
            body = base64.b64decode(body, validate=True).decode("utf-8", "replace")
        except Exception as exc:
            raise ValueError("Invalid response encoding") from exc
    mime = str(content.get("mimeType", ""))
    if any(mime.startswith(prefix) for prefix in ("image/", "audio/", "video/", "application/octet-stream")):
        body = "[Binary body omitted]"
    post = request.get("postData", {}) or {}
    meta = {"url": url, "method": method, "status": status, "request_headers": header_map(request.get("headers", [])),
            "response_headers": header_map(response.get("headers", [])), "request_body": str(post.get("text", ""))[:16000],
            "response_body": body[:24000], "request_body_truncated": len(str(post.get("text", ""))) > 16000,
            "response_body_truncated": len(body) > 24000, "mime": mime, "observed_at": str(timestamp)[:100],
            "endpoint": f"{method} {urlsplit(url).scheme}://{urlsplit(url).netloc}{urlsplit(url).path}"}
    return record("http", f"{method} {url} → {status}", source, url, identity, meta)


def parse_har(content, source, identity):
    data = json.loads(content)
    entries = data.get("log", {}).get("entries")
    if not isinstance(entries, list):
        raise ValueError("Expected a HAR file with log.entries")
    return [http_record(item.get("request", {}), item.get("response", {}), source, identity, item.get("startedDateTime", "")) for item in entries]


def raw_message(element):
    if element is None:
        return ""
    raw = element.text or ""
    if element.get("base64") == "true":
        try:
            raw = base64.b64decode(re.sub(r"\s", "", raw), validate=True).decode("utf-8", "replace")
        except Exception as exc:
            raise ValueError("Invalid Burp message encoding") from exc
    return raw


def split_http(raw):
    sections = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
    lines = sections[0].splitlines()
    headers = []
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers.append({"name": name.strip(), "value": value.strip()})
    return headers, sections[1] if len(sections) > 1 else ""


def parse_burp(content, source, identity):
    root = xml_root(content)
    if root.tag == "issues":
        return parse_burp_issues(root, source, identity)
    if root.tag != "items":
        raise ValueError("Expected a Burp HTTP-history XML export")
    result = []
    for item in root.findall("item"):
        req_headers, req_body = split_http(raw_message(item.find("request")))
        res_headers, res_body = split_http(raw_message(item.find("response")))
        result.append(http_record({"url": item.findtext("url", ""), "method": item.findtext("method", "GET"), "headers": req_headers, "postData": {"text": req_body}},
                                 {"status": item.findtext("status", "0"), "headers": res_headers,
                                  "content": {"text": res_body, "mimeType": item.findtext("mimetype", "")}}, source, identity, item.findtext("time", "")))
    return result


def parse_burp_issues(root, source, identity):
    from urllib.parse import urljoin
    result = []
    for issue in root.findall("issue"):
        target = urljoin(issue.findtext("host", ""), issue.findtext("path", "/"))
        keys = []
        for pair in issue.findall("requestresponse"):
            request = raw_message(pair.find("request"))
            response = raw_message(pair.find("response"))
            request_headers, request_body = split_http(request)
            response_headers, response_body = split_http(response)
            first = request.splitlines()[0].split(" ") if request else ["GET", "/"]
            url = urljoin(target, first[1] if len(first) > 1 else "/")
            status_match = re.match(r"HTTP/\S+\s+(\d{3})", response)
            event = http_record({"url": url, "method": first[0], "headers": request_headers, "postData": {"text": request_body}},
                {"status": int(status_match[1]) if status_match else 0, "headers": response_headers, "content": {"text": response_body}}, source, identity)
            keys.append(http_key(event["metadata"]))
            result.append(event)
        metadata = {"scanner": "Burp", "name": issue.findtext("name", "Scanner observation"),
            "severity": issue.findtext("severity", "unrated"), "confidence": issue.findtext("confidence", "unknown"),
            "detail": issue.findtext("issueDetail", "")[:20000], "background": issue.findtext("issueBackground", "")[:10000],
            "http_keys": keys[:50], "scanner_reference": issue.findtext("serialNumber", "")}
        result.append(record("scanner_issue", metadata["name"], source, safe_url(target), identity, metadata))
    return result


def parse_export(filename, content, format="auto", target="", identity="unlabeled"):
    text(content, 20_000_000)
    source = filename.replace("\\", "/").split("/")[-1][:180] or "import"
    if source.lower().endswith(".burp"):
        raise ValueError("Upload native .burp files in Project review, then import saved data with the Burp companion. Native archives are not text transcripts.")
    stripped = content.lstrip("\ufeff \t\r\n")
    if format == "auto":
        if stripped.startswith("<"):
            root = xml_root(stripped)
            format = "nmap" if root.tag == "nmaprun" else "burp" if root.tag in {"items", "issues"} else "unknown"
        elif source.lower().endswith(".har") or '"log"' in stripped[:200]:
            format = "har"
        elif source.lower().endswith((".jsonl", ".ndjson")):
            format = "jsonl"
        else:
            format = "terminal"
    if format == "nmap":
        result = parse_nmap(stripped, source)
    elif format == "har":
        result = parse_har(stripped, source, identity)
    elif format == "burp":
        result = parse_burp(stripped, source, identity)
    elif format == "jsonl":
        result = []
        for line in stripped.splitlines():
            if line.strip():
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError("Each JSONL line must be an event object")
                item.setdefault("source", source)
                item.setdefault("target", target)
                item.setdefault("identity", identity)
                result.append(item)
    elif format in {"terminal", "note"}:
        content = clean(content)
        result = [record(format, content[start:start + 24000], source, target, identity) for start in range(0, len(content), 24000)]
    else:
        raise ValueError("Unsupported format. Use Nmap XML, Burp XML, HAR, JSONL, or text.")
    if len(result) > 10000:
        raise ValueError("Export contains more than 10,000 records; split it first")
    return result
