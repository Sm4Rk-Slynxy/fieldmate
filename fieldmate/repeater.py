"""HTTP request TEXT generation only. This module has no transport or execution API."""
import re
from urllib.parse import urlsplit, unquote
from .core import text, clean, safe_url

REMOVED = {"host","content-length","transfer-encoding","connection","proxy-connection","accept-encoding",":authority",":method",":path",":scheme"}
SENSITIVE = {"authorization","proxy-authorization","cookie","x-api-key"}


def replace_secrets(value):
    return re.sub(r"\[REDACTED(?:_[A-Z]+)?\]|%5BREDACTED(?:_[A-Z]+)?%5D", "<REPLACE_SECRET>",value,flags=re.I)


def template(event,changes=None):
    if event["kind"] != "http" or event["scope_state"] != "in_scope":
        raise ValueError("Repeater templates require captured in-scope HTTP evidence")
    metadata = event["metadata"]
    url = urlsplit(safe_url(metadata.get("url",event["target"])))
    changes = changes or {}
    if not isinstance(changes,dict) or set(changes) - {"method","path","headers","body"}:
        raise ValueError("Unsupported manual request changes")
    method = text(changes.get("method",metadata.get("method","GET")),20).upper()
    if not re.fullmatch(r"[A-Z-]+",method) or method in {"CONNECT","PRI"}:
        raise ValueError("Invalid manual HTTP method")
    original_path = (url.path or "/") + ("?" + url.query if url.query else "")
    path = text(changes.get("path",original_path),16000)
    if not path.startswith("/") or path.startswith("//") or any(c in path for c in "\r\n\x00 #") or "\\" in path or "\r" in unquote(path) or "\n" in unquote(path):
        raise ValueError("Manual request path must be an origin-relative path without line breaks")
    headers = {}
    for name,value in metadata.get("request_headers",{}).items():
        if name.lower() in REMOVED:
            continue
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name) or any(c in str(value) for c in "\r\n\0"):
            continue
        headers[name] = f"<YOUR_{name.upper().replace('-','_')}_VALUE>" if name.lower() in SENSITIVE else replace_secrets(str(value))
    modifications = changes.get("headers",{})
    if not isinstance(modifications,dict) or len(modifications) > 30:
        raise ValueError("Manual headers must be an object with at most 30 entries")
    for name,value in modifications.items():
        if not isinstance(name,str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+",name) or name.lower() in REMOVED:
            raise ValueError("Host, framing, and connection headers cannot be overridden")
        headers = {k:v for k,v in headers.items() if k.lower() != name.lower()}
        if value is not None:
            value = text(value,4000)
            if any(c in value for c in "\r\n\0"):
                raise ValueError("Manual headers cannot contain line breaks")
            headers[name] = replace_secrets(clean(value,header_lines=False))
    body = replace_secrets(text(changes.get("body",metadata.get("request_body","")),24000))
    warnings = ["Text only: Fieldmate has not sent this request. Paste into Burp Repeater and choose the shown destination manually.",
                "Compare baseline and candidate responses. A reflected value, status code, or scanner confidence alone is not proof."]
    if metadata.get("request_body_truncated") and "body" not in changes:
        body = "<RESTORE_COMPLETE_BODY_FROM_BURP>"
        warnings.append("The captured body was truncated; restore the complete original body before testing.")
    if "<" in body or "<" in path or any("<" in v for v in headers.values()):
        warnings.append("Replace placeholders and redacted secrets from the original project. Let Burp update Content-Length after edits.")
    lines = [f"{method} {replace_secrets(path)} HTTP/1.1", "Host: " + url.netloc]
    lines.extend(f"{name}: {value}" for name,value in headers.items())
    if body or method in {"POST","PUT","PATCH"}:
        lines.append("Content-Length: " + str(len(body.encode("utf-8"))))
    request = "\r\n".join(lines) + "\r\n\r\n" + body
    return {"evidence_id":event["id"],"destination":{"host":url.hostname,"port":url.port or (443 if url.scheme=="https" else 80),"tls":url.scheme=="https"},
            "request":request,"warnings":warnings,"never_sent":True,"modified":bool(changes)}
