"""Local collector client. Failed sends are retained as private, redacted JSONL."""
import json
import os
from pathlib import Path
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler
from urllib.parse import urlsplit
from .core import redact


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Client:
    def __init__(self, directory, url="http://127.0.0.1:8741"):
        self.directory = Path(directory).resolve()
        self.url = url.rstrip("/")
        p = urlsplit(self.url)
        if p.scheme != "http" or p.hostname not in {"127.0.0.1", "localhost"} or p.path not in {"", "/"} or p.query or p.fragment or p.username or p.password:
            raise ValueError("Collectors connect only to the local Fieldmate dashboard")
        self.token = (self.directory / "token").read_text().strip()
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def call(self, path, data=None):
        raw = json.dumps(data).encode() if data is not None else None
        request = Request(self.url + "/api/" + path, data=raw,
                          headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=10) as response:
                return json.load(response)
        except Exception as exc:
            from urllib.error import HTTPError
            if isinstance(exc, HTTPError):
                try:
                    message = json.load(exc).get("error", "Local API rejected the request")
                except Exception:
                    message = "Local API rejected the request"
                raise ValueError(message) from exc
            raise ValueError("Cannot reach Fieldmate. Start the dashboard first and check --data/--url.") from exc

    def send(self, eid, events):
        return self.call(f"engagements/{eid}/events", {"events": events})

    def spool(self, events, session):
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.directory / f"unsent-{session}.jsonl"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as stream:
            for event in events:
                stream.write(json.dumps(redact(event), ensure_ascii=False) + "\n")
        return path
