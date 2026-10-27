"""Private SQLite persistence. No target traffic is generated here."""
import json
import html
import os
import re
import secrets
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from .core import now, text, clean, redact, validate_scope, in_scope, host_of, safe_url, fingerprint, KINDS, STATES

DEFAULT_SETTINGS = {"base_url": "", "model": "", "api_key": "", "vision": False,
                    "auto_analyze": False, "interval": 45, "context_chars": 24000,
                    "max_tokens": 2400, "timeout": 120, "structured": False}


def markdown_text(value):
    """Keep untrusted report text literal, including remote images and raw HTML."""
    value = html.escape(str(value), quote=False)
    return re.sub(r"([\\`*_{}\[\]()#+.!|~\-])", r"\\\1", value)


class Store:
    def __init__(self, directory):
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.directory, 0o700)
        self.path = self.directory / "fieldmate.sqlite3"
        self.lock = threading.RLock()
        token_path = self.directory / "token"
        try:
            fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                stream.write(secrets.token_urlsafe(32))
        except FileExistsError:
            pass
        os.chmod(token_path, 0o600)
        self.token = token_path.read_text().strip()
        if len(self.token) < 32:
            raise ValueError("Invalid local token file")
        with self.connect() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS engagements(id TEXT PRIMARY KEY, name TEXT, scope TEXT, notes TEXT, created TEXT);
            CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, engagement TEXT REFERENCES engagements(id), kind TEXT,
              source TEXT, target TEXT, identity TEXT, content TEXT, metadata TEXT, created TEXT, digest TEXT, scope_state TEXT,
              UNIQUE(engagement,digest));
            CREATE INDEX IF NOT EXISTS event_engagement ON events(engagement,created);
            CREATE TABLE IF NOT EXISTS tests(id TEXT PRIMARY KEY, engagement TEXT REFERENCES engagements(id), subject TEXT,
              check_name TEXT, identity TEXT, state TEXT, notes TEXT, evidence TEXT, updated TEXT,
              UNIQUE(engagement,subject,check_name,identity));
            CREATE TABLE IF NOT EXISTS suggestions(id TEXT PRIMARY KEY, engagement TEXT REFERENCES engagements(id), dedup TEXT,
              title TEXT, kind TEXT, priority TEXT, observation TEXT, next_step TEXT, rationale TEXT, evidence TEXT,
              subject TEXT, check_name TEXT, origin TEXT, state TEXT DEFAULT 'open', snooze_until TEXT DEFAULT '', created TEXT,
              UNIQUE(engagement,dedup));
            CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY, engagement TEXT REFERENCES engagements(id), title TEXT,
              severity TEXT, status TEXT, reproduction TEXT, impact TEXT, evidence TEXT, created TEXT);
            CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1), value TEXT);
            CREATE TABLE IF NOT EXISTS analyses(id TEXT PRIMARY KEY, engagement TEXT REFERENCES engagements(id), status TEXT,
              message TEXT, created TEXT, completed TEXT);
            """)
        os.chmod(self.path, 0o600)
        from .projects import initialize
        initialize(self)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def rows(self, sql, args=()):
        with self.lock, self.connect() as db:
            return [dict(row) for row in db.execute(sql, args)]

    def execute(self, sql, args=()):
        with self.lock, self.connect() as db:
            db.execute(sql, args)

    def engagement(self, eid):
        rows = self.rows("SELECT * FROM engagements WHERE id=?", (eid,))
        if not rows:
            raise KeyError("Engagement not found")
        return {**rows[0], "scope": json.loads(rows[0]["scope"])}

    def engagements(self):
        return [{**r, "scope": json.loads(r["scope"])} for r in self.rows("SELECT * FROM engagements ORDER BY created DESC")]

    def create_engagement(self, name, scope, notes=""):
        name = text(name, 160).strip()
        if not name:
            raise ValueError("An engagement name is required")
        eid = str(uuid.uuid4())
        self.execute("INSERT INTO engagements VALUES(?,?,?,?,?)", (eid, name, json.dumps(validate_scope(scope)), redact(text(notes, 10000)), now()))
        return self.engagement(eid)

    def settings(self, private=False):
        rows = self.rows("SELECT value FROM settings WHERE id=1")
        value = {**DEFAULT_SETTINGS, **(json.loads(rows[0]["value"]) if rows else {})}
        if not private:
            value["has_api_key"] = bool(value["api_key"])
            value.pop("api_key")
        return value

    def save_settings(self, patch):
        from .inference import validate_base_url
        value = self.settings(private=True)
        for key in DEFAULT_SETTINGS:
            if key in patch:
                value[key] = patch[key]
        value["base_url"] = text(value["base_url"], 1000).strip().rstrip("/")
        if value["base_url"]:
            value["base_url"] = validate_base_url(value["base_url"])
        value["model"] = text(value["model"], 500).strip()
        value["api_key"] = text(value["api_key"], 2000).strip()
        if any(c in value["api_key"] for c in "\r\n"):
            raise ValueError("Invalid API key")
        for key in ("vision", "auto_analyze", "structured"):
            if not isinstance(value[key], bool):
                raise ValueError(f"{key} must be a boolean")
        for key, lo, hi in (("interval", 20, 600), ("context_chars", 4000, 80000), ("max_tokens", 256, 8000), ("timeout", 10, 300)):
            if isinstance(value[key], bool) or not isinstance(value[key], int) or not lo <= value[key] <= hi:
                raise ValueError(f"{key} must be between {lo} and {hi}")
        self.execute("INSERT INTO settings VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value", (json.dumps(value),))
        return self.settings()

    def ingest(self, eid, records):
        engagement = self.engagement(eid)
        if not isinstance(records, list) or not 1 <= len(records) <= 10000:
            raise ValueError("Import 1–10,000 records at a time")
        prepared = []
        for record in records:
            if not isinstance(record, dict) or record.get("kind") not in KINDS:
                raise ValueError("Unsupported evidence type")
            kind = record["kind"]
            target = text(record.get("target", ""), 16000).strip()
            if target.startswith(("http://", "https://")):
                target = safe_url(target)
            if target and not host_of(target):
                raise ValueError("Invalid target")
            record = {"kind": kind, "source": text(record.get("source", "manual"), 200), "target": target,
                      "identity": text(record.get("identity", "unlabeled"), 100),
                      "content": text(record.get("content", ""), 100000), "metadata": record.get("metadata", {})}
            if not isinstance(record["metadata"], dict) or len(json.dumps(record["metadata"])) > (8000000 if kind == "screenshot" else 200000):
                raise ValueError("Invalid or oversized metadata")
            if kind == "http":
                from urllib.parse import urlsplit
                metadata = record["metadata"]
                url = safe_url(metadata.get("url", target))
                if host_of(url) != host_of(target):
                    raise ValueError("HTTP metadata and target must refer to the same host")
                method = text(metadata.get("method", "GET"), 20).upper()
                import re
                if not re.fullmatch(r"[A-Z-]+", method):
                    raise ValueError("Invalid HTTP method")
                parts = urlsplit(url)
                metadata.update({"url": url, "method": method, "endpoint": f"{method} {parts.scheme}://{parts.netloc}{parts.path}"})
                request_headers = metadata.get("request_headers", {})
                response_headers = metadata.get("response_headers", {})
                if not isinstance(request_headers, dict) or not isinstance(response_headers, dict):
                    raise ValueError("HTTP headers must be objects")
                metadata["credentials_present"] = any(str(k).lower() in {"authorization", "cookie", "x-api-key"} for k in request_headers)
                cookies = []
                for key, value in response_headers.items():
                    if str(key).lower() != "set-cookie":
                        continue
                    for line in str(value).splitlines():
                        pieces = line.split(";")
                        cookie_name = pieces[0].split("=", 1)[0].strip()[:100]
                        attributes = {p.strip().split("=", 1)[0].lower(): p.strip().split("=", 1)[-1] for p in pieces[1:]}
                        cookies.append({"cookie_name": cookie_name, "secure": "secure" in attributes, "httponly": "httponly" in attributes, "samesite": attributes.get("samesite", "unspecified")[:30]})
                if cookies:
                    metadata["cookie_attributes"] = cookies[:30]
            if kind == "service":
                metadata = record["metadata"]
                if not isinstance(metadata.get("port"), int) or isinstance(metadata["port"], bool) or not 1 <= metadata["port"] <= 65535 or metadata.get("protocol", "tcp") not in {"tcp", "udp", "sctp"}:
                    raise ValueError("Invalid service port or protocol")
            if kind == "screenshot":
                from .core import image_bytes
                raw, mime = image_bytes(record["metadata"].get("image_base64", ""))
                record["metadata"]["mime"] = mime
            record = redact(record)
            if kind == "http":
                from .ingest import http_key
                record["metadata"]["http_key"] = http_key(record["metadata"])
            elif kind == "scanner_issue":
                record["target"] = safe_url(record["target"])
                keys = record["metadata"].get("http_keys", [])
                if not isinstance(keys, list) or len(keys) > 50 or any(not isinstance(k, str) or len(k) > 100 for k in keys):
                    raise ValueError("Invalid scanner evidence references")
            state = "in_scope" if in_scope(target, engagement["scope"]) else "out_of_scope" if target else "unattributed"
            prepared.append((str(uuid.uuid4()), eid, kind, record["source"], record["target"], record["identity"], record["content"],
                             json.dumps(record["metadata"]), now(), fingerprint(record), state))
        inserted = []
        with self.lock, self.connect() as db:
            for row in prepared:
                cursor = db.execute("INSERT OR IGNORE INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?)", row)
                if cursor.rowcount:
                    inserted.append(row[0])
        return {"inserted": len(inserted), "duplicates": len(records) - len(inserted), "ids": inserted}

    def events(self, eid, limit=None, images=False):
        self.engagement(eid)
        columns = "*" if images else "id,engagement,kind,source,target,identity,content,json_remove(metadata,'$.image_base64') AS metadata,created,digest,scope_state"
        rows = self.rows(f"SELECT {columns} FROM events WHERE engagement=? ORDER BY created DESC, rowid DESC" + (" LIMIT ?" if limit else ""), (eid, limit) if limit else (eid,))
        return [{**r, "metadata": json.loads(r["metadata"])} for r in rows]

    def event(self, eid, identifier, images=False):
        columns = "*" if images else "id,engagement,kind,source,target,identity,content,json_remove(metadata,'$.image_base64') AS metadata,created,digest,scope_state"
        rows = self.rows(f"SELECT {columns} FROM events WHERE engagement=? AND id=?", (eid, identifier))
        if not rows:
            raise KeyError("Evidence not found")
        return {**rows[0], "metadata": json.loads(rows[0]["metadata"])}

    def event_summaries(self, eid):
        """Inventory needs identifiers and protocol facts, never every saved body."""
        keys = ("endpoint", "service", "port", "protocol", "method", "status")
        metadata = "json_object(" + ",".join(f"'{k}',json_extract(metadata,'$.{k}')" for k in keys) + ")"
        rows = self.rows(f"SELECT id,kind,target,identity,scope_state,{metadata} AS metadata FROM events WHERE engagement=? ORDER BY created DESC,rowid DESC", (eid,))
        return [{**r, "metadata": json.loads(r["metadata"])} for r in rows]

    def iter_events(self, eid, project_id=None, in_scope_only=False, max_rowid=None):
        """Read bounded pages without holding a database transaction over inference."""
        self.engagement(eid)
        if max_rowid is None:
            max_rowid = self.rows("SELECT coalesce(max(rowid),0) AS n FROM events WHERE engagement=?", (eid,))[0]["n"]
        before = max_rowid + 1
        while True:
            where = "engagement=? AND rowid<?"
            args = [eid, before]
            if in_scope_only:
                where += " AND scope_state='in_scope'"
            if project_id is not None:
                where += " AND json_extract(metadata,'$.project_id')=? AND kind IN ('http','scanner_issue')"
                args.append(project_id)
            rows = self.rows("SELECT rowid AS page_rowid,id,engagement,kind,source,target,identity,content,json_remove(metadata,'$.image_base64') AS metadata,created,digest,scope_state FROM events WHERE " + where + " ORDER BY rowid DESC LIMIT 64", args)
            if not rows:
                return
            before = rows[-1]["page_rowid"]
            for row in rows:
                row.pop("page_rowid")
                yield {**row, "metadata": json.loads(row["metadata"])}

    def check_evidence(self, eid, ids):
        if not isinstance(ids, list) or len(ids) > 50 or any(not isinstance(i, str) for i in ids):
            raise ValueError("Evidence must be a list of at most 50 IDs")
        if not ids:
            return []
        placeholders = ",".join("?" for _ in ids)
        valid = {r["id"] for r in self.rows(f"SELECT id FROM events WHERE engagement=? AND scope_state='in_scope' AND id IN ({placeholders})", (eid, *ids))}
        if any(i not in valid for i in ids):
            raise ValueError("Evidence must belong to this engagement and be in scope")
        return list(dict.fromkeys(ids))

    def save_test(self, eid, data):
        self.engagement(eid)
        state = data.get("state", "attempted")
        if state not in STATES:
            raise ValueError("Invalid test state")
        subject = text(data.get("subject", ""), 2000).strip()
        check = text(data.get("check_name", ""), 100).strip()
        identity = text(data.get("identity", "unlabeled"), 100)
        if not subject or not check:
            raise ValueError("A subject and check name are required")
        evidence = self.check_evidence(eid, data.get("evidence", []))
        notes = redact(text(data.get("notes", ""), 10000))
        self.execute("""INSERT INTO tests VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(engagement,subject,check_name,identity)
          DO UPDATE SET state=excluded.state,notes=excluded.notes,evidence=excluded.evidence,updated=excluded.updated""",
          (str(uuid.uuid4()), eid, subject, check, identity, state, notes, json.dumps(evidence), now()))
        return {"saved": True}

    def tests(self, eid):
        return [{**r, "evidence": json.loads(r["evidence"])} for r in self.rows("SELECT * FROM tests WHERE engagement=? ORDER BY updated DESC", (eid,))]

    def relabel(self, eid, identifier, identity, same_source=False):
        identity = clean(text(identity, 100), header_lines=False).strip()
        if not identity:
            raise ValueError("An identity label is required")
        event = self.event(eid, identifier)
        if same_source:
            self.execute("UPDATE events SET identity=? WHERE engagement=? AND source=? AND kind=?", (identity, eid, event["source"], event["kind"]))
        else:
            self.execute("UPDATE events SET identity=? WHERE engagement=? AND id=?", (identity, eid, identifier))
        return {"saved": True}

    def add_suggestion(self, eid, data, origin):
        self.engagement(eid)
        evidence = self.check_evidence(eid, data.get("evidence", []))
        if not evidence:
            raise ValueError("A suggestion needs in-scope evidence")
        kind = data.get("kind", "hypothesis")
        priority = data.get("priority", "medium")
        if kind not in {"hypothesis", "coverage", "evidence"} or priority not in {"high", "medium", "low"}:
            raise ValueError("Invalid suggestion classification")
        fields = [clean(text(data.get(k, ""), limit), header_lines=k not in {"check_name", "subject"}).strip() for k, limit in
                  (("title", 200), ("observation", 3000), ("next_step", 3000), ("rationale", 3000), ("subject", 2000), ("check_name", 100))]
        title, observation, next_step, rationale, subject, check = fields
        if not all((title, observation, next_step, subject, check)):
            raise ValueError("Suggestion is missing required fields")
        dedup = fingerprint({"subject": subject, "check": check, "kind": kind})
        sid = str(uuid.uuid4())
        self.execute("""INSERT INTO suggestions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?, 'open','',?)
          ON CONFLICT(engagement,dedup) DO UPDATE SET evidence=excluded.evidence,observation=excluded.observation,
          next_step=excluded.next_step,rationale=excluded.rationale WHERE suggestions.state='open'""",
          (sid, eid, dedup, title, kind, priority, observation, next_step, rationale, json.dumps(evidence), subject, check, origin, now()))

    def suggestions(self, eid):
        return [{**r, "evidence": json.loads(r["evidence"])} for r in self.rows("SELECT * FROM suggestions WHERE engagement=? ORDER BY CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,created DESC", (eid,))]

    def feedback(self, eid, sid, state):
        from datetime import datetime, timedelta, timezone
        if state not in {"open", "useful", "tested", "dismissed", "snoozed"}:
            raise ValueError("Invalid feedback")
        row = self.rows("SELECT * FROM suggestions WHERE id=? AND engagement=?", (sid, eid))
        if not row:
            raise KeyError("Suggestion not found")
        until = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat(timespec="milliseconds") if state == "snoozed" else ""
        self.execute("UPDATE suggestions SET state=?,snooze_until=? WHERE id=? AND engagement=?", (state, until, sid, eid))
        if state == "tested":
            r = row[0]
            check, _, identity = r["check_name"].partition(":") if r["origin"] == "rules" else (r["check_name"], "", "unlabeled")
            self.save_test(eid, {"subject": r["subject"], "check_name": check, "identity": identity or "unlabeled", "state": "attempted",
                                 "notes": "Marked already tested. Record the result and identity in Coverage.", "evidence": json.loads(r["evidence"])})
        return {"saved": True}

    def save_finding(self, eid, data):
        self.engagement(eid)
        evidence = self.check_evidence(eid, data.get("evidence", []))
        title = redact(text(data.get("title", ""), 200)).strip()
        reproduction = redact(text(data.get("reproduction", ""), 20000)).strip()
        impact = redact(text(data.get("impact", ""), 10000)).strip()
        status, severity = data.get("status", "draft"), data.get("severity", "unrated")
        if not title or status not in {"draft", "confirmed", "dismissed"} or severity not in {"unrated", "info", "low", "medium", "high", "critical"}:
            raise ValueError("Invalid finding")
        if status == "confirmed" and not (evidence and reproduction and impact):
            raise ValueError("Confirmed findings need evidence, reproduction steps, and impact")
        fid = data.get("id")
        if fid:
            if not self.rows("SELECT id FROM findings WHERE id=? AND engagement=?", (fid, eid)):
                raise KeyError("Finding not found")
            self.execute("UPDATE findings SET title=?,severity=?,status=?,reproduction=?,impact=?,evidence=? WHERE id=? AND engagement=?", (title, severity, status, reproduction, impact, json.dumps(evidence), fid, eid))
        else:
            fid = str(uuid.uuid4())
            self.execute("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?)", (fid, eid, title, severity, status, reproduction, impact, json.dumps(evidence), now()))
        return {"id": fid}

    def findings(self, eid):
        return [{**r, "evidence": json.loads(r["evidence"])} for r in self.rows("SELECT * FROM findings WHERE engagement=? ORDER BY created DESC", (eid,))]

    def report(self, eid):
        e = self.engagement(eid)
        literal = markdown_text
        parts = [f"# {literal(e['name'])}", f"Exported {now()}", "## Scope", "\n".join(f"- {literal(s)}" for s in e["scope"]), "## Engagement notes", literal(e["notes"])]
        for f in self.findings(eid):
            parts.extend([f"## {literal(f['title'])}", f"Status: {f['status']} · Severity: {f['severity']}", "### Reproduction", literal(f["reproduction"]) or "Not recorded", "### Impact", literal(f["impact"]) or "Not recorded", "### Evidence"])
            for identifier in f["evidence"]:
                event = self.event(eid, identifier)
                parts.extend([f"- {identifier} · {event['kind']} · {literal(event['target'])} · {event['created']}", "    " + event["content"][:4000].replace("\n", "\n    ")])
        from .projects import assessments
        review_items = assessments(self, eid)
        if review_items:
            parts.extend(["## Project review hypotheses", "AI assessments are advisory. Requests below are text for manual Repeater use and were never sent by Fieldmate."])
        for item in review_items:
            parts.extend([f"### {literal(item['title'])}", f"Assessment: {item['assessment']} · Tester disposition: {item['disposition']}",
                          literal(item["explanation"]), "Supporting evidence: " + ", ".join(item["evidence"]), "Counter-evidence: " + ", ".join(item["counter_evidence"]),
                          "False-positive checks:\n" + "\n".join("- " + literal(check) for check in item["false_positive_checks"])])
            for test in item["manual_tests"]:
                parts.extend([f"Manual Repeater test: {literal(test['title'])}", "Expected evidence: " + literal(test["expected"]),
                              "    " + test["request"].replace("\n", "\n    ")])
        parts.extend(["## Recorded tests", "\n".join(f"- {literal(t['subject'])} · {literal(t['check_name'])} · {literal(t['identity'])} · {t['state']}: {literal(t['notes'])}" for t in self.tests(eid)), "", "Coverage describes captured evidence; unobserved work may have happened elsewhere."])
        return "\n\n".join(parts)
