"""Native archive staging and review persistence. Archives are never executed."""
import hashlib
import json
import os
import shutil
import uuid
from pathlib import Path
from .core import now, text, redact

MAX_PROJECT_BYTES = 10 * 1024**3


def initialize(store):
    with store.lock, store.connect() as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY, engagement TEXT REFERENCES engagements(id),
          filename TEXT, bytes INTEGER, sha256 TEXT, status TEXT, message TEXT, created TEXT, updated TEXT);
        CREATE TABLE IF NOT EXISTS review_runs(id TEXT PRIMARY KEY, engagement TEXT REFERENCES engagements(id),
          project TEXT REFERENCES projects(id), status TEXT, total_batches INTEGER, completed_batches INTEGER,
          failed_batches INTEGER, reviewed_events INTEGER, total_events INTEGER, message TEXT, created TEXT, completed TEXT);
        CREATE TABLE IF NOT EXISTS assessments(id TEXT PRIMARY KEY, engagement TEXT REFERENCES engagements(id),
          project TEXT REFERENCES projects(id), run TEXT REFERENCES review_runs(id), dedup TEXT, title TEXT,
          assessment TEXT, explanation TEXT, evidence TEXT, counter_evidence TEXT, false_positive_checks TEXT,
          manual_tests TEXT, disposition TEXT, created TEXT, UNIQUE(project,dedup));
        """)


def project(store, eid, pid):
    rows = store.rows("SELECT * FROM projects WHERE engagement=? AND id=?", (eid, pid))
    if not rows:
        raise KeyError("Project not found")
    row = rows[0]
    counts = store.rows("SELECT kind,count(*) AS n FROM events WHERE engagement=? AND json_extract(metadata,'$.project_id')=? GROUP BY kind", (eid, pid))
    row["counts"] = {r["kind"]: r["n"] for r in counts}
    row["in_scope_events"] = store.rows("SELECT count(*) AS n FROM events WHERE engagement=? AND json_extract(metadata,'$.project_id')=? AND scope_state='in_scope'", (eid,pid))[0]["n"]
    row["has_archive"] = row["bytes"] > 0
    return row


def projects(store, eid):
    return [project(store,eid,r["id"]) for r in store.rows("SELECT id FROM projects WHERE engagement=? ORDER BY created DESC", (eid,))]


def create_project(store, eid, filename="Opened Burp project", length=0, digest=""):
    store.engagement(eid)
    filename = text(filename, 200).replace("\\", "/").split("/")[-1].strip()
    if not filename or any(ord(c) < 32 for c in filename):
        raise ValueError("Invalid project filename")
    pid = str(uuid.uuid4())
    message = "Archive stored only. Open this project in Burp, then use the Fieldmate companion to import saved traffic and scanner issues."
    if not length:
        message = "Waiting for saved data from the opened Burp project or an exported traffic/issues file."
    store.execute("INSERT INTO projects VALUES(?,?,?,?,?,'awaiting_data',?,?,?)", (pid,eid,filename,length,digest,message,now(),now()))
    return project(store,eid,pid)


def upload(store, eid, filename, length, stream):
    store.engagement(eid)
    if not filename.lower().endswith(".burp"):
        raise ValueError("Native archive uploads must have a .burp extension")
    if not 0 < length <= MAX_PROJECT_BYTES:
        raise ValueError("Upload a .burp file between 1 byte and 10 GiB")
    directory = store.directory / "projects"
    directory.mkdir(mode=0o700,exist_ok=True)
    if shutil.disk_usage(directory).free < length + 100_000_000:
        raise ValueError("Not enough free space to retain this project archive")
    temporary = directory / (str(uuid.uuid4()) + ".upload")
    digest = hashlib.sha256()
    pid = None
    try:
        with temporary.open("xb") as output:
            os.chmod(temporary,0o600)
            remaining = length
            while remaining:
                block = stream.read(min(1024**2,remaining))
                if not block:
                    raise ValueError("Project upload was incomplete")
                output.write(block); digest.update(block); remaining -= len(block)
        value = create_project(store,eid,filename,length,digest.hexdigest())
        pid = value["id"]
        temporary.rename(directory / (pid + ".burp"))
        return value
    except Exception:
        temporary.unlink(missing_ok=True)
        if pid:
            store.execute("DELETE FROM projects WHERE id=?",(pid,))
        raise


def archive_path(store,eid,pid):
    value = project(store,eid,pid)
    if not value["has_archive"]:
        raise KeyError("This project was linked without uploading an archive")
    return store.directory / "projects" / (value["id"] + ".burp")


def ingest_batch(store,eid,pid,events):
    project(store,eid,pid)
    if not isinstance(events,list) or not 1 <= len(events) <= 100:
        raise ValueError("Project batches must contain 1–100 saved HTTP messages or scanner issues")
    records = []
    for original in events:
        if not isinstance(original,dict) or original.get("kind") not in {"http","scanner_issue"}:
            raise ValueError("Project evidence must be saved HTTP messages or scanner issues")
        event = {**original, "metadata": {**original.get("metadata",{}), "project_id":pid}}
        event["source"] = "burp-project/" + pid
        records.append(event)
    result = store.ingest(eid,records)
    store.execute("UPDATE projects SET status='importing',message='Saved evidence is arriving from Burp. No target requests are sent.',updated=? WHERE id=?",(now(),pid))
    return result


def complete_import(store,eid,pid,failed=False):
    value = project(store,eid,pid)
    total = sum(value["counts"].values())
    status = "import_failed" if failed else "ready" if total else "empty"
    message = "Import interrupted; partial evidence is retained. Retry the import before a full review." if failed else f"Imported {total} saved events; {value['in_scope_events']} are in engagement scope. This excludes Repeater-only tabs not exposed by the project API."
    store.execute("UPDATE projects SET status=?,message=?,updated=? WHERE id=?", (status,message,now(),pid))
    return project(store,eid,pid)


def runs(store,eid):
    return store.rows("SELECT * FROM review_runs WHERE engagement=? ORDER BY created DESC LIMIT 30",(eid,))


def assessments(store,eid,pid=None):
    rows = store.rows("SELECT * FROM assessments WHERE engagement=?" + (" AND project=?" if pid else "") + " ORDER BY created DESC",(eid,pid) if pid else (eid,))
    for row in rows:
        for key in ("evidence","counter_evidence","false_positive_checks","manual_tests"):
            row[key] = json.loads(row[key])
    return rows


def save_assessment(store,eid,pid,run,data):
    from .core import fingerprint
    dedup = fingerprint({"title":data["title"].lower(),"evidence":sorted(data["evidence"]),"assessment":data["assessment"]})
    store.execute("""INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?,?,?,?,'open',?) ON CONFLICT(project,dedup)
      DO UPDATE SET run=excluded.run,explanation=excluded.explanation,counter_evidence=excluded.counter_evidence,
      false_positive_checks=excluded.false_positive_checks,manual_tests=excluded.manual_tests""",
      (str(uuid.uuid4()),eid,pid,run,dedup,data["title"],data["assessment"],data["explanation"],json.dumps(data["evidence"]),
       json.dumps(data["counter_evidence"]),json.dumps(data["false_positive_checks"]),json.dumps(data["manual_tests"]),now()))


def disposition(store,eid,identifier,value):
    if value not in {"open","validated","ruled_out","needs_more_evidence"}:
        raise ValueError("Invalid tester disposition")
    if not store.rows("SELECT id FROM assessments WHERE id=? AND engagement=?",(identifier,eid)):
        raise KeyError("Review item not found")
    store.execute("UPDATE assessments SET disposition=? WHERE id=? AND engagement=?",(value,identifier,eid))
    return {"saved":True}
