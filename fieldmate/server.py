"""Authenticated loopback-only HTTP app, using only Python's standard library."""
import base64
import json
import logging
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, unquote
from . import __version__
from .core import text, image_bytes, now
from .engine import AnalysisManager, snapshot
from .ingest import parse_export, record
from .inference import list_models
from .store import Store

LOG = logging.getLogger("fieldmate")
STATIC = Path(__file__).parent / "static"
MAX_BODY = 24_000_000


class AppServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, store):
        if address[0] != "127.0.0.1":
            raise ValueError("The dashboard must bind to 127.0.0.1")
        self.store = store
        self.manager = AnalysisManager(store)
        super().__init__(address, Handler)
        self.allowed_hosts = {f"127.0.0.1:{self.server_port}", f"localhost:{self.server_port}"}
        store.execute("UPDATE analyses SET status='failed',message='Server restarted during review; please retry.',completed=? WHERE status='running'", (now(),))
        store.execute("UPDATE review_runs SET status='interrupted',message='Server restarted; previous results are retained. Start a new review.',completed=? WHERE status='running'", (now(),))

    def server_close(self):
        self.manager.stop.set()
        self.manager.cancel_event.set()
        super().server_close()


class Handler(BaseHTTPRequestHandler):
    server_version = "Fieldmate"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, format, *args):
        # Do not log paths, authorization headers, or user evidence.
        pass

    def send(self, status, data, mime="application/json; charset=utf-8", download=False):
        if isinstance(data, (dict, list)):
            data = json.dumps(data, ensure_ascii=False).encode()
        elif isinstance(data, str):
            data = data.encode()
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; media-src blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=(), display-capture=(self)")
        if download:
            self.send_header("Content-Disposition", 'attachment; filename="fieldmate-report.md"')
        self.end_headers()
        self.wfile.write(data)

    def guard(self, auth=True):
        if self.headers.get("Host") not in self.server.allowed_hosts:
            raise PermissionError("Invalid local host")
        origin = self.headers.get("Origin")
        if origin and origin not in {"http://" + host for host in self.server.allowed_hosts}:
            raise PermissionError("Cross-origin requests are not allowed")
        if auth:
            supplied = self.headers.get("Authorization", "")
            if not secrets.compare_digest(supplied, "Bearer " + self.server.store.token):
                raise PermissionError("A valid local access token is required")

    def body(self):
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            raise ValueError("Use application/json")
        if self.headers.get("Transfer-Encoding"):
            raise ValueError("Chunked requests are not supported")
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= MAX_BODY:
            raise ValueError("Request exceeds 24 MB or has no body")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError("Incomplete request")
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Expected a JSON object")
        return data

    def do_GET(self):
        self.dispatch("GET")

    def do_POST(self):
        self.dispatch("POST")

    def dispatch(self, method):
        try:
            self.route(method)
        except PermissionError as exc:
            self.send(403, {"error": str(exc)})
        except KeyError as exc:
            self.send(404, {"error": str(exc.args[0])})
        except (ValueError, TypeError, OverflowError, RecursionError) as exc:
            self.send(400, {"error": str(exc)[:500]})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception:
            LOG.exception("Request failed")
            self.send(500, {"error": "Local server error; see the terminal log"})

    def route(self, method):
        path = urlsplit(self.path).path
        store = self.server.store
        if method == "GET" and path in {"/", "/app.js", "/style.css", "/icon.svg"}:
            self.guard(auth=False)
            name = {"/": "index.html"}.get(path, path[1:])
            mime = {"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8", "icon.svg": "image/svg+xml"}[name]
            self.send(200, (STATIC / name).read_bytes(), mime)
            return
        self.guard()
        if method == "GET" and path == "/api/bootstrap":
            self.send(200, {"version": __version__, "engagements": store.engagements(), "settings": store.settings()})
            return
        segments = path.strip("/").split("/")
        if method == "POST" and len(segments)==4 and segments[:2]==["api","engagements"] and segments[3]=="projects" and self.headers.get("Content-Type","").split(";")[0]=="application/octet-stream":
            from .projects import upload
            if self.headers.get("Transfer-Encoding"):
                raise ValueError("Project uploads require Content-Length")
            self.connection.settimeout(120)
            value = upload(store,segments[2],unquote(self.headers.get("X-Filename","")),int(self.headers.get("Content-Length","0")),self.rfile)
            self.send(201,value)
            return
        data = self.body() if method == "POST" else {}
        if method == "POST" and path == "/api/engagements":
            self.send(201, store.create_engagement(data.get("name", ""), data.get("scope", []), data.get("notes", "")))
            return
        if method == "POST" and path == "/api/settings":
            self.send(200, store.save_settings(data))
            return
        if method == "POST" and path == "/api/models":
            # Uses saved configuration, so an API key is never echoed to the browser.
            self.send(200, {"models": list_models(store.settings(private=True))})
            return
        if method == "POST" and path == "/api/demo":
            from .demo import create_demo
            self.send(201, create_demo(store))
            return
        segments = path.strip("/").split("/")
        if len(segments) < 3 or segments[:2] != ["api", "engagements"]:
            raise KeyError("Route not found")
        eid = segments[2]
        store.engagement(eid)
        action = segments[3] if len(segments) > 3 else ""
        if action=="projects":
            from . import projects
            if len(segments)==4:
                if method=="GET":
                    self.send(200,projects.projects(store,eid))
                elif method=="POST":
                    self.send(201,projects.create_project(store,eid,data.get("filename","Opened Burp project")))
                else:
                    raise KeyError("Route not found")
                return
            pid = segments[4]
            value = projects.project(store,eid,pid)
            operation = segments[5] if len(segments)>5 else ""
            if method=="GET" and not operation:
                self.send(200,value)
            elif method=="GET" and operation=="archive":
                filename = projects.archive_path(store,eid,pid)
                self.send_response(200)
                self.send_header("Content-Type","application/octet-stream")
                self.send_header("Content-Length",str(filename.stat().st_size))
                self.send_header("Content-Disposition",f'attachment; filename="{pid}.burp"')
                self.send_header("Cache-Control","no-store")
                self.send_header("X-Content-Type-Options","nosniff")
                self.end_headers()
                with filename.open("rb") as stream:
                    import shutil
                    shutil.copyfileobj(stream,self.wfile,1024**2)
            elif method=="POST" and operation=="batches":
                self.send(201,projects.ingest_batch(store,eid,pid,data.get("events")))
            elif method=="POST" and operation=="complete":
                if not isinstance(data.get("failed",False),bool):
                    raise ValueError("failed must be a boolean")
                self.send(200,projects.complete_import(store,eid,pid,data.get("failed",False)))
            elif method=="POST" and operation=="export":
                records = parse_export(text(data.get("filename","export.xml"),200),text(data.get("content",""),20_000_000),data.get("format","auto"),"",text(data.get("identity","unlabeled"),100))
                total=0
                for start in range(0,len(records),100):
                    total += projects.ingest_batch(store,eid,pid,records[start:start+100])["inserted"]
                self.send(201,{"inserted":total,"project":projects.complete_import(store,eid,pid)})
            elif method=="POST" and operation=="review":
                self.send(202,self.server.manager.start(eid,project_id=pid))
            else:
                raise KeyError("Route not found")
        elif method=="GET" and action=="repeater" and len(segments)==5:
            from .repeater import template
            self.send(200,template(store.event(eid,segments[4])))
        elif method=="POST" and action=="review-cancel":
            self.send(200,self.server.manager.cancel(eid,data.get("id")))
        elif method=="POST" and action=="assessment-disposition":
            from .projects import disposition
            self.send(200,disposition(store,eid,data.get("id"),data.get("disposition")))
        elif method == "GET" and not action:
            self.send(200, snapshot(store, eid))
        elif method == "GET" and action == "events" and len(segments) == 5:
            self.send(200, store.event(eid, segments[4]))
        elif method == "GET" and action == "image" and len(segments) == 5:
            event = store.event(eid, segments[4], images=True)
            if event["kind"] != "screenshot":
                raise KeyError("Image not found")
            raw, mime = image_bytes(event["metadata"]["image_base64"])
            self.send(200, raw, mime)
        elif method == "GET" and action == "report":
            self.send(200, store.report(eid), "text/markdown; charset=utf-8", download=True)
        elif method == "POST" and action == "events":
            self.send(201, store.ingest(eid, data.get("events")))
        elif method == "POST" and action == "import":
            records = parse_export(text(data.get("filename", "import"), 200), text(data.get("content", ""), 20_000_000),
                                   data.get("format", "auto"), text(data.get("target", ""), 16000), text(data.get("identity", "unlabeled"), 100))
            self.send(201, store.ingest(eid, records) if records else {"inserted": 0, "duplicates": 0, "ids": []})
        elif method == "POST" and action == "screenshot":
            target = text(data.get("target", ""), 16000).strip()
            if not target:
                raise ValueError("Label screenshots with their target")
            raw, mime = image_bytes(data.get("image_base64", ""))
            self.send(201, store.ingest(eid, [record("screenshot", text(data.get("content", "Screen capture"), 3000), "screen", target,
                text(data.get("identity", "unlabeled"), 100), {"image_base64": base64.b64encode(raw).decode(), "mime": mime})]))
        elif method == "POST" and action == "tests":
            self.send(200, store.save_test(eid, data))
        elif method == "POST" and action == "attribution":
            if not isinstance(data.get("same_source", False), bool):
                raise ValueError("same_source must be a boolean")
            self.send(200, store.relabel(eid, data.get("id"), data.get("identity"), data.get("same_source", False)))
        elif method == "POST" and action == "feedback":
            self.send(200, store.feedback(eid, data.get("id"), data.get("state")))
        elif method == "POST" and action == "findings":
            self.send(200, store.save_finding(eid, data))
        elif method == "POST" and action == "review":
            self.send(202, self.server.manager.start(eid, text(data.get("question", ""), 4000)))
        else:
            raise KeyError("Route not found")


def serve(directory, port=8741, open_browser=False):
    store = Store(directory)
    server = AppServer(("127.0.0.1", port), store)
    thread = threading.Thread(target=server.manager.schedule, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/#token={store.token}"
    print(f"Fieldmate {__version__} · passive pentest partner", flush=True)
    print(f"Dashboard: http://127.0.0.1:{server.server_port}", flush=True)
    print(f"Local access token: {store.directory / 'token'}", flush=True)
    print("Use --open to launch an authenticated browser tab. Ctrl+C stops the server.", flush=True)
    if open_browser:
        import webbrowser
        webbrowser.open(url)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
