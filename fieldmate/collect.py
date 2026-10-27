"""Opt-in terminal capture and directory watching. No commands are AI-generated."""
import codecs
import json
import os
import queue
import select
import signal
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from .core import clean, now
from .ingest import record, parse_export


def capture(client, eid, target, identity, shell=None):
    import fcntl
    import pty
    import struct
    import termios
    import tty
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError("Terminal capture needs an interactive terminal")
    client.call(f"engagements/{eid}")
    session = str(uuid.uuid4())
    pending = queue.Queue(maxsize=100)
    stop = threading.Event()

    def sender():
        while True:
            events = pending.get()
            if events is None:
                pending.task_done()
                break
            try:
                client.send(eid, events)
            except Exception:
                client.spool(events, session)
            finally:
                pending.task_done()

    worker = threading.Thread(target=sender, daemon=True)
    worker.start()
    old_settings = termios.tcgetattr(sys.stdin)
    shell = shell or os.environ.get("SHELL", "/bin/bash")
    bash = Path(shell).name == "bash"
    rc_path = None
    if bash:
        fd, rc_path = tempfile.mkstemp(prefix="fieldmate-shell-", suffix=".bash", dir=client.directory)
        with os.fdopen(fd, "w") as stream:
            stream.write('''[ -f ~/.bashrc ] && source ~/.bashrc
__fieldmate_started=0
__fieldmate_prompt() {
    local fieldmate_status=$?
    if [ "$__fieldmate_started" = 0 ]; then
        __fieldmate_started=1
        return "$fieldmate_status"
    fi
    local fieldmate_last
    fieldmate_last="$(builtin history 1)"
    FIELDMATE_LAST_COMMAND="$fieldmate_last" FIELDMATE_LAST_STATUS="$fieldmate_status" FIELDMATE_LAST_CWD="$PWD" "$FIELDMATE_PYTHON" -m fieldmate hook >/dev/null 2>&1
    return "$fieldmate_status"
}
if declare -p PROMPT_COMMAND 2>/dev/null | grep -q 'declare -a'; then
    PROMPT_COMMAND=(__fieldmate_prompt "${PROMPT_COMMAND[@]}")
else
    PROMPT_COMMAND="__fieldmate_prompt${PROMPT_COMMAND:+; $PROMPT_COMMAND}"
fi
''')
    print(f"Fieldmate recording output for {target}. Exit this shell to stop. Failed uploads are retained privately.")
    pid, master = pty.fork()
    if pid == 0:
        os.environ.update({"FIELDMATE_DATA": str(client.directory), "FIELDMATE_URL": client.url,
                          "FIELDMATE_ENGAGEMENT": eid, "FIELDMATE_TARGET": target, "FIELDMATE_IDENTITY": identity,
                          "FIELDMATE_SESSION": session, "FIELDMATE_PYTHON": sys.executable,
                          "PYTHONPATH": str(Path(__file__).parent.parent) + os.pathsep + os.environ.get("PYTHONPATH", "")})
        os.execv(shell, [shell, "--rcfile", rc_path, "-i"] if bash else [shell, "-i"])

    def resize(*_):
        try:
            dimensions = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, b"\0" * 8)
            fcntl.ioctl(master, termios.TIOCSWINSZ, dimensions)
        except OSError:
            pass

    old_winch = signal.signal(signal.SIGWINCH, resize)
    resize()
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    buffer, last, sequence = "", time.monotonic(), 0

    def flush(final=False):
        nonlocal buffer, last, sequence
        content = clean(buffer)
        buffer, last = "", time.monotonic()
        if not content.strip():
            return
        sequence += 1
        events = [record("terminal", content[:100000], "terminal/" + session, target, identity,
                         {"session": session, "sequence": sequence, "captured_at": now()})]
        if final:
            try:
                client.send(eid, events)
            except Exception:
                client.spool(events, session)
            return
        try:
            pending.put_nowait(events)
        except queue.Full:
            client.spool(events, session)

    try:
        tty.setraw(sys.stdin.fileno())
        while True:
            ready, _, _ = select.select([sys.stdin, master], [], [], 0.2)
            if sys.stdin in ready:
                data = os.read(sys.stdin.fileno(), 4096)
                if data:
                    os.write(master, data)
            if master in ready:
                try:
                    data = os.read(master, 8192)
                except OSError:
                    break
                if not data:
                    break
                os.write(sys.stdout.fileno(), data)
                buffer += decoder.decode(data)
            if buffer and (len(buffer) > 24000 or time.monotonic() - last > 2):
                flush()
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
        signal.signal(signal.SIGWINCH, old_winch)
        os.close(master)
        buffer += decoder.decode(b"", final=True)
        flush(final=True)
        # Preserve backlog privately rather than making shell exit wait on every upload.
        while True:
            try:
                unsent = pending.get_nowait()
            except queue.Empty:
                break
            client.spool(unsent, session)
            pending.task_done()
        pending.put(None)
        worker.join(timeout=12)
        os.waitpid(pid, 0)
        if rc_path:
            Path(rc_path).unlink(missing_ok=True)
        print("\nCapture stopped. Check Evidence in Fieldmate.")


def shell_hook(client, eid, target, identity):
    import re
    command = re.sub(r"^\s*\d+\s+", "", os.environ.get("FIELDMATE_LAST_COMMAND", "")).strip()
    if not command:
        return
    event = record("command", command, "shell-hook", target, identity,
                   {"cwd": os.environ.get("FIELDMATE_LAST_CWD", ""), "exit_status": int(os.environ.get("FIELDMATE_LAST_STATUS", "0")),
                    "session": os.environ.get("FIELDMATE_SESSION", ""), "completed_at": now()})
    try:
        client.send(eid, [event])
    except Exception:
        client.spool([event], os.environ.get("FIELDMATE_SESSION", "hook"))


def watch(client, eid, directory, target, identity):
    directory = Path(directory).resolve()
    if not directory.is_dir():
        raise ValueError("Watch path must be a directory")
    client.call(f"engagements/{eid}")
    seen, offsets, previous = {}, {}, {}
    print(f"Watching {directory}. Existing exports will be imported. Ctrl+C stops.", flush=True)
    try:
        while True:
            for path in directory.rglob("*"):
                if path.is_symlink() or not path.is_file() or client.directory in path.parents or any(p.startswith(".") for p in path.relative_to(directory).parts):
                    continue
                if path.suffix.lower() not in {".xml", ".har", ".jsonl", ".ndjson", ".log", ".txt"}:
                    continue
                stat = path.stat()
                signature = (stat.st_size, stat.st_mtime_ns, stat.st_ino)
                if seen.get(path) == signature or previous.get(path) != signature:
                    previous[path] = signature
                    continue
                if stat.st_size > 20_000_000:
                    print(f"Skipped oversized file: {path.name}", flush=True)
                    seen[path] = signature
                    continue
                try:
                    if path.suffix.lower() in {".log", ".txt"}:
                        prior_inode, offset = offsets.get(path, (stat.st_ino, 0))
                        if prior_inode != stat.st_ino or stat.st_size < offset:
                            offset = 0
                        with path.open("rb") as stream:
                            stream.seek(offset)
                            raw = stream.read(200000)
                        records = parse_export(path.name, raw.decode("utf-8", "replace"), "terminal", target, identity)
                        for event in records:
                            event["metadata"].update({"file_offset": offset, "inode": stat.st_ino})
                        if records:
                            client.send(eid, records)
                        offsets[path] = (stat.st_ino, offset + len(raw))
                        if offset + len(raw) < stat.st_size:
                            continue
                    else:
                        content = path.read_text(errors="replace")
                        records = parse_export(path.name, content, "auto", target, identity)
                        if records:
                            client.send(eid, records)
                    seen[path] = signature
                    print(f"Imported {path.name}", flush=True)
                except Exception as exc:
                    print(f"Could not import {path.name}: {exc}", file=sys.stderr, flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nWatcher stopped.")
