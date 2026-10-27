import argparse
import json
import os
import sys
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Fieldmate — passive local pentest partner")
    parser.add_argument("--data", default=os.environ.get("FIELDMATE_DATA", str(Path.cwd() / ".fieldmate")), help="Private data directory (same for server and collectors)")
    parser.add_argument("--url", default=os.environ.get("FIELDMATE_URL", "http://127.0.0.1:8741"), help="Local dashboard address")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Start the local dashboard")
    serve.add_argument("--port", type=int, default=8741)
    serve.add_argument("--open", action="store_true", help="Open an authenticated browser tab")
    commands.add_parser("open", help="Open the dashboard using its local token")
    commands.add_parser("list", help="List engagements")
    create = commands.add_parser("create", help="Create an engagement")
    create.add_argument("name")
    create.add_argument("--scope", action="append", required=True)
    commands.add_parser("demo", help="Create an explicitly synthetic demo engagement")
    for name in ("capture", "watch", "import", "replay", "review", "report", "hook"):
        cmd = commands.add_parser(name)
        cmd.add_argument("--engagement", default=os.environ.get("FIELDMATE_ENGAGEMENT"), required=name != "hook" and not os.environ.get("FIELDMATE_ENGAGEMENT"))
        if name in {"capture", "watch", "import", "replay", "hook"}:
            cmd.add_argument("--target", default=os.environ.get("FIELDMATE_TARGET", ""), required=name == "capture" and not os.environ.get("FIELDMATE_TARGET"))
            cmd.add_argument("--identity", default=os.environ.get("FIELDMATE_IDENTITY", "unlabeled"))
        if name in {"import", "replay"}:
            cmd.add_argument("file", type=Path)
            cmd.add_argument("--format", default="auto", choices=["auto", "nmap", "burp", "har", "jsonl", "terminal", "note"])
        if name == "watch":
            cmd.add_argument("path", type=Path)
        if name == "capture":
            cmd.add_argument("--shell", help="Default: $SHELL. Bash gets command-completion hooks.")
        if name == "replay":
            cmd.add_argument("--delay", type=float, default=0.2)
            cmd.add_argument("--review-every", type=int, default=0)
        if name == "review":
            cmd.add_argument("--question", default="")
        if name == "report":
            cmd.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if args.command == "serve":
            from .server import serve
            serve(args.data, args.port, args.open)
            return
        from .client import Client
        client = Client(args.data, args.url)
        if args.command == "open":
            import webbrowser
            webbrowser.open(client.url + "/#token=" + client.token)
            return
        if args.command == "list":
            for engagement in client.call("bootstrap")["engagements"]:
                print(engagement["id"], engagement["name"])
            return
        if args.command == "create":
            print(json.dumps(client.call("engagements", {"name": args.name, "scope": args.scope}), indent=2))
        elif args.command == "demo":
            print(json.dumps(client.call("demo", {}), indent=2))
        elif args.command in {"capture", "watch", "hook"}:
            from .collect import capture, watch, shell_hook
            if args.command == "capture":
                capture(client, args.engagement, args.target, args.identity, args.shell)
            elif args.command == "watch":
                watch(client, args.engagement, args.path, args.target, args.identity)
            else:
                shell_hook(client, args.engagement, args.target, args.identity)
        elif args.command in {"import", "replay"}:
            from .ingest import parse_export
            if args.file.stat().st_size > 20_000_000:
                raise ValueError("Split files larger than 20 MB before importing")
            records = parse_export(args.file.name, args.file.read_text(errors="replace"), args.format, args.target, args.identity)
            if args.command == "import":
                print(json.dumps(client.send(args.engagement, records) if records else {"inserted": 0}, indent=2))
            else:
                if client.call(f"engagements/{args.engagement}")["total_events"]:
                    raise ValueError("Replay requires an empty engagement to avoid exposing future evidence")
                if not 0 <= args.delay <= 60 or args.review_every < 0:
                    raise ValueError("Use --delay 0–60 and --review-every >= 0")
                for i, event in enumerate(records, 1):
                    client.send(args.engagement, [event])
                    if args.review_every and i % args.review_every == 0:
                        client.call(f"engagements/{args.engagement}/review", {})
                        while True:
                            state = client.call(f"engagements/{args.engagement}")
                            if state["analyses"] and state["analyses"][0]["status"] != "running":
                                break
                            time.sleep(1)
                    time.sleep(args.delay)
                print(f"Replayed {len(records)} events in file order.")
        elif args.command == "review":
            print(json.dumps(client.call(f"engagements/{args.engagement}/review", {"question": args.question})))
        elif args.command == "report":
            from urllib.request import Request
            request = Request(client.url + f"/api/engagements/{args.engagement}/report", headers={"Authorization": "Bearer " + client.token})
            with client.opener.open(request, timeout=15) as response:
                args.output.write_bytes(response.read())
            print(f"Saved {args.output}")
    except (ValueError, OSError) as exc:
        print(f"Fieldmate: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
