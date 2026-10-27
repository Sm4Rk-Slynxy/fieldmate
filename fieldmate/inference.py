"""Bounded LAN-only chat-completions client for Unsloth Studio."""
import http.client
import ipaddress
import json
import socket
import ssl
from urllib.parse import urlsplit

PRIVATE_NETWORKS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fc00::/7")]


def allowed_address(address):
    ip = ipaddress.ip_address(address.split("%")[0])
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    return any(ip.version == network.version and ip in network for network in PRIVATE_NETWORKS)


def validate_base_url(value):
    try:
        p = urlsplit(value)
        if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password or p.query or p.fragment:
            raise ValueError("Use an HTTP(S) LAN API URL without credentials or query parameters")
        if p.port is not None and not 1 <= p.port <= 65535:
            raise ValueError("Invalid server port")
        if p.path.rstrip("/") not in {"", "/v1"}:
            raise ValueError("Use the server address, optionally ending in /v1")
        # Validate literal addresses now. Hostnames are resolved and pinned per request.
        try:
            ipaddress.ip_address(p.hostname)
        except ValueError:
            if p.hostname != "localhost" and "." not in p.hostname and not p.hostname.replace("-", "").isalnum():
                raise ValueError("Invalid LAN hostname")
        else:
            if not allowed_address(p.hostname):
                raise ValueError("Inference must use a loopback or private LAN address")
        return value.rstrip("/") + ("/v1" if not p.path.rstrip("/") else "")
    except (TypeError, AttributeError) as exc:
        raise ValueError("Invalid inference URL") from exc


def request_json(settings, path, payload=None, timeout=None):
    base = validate_base_url(settings["base_url"])
    parts = urlsplit(base)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        addresses = socket.getaddrinfo(parts.hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise ValueError("Could not resolve the inference server hostname") from exc
    if not addresses or any(not allowed_address(a[4][0]) for a in addresses):
        raise ValueError("Inference hostname must resolve only to private LAN or loopback addresses")
    address = addresses[0][4][0]
    connection = http.client.HTTPConnection(address, port, timeout=timeout or settings["timeout"])
    body = json.dumps(payload, ensure_ascii=False).encode() if payload is not None else None
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    host += f":{port}"
    headers = {"Host": host, "Accept": "application/json", "Content-Type": "application/json"}
    if settings.get("api_key"):
        headers["Authorization"] = "Bearer " + settings["api_key"]
    try:
        # Connect to the checked IP once, preserving Host and TLS hostname verification.
        connection.connect()
        if parts.scheme == "https":
            connection.sock = ssl.create_default_context().wrap_socket(connection.sock, server_hostname=parts.hostname)
        connection.request("POST" if body is not None else "GET", parts.path + path, body, headers)
        response = connection.getresponse()
        raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("Inference response exceeded the size limit")
        if response.status != 200:
            if response.status in {401, 403}:
                raise ValueError("Unsloth rejected the API key. Check Settings → API in Unsloth Studio.")
            if response.status == 404:
                raise ValueError("API route not found. Check the Unsloth address and API version.")
            raise ValueError(f"Inference server returned HTTP {response.status}; check its model and API logs")
        try:
            value = json.loads(raw)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("Inference server returned non-JSON content") from exc
        if not isinstance(value, dict):
            raise ValueError("Invalid inference response")
        return value
    except (OSError, http.client.HTTPException) as exc:
        raise ValueError("Cannot reach the inference API. Check LAN access, port, and whether the model is loaded.") from exc
    finally:
        connection.close()


def list_models(settings):
    value = request_json(settings, "/models", timeout=10)
    models = value.get("data", [])
    if not isinstance(models, list):
        raise ValueError("The server returned an invalid model list")
    return [{"id": str(m["id"])[:500], "loaded": m.get("loaded")} for m in models if isinstance(m, dict) and isinstance(m.get("id"), str)][:200]


def completion(settings, messages):
    if not settings.get("base_url") or not settings.get("model"):
        raise ValueError("Connect your Unsloth server and select a model in Settings")
    payload = {"model": settings["model"], "messages": messages, "stream": False,
               "temperature": 0.2, "max_tokens": settings["max_tokens"],
               "enable_tools": False, "enabled_tools": [], "tool_choice": "none"}
    if settings.get("structured"):
        payload["response_format"] = {"type": "json_object"}
    value = request_json(settings, "/chat/completions", payload)
    try:
        message = value["choices"][0]["message"]
        if message.get("tool_calls"):
            raise ValueError("Model requested tools; Fieldmate does not execute them")
        content = message["content"]
        if not isinstance(content, str) or not content.strip():
            raise ValueError("Model returned no text. Increase the output budget or adjust model reasoning settings.")
        return content
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError("Invalid chat-completions response") from exc
