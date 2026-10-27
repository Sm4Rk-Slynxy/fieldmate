"""Explicitly labeled synthetic engagement for exploring the interface."""
from .ingest import record, http_record


def create_demo(store):
    e = store.create_engagement("Northstar · practice lab", ["192.168.56.0/24", "portal.example.test"],
        "SYNTHETIC DEMO DATA. Internal network and customer portal exercise. Compare two customer identities and an administrator. No real systems have been contacted.")
    eid = e["id"]
    records = []
    for port, name, product in ((443, "https", "Customer portal"), (445, "microsoft-ds", "File service"), (8080, "http", "Management interface")):
        records.append(record("service", f"192.168.56.12:{port}/tcp open · {name} · {product}", "demo/nmap.xml", "192.168.56.12",
                              metadata={"port": port, "protocol": "tcp", "service": name, "product": product, "version": ""}))
    for method, path, identity, status, body in (("GET", "/api/profile", "customer-a", 200, '{"id":"customer-a","role":"customer"}'),
        ("GET", "/api/invoices/1042", "customer-a", 200, '{"invoice":1042,"owner":"customer-a","total":240}'),
        ("GET", "/api/invoices/1042", "customer-b", 403, '{"error":"forbidden"}'),
        ("POST", "/api/admin/export", "administrator", 202, '{"job":"demo-job-1"}')):
        records.append(http_record({"url": "https://portal.example.test" + path, "method": method, "headers": []},
                                   {"status": status, "content": {"text": body, "mimeType": "application/json"}}, "demo/proxy.har", identity))
    records.append(record("terminal", "$ curl -I https://portal.example.test\nHTTP/2 200\nserver: nginx\ncontent-type: text/html", "demo/terminal", "portal.example.test", "customer-a"))
    records.append(record("note", "Invoice ownership check returned 403 for customer-b. Export endpoint has only been observed as administrator; expected access rules still need confirming.", "demo/tester-note", "portal.example.test", "customer-b"))
    result = store.ingest(eid, records)
    store.save_test(eid, {"subject": "GET https://portal.example.test/api/invoices/1042", "check_name": "authorization", "identity": "customer-b",
                         "state": "attempted", "notes": "Cross-customer read returned 403. Tested this invoice only; broader object coverage remains open.", "evidence": [result["ids"][5]]})
    from .engine import run_rules
    run_rules(store, eid)
    return e
