# Security and private data

Fieldmate is a passive, local analysis tool. It does not execute model-generated commands, send generated Repeater requests, start scans, or automatically validate findings. The terminal collector runs only the interactive shell explicitly started by its user.

## Storage

The default `.fieldmate/` directory contains private engagement evidence, original Burp archives, screenshots, the dashboard token, and the configured inference API key. It is excluded from source control. Keep custom `--data` directories outside the repository or in an explicitly ignored directory. Application storage is not encrypted.

Original `.burp` archives and screenshot pixels are not redacted. Text redaction is best effort. Account names, target addresses, client names, business data, and unusual credentials can remain in captured evidence. Never publish real captures or use them as README illustrations.

The dashboard binds to `127.0.0.1`. API requests require the local bearer token and pass Host/Origin checks. Inference is restricted to loopback or private LAN addresses, pins validated DNS answers, and does not follow redirects. Your configured inference server receives selected evidence; use a trusted local model. HTTP LAN inference traffic is unencrypted unless you configure HTTPS.

## Reporting a vulnerability

Do not put credentials, client traffic, or an exploitable issue containing private evidence in a public issue. When available, use the repository's GitHub private vulnerability reporting feature. Remove unrelated client evidence from any minimal reproduction.

The project has not received an independent security audit. See `REVIEW.md` and `VERIFICATION.md` for what was checked and the remaining limits.
