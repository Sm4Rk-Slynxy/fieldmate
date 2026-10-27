# Code and publication review — 2026-10-27

Manual review covered the Python server, ingestion/storage, model client, review validation, Repeater text generation, collectors, browser interface, Burp companion, and publication files. Local regression and end-to-end tests accompany the changes. This is not an independent security audit.

## Findings addressed

| Priority | Finding | Change |
|---|---|---|
| High | Exported reports interpolated user/model text as active Markdown/HTML, allowing remote-image references in a report viewer. | Escape report prose and headings as literal text; keep request/evidence blocks indented. |
| High | Project review and dashboard inventory loaded all saved response bodies into memory, undermining large-project handling. | Page evidence reads, stream bounded review batches, retain only the current batch lookup, use compact inventory records, and bound model context candidates. |
| Medium | Downloading a retained archive buffered the entire file in browser memory. | Stream to a user-selected file where supported; limit the fallback to 100 MiB. |
| Medium | Live Burp forwarding excerpted bodies without truncation flags, so an incomplete request could appear complete. | Record request/response truncation flags; Repeater requires restoration of a truncated request body. |
| Medium | Text redaction missed password aliases, session values, and URL user-info in free text. | Extend best-effort redaction and regression coverage. Existing private data is not retroactively rewritten. |
| Medium | Existing token-file permissions could remain wider than intended. | Restore mode 0600 on initialization. |
| Medium | Review assessments after the first 20 were retained but inaccessible from the project page. | Add Show more assessments. |
| Medium | Publication had no explicit source boundary and tests included a machine-specific home path. | Remove the path, strengthen ignore rules, add an allowlist package builder with credential/path checks, and exclude all private runtime files. |

Evidence ownership checks now query only the cited IDs rather than loading every in-scope ID for each suggestion. Report export fetches only referenced evidence instead of every response body.

## Preserved boundaries

No model-output execution or target-request transport was added. Suggestions and Repeater candidates remain text. Scope, citation validation, private inference destinations, local authentication, and human-only finding/disposition decisions remain enforced. Native `.burp` files are staged unchanged; saved-data extraction still requires the companion or a readable export.

## Remaining limits

- The 10 GiB archive boundary and 1 MiB streaming reads are tested with simulated/short streams; a real 10 GiB end-to-end transfer has not been performed.
- Compact inventory and saved assessments still scale with the number of distinct subjects/results. Reviews read evidence in pages and model batches, but cannot compare every possible request pair across batches. Full dataset recall is not guaranteed.
- General evidence review ranks at most 256 candidates before applying the configured prompt budget. Project review covers all eligible saved events at the start of that review, in separate batches. New evidence requires a later review.
- A live Unsloth installation, the installed Burp version, and real desktop sharing still need environment checks. Synthetic inference tests do not measure pentest accuracy.
- Secret redaction is best effort. Original archives and screenshot pixels can contain sensitive information. Runtime data stays private and is not included in the publication package.
- CodeRabbit CLI is signed out. Its skill requests `coderabbit auth login` before an external review; no CodeRabbit analysis was run or claimed.
