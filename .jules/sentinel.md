## 2025-05-29 - SSRF Bypass via IPv4-mapped IPv6
**Vulnerability:** The `assertSafeTarget` URL guard logic failed to block IPv4-mapped IPv6 addresses like `[::ffff:127.0.0.1]` or the unspecified IPv6 address `[::]`, potentially allowing an SSRF attack against internal or private targets.
**Learning:** The URL hostname extraction maintains the IPv6 bracket notation, allowing evasion of textual pattern matches if `[::]` or `[::ffff:...` representations are not explicitly blocked in regexes targeting `127.0.0.1` and `localhost`.
**Prevention:** Always add specific checks for IPv4-mapped IPv6 addresses (`/^\[?(0:0:0:0:0:ffff:|::ffff:)/i`) and unspecified addresses (`/^\[?::\]?$/`) when building manual URL blocklists for SSRF mitigations.

## 2026-05-30 - SSRF Array Bypass via String Coercion
**Vulnerability:** The `assertSafeTarget` URL guard could be bypassed by supplying an array of targets instead of a single string. When an array like `["https://safe.com", "http://127.0.0.1"]` is coerced to a string via `String(target)`, it becomes `"https://safe.com,http://127.0.0.1"`. This causes `new URL()` to parse `safe.com,http` as the hostname, entirely bypassing the private IP regex checks. Because `runPipeline` natively supports an array of targets, the pipeline would proceed to fetch the internal IP.
**Learning:** Type coercion can be weaponized to defeat validation logic. When building validation functions that feed into sinks that accept multiple types (e.g. string or array), the validation must handle array inputs explicitly rather than relying on implicit string coercion.
**Prevention:** Explicitly check for `Array.isArray(target)` and apply validation to each element individually before proceeding.

## 2026-05-31 - Cross-Site Scripting (XSS) via Unsanitized LLM Output
**Vulnerability:** The classification service (`src/classify/aiml-client.js`) extracted the `summary` and `signals` array fields from untrusted LLM outputs without sanitizing them. These fields could contain injected HTML tags that execute malicious scripts when rendered by downstream API consumers or the UI, leading to Stored XSS.
**Learning:** Data originating from untrusted LLM outputs must be treated as malicious. Frontend-only escaping is insufficient when multiple APIs consume this data. The data must be sanitized at the boundary before storing or broadcasting it.
**Prevention:** Always HTML-encode untrusted AI/LLM outputs (converting `<` to `&lt;`, `>` to `&gt;`, etc.) before storing or transmitting them to prevent downstream XSS. Regex-based stripping is fragile and bypassable.
