## 2025-05-29 - SSRF Bypass via IPv4-mapped IPv6
**Vulnerability:** The `assertSafeTarget` URL guard logic failed to block IPv4-mapped IPv6 addresses like `[::ffff:127.0.0.1]` or the unspecified IPv6 address `[::]`, potentially allowing an SSRF attack against internal or private targets.
**Learning:** The URL hostname extraction maintains the IPv6 bracket notation, allowing evasion of textual pattern matches if `[::]` or `[::ffff:...` representations are not explicitly blocked in regexes targeting `127.0.0.1` and `localhost`.
**Prevention:** Always add specific checks for IPv4-mapped IPv6 addresses (`/^\[?(0:0:0:0:0:ffff:|::ffff:)/i`) and unspecified addresses (`/^\[?::\]?$/`) when building manual URL blocklists for SSRF mitigations.

## 2026-05-30 - SSRF Array Bypass via String Coercion
**Vulnerability:** The `assertSafeTarget` URL guard could be bypassed by supplying an array of targets instead of a single string. When an array like `["https://safe.com", "http://127.0.0.1"]` is coerced to a string via `String(target)`, it becomes `"https://safe.com,http://127.0.0.1"`. This causes `new URL()` to parse `safe.com,http` as the hostname, entirely bypassing the private IP regex checks. Because `runPipeline` natively supports an array of targets, the pipeline would proceed to fetch the internal IP.
**Learning:** Type coercion can be weaponized to defeat validation logic. When building validation functions that feed into sinks that accept multiple types (e.g. string or array), the validation must handle array inputs explicitly rather than relying on implicit string coercion.
**Prevention:** Explicitly check for `Array.isArray(target)` and apply validation to each element individually before proceeding.

## 2025-03-08 - Fix SSRF blocklist bypass via trailing dots and IPv4-mapped IPv6
**Vulnerability:** Found that appending a trailing dot to a hostname (e.g. localhost.) or using IPv4-mapped IPv6 formats (e.g. [::127.0.0.1]) bypassed the literal SSRF checks in assertSafeTarget.
**Learning:** Node's URL parser preserves trailing dots in FQDNs and normalizes IPv4-mapped IPv6 addresses (like [::127.0.0.1] to [::7f00:1]), which allows bypassing strict string matching or regex filters looking for typical private IPs/hosts.
**Prevention:** Always strip the trailing dot before validating hostnames and include specific regex blocks for normalized IPv4-mapped IPv6 formats like /^\[?::(?:ffff:)?7f[0-9a-f]{2}:[0-9a-f]{1,4}\]?$/i.
