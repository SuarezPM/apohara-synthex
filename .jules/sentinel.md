## 2025-05-29 - SSRF Bypass via IPv4-mapped IPv6
**Vulnerability:** The `assertSafeTarget` URL guard logic failed to block IPv4-mapped IPv6 addresses like `[::ffff:127.0.0.1]` or the unspecified IPv6 address `[::]`, potentially allowing an SSRF attack against internal or private targets.
**Learning:** The URL hostname extraction maintains the IPv6 bracket notation, allowing evasion of textual pattern matches if `[::]` or `[::ffff:...` representations are not explicitly blocked in regexes targeting `127.0.0.1` and `localhost`.
**Prevention:** Always add specific checks for IPv4-mapped IPv6 addresses (`/^\[?(0:0:0:0:0:ffff:|::ffff:)/i`) and unspecified addresses (`/^\[?::\]?$/`) when building manual URL blocklists for SSRF mitigations.

## 2026-05-30 - SSRF Array Bypass via String Coercion
**Vulnerability:** The `assertSafeTarget` URL guard could be bypassed by supplying an array of targets instead of a single string. When an array like `["https://safe.com", "http://127.0.0.1"]` is coerced to a string via `String(target)`, it becomes `"https://safe.com,http://127.0.0.1"`. This causes `new URL()` to parse `safe.com,http` as the hostname, entirely bypassing the private IP regex checks. Because `runPipeline` natively supports an array of targets, the pipeline would proceed to fetch the internal IP.
**Learning:** Type coercion can be weaponized to defeat validation logic. When building validation functions that feed into sinks that accept multiple types (e.g. string or array), the validation must handle array inputs explicitly rather than relying on implicit string coercion.
**Prevention:** Explicitly check for `Array.isArray(target)` and apply validation to each element individually before proceeding.

## 2024-06-24 - SSRF Bypasses via Node.js Normalization
**Vulnerability:** The SSRF blocklist in `src/guard.js` could be bypassed using Fully Qualified Domain Names (FQDNs) with a trailing dot (e.g., `localhost.`) or through Node.js URL parser's normalization of IPv4-mapped IPv6 addresses (e.g., `[::127.0.0.1]` normalizing to `[::7f00:1]`).
**Learning:** Node's `new URL()` implementation preserves FQDN trailing dots and normalizes IPv4-mapped IPv6 addresses to hex format, bypassing simple regex matching if these exact behaviors are not accounted for in blocklists.
**Prevention:** Always strip trailing dots (`.replace(/\.$/, '')`) from the `hostname` after parsing with `new URL()` but before running regex checks, and explicitly include regex rules to block all normalized IPv6 formats if IPv6 is disallowed or if the application blocklists private ranges.
