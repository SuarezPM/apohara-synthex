## 2025-05-29 - SSRF Bypass via IPv4-mapped IPv6
**Vulnerability:** The `assertSafeTarget` URL guard logic failed to block IPv4-mapped IPv6 addresses like `[::ffff:127.0.0.1]` or the unspecified IPv6 address `[::]`, potentially allowing an SSRF attack against internal or private targets.
**Learning:** The URL hostname extraction maintains the IPv6 bracket notation, allowing evasion of textual pattern matches if `[::]` or `[::ffff:...` representations are not explicitly blocked in regexes targeting `127.0.0.1` and `localhost`.
**Prevention:** Always add specific checks for IPv4-mapped IPv6 addresses (`/^\[?(0:0:0:0:0:ffff:|::ffff:)/i`) and unspecified addresses (`/^\[?::\]?$/`) when building manual URL blocklists for SSRF mitigations.

## 2026-05-30 - SSRF Array Bypass via String Coercion
**Vulnerability:** The `assertSafeTarget` URL guard could be bypassed by supplying an array of targets instead of a single string. When an array like `["https://safe.com", "http://127.0.0.1"]` is coerced to a string via `String(target)`, it becomes `"https://safe.com,http://127.0.0.1"`. This causes `new URL()` to parse `safe.com,http` as the hostname, entirely bypassing the private IP regex checks. Because `runPipeline` natively supports an array of targets, the pipeline would proceed to fetch the internal IP.
**Learning:** Type coercion can be weaponized to defeat validation logic. When building validation functions that feed into sinks that accept multiple types (e.g. string or array), the validation must handle array inputs explicitly rather than relying on implicit string coercion.
**Prevention:** Explicitly check for `Array.isArray(target)` and apply validation to each element individually before proceeding.

## 2026-06-01 - SSRF Bypass via FQDN Trailing Dots and IPv6 Mapped Loopback Addresses
**Vulnerability:** The `assertSafeTarget` URL guard could be bypassed by adding a trailing dot to an FQDN (e.g., `localhost.`) or by using normalized IPv4-compatible/mapped IPv6 loopbacks (e.g., `[::127.0.0.1]` which normalizes to `[::7f00:1]`). The URL parser retains the trailing dot and normalizes the IPv6 address, bypassing the exact string matches for `localhost` and `127.0.0.1`.
**Learning:** URL parsers in Node.js normalize IP addresses and retain FQDN structures that might evade literal regex blocklists if not accounted for. Trailing dots in hostnames and IPv6 mappings are valid syntaxes that must be explicitly normalized or blocked before applying blocklist filters.
**Prevention:** Always strip trailing dots from hostnames (`hostname.replace(/\.$/, '')`) and explicitly block normalized IPv6 mapped representations (e.g., `/^\[?::(?:ffff:)?7f[0-9a-f]{2}:[0-9a-f]{1,4}\]?$/i`) before validating the URL against private host blocklists.
