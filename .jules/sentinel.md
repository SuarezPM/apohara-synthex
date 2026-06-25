## 2025-05-29 - SSRF Bypass via IPv4-mapped IPv6
**Vulnerability:** The `assertSafeTarget` URL guard logic failed to block IPv4-mapped IPv6 addresses like `[::ffff:127.0.0.1]` or the unspecified IPv6 address `[::]`, potentially allowing an SSRF attack against internal or private targets.
**Learning:** The URL hostname extraction maintains the IPv6 bracket notation, allowing evasion of textual pattern matches if `[::]` or `[::ffff:...` representations are not explicitly blocked in regexes targeting `127.0.0.1` and `localhost`.
**Prevention:** Always add specific checks for IPv4-mapped IPv6 addresses (`/^\[?(0:0:0:0:0:ffff:|::ffff:)/i`) and unspecified addresses (`/^\[?::\]?$/`) when building manual URL blocklists for SSRF mitigations.

## 2026-05-30 - SSRF Array Bypass via String Coercion
**Vulnerability:** The `assertSafeTarget` URL guard could be bypassed by supplying an array of targets instead of a single string. When an array like `["https://safe.com", "http://127.0.0.1"]` is coerced to a string via `String(target)`, it becomes `"https://safe.com,http://127.0.0.1"`. This causes `new URL()` to parse `safe.com,http` as the hostname, entirely bypassing the private IP regex checks. Because `runPipeline` natively supports an array of targets, the pipeline would proceed to fetch the internal IP.
**Learning:** Type coercion can be weaponized to defeat validation logic. When building validation functions that feed into sinks that accept multiple types (e.g. string or array), the validation must handle array inputs explicitly rather than relying on implicit string coercion.
**Prevention:** Explicitly check for `Array.isArray(target)` and apply validation to each element individually before proceeding.

## 2025-06-25 - SSRF Bypass via FQDN Trailing Dots and IPv4-Compatible IPv6
**Vulnerability:** The `assertSafeTarget` logic was vulnerable to two forms of SSRF bypass. First, passing a hostname with a trailing dot (`localhost.`) bypassed string-matching regexes because `new URL()` preserves the dot. Second, IPv4-compatible IPv6 addresses (`[::192.168.1.1]`) were normalized by `new URL()` to unmapped hex formats (like `[::c0a8:101]`), which evaded the `[::ffff:]` mapped-IPv6 blocklist.
**Learning:** URL parsers in Node.js preserve FQDN trailing dots and perform normalization on IPv4-compatible IPv6 addresses, which can convert them into hex strings that evade static allowlists.
**Prevention:** Always strip trailing dots (`u.hostname.replace(/\.$/, '')`) prior to executing hostname validation, and use comprehensive regular expressions that catch both mapped and compatible IPv6 configurations (`/^\[?::(?:ffff:)?(?:[0-9a-f]{1,4}:){0,2}[0-9a-f]{1,4}\]?$/i`) when dealing with internal SSRF filtering.
