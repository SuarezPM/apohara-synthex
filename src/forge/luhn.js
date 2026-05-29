// Luhn checksum (mod-10) — used by DJL-PII-002 to gate the 13-19 digit
// credit-card-candidate regex. Filters non-CC numeric runs (order-IDs,
// tracking numbers, timestamps) that the regex would otherwise REVIEW.
//
// v0.8.0 Commit 1C (audit 2026-05-29 reviewer F10). Pure, zero-dep.
//
// Honest framing: Luhn raises *precision*, not recall. DJL-PII-002 is
// severity 7 → REVIEW (not BLOCK), so Luhn does NOT change what gets
// blocked — it cuts false REVIEW flags + false PII-gate fires on
// non-card digit runs. Does not "stop a leak."

/**
 * RFC 4226-ish mod-10 checksum. Returns true iff `digits` is a valid
 * Luhn-checked sequence of decimal digits. Strips any non-digit before
 * validating, so callers can pass "4111-1111-1111-1111" or "4111 1111
 * 1111 1111" directly without pre-normalizing.
 *
 * @param {string} digits
 * @returns {boolean}
 */
export function luhnValid(digits) {
  const ds = String(digits ?? "").replace(/\D/g, "");
  if (ds.length < 12 || ds.length > 19) return false;
  let sum = 0;
  let dbl = false;
  for (let i = ds.length - 1; i >= 0; i--) {
    let d = ds.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (dbl) { d *= 2; if (d > 9) d -= 9; }
    sum += d;
    dbl = !dbl;
  }
  return sum % 10 === 0;
}
