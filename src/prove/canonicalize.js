// CANONICALIZE — JSON canonicalization para HMAC determinista del Evidence Report v2.
// Implementación minimalista inspirada en RFC 8785 (JCS) — cubre nuestro shape de payload
// (objetos planos + arrays + strings + números enteros + booleanos + null), no es JCS-completa.
//
// Garantía clave: dos llamadas a `canonicalize(payload)` sobre objetos con MISMOS datos pero
// claves insertadas en orden distinto producen el MISMO bytestring → mismo HMAC.
//
// Comportamiento explícito para tipos no-canónicos (T3 AC#N1):
//   - `undefined`  → omitir clave (consistente con JSON.stringify default)
//   - `Date`       → TypeError ("Date object — serializar a ISO 8601 string antes")
//   - `BigInt`     → TypeError ("BigInt no soportado — usar string")
//   - `NaN`        → RangeError ("número no finito")
//   - `Infinity`   → RangeError ("número no finito")
//   - circular ref → TypeError ("referencia circular detectada")
//   - claves no-string → coerce a string + ordenar alfabéticamente
//
// NO contemplado (rechazar explícitamente vs silenciar es la elección honesta):
//   - Symbol como clave o valor (TypeError implícito porque no es enumerable)
//   - Function como valor (omitido por JSON.stringify default — aquí también)

const _seen = new WeakSet();

export function canonicalize(value) {
  _seen.clear?.(); // no es necesario para WeakSet, pero documentamos la intención
  return _stringify(value, new WeakSet());
}

function _stringify(value, seen) {
  // null antes de typeof (typeof null === "object")
  if (value === null) return "null";

  const t = typeof value;

  if (t === "undefined") return undefined; // marker — el caller decide omitir

  if (t === "boolean") return value ? "true" : "false";

  if (t === "bigint") {
    throw new TypeError("canonicalize: BigInt no soportado — usar string");
  }

  if (t === "number") {
    if (!Number.isFinite(value)) {
      throw new RangeError("canonicalize: número no finito (NaN/Infinity no soportados)");
    }
    // JSON.stringify produce la forma canónica para enteros y la mayoría de floats usuales.
    // Esto es suficiente para el shape de Synthex payload (severities, counts, timestamps int).
    return JSON.stringify(value);
  }

  if (t === "string") return JSON.stringify(value);

  if (t === "function" || t === "symbol") {
    return undefined; // omit (consistente con JSON.stringify default)
  }

  // Objects (incluye arrays, Date, plain objects). Tag detection.
  if (value instanceof Date) {
    throw new TypeError("canonicalize: Date object — serializar a ISO 8601 string antes");
  }

  if (seen.has(value)) {
    throw new TypeError("canonicalize: referencia circular detectada");
  }
  seen.add(value);

  if (Array.isArray(value)) {
    const items = value.map((v) => {
      const s = _stringify(v, seen);
      return s === undefined ? "null" : s; // JSON: undefined en array → null
    });
    seen.delete(value);
    return "[" + items.join(",") + "]";
  }

  // Plain object — claves ordenadas alfabéticamente (coerce a string).
  const keys = Object.keys(value)
    .map(String)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const parts = [];
  for (const k of keys) {
    const v = value[k];
    const ser = _stringify(v, seen);
    if (ser === undefined) continue; // omit undefined values
    parts.push(JSON.stringify(k) + ":" + ser);
  }
  seen.delete(value);
  return "{" + parts.join(",") + "}";
}
