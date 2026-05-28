# DJL parity — Synthex (JS) vs Aegis (Python)

**Status (post Commit D)**: a documentar tras correr `npm test test/djl.test.js`.

Este archivo registra cualquier divergencia entre `src/forge/djl.js` (port JS standalone) y
`apohara-aegis/apohara_aegis/djl.py @ f24d957f7edc8e9054226c0d70a6adc617fa48f8` (Python source
of truth).

## Disciplina

- **Conteo de reglas correcto** (CRIT-1 ronda 1 del flujo ralplan): usar
  `grep -nE 'id="DJL-' apohara-aegis/apohara_aegis/djl.py | wc -l` (cuenta definiciones, NO
  docstrings). `grep -c '"DJL-..."'` duplica menciones porque `DJL-PI-001` aparece en el
  docstring de `DjlRule` línea 55. La verdad verificada es **78 reglas**.

- **Toda regla con `severity >= 8`** que diverja entre Python y JS bloquea merge sin
  excepción (escape hatch `SYNTHEX_ALLOW_SEV8_DIVERGENCE=1` solo para debug local, jamás CI).

- **Tasa global de paridad ≥ 95%** (74/78) para que `npm test` pase. Cualquier divergencia
  bajo ese threshold debe documentarse aquí con: `(rule_id, fixture, comportamiento Python,
  comportamiento JS, root cause, decisión: fix-en-port | fix-en-Aegis | accept)`.

- **Diferencias regex Python↔ECMAScript** documentadas como contexto:
  - Python `re.IGNORECASE` ↔ JS `/i` — 1:1.
  - Lookbehind variable-width: Python sí, ECMAScript hasta hace poco solo fixed-width. Las
    reglas DJL usan solo lookbehind fixed-width (DJL-PII-008: `(?<!\d)\d{11}(?!\d)`).
  - `re.VERBOSE`: Python sí, JS no. Las reglas DJL no usan VERBOSE — todos los patterns son
    de una línea o concatenados explícitamente.
  - Unicode property escapes: ambos lo soportan; JS necesita flag `u` para `\p{...}` literal,
    pero las reglas DJL usan ranges literales (`[Ѐ-ӿͰ-Ͽ]`) que funcionan sin flag.
  - Bidi controls (DJL-PI-011): caracteres literales en ambos. JS los acepta en regex
    literal directamente.

## Divergencias registradas

(vacío al cierre de Commit D si la paridad es 78/78)

| rule_id | severity | kind | fixture (truncated) | python verdict | js verdict | root cause | decision |
|---------|----------|------|---------------------|----------------|------------|------------|----------|

## Re-port futuro

Cuando Aegis avance:
1. `git -C apohara-aegis pull && git -C apohara-aegis rev-parse HEAD` → nuevo sha pin.
2. `diff apohara-aegis/apohara_aegis/djl.py <commit anterior>` para ver qué reglas cambiaron.
3. Re-port quirúrgico de las reglas afectadas en `src/forge/djl.js`.
4. Actualizar sha pin en headers de `src/forge/djl.js` y `test/djl-fixtures.js` (los dos
   deben matchear — verificado por T4 AC#N4 assert mecánico).
5. Re-correr `npm test test/djl.test.js` para validar paridad post-actualización.
6. Si paridad cae < 95% o aparece nueva divergencia en `severity >= 8`, NO mergear:
   abrir issue paralelo en Aegis o documentar aquí con root cause antes de hacer el bump.

## Follow-up FU-8 (post-hackathon)

Pyodide-en-CI para paridad estricta: `npm run test:parity-strict` carga `djl.py` real vía
Pyodide y compara verdict-por-verdict contra `djl.js` sobre las 156 fixtures (78 positivos +
78 negativos). No toca runtime de Synthex — solo CI dev. Cierra R1 estructuralmente sin
pagar el coste de Pyodide en bundle. Estimado: 3-4h.
