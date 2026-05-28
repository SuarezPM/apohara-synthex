# Synthex Performance Baselines

Documento de referencias empíricas para citar honestamente en SLIDES.

Reglas:
- Cada número viene de una corrida real, no estimado.
- Indicar host + fecha + comando para reproducir.
- Nunca extrapolar de una host/red a "universal".

---

## DigiCert TSA RTT (T0.7 baseline, v0.6.0)

**Captura:** 2026-05-28 desde `CachyOS-PC` (Pablo, AMD Ryzen 5 3600,
red doméstica UTC-3).

**Comando:** `node scripts/bench-tsa-rtt.mjs --samples 20`

**Resultado** (`logs/digicert-rtt-baseline.json`):

| Métrica | Valor |
|---|---|
| Samples requested / succeeded | 20 / 20 |
| Samples failed | 0 |
| p50 | 197 ms |
| p95 | **385 ms** |
| p99 | 451 ms |
| min | 193 ms |
| max | 451 ms |
| mean | ~225 ms |

**Gate SC-3b:** umbral 1500 ms. **PASS** (p95 384.7 ms ≈ 26 % del budget).

**Lectura honesta:**
- Estos números reflejan **un host + una red + 20 muestras** en una ventana
  de ~5 segundos. NO son universales.
- Para SLIDES decir literal: "Medido desde CachyOS-PC en 2026-05-28,
  p95 DigiCert RTT 385 ms — más datos en `logs/digicert-rtt-baseline.json`."
- El bench debe rerun antes de cada release para detectar regresiones de la
  TSA o de la red del host de demo.

**Fallback documentado:** Si en otro host p95 > 1500 ms, considerar:
- Sectigo (`http://timestamp.sectigo.com`).
- GlobalSign (`http://timestamp.globalsign.com/tsa/r6advanced1`).
- Apple (`http://timestamp.apple.com/ts01`) — solo iOS/macOS use case.

---

## Suite test runtime (v0.6.0-rc.0)

**Comando:** `npm test`
**Host:** CachyOS-PC (Pablo)
**Captura:** 2026-05-28

| Métrica | Valor |
|---|---|
| Total tests | 170 |
| Pass | 160 |
| Fail | 0 |
| Skip | 10 |
| Wall clock | ~875 ms |

(Skipped son network-dependent: tests que requieren `SYNTHEX_NETWORK_TESTS=1`.)
