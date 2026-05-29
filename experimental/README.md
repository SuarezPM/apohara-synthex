# Experimental — prior art, not wired

**EN** — `inv15-gate.js` is the JS port of the **INV-15** invariant from the
Apohara *Context_Forge* paper ([Zenodo DOI 10.5281/zenodo.20277875](https://doi.org/10.5281/zenodo.20277875)).
It exposes `computeJcrRisk` (deterministic O(1) JCR risk heuristic) and
`shouldUseDensePrefill` (force dense-prefill / KV-cache bypass for judge/critic
roles above the risk threshold). It is kept here as **cited prior art only** — it
is **not wired into the Synthex scraping pipeline**, which has no KV-cache surface
to protect (no shared judge/critic cache reuse). Cited, not claimed.

**ES** — `inv15-gate.js` es el port a JS del invariante **INV-15** del paper
*Context_Forge* de Apohara ([Zenodo DOI 10.5281/zenodo.20277875](https://doi.org/10.5281/zenodo.20277875)).
Expone `computeJcrRisk` (heurístico determinista O(1) de riesgo JCR) y
`shouldUseDensePrefill` (fuerza dense-prefill / bypass de KV-cache para roles
juez/crítico por encima del umbral de riesgo). Se conserva aquí como **prior-art
citado únicamente** — **NO está cableado al pipeline de scraping de Synthex**, que
no tiene superficie KV-cache que proteger (sin reúso de cache juez/crítico
compartida). Citado, no reclamado.

Tests: `test/experimental/inv15-gate.test.js` (`node --test`).
