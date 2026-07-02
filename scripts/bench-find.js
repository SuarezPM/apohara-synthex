const { performance } = require('node:perf_hooks');

const safe = Array.from({ length: 10000 }, (_, i) => ({ url: `http://example.com/${i}`, content: "test" }));
const djlReviewed = Array.from({ length: 5000 }, (_, i) => ({ url: `http://example.com/${i}`, reason: "PI-1" }));
const prefReviewed = Array.from({ length: 5000 }, (_, i) => ({ url: `http://example.com/${i + 5000}`, reason: "PI-1" }));

const _isInjectionRow = () => true;

function testArrayFind() {
  const reviewBand = new Map();
  const start = performance.now();
  for (const d of [...djlReviewed, ...prefReviewed]) {
    if (reviewBand.has(d.url) || !_isInjectionRow(d)) continue;
    const doc = safe.find((s) => s.url === d.url);
    if (doc) reviewBand.set(d.url, doc);
  }
  return performance.now() - start;
}

function testMapLookup() {
  const reviewBand = new Map();
  const start = performance.now();
  const safeByUrl = new Map(safe.map(s => [s.url, s]));
  for (const d of [...djlReviewed, ...prefReviewed]) {
    if (reviewBand.has(d.url) || !_isInjectionRow(d)) continue;
    const doc = safeByUrl.get(d.url);
    if (doc) reviewBand.set(d.url, doc);
  }
  return performance.now() - start;
}

const findTime = testArrayFind();
const mapTime = testMapLookup();

console.log(`Array find time: ${findTime.toFixed(2)}ms`);
console.log(`Map lookup time: ${mapTime.toFixed(2)}ms`);
console.log(`Improvement: ${(findTime / mapTime).toFixed(1)}x`);
