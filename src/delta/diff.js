// DELTA/diff — comparación entre dos snapshots normalizados.
// Granularidad: chunks de bloque semántico (<p>, <li>, <h1..6>, texto entre
// líneas en blanco). NO char-level — eso lo difiere v0.7+ tras feedback real.
//
// Output shape estable:
//   {
//     added:   [{chunk, hash}, ...]   // chunks en curr que NO están en prev
//     removed: [{chunk, hash}, ...]   // chunks en prev que NO están en curr
//     changed: []                     // reservado v0.7: chunks similares pero distintos
//   }
// "changed" hoy queda vacío: un chunk modificado se reporta como
// (removed: viejo) + (added: nuevo). v0.7+ puede emparejar por similitud y
// poblar "changed" con {before, after, similarity}.
//
// Cold start: prev=null → added contiene todos los chunks de curr.

import { createHash } from "node:crypto";

const BLOCK_SPLIT = /<\/?(?:p|li|h[1-6]|tr|article|section|div)\b[^>]*>|\n\s*\n/i;
const TAG_STRIP = /<[^>]+>/g;
const WHITESPACE_RUN = /\s+/g;

function chunksOf(text) {
  const raw = (text ?? "").split(BLOCK_SPLIT);
  const out = [];
  for (const piece of raw) {
    const clean = piece.replace(TAG_STRIP, " ").replace(WHITESPACE_RUN, " ").trim();
    if (clean.length >= 8) out.push(clean);
  }
  return out;
}

function chunkHash(chunk) {
  return createHash("sha256").update(chunk, "utf8").digest("hex").slice(0, 16);
}

/**
 * Diff entre dos snapshots normalizados. Stateless, sin IO, sin random.
 * @param {string|null} prev  contenido del snapshot previo (null = cold start)
 * @param {string} curr        contenido del snapshot actual
 * @returns {{added: Array<{chunk:string, hash:string}>, removed: Array<{chunk:string, hash:string}>, changed: Array}}
 */
export function diffSnapshots(prev, curr) {
  if (curr !== null && typeof curr !== "string") {
    throw new TypeError(`diffSnapshots curr expects string, got ${typeof curr}`);
  }
  if (prev !== null && prev !== undefined && typeof prev !== "string") {
    throw new TypeError(`diffSnapshots prev expects string|null, got ${typeof prev}`);
  }

  const currChunks = chunksOf(curr);
  if (prev === null || prev === undefined) {
    // Cold start: todo el contenido actual es "added".
    return {
      added: currChunks.map((c) => ({ chunk: c, hash: chunkHash(c) })),
      removed: [],
      changed: [],
    };
  }

  const prevChunks = chunksOf(prev);
  const prevSet = new Map(prevChunks.map((c) => [chunkHash(c), c]));
  const currSet = new Map(currChunks.map((c) => [chunkHash(c), c]));

  const added = [];
  for (const [h, c] of currSet) {
    if (!prevSet.has(h)) added.push({ chunk: c, hash: h });
  }
  const removed = [];
  for (const [h, c] of prevSet) {
    if (!currSet.has(h)) removed.push({ chunk: c, hash: h });
  }

  return { added, removed, changed: [] };
}
