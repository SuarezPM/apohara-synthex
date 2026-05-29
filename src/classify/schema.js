// CLASSIFY/schema — strict zod validation of the four-field classification
// shape produced by parseClassification(). Layer-3 hardening (output-shape),
// orthogonal to Layer-1 DJL and Layer-2 injection-guard which both work on
// INPUT. Closes the silent-key-dropping path: parseClassification's whitelist
// would historically drop unexpected keys without trace; .strict() rejects
// them AND surfaces the rejection via onSchemaViolation so the pipeline can
// record a SCHEMA_VIOLATION decision row.
//
// Wire: see src/classify/aiml-client.js — called AFTER parseClassification(),
// BEFORE attaching emit-metadata (truncated/charsSeen/lowConfidenceTier are
// intentionally OUT of the strict shape; they live in HMAC_EXCLUDED_KEYS).
import { z } from "zod";

export const ClassificationSchema = z
  .object({
    lens: z.string().min(1),
    severity: z.number().int().min(0).max(10),
    summary: z.string().max(400),
    signals: z.array(z.string()).max(32),
  })
  .strict(); // additionalProperties:false — rejects smuggled keys

/**
 * Validate a parsed classification. Returns `{ok:true, value}` on success or
 * `{ok:false, error}` (compact reason string) on failure. NEVER throws.
 */
export function validateClassification(obj) {
  const r = ClassificationSchema.safeParse(obj);
  if (r.success) return { ok: true, value: r.data };
  const error = r.error.issues
    .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
    .join("; ");
  return { ok: false, error };
}

// Stable policy bundle version (changes only if the schema shape changes).
export const SCHEMA_POLICY_BUNDLE_VERSION = "schema-v1-strict";
