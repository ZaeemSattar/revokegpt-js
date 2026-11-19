import { z } from 'zod';
import { ANNOTATION_REASONS } from './api/assessments.js';

/**
 * The message the edge enqueues for each accepted `:annotate` call and the jobs consumer writes
 * (M6 Task 7). It is internal, not part of the public API: one schema for both sides so they cannot
 * drift. `tid` is 32 lowercase hex characters, `iat` Unix seconds (the assessment's creation time),
 * `receivedAt` Unix milliseconds (when the edge accepted the call). The assessment's `aid` already
 * binds `tid`, `iat`, the score and the mode to the site, so the consumer trusts the edge's decode.
 */
export const ANNOTATION_QUEUE_VERSION = 1;

export const AnnotationMessage = z
  .strictObject({
    v: z.literal(ANNOTATION_QUEUE_VERSION),
    siteId: z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/),
    aid: z.string().regex(/^[A-Za-z0-9_-]{42}$/),
    tid: z.string().regex(/^[0-9a-f]{32}$/),
    iat: z.number().int().min(0).max(0xffffffff),
    scoreTenths: z.number().int().min(0).max(10),
    mode: z.number().int().min(0).max(3),
    annotation: z.enum(['LEGITIMATE', 'FRAUDULENT']).nullable(),
    reasons: z.array(z.enum(ANNOTATION_REASONS)).max(14),
    receivedAt: z.number().int().min(0),
  })
  .refine((m) => m.annotation !== null || m.reasons.length > 0);
export type AnnotationMessage = z.infer<typeof AnnotationMessage>;
