import { z } from 'zod';
import { API_ERROR_CODES } from '../errors.js';

export const ApiError = z.looseObject({
  error: z.looseObject({
    code: z
      .string()
      .max(64)
      .meta({
        description: `Known codes: ${API_ERROR_CODES.join(', ')}. Clients must tolerate new codes.`,
      }),
    message: z.string().max(1024),
    requestId: z.string().max(128),
  }),
});
export type ApiError = z.infer<typeof ApiError>;
