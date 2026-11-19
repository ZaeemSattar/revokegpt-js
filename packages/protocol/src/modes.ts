export const MODES = Object.freeze(['invisible', 'checkbox', 'score'] as const);
export type Mode = (typeof MODES)[number];
