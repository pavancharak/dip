/**
 * Change journal. Stateful components report each committed change through this
 * callback, so a durable log can rebuild their state after a restart. The callback is
 * optional: without it, state is in memory only.
 */
export type Journal = (kind: string, payload: unknown) => void;
