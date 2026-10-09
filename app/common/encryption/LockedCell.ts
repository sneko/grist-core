/**
 * What members of an encrypted document see in place of private values they can't read (see
 * ColumnPrivacy.ts), in their data engine and in the document (which displays it as a lock). In a
 * module of its own, as the rest of the client uses it without loading the encryption code.
 */
export const LOCKED_CELL = "locked";

export function isLockedCell(value: unknown): boolean {
  return value === LOCKED_CELL;
}
