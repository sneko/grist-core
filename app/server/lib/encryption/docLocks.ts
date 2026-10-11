/**
 * Documents locked for a while by one member, e.g. while being converted to or from encryption
 * (see EncryptionConversion.ts): others can't open or change them until it's done, and see that
 * it's in progress. Locks are held in memory by the doc worker serving the document (the one that
 * any opening or change goes through), and released if their holder disconnects.
 */
import { ApiError } from "app/common/ApiError";
import { DocLockInfo } from "app/common/encryption/EncryptionTypes";
import { Client } from "app/server/lib/Client";
import { OptDocSession } from "app/server/lib/DocSession";

export interface DocLock extends DocLockInfo {
  // Who holds the lock, if a browser does.
  client?: Client;
  // The session allowed to open the document while locked, if any (e.g. to read a document being
  // encrypted).
  session?: OptDocSession;
  // Called once released (e.g. to drop what was prepared for a conversion that didn't finish).
  onRelease?: () => Promise<void>;
  stopListening?: () => void;
  // Keeps the lock for a while longer.
  renew?: () => void;
}

const locks = new Map<string, DocLock>();

export function getDocLock(docId: string): DocLock | undefined {
  return locks.get(docId);
}

/** Locks a document, unless it's locked already (then throws). */
export function lockDoc(docId: string, lock: DocLock) {
  const existing = locks.get(docId);
  if (existing) { throw docLockedError(existing); }
  locks.set(docId, lock);
}

export function unlockDoc(docId: string, lock: DocLock) {
  if (locks.get(docId) === lock) { locks.delete(docId); }
}

/** Throws if the document is locked, unless for the session the lock allows. */
export function assertDocUnlocked(docId: string, docSession?: OptDocSession) {
  const lock = locks.get(docId);
  if (lock && !(docSession && lock.session === docSession)) { throw docLockedError(lock); }
}

export function docLockedError(lock: DocLockInfo) {
  return new ApiError(DOC_LOCKED_MESSAGE, 423,
    { code: "DocLocked", docLock: { reason: lock.reason, userName: lock.userName } });
}

export const DOC_LOCKED_MESSAGE = "This document is being changed by another member, " +
  "and will be available again as soon as they're done";
