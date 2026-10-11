/**
 * What members see while a member locks a document for a while (see app/server/lib/encryption/docLocks.ts),
 * e.g. while converting it to or from end-to-end encryption: a message over the document, until
 * it's done. Small, and used for regular documents too (so not part of the encryption chunk).
 */
import { makeT } from "app/client/lib/localization";
import { testId } from "app/client/ui2018/cssVars";
import { loadingDots } from "app/client/ui2018/loaders";
import { cssModalBody, cssModalTitle, IModalControl, modal } from "app/client/ui2018/modals";
import { DocLockInfo } from "app/common/encryption/EncryptionTypes";

import { dom } from "grainjs";

import type { Comm } from "app/client/components/Comm";

const t = makeT("lockOverlay");

// How often to check whether a document we couldn't open got unlocked.
const CHECK_INTERVAL_MS = 3000;

// Documents locked by this browser (whose own lock shouldn't hide what it's doing).
const lockedHere = new Set<string>();

// How often a browser holding a lock renews it (the server releases it otherwise, see
// EncryptionRelay's Deps.lockExpiryMs).
const RENEW_INTERVAL_MS = 15000;

/**
 * Notes that this browser is locking a document (until the returned function is called), and
 * keeps the lock with `renew`.
 */
export function lockingHere(docId: string, renew: () => Promise<void>): () => void {
  lockedHere.add(docId);
  const timer = setInterval(() => renew().catch(e => console.warn("Could not renew the lock", e)), RENEW_INTERVAL_MS);
  return () => {
    clearInterval(timer);
    lockedHere.delete(docId);
  };
}

export function isLockedHere(docId: string): boolean {
  return lockedHere.has(docId);
}

export function describeLock(lock: DocLockInfo): string {
  const name = lock.userName || t("A member");
  switch (lock.reason) {
    case "encrypting": return t("{{name}} is encrypting this document end to end. " +
      "It will open again as soon as it's done.", { name });
    case "decrypting": return t("{{name}} is making this document a regular one (not end-to-end encrypted " +
      "anymore). It will open again as soon as it's done.", { name });
    case "restoring": return t("{{name}} is restoring an earlier version of this document. " +
      "It will open again as soon as it's done.", { name });
  }
}

/**
 * Shows that a document is locked, until close() is called on the result. Can't be dismissed.
 */
export function showLockOverlay(lock: DocLockInfo): { close: () => void, update: (lock: DocLockInfo) => void } {
  let ctl: IModalControl | undefined;
  let closed = false;
  const message = dom("div", describeLock(lock));
  modal((control) => {
    ctl = control;
    if (closed) { setTimeout(() => control.close(), 0); }
    return [
      cssModalTitle(t("Please wait"), testId("lock-overlay")),
      cssModalBody(message, dom("div", loadingDots())),
    ];
  }, { noClickAway: true, noEscapeKey: true });
  return {
    close: () => { closed = true; ctl?.close(); },
    update: (newLock) => { message.textContent = describeLock(newLock); },
  };
}

/**
 * For a document that couldn't be opened because it's locked: shows it until it's unlocked, and
 * then reloads the page (opening the document as it is now).
 */
export function waitForUnlock(comm: Comm, docId: string, lock: DocLockInfo) {
  if (isLockedHere(docId)) { return; }
  const overlay = showLockOverlay(lock);
  const timer = setInterval(async () => {
    try {
      const current: DocLockInfo | null = await comm._makeRequest(null, docId, "getDocLock", docId);
      if (!current) {
        clearInterval(timer);
        overlay.close();
        window.location.reload();
      } else {
        overlay.update(current);
      }
    } catch (e) {
      // E.g. not connected: try again later.
    }
  }, CHECK_INTERVAL_MS);
}
