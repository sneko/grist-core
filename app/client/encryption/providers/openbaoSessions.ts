/**
 * Where the "openbao" provider keeps sign-ins to OpenBao in the browser (localStorage, until they
 * expire, so that documents opened after a reload or in other tabs need no new sign-in), and how
 * they're forgotten when the user signs out of Grist or switches accounts.
 *
 * Kept apart from the rest of the provider (and its dependencies) so that signing out of Grist
 * (./signOut.ts) can call forgetOpenBaoSessions() without loading the encryption code.
 */
import type { OpenBaoSession } from "app/common/encryption/OpenBaoKeyVault";

const PREFIX = "grist-openbao-session:";

export interface SessionStorage {
  readonly length?: number;
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
  key?(index: number): string | null;
}

export function sessionStorageKey(openBaoUrl: string, vaultUserId: string) {
  return `${PREFIX}${JSON.stringify([openBaoUrl, vaultUserId])}`;
}

export function isSessionStorageKey(key: string) {
  return key.startsWith(PREFIX);
}

export function loadSession(storage: SessionStorage | null, key: string): OpenBaoSession | null {
  try {
    const session = JSON.parse(storage?.getItem(key) || "null");
    if (session && typeof session.token === "string" && typeof session.subject === "string" &&
      (session.expiresAt === null || session.expiresAt > Date.now())) {
      return session;
    }
    storage?.removeItem(key);
  } catch {
    // (Unavailable or unreadable storage: sign in again.)
  }
  return null;
}

/** Keeps a sign-in; returns whether it could (otherwise it's for the page to keep). */
export function saveSession(storage: SessionStorage | null, key: string, session: OpenBaoSession): boolean {
  try {
    if (!storage) { return false; }
    storage.setItem(key, JSON.stringify(session));
    return true;
  } catch {
    return false;
  }
}

/** Forgets the kept sign-in, if it's still this one (not a newer one, e.g. from another tab). */
export function forgetSession(storage: SessionStorage | null, key: string, session: OpenBaoSession) {
  try {
    if (loadSession(storage, key)?.token === session.token) { storage?.removeItem(key); }
  } catch {
    // (Unavailable storage: nothing kept.)
  }
}

/**
 * Forgets every sign-in to OpenBao kept in this browser (but `except`'s), and asks OpenBao to
 * revoke their tokens (as the page may be unloading: `keepalive`, without waiting). For signing
 * out of Grist, and for another user's sign-ins left in the browser.
 */
export function forgetOpenBaoSessions(storage: SessionStorage | null = defaultStorage(),
  options: { except?: string } = {}) {
  try {
    if (!storage?.key || storage.length === undefined) { return; }
    const keys: string[] = [];
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      if (key?.startsWith(PREFIX) && key !== options.except) { keys.push(key); }
    }
    for (const key of keys) {
      try {
        const [openBaoUrl] = JSON.parse(key.slice(PREFIX.length));
        const session = loadSession(storage, key);
        if (session && typeof openBaoUrl === "string") {
          fetch(`${openBaoUrl.replace(/\/$/, "")}/v1/auth/token/revoke-self`, {
            method: "POST", keepalive: true, headers: { "X-Vault-Token": session.token },
          }).catch(() => {});
        }
      } catch {
        // (Not one of ours after all.)
      }
      storage.removeItem(key);
    }
  } catch {
    // (Unavailable storage: nothing kept.)
  }
}

function defaultStorage(): SessionStorage | null {
  try { return window.localStorage; } catch { return null; }
}
