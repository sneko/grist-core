/**
 * The "openbao" provider in the browser: signing in to OpenBao, and keeping the token (see
 * app/common/encryption/OpenBaoKeyVault.ts for the keys themselves, and ./openbaoSessions.ts for
 * where sign-ins are kept).
 *
 * Signing in opens a tab (from the user's click, as browsers require), where OpenBao runs the OIDC
 * sign-in with the identity provider Grist uses: when the user is still signed in there, the tab
 * closes at once; otherwise it shows the provider's form. It comes back to a page of Grist
 * (OPENBAO_CALLBACK_PATH), which hands what it came back with to this page, which finishes the
 * sign-in with OpenBao. A hidden iframe can't do it silently: browsers withhold the provider's
 * cookies there.
 *
 * The callback page hands the result both to the page that opened it and on a BroadcastChannel:
 * identity providers sending `Cross-Origin-Opener-Policy: same-origin` (LaSuite Accounts and
 * ProConnect do) sever the tab from this page (`window.opener` is gone, and the tab looks closed
 * from here), and the channel, between pages of Grist's origin, still reaches it. For the same
 * reason, a tab looking closed doesn't mean the user gave up: this page waits for the result
 * (until a timeout), and the user can cancel from Grist's own dialog.
 */
import {
  forgetOpenBaoSessions, forgetSession, isSessionStorageKey, loadSession, saveSession, SessionStorage,
  sessionStorageKey,
} from "app/client/encryption/providers/openbaoSessions";
import {
  finishOpenBaoSignIn, isValidOpenBaoKeyName, OPENBAO_CALLBACK_CHANNEL, OPENBAO_CALLBACK_PATH, OpenBaoKeyVault,
  OpenBaoSession, startOpenBaoSignIn,
} from "app/common/encryption/OpenBaoKeyVault";
import { OpenBaoEncryptionProviderConfig } from "app/common/gristUrls";

/** A tab opened for signing in. */
export interface SignInTab {
  readonly closed: boolean;
  navigate(url: string): void;
  close(): void;
}

/** What of the browser signing in uses (a stand-in in tests). */
export interface OpenBaoBrowser {
  origin: string;
  storage: SessionStorage | null;
  // How long to wait for the sign-in to come back (default: 10 minutes).
  timeoutMs?: number;
  // Calls back in `ms` (to renew the sign-in when it nears its expiry); returns how to cancel it.
  // Absent in tests that don't renew.
  after?(ms: number, callback: () => void): () => void;
  // Calls back when another tab of Grist changes the sign-ins kept (renewed, signed in or out).
  onStorageChange?(callback: () => void): void;
  // Opens a tab, synchronously (it must happen within the user's click); null if the browser blocked it.
  openTab(): SignInTab | null;
  // Listens to what callback pages hand back (the query string each came back with).
  onCallback(tab: SignInTab, listener: (search: string) => void): () => void;
}

export function createOpenBaoKeyVault(config: OpenBaoEncryptionProviderConfig, vaultUserId: string | null,
  browser: OpenBaoBrowser = realBrowser()): Promise<OpenBaoKeyVault> {
  if (!vaultUserId) {
    return Promise.reject(new Error("Your account is not known to the key service: sign in to Grist with " +
      "your organization's identity provider"));
  }
  if (!isValidOpenBaoKeyName(vaultUserId)) {
    return Promise.reject(new Error(`Your account's identifier (${vaultUserId}) can't name a key in the key ` +
      "service (only letters, digits, '_', and '.' or '-' inside, can): encrypted documents aren't available to you"));
  }
  const storageKey = sessionStorageKey(config.url, vaultUserId);
  // Sign-ins kept for other users (e.g. someone who used this browser before, without signing out
  // of Grist): of no use to this one, and not to be left behind.
  forgetOpenBaoSessions(browser.storage, { except: storageKey });
  // Kept in this page instead when the browser's storage is unavailable.
  let current: OpenBaoSession | null = null;
  let inPageOnly = !browser.storage;
  const save = (session: OpenBaoSession) => {
    inPageOnly = !saveSession(browser.storage, storageKey, session);
    current = session;
    scheduleRenewal();
  };
  const forget = (session: OpenBaoSession) => {
    forgetSession(browser.storage, storageKey, session);
    if (current?.token === session.token) { current = null; }
    scheduleRenewal();
  };

  const signIn = async (): Promise<boolean> => {
    // First, synchronously, within the click: a tab opened after an await would be blocked.
    const tab = browser.openTab();
    if (!tab) {
      throw new Error("The browser blocked the window for signing in to the key service: allow pop-ups " +
        "for this site, then try again");
    }
    try {
      const { authUrl, clientNonce, state } = await startOpenBaoSignIn(config, browser.origin + OPENBAO_CALLBACK_PATH);
      const search = await new Promise<string | null>((resolve) => {
        const timer = setTimeout(() => done(null), browser.timeoutMs ?? 10 * 60 * 1000);
        // Only this sign-in's result counts (another one, e.g. from another tab, has another state).
        const stop = browser.onCallback(tab, (s) => {
          if (new URLSearchParams(s).get("state") === state) { done(s); }
        });
        function done(result: string | null) { clearTimeout(timer); stop(); resolve(result); }
        tab.navigate(authUrl);
      });
      if (search === null) { return false; }
      const session = await finishOpenBaoSignIn(config, search, clientNonce);
      if (session.subject !== vaultUserId) {
        await vault.revoke(session);
        throw new Error("You signed in to the key service as another user than in Grist: sign in as the same " +
          "user in both");
      }
      save(session);
      return true;
    } finally {
      if (!tab.closed) { tab.close(); }
    }
  };

  const vault = new OpenBaoKeyVault({
    config, vaultUserId, signIn,
    // (Read again each time: another tab may have renewed it, or signed in again, meanwhile.)
    session: () => inPageOnly ? current : loadSession(browser.storage, storageKey),
    saveSession: save,
    forgetSession: forget,
  });

  // An open document makes few calls to OpenBao: renew the sign-in when it nears its expiry all the
  // same, at that time (planned again whenever this or another tab renews it, or signs in again).
  let cancelRenewal: (() => void) | undefined;
  function scheduleRenewal() {
    cancelRenewal?.();
    cancelRenewal = undefined;
    const renewalTime = vault.renewalTime();
    if (renewalTime === null || !browser.after) { return; }
    // (Not before a minute: when OpenBao can't be reached, tried again every minute until it expires.)
    cancelRenewal = browser.after(Math.max(renewalTime - Date.now(), MIN_RENEWAL_DELAY_MS), () => {
      vault.keepAlive().catch(() => {}).finally(scheduleRenewal);
    });
  }
  scheduleRenewal();
  browser.onStorageChange?.(scheduleRenewal);
  return Promise.resolve(vault);
}

const MIN_RENEWAL_DELAY_MS = 60 * 1000;

export function realBrowser(): OpenBaoBrowser {
  let storage: Storage | null = null;
  try { storage = window.localStorage; } catch { /* Unavailable (e.g. blocked site data). */ }
  const windows = new WeakMap<SignInTab, Window>();
  return {
    origin: window.location.origin,
    storage,
    after(ms, callback) {
      // (Browsers fire timers of more than 2^31 - 1 ms at once.)
      const timer = setTimeout(callback, Math.min(ms, 2 ** 31 - 1));
      return () => clearTimeout(timer);
    },
    onStorageChange(callback) {
      window.addEventListener("storage", (event) => {
        if (event.key === null || isSessionStorageKey(event.key)) { callback(); }
      });
    },
    openTab() {
      // (A name of its own: two sign-ins never share a window.)
      const name = `grist-openbao-sign-in-${Math.random().toString(36).slice(2)}`;
      const win = window.open("about:blank", name, "popup,width=520,height=680");
      if (!win) { return null; }
      const tab: SignInTab = {
        navigate: (url) => { win.location.href = url; },
        close: () => win.close(),
        get closed() { return win.closed; },
      };
      windows.set(tab, win);
      return tab;
    },
    onCallback(tab, listener) {
      const accept = (data: any) => {
        const search = data?.gristOpenBaoCallback;
        if (typeof search === "string") { listener(search); }
      };
      // From the tab itself (only it, on Grist's own origin)...
      const onMessage = (event: MessageEvent) => {
        if (event.origin === window.location.origin && event.source === windows.get(tab)) { accept(event.data); }
      };
      window.addEventListener("message", onMessage);
      // ...or, when the identity provider severed it from this page, from Grist's origin over the channel.
      let channel: BroadcastChannel | null = null;
      try {
        channel = new BroadcastChannel(OPENBAO_CALLBACK_CHANNEL);
        channel.onmessage = event => accept(event.data);
      } catch {
        // (No BroadcastChannel: only the tab's message.)
      }
      return () => {
        window.removeEventListener("message", onMessage);
        channel?.close();
      };
    },
  };
}
