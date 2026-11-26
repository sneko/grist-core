/**
 * What key providers keep in the browser for the user, forgotten when they sign out of Grist.
 *
 * Kept apart from the providers themselves (and their dependencies), so that the account menu can
 * call it without loading the encryption code: each provider adds here a light function of its own
 * (the "lasuite" provider keeps nothing in Grist's pages: its sign-in lives at the service's origin).
 */
import { forgetOpenBaoSessions } from "app/client/encryption/providers/openbaoSessions";

const forgetters: (() => void)[] = [
  () => forgetOpenBaoSessions(),
];

/** Forgets every key provider's sign-in kept in this browser (whichever provider is configured). */
export function forgetEncryptionProviderSessions() {
  for (const forget of forgetters) {
    try { forget(); } catch { /* (Signing out of Grist goes on.) */ }
  }
}
