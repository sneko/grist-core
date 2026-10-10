/**
 * Which custom widgets end-to-end encrypted documents may use. A widget sees the document's
 * content, decrypted, and could send it anywhere: only widgets served by Grist itself (its own
 * widgets and installed plugins), and those the server's configuration allows
 * (GRIST_ENCRYPTION_ALLOWED_WIDGETS), may be used. In a module of its own, as the rest of the
 * client uses it without loading the encryption code.
 */
import { getGristConfig } from "app/common/urlUtils";

/** Whether the widget at this URL may be used in encrypted documents. */
export function isWidgetAllowedInEncryptedDoc(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url, window.location.href);
  } catch (e) {
    return false;
  }
  const config = getGristConfig();
  const trustedOrigins = [window.location.href, config.homeUrl, config.pluginUrl]
    .filter((u): u is string => Boolean(u))
    .map(u => new URL(u, window.location.href).origin);
  if (trustedOrigins.includes(parsed.origin)) { return true; }
  return (config.encryption?.allowedWidgets || []).some(prefix => parsed.href.startsWith(prefix));
}

/** Whether custom widgets given by URL can be used in encrypted documents at all. */
export function canAddWidgetsByUrlInEncryptedDoc(): boolean {
  return Boolean(getGristConfig().encryption?.allowedWidgets?.length);
}
