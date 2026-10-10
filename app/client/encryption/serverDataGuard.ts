/**
 * Keeps the REST API client of an end-to-end encrypted document from sending its data to the
 * server (or asking the server for it, which it can't read anyway). Features relying on it are
 * hidden for encrypted documents, or do the work in the browser instead: this makes sure that
 * none is missed, whatever the code path. In a module of its own, as the rest of the client uses
 * it without loading the encryption code.
 */
import { ENCRYPTED_DOC_SERVER_ERROR } from "app/common/encryption/EncryptionTypes";
import { DocAPI } from "app/common/UserAPI";

// Methods sending content to the server, or reading it from there.
const REFUSED_METHODS = new Set<string>([
  "upload", "uploadAttachment", "uploadAttachmentArchive", "addRows", "updateRows", "removeRows", "addOrUpdateRows",
  "replace", "sendToDrive", "copyDoc", "fork", "sql", "getRows", "getRecords", "getTables", "download",
  "compareDoc", "addTriggers", "updateTriggers", "addWebhook", "updateWebhook",
]);

/** Returns the given API, or for encrypted documents, a version of it refusing such methods. */
export function guardDocApi<T extends DocAPI>(api: T, isEncrypted: boolean): T {
  if (!isEncrypted) { return api; }
  return new Proxy(api, {
    get(target, prop, receiver) {
      if (typeof prop === "string" && REFUSED_METHODS.has(prop)) {
        return () => Promise.reject(new Error(ENCRYPTED_DOC_SERVER_ERROR));
      }
      return Reflect.get(target, prop, receiver);
    },
  });
}
