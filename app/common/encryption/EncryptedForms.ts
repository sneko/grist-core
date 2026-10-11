/**
 * Forms of encrypted documents. The server can't read encrypted documents, nor write to them, so
 * forms work differently than for regular documents:
 *
 *  - Publishing a form gives it a key pair, and a "link key". Both are kept in the document (in
 *    the form's settings, readable by its members only). What respondents need to fill the form
 *    (its questions, choices...: a FormSpec) is encrypted with the link key and stored by the
 *    server. The link key is in the form's link, after "#", which browsers never send to servers:
 *    only those who got the link can read the form.
 *  - Respondents' browsers encrypt their answers with the form's public key (taken from the spec,
 *    which the server can't change without the link key), and send them to the server, which keeps
 *    them in the document's inbox. Only members can decrypt them (with the form's private key).
 *  - Browsers of members who can edit the document add the answers in the inbox to the document,
 *    as any change, removing them from the inbox at the same time (see LocalActiveDoc).
 *
 * Answers are encrypted with ECIES: an ephemeral ECDH key pair (P-256) agrees on a secret with the
 * form's public key, from which HKDF derives an AES-GCM key. All with WebCrypto, available in
 * browsers and Node.
 */
import {
  base64ToBytes, bytesToBase64, concatBytes, utf8Decode, utf8Encode,
} from "app/common/encryption/EncryptionCrypto";

const ECDH = { name: "ECDH", namedCurve: "P-256" } as const;
const PUBLIC_KEY_BYTES = 65;    // Uncompressed P-256 point.
const IV_BYTES = 12;
const HKDF_INFO = utf8Encode("grist-encrypted-form-v1");
const FORMAT_VERSION = 1;

/**
 * What a form's settings keep (in shareOptions.encryptedForm), readable by the document's members.
 * For forms filling private columns, the private key is sealed with the keys of those columns
 * (`sealedPrivateKey`): only members who can read all of them can read answers.
 */
export interface EncryptedFormKeys {
  formId: string;       // Identifies the form for the server (random).
  publicKey: string;    // base64 (raw P-256 point).
  privateKey?: string;  // base64 (PKCS#8), for forms filling no private column.
  sealedPrivateKey?: { keyIds: string[], data: string };   // Otherwise: encrypted with these keys.
  // The scopes of the private columns the form fills (sealedPrivateKey is for their keys).
  scopes?: string[];
  linkKey: string;      // base64url (32 bytes, for AES-GCM), the part of the form's link after "#".
}

/** What respondents get (encrypted with the link key): the form, and where to send answers. */
export interface FormSpec {
  v: 1;
  formId: string;
  publicKey: string;
  // As returned by GET /api/docs/:docId/forms/:vsId for regular documents (see FormAPI.Form).
  form: any;
}

/** What respondents send (encrypted with the form's public key). */
export interface FormAnswer {
  v: 1;
  tableId: string;
  colValues: { [colId: string]: any };
  // Files attached in the answer (uploaded encrypted, see encryptFormFile()), by column. Their
  // cells in colValues refer to them by negative ids: -1 for the first file, -2 for the next...
  files?: FormAnswerFile[];
}

export interface FormAnswerFile {
  fileId: string;       // As stored by the server.
  key: string;          // base64: the key the file is encrypted with.
  name: string;
  size: number;
}

/** Encrypts a file attached in an answer, with a new key (that goes in the encrypted answer). */
export async function encryptFormFile(data: Uint8Array): Promise<{ key: string, payload: Uint8Array }> {
  const raw = randomBytes(32);
  return { key: bytesToBase64(raw), payload: await aesEncrypt(await importAesKey(raw), data) };
}

export async function decryptFormFile(key: string, payload: Uint8Array): Promise<Uint8Array> {
  return aesDecrypt(await importAesKey(base64ToBytes(key)), payload);
}

function subtle(): SubtleCrypto {
  return globalThis.crypto.subtle;
}

function randomBytes(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

export function makeFormId(): string {
  return Array.from(randomBytes(16), b => b.toString(16).padStart(2, "0")).join("");
}

/** New keys for a form. */
export async function generateFormKeys(): Promise<EncryptedFormKeys> {
  const pair = await subtle().generateKey(ECDH, true, ["deriveBits"]);
  return {
    formId: makeFormId(),
    publicKey: bytesToBase64(new Uint8Array(await subtle().exportKey("raw", pair.publicKey))),
    privateKey: bytesToBase64(new Uint8Array(await subtle().exportKey("pkcs8", pair.privateKey))),
    linkKey: toBase64Url(randomBytes(32)),
  };
}

/** Encrypts a form's spec with its link key. */
export async function encryptFormSpec(linkKey: string, spec: FormSpec): Promise<Uint8Array> {
  return aesEncrypt(await importAesKey(fromBase64Url(linkKey)), utf8Encode(JSON.stringify(spec)));
}

/** Decrypts a form's spec (from the server, which mustn't be able to change it). */
export async function decryptFormSpec(linkKey: string, payload: Uint8Array): Promise<FormSpec> {
  const spec = JSON.parse(utf8Decode(await aesDecrypt(await importAesKey(fromBase64Url(linkKey)), payload)));
  if (spec?.v !== 1 || typeof spec.formId !== "string" || typeof spec.publicKey !== "string" || !spec.form) {
    throw new Error("Invalid form");
  }
  return spec;
}

/** Encrypts an answer for a form, given its public key. */
export async function encryptFormAnswer(publicKey: string, answer: FormAnswer): Promise<Uint8Array> {
  const formKey = await subtle().importKey("raw", base64ToBytes(publicKey) as BufferSource, ECDH, false, []);
  const ephemeral = await subtle().generateKey(ECDH, true, ["deriveBits"]);
  const ephemeralPublic = new Uint8Array(await subtle().exportKey("raw", ephemeral.publicKey));
  const key = await deriveKey(ephemeral.privateKey, formKey, ephemeralPublic);
  return concatBytes(Uint8Array.of(FORMAT_VERSION), ephemeralPublic,
    await aesEncrypt(key, utf8Encode(JSON.stringify(answer))));
}

/** Decrypts an answer to a form (sent by anyone with the form's link: throws if it's not one). */
export async function decryptFormAnswer(privateKey: string, payload: Uint8Array): Promise<FormAnswer> {
  if (payload[0] !== FORMAT_VERSION || payload.length < 1 + PUBLIC_KEY_BYTES + IV_BYTES) {
    throw new Error("Invalid answer");
  }
  const ephemeralPublic = payload.subarray(1, 1 + PUBLIC_KEY_BYTES);
  const formKey = await subtle().importKey("pkcs8", base64ToBytes(privateKey) as BufferSource, ECDH, false,
    ["deriveBits"]);
  const ephemeral = await subtle().importKey("raw", ephemeralPublic as BufferSource, ECDH, false, []);
  const key = await deriveKey(formKey, ephemeral, ephemeralPublic);
  const answer = JSON.parse(utf8Decode(await aesDecrypt(key, payload.subarray(1 + PUBLIC_KEY_BYTES))));
  if (answer?.v !== 1 || typeof answer.tableId !== "string" || !answer.colValues ||
    typeof answer.colValues !== "object" || Array.isArray(answer.colValues) ||
    (answer.files !== undefined && !(Array.isArray(answer.files) && answer.files.every((f: any) =>
      typeof f?.fileId === "string" && typeof f.key === "string" && typeof f.name === "string" &&
      typeof f.size === "number")))) {
    throw new Error("Invalid answer");
  }
  return answer;
}

async function deriveKey(privateKey: CryptoKey, publicKey: CryptoKey, salt: Uint8Array): Promise<CryptoKey> {
  const secret = await subtle().deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  const hkdfKey = await subtle().importKey("raw", secret, "HKDF", false, ["deriveKey"]);
  return subtle().deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: HKDF_INFO as BufferSource },
    hkdfKey, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function importAesKey(raw: Uint8Array): Promise<CryptoKey> {
  if (raw.length !== 32) { throw new Error("Invalid form link"); }
  return subtle().importKey("raw", raw as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function aesEncrypt(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const iv = randomBytes(IV_BYTES);
  const ciphertext = await subtle().encrypt({ name: "AES-GCM", iv: iv as BufferSource }, key, data as BufferSource);
  return concatBytes(iv, new Uint8Array(ciphertext));
}

async function aesDecrypt(key: CryptoKey, payload: Uint8Array): Promise<Uint8Array> {
  const iv = payload.subarray(0, IV_BYTES);
  return new Uint8Array(await subtle().decrypt({ name: "AES-GCM", iv: iv as BufferSource }, key,
    payload.subarray(IV_BYTES) as BufferSource));
}

export function toBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(text: string): Uint8Array {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  return base64ToBytes(base64 + "=".repeat((4 - base64.length % 4) % 4));
}

/** The share key of an encrypted form's link (see FormModel), and how to read it back. */
export const ENCRYPTED_FORM_PREFIX = "encrypted.";

export function makeEncryptedFormShareKey(docId: string, formId: string): string {
  return `${ENCRYPTED_FORM_PREFIX}${docId}.${formId}`;
}

export function parseEncryptedFormShareKey(shareKey: string): { docId: string, formId: string } | null {
  const match = /^encrypted\.([A-Za-z0-9]+)\.([0-9a-f]{32})$/.exec(shareKey);
  return match ? { docId: match[1], formId: match[2] } : null;
}
