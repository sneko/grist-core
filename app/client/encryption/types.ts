/**
 * What the rest of the client can do with an encrypted document's keys (implemented by
 * EncryptedDocSession, and exposed as DocComm.encryption). Kept apart so that UI code can use it
 * without loading the encryption code, which only encrypted documents load.
 */
import { CellValue, UserAction } from "app/common/DocActions";
import { EncryptedSnapshotInfo, EncryptionMember } from "app/common/encryption/EncryptionTypes";

import { Emitter } from "grainjs";

/**
 * Who got access to a key, and who couldn't yet: members who haven't enabled encryption (set up
 * their keys in the encryption service) can't be given any.
 */
export interface KeyGrantResult {
  granted: EncryptionMember[];
  notReady: EncryptionMember[];
}

export interface IDocEncryption {
  readonly isOwner: boolean;
  readonly canEdit: boolean;
  readonly userId: number | null;
  // Emitted when keys or members change, or which columns are private.
  readonly keysChanged: Emitter;
  /** Whether the user's changes are suggestions (they can't edit, but the document accepts suggestions). */
  readonly isSuggesting: boolean;
  /** How many changes are waiting to be sent as a suggestion. */
  readonly pendingSuggestionCount: number;
  /** Emitted when suggestions are added or handled, or when changes are made while suggesting. */
  readonly suggestionsChanged: Emitter;
  readonly inboxChanged: Emitter;
  /** Whether the user can read all of the document (needed to decrypt or copy it). */
  readonly canReadAll: boolean;
  /** The scopes whose keys are needed to read a column (empty if anyone can). */
  columnScopes(tableId: string, colId: string): string[];
  /** The scope of a private column (not counting formulas reading other private columns). */
  columnOwnScope(colRef: number): string | null;
  /** Whether the user holds the current key of a scope. */
  canReadScope(scope: string): boolean;
  /** Why the user can't change values of a data column (see ColumnPrivacy.whyCantEditValues()). */
  whyCantEditValues(tableId: string, colId: string): "noAccess" | "usedByFrozen" | null;
  listMembers(): Promise<EncryptionMember[]>;
  getPendingMembers(): Promise<EncryptionMember[]>;
  grantPendingKeys(): Promise<KeyGrantResult>;
  /** Before members are made owners: gives them the keys of all private tables and columns. */
  prepareOwners(emails: string[]): Promise<void>;
  getPendingEncryption(): Promise<Map<string, { canAccept: boolean }>>;
  acceptMember(email: string): Promise<void>;
  setReviewMembers(review: () => void): void;
  /** Opens the sharing dialog (see setReviewMembers()). */
  reviewMembers(): void;
  makeColumnPrivate(colRef: number, userIds: number[]): Promise<KeyGrantResult>;
  makeColumnPublic(colRef: number): Promise<void>;
  makeTablePrivate(tableRef: number, userIds: number[]): Promise<KeyGrantResult>;
  makeTablePublic(tableRef: number): Promise<void>;
  tableScope(tableRef: number): string | null;
  getScopeAudience(scope: string): Promise<EncryptionMember[]>;
  setScopeAudience(scope: string, userIds: number[]): Promise<KeyGrantResult>;

  /** Imports files as new tables, parsing them in the browser. Returns the new tables' ids. */
  importFiles(files: File[]): Promise<string[]>;
  /** Imports a Google Drive file (downloaded by the browser, given the user's authorization code). */
  importFromGoogleDrive(url: string, code: string): Promise<string[]>;
  submitSuggestion(desc: string): Promise<void>;
  discardSuggestion(): Promise<void>;
  /** Suggestions waiting (all of them for members who can edit; their own for others). */
  listSuggestions(): Promise<{ id: number, userName: string, timeMs: number, desc: string,
    userActions: UserAction[] }[]>;
  applySuggestion(id: number): Promise<void>;
  dismissSuggestion(id: number): Promise<void>;
  /** Publishes a form section as an encrypted form (see EncryptedForms.ts). */
  publishForm(sectionId: number): Promise<void>;
  unpublishForm(sectionId: number): Promise<void>;
  /** Answers to a form waiting to be added, and why this member doesn't add them if it can't. */
  getWaitingAnswers(sectionId: number): Promise<WaitingAnswers>;
  /** The link to a published form (including its link key). */
  getFormUrl(sectionId: number): string | null;
  /** The versions the document can be restored to, newest first. */
  listSnapshots(): Promise<(EncryptedSnapshotInfo & { userName: string })[]>;
  /** Restores a version of the document (by an owner who can read all of it). Reloads the page. */
  restoreSnapshot(actionNum: number): Promise<void>;
  /** Makes the document a regular one (by an owner who can read all of it). */
  decryptDocument(onProgress: (fraction: number, step: string) => void): Promise<void>;
  /** Copies the document into a new encrypted document. */
  copyTo(newDocId: string, options: { asTemplate: boolean },
    onProgress: (fraction: number, step: string) => void): Promise<{ waitingMembers: string[] }>;
  /** Builds an Excel workbook in the browser: one sheet per [name, header, rows]. */
  exportXlsx(sheets: [string, string[], CellValue[][]][]): Promise<Uint8Array>;
}

export interface WaitingAnswers {
  count: number;
  more: boolean;          // There may be more than `count` (the server lists a limited number).
  reason: "keys" | "blocked" | null;
  // For "keys": the private tables and columns the member can't read (as members made them private).
  missing?: { kind: "table" | "column", name: string }[];
  message?: string;       // For "blocked": why adding them was refused.
}
