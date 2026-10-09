/**
 * What the rest of the client can do with an encrypted document's keys (implemented by
 * EncryptedDocSession, and exposed as DocComm.encryption). Kept apart so that UI code can use it
 * without loading the encryption code, which only encrypted documents load.
 */
import { EncryptionMember } from "app/common/encryption/EncryptionTypes";

import { Emitter } from "grainjs";

export interface IDocEncryption {
  readonly isOwner: boolean;
  readonly canEdit: boolean;
  readonly userId: number | null;
  // Emitted when keys or members change, or which columns are private.
  readonly keysChanged: Emitter;
  /** The scopes whose keys are needed to read a column (empty if anyone can). */
  columnScopes(tableId: string, colId: string): string[];
  /** The scope of a private column (not counting formulas reading other private columns). */
  columnOwnScope(colRef: number): string | null;
  /** Whether the user holds the current key of a scope. */
  canReadScope(scope: string): boolean;
  listMembers(): Promise<EncryptionMember[]>;
  getPendingMembers(): Promise<EncryptionMember[]>;
  grantPendingKeys(): Promise<EncryptionMember[]>;
  makeColumnPrivate(colRef: number, userIds: number[]): Promise<void>;
  makeColumnPublic(colRef: number): Promise<void>;
  getScopeAudience(scope: string): Promise<EncryptionMember[]>;
  setScopeAudience(scope: string, userIds: number[]): Promise<void>;
  requestKeyRotation(scope?: string): Promise<void>;
  /** Imports files as new tables, parsing them in the browser. Returns the new tables' ids. */
  importFiles(files: File[]): Promise<string[]>;
}
