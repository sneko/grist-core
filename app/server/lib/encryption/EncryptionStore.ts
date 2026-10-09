/**
 * Keys of encrypted documents, in the home database: which keys a document has (and for what),
 * and each member's copy of them, wrapped for them by the encryption service (see
 * app/gen-server/entity/DocEncryption.ts). The server can't use any of them.
 */
import { DocKeyInfo, DocKeyRecord, ScopeBinding } from "app/common/encryption/EncryptionTypes";
import { DocEncryptionKey, DocEncryptionKeyWrap, DocEncryptionScope } from "app/gen-server/entity/DocEncryption";
import { HomeDBManager } from "app/gen-server/lib/homedb/HomeDBManager";

import { EntityManager, In, IsNull } from "typeorm";

export class EncryptionStore {
  constructor(private _dbManager: HomeDBManager) {}

  private get _manager() { return this._dbManager.connection.manager; }

  public async getKeys(docId: string): Promise<DocKeyInfo[]> {
    const keys = await this._manager.find(DocEncryptionKey, { where: { docId }, order: { createdAt: "ASC" } });
    return keys.map(toKeyInfo);
  }

  /** The key currently in use for a scope, if any. */
  public async getCurrentKey(docId: string, scope: string, manager?: EntityManager): Promise<DocKeyInfo | null> {
    const key = await (manager || this._manager).findOne(DocEncryptionKey, {
      where: { docId, scope, retiredAt: IsNull() },
    });
    return key ? toKeyInfo(key) : null;
  }

  public async getWraps(docId: string, options: { userId?: number, keyIds?: string[] } = {}): Promise<DocKeyRecord[]> {
    const wraps = await this._manager.find(DocEncryptionKeyWrap, {
      where: {
        docId,
        ...(options.userId !== undefined ? { userId: options.userId } : {}),
        ...(options.keyIds ? { keyId: In(options.keyIds) } : {}),
      },
    });
    return wraps.map(toKeyRecord);
  }

  /** Which columns are (or were) private (see ScopeBinding). */
  public async getBindings(docId: string, manager?: EntityManager): Promise<ScopeBinding[]> {
    const scopes = await (manager || this._manager).find(DocEncryptionScope, {
      where: { docId }, order: { boundAt: "ASC" },
    });
    return scopes.map(s => ({ scope: s.scope, colRef: s.colRef, boundAt: s.boundAt, releasedAt: s.releasedAt }));
  }

  /** Records that a column became private at the given entry of the history. */
  public async bindScope(manager: EntityManager, docId: string, scope: string, colRef: number,
    actionNum: number, createdBy: number | null) {
    await manager.insert(DocEncryptionScope, manager.create(DocEncryptionScope, {
      docId, scope, colRef, boundAt: actionNum, releasedAt: null, createdBy, createdAt: new Date(),
    }));
  }

  /** Records that a column became public again at the given entry of the history. */
  public async releaseScope(manager: EntityManager, docId: string, scope: string, actionNum: number) {
    await manager.update(DocEncryptionScope, { docId, scope, releasedAt: IsNull() }, { releasedAt: actionNum });
  }

  public async hasAnyKey(docId: string): Promise<boolean> {
    return (await this._manager.count(DocEncryptionKey, { where: { docId } })) > 0;
  }

  /**
   * Adds a new key for a scope, with the given wraps, retiring the scope's current key if any.
   * Runs within the given transaction.
   */
  public async addKey(manager: EntityManager, docId: string, scope: string, keyId: string,
    wraps: DocKeyRecord[], createdBy: number | null, actionNum: number) {
    if (await manager.findOne(DocEncryptionKey, { where: { docId, keyId } })) {
      throw new Error(`Key ${keyId} already exists`);
    }
    await manager.update(DocEncryptionKey, { docId, scope, retiredAt: IsNull() },
      { retiredAt: new Date(), rotateOnNextEdit: false });
    await manager.insert(DocEncryptionKey, manager.create(DocEncryptionKey, {
      docId, keyId, scope, createdBy, rotateOnNextEdit: false, retiredAt: null, createdAt: new Date(), actionNum,
    }));
    await this._insertWraps(manager, docId, wraps, createdBy);
  }

  /** Adds or replaces wraps of existing keys. */
  public async setWraps(docId: string, wraps: DocKeyRecord[], createdBy: number | null) {
    if (wraps.length === 0) { return; }
    await this._dbManager.connection.transaction(async (manager) => {
      for (const wrap of wraps) {
        await manager.delete(DocEncryptionKeyWrap, { docId, keyId: wrap.keyId, userId: wrap.userId });
      }
      await this._insertWraps(manager, docId, wraps, createdBy);
    });
  }

  /**
   * Removes users' copies of the given keys (or of all keys, if keyIds isn't given), and flags
   * the current keys of the affected scopes for replacement on the next edit. Returns the
   * scopes that got flagged.
   */
  public async revokeWraps(docId: string, userIds: number[], keyIds?: string[]): Promise<string[]> {
    if (userIds.length === 0) { return []; }
    return this._dbManager.connection.transaction(async (manager) => {
      const wraps = await manager.find(DocEncryptionKeyWrap, {
        where: { docId, userId: In(userIds), ...(keyIds ? { keyId: In(keyIds) } : {}) },
      });
      if (wraps.length === 0) { return []; }
      const revokedKeyIds = [...new Set(wraps.map(w => w.keyId))];
      await manager.delete(DocEncryptionKeyWrap, {
        docId, userId: In(userIds), keyId: In(revokedKeyIds),
      });
      const keys = await manager.find(DocEncryptionKey, { where: { docId, keyId: In(revokedKeyIds) } });
      const scopes = [...new Set(keys.map(k => k.scope))];
      await manager.update(DocEncryptionKey, { docId, scope: In(scopes), retiredAt: IsNull() },
        { rotateOnNextEdit: true });
      return scopes;
    });
  }

  /** Flags the current key of a scope for replacement on the next edit. */
  public async requestRotation(docId: string, scope: string) {
    await this._manager.update(DocEncryptionKey, { docId, scope, retiredAt: IsNull() }, { rotateOnNextEdit: true });
  }

  private async _insertWraps(manager: EntityManager, docId: string, wraps: DocKeyRecord[],
    createdBy: number | null) {
    if (wraps.length === 0) { return; }
    await manager.insert(DocEncryptionKeyWrap, wraps.map(w => manager.create(DocEncryptionKeyWrap, {
      docId, keyId: w.keyId, userId: w.userId, wrappedKey: w.wrappedKey, keyVersion: w.keyVersion, createdBy,
      createdAt: new Date(),
    })));
  }
}

function toKeyInfo(key: DocEncryptionKey): DocKeyInfo {
  return {
    keyId: key.keyId,
    scope: key.scope,
    current: !key.retiredAt,
    rotateOnNextEdit: Boolean(key.rotateOnNextEdit),
    actionNum: key.actionNum ?? 0,
  };
}

function toKeyRecord(wrap: DocEncryptionKeyWrap): DocKeyRecord {
  return { keyId: wrap.keyId, userId: wrap.userId, wrappedKey: wrap.wrappedKey, keyVersion: wrap.keyVersion };
}
