import { nativeValues } from "app/gen-server/lib/values";
import * as sqlUtils from "app/gen-server/sqlUtils";

import { MigrationInterface, QueryRunner, Table } from "typeorm";

/**
 * Keys of encrypted documents (see app/common/encryption/EncryptionTypes.ts). The content of
 * these documents is stored, as ciphertext, in their usual document storage; the home database
 * holds what plays the role of their access list: each key, and each member's copy of it,
 * wrapped by the encryption service for that member alone.
 */
export class DocEncryption1791565390867 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    const dbType = queryRunner.connection.driver.options.type;
    const datetime = sqlUtils.datetime(dbType);
    const now = sqlUtils.now(dbType);
    await queryRunner.createTable(new Table({
      name: "doc_encryption_keys",
      columns: [
        { name: "doc_id", type: "varchar", isPrimary: true },
        { name: "key_id", type: "varchar", isPrimary: true },
        // What the key encrypts: "doc" for the document, or "column:<id>" for private columns.
        { name: "scope", type: "varchar" },
        // Set when someone holding the key lost access: the next edit replaces the key.
        { name: "rotate_on_next_edit", type: nativeValues.booleanType, default: nativeValues.falseValue },
        // Set when the key was replaced by a newer one for its scope (it stays to read older content).
        { name: "retired_at", type: datetime, isNullable: true },
        // The entry of the document's history where the key took effect (0 for the first one).
        { name: "action_num", type: "integer", default: 0 },
        { name: "created_by", type: "integer", isNullable: true },
        { name: "created_at", type: datetime, default: now },
      ],
      foreignKeys: [
        { columnNames: ["doc_id"], referencedTableName: "docs", referencedColumnNames: ["id"], onDelete: "CASCADE" },
      ],
    }));
    await queryRunner.createTable(new Table({
      name: "doc_encryption_key_wraps",
      columns: [
        { name: "doc_id", type: "varchar", isPrimary: true },
        { name: "key_id", type: "varchar", isPrimary: true },
        { name: "user_id", type: "integer", isPrimary: true },
        { name: "wrapped_key", type: "text" },
        // Version of the member's own encryption key this copy was wrapped with.
        { name: "key_version", type: "integer" },
        { name: "created_by", type: "integer", isNullable: true },
        { name: "created_at", type: datetime, default: now },
      ],
      foreignKeys: [
        {
          columnNames: ["doc_id", "key_id"],
          referencedTableName: "doc_encryption_keys",
          referencedColumnNames: ["doc_id", "key_id"],
          onDelete: "CASCADE",
        },
        { columnNames: ["user_id"], referencedTableName: "users", referencedColumnNames: ["id"], onDelete: "CASCADE" },
      ],
    }));
    // Which columns are private, and since when: kept by the server (rather than in the
    // encrypted document, which any member can change) so that only members allowed to can make
    // columns private or public again.
    await queryRunner.createTable(new Table({
      name: "doc_encryption_scopes",
      columns: [
        { name: "doc_id", type: "varchar", isPrimary: true },
        { name: "scope", type: "varchar", isPrimary: true },
        // The column (its row id in _grist_Tables_column) whose values the scope's keys protect.
        { name: "col_ref", type: "integer" },
        // The entries of the document's history where the column became private, and public again.
        { name: "bound_at", type: "integer" },
        { name: "released_at", type: "integer", isNullable: true },
        { name: "created_by", type: "integer", isNullable: true },
        { name: "created_at", type: datetime, default: now },
      ],
      foreignKeys: [
        { columnNames: ["doc_id"], referencedTableName: "docs", referencedColumnNames: ["id"], onDelete: "CASCADE" },
      ],
    }));
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable("doc_encryption_scopes");
    await queryRunner.dropTable("doc_encryption_key_wraps");
    await queryRunner.dropTable("doc_encryption_keys");
  }
}
