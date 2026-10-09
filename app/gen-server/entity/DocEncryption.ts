/**
 * Keys of encrypted documents (see app/common/encryption/EncryptionTypes.ts). Wrapped keys are
 * base64-encoded ciphertext, which only the encryption service, on behalf of their recipient, can
 * open.
 */
import { Document } from "app/gen-server/entity/Document";
import { User } from "app/gen-server/entity/User";
import { nativeValues } from "app/gen-server/lib/values";

import { Column, Entity, JoinColumn, ManyToOne, PrimaryColumn } from "typeorm";

@Entity({ name: "doc_encryption_keys" })
export class DocEncryptionKey {
  @PrimaryColumn({ name: "doc_id", type: String })
  public docId: string;

  @PrimaryColumn({ name: "key_id", type: String })
  public keyId: string;

  @ManyToOne(_type => Document, { onDelete: "CASCADE" })
  @JoinColumn({ name: "doc_id" })
  public doc: Document;

  @Column({ name: "scope", type: String })
  public scope: string;

  @Column({ name: "rotate_on_next_edit", type: nativeValues.booleanType, default: nativeValues.falseValue })
  public rotateOnNextEdit: boolean;

  @Column({ name: "retired_at", type: Date, nullable: true })
  public retiredAt: Date | null;

  @Column({ name: "action_num", type: Number, default: 0 })
  public actionNum: number;

  @Column({ name: "created_by", type: Number, nullable: true })
  public createdBy: number | null;

  @Column({ name: "created_at", type: Date, default: () => "CURRENT_TIMESTAMP" })
  public createdAt: Date;
}

@Entity({ name: "doc_encryption_key_wraps" })
export class DocEncryptionKeyWrap {
  @PrimaryColumn({ name: "doc_id", type: String })
  public docId: string;

  @PrimaryColumn({ name: "key_id", type: String })
  public keyId: string;

  @PrimaryColumn({ name: "user_id", type: Number })
  public userId: number;

  @ManyToOne(_type => User, { onDelete: "CASCADE" })
  @JoinColumn({ name: "user_id" })
  public user: User;

  @Column({ name: "wrapped_key", type: "text" })
  public wrappedKey: string;

  @Column({ name: "key_version", type: Number })
  public keyVersion: number;

  @Column({ name: "created_by", type: Number, nullable: true })
  public createdBy: number | null;

  @Column({ name: "created_at", type: Date, default: () => "CURRENT_TIMESTAMP" })
  public createdAt: Date;
}

@Entity({ name: "doc_encryption_scopes" })
export class DocEncryptionScope {
  @PrimaryColumn({ name: "doc_id", type: String })
  public docId: string;

  @PrimaryColumn({ name: "scope", type: String })
  public scope: string;

  @ManyToOne(_type => Document, { onDelete: "CASCADE" })
  @JoinColumn({ name: "doc_id" })
  public doc: Document;

  @Column({ name: "col_ref", type: Number })
  public colRef: number;

  @Column({ name: "bound_at", type: Number })
  public boundAt: number;

  @Column({ name: "released_at", type: Number, nullable: true })
  public releasedAt: number | null;

  @Column({ name: "created_by", type: Number, nullable: true })
  public createdBy: number | null;

  @Column({ name: "created_at", type: Date, default: () => "CURRENT_TIMESTAMP" })
  public createdAt: Date;
}
