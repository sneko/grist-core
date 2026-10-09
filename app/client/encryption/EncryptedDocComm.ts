/**
 * The DocComm of an end-to-end encrypted document: instead of calling the server's ActiveDoc,
 * document methods are served by the browser itself (see EncryptedDocSession).
 */
import { Comm } from "app/client/components/Comm";
import { DocComm } from "app/client/components/DocComm";
import { EncryptedDocSession } from "app/client/encryption/EncryptedDocSession";
import { Notifier } from "app/client/models/NotifyModel";
import { ActiveDocAPI } from "app/common/ActiveDocAPI";
import { OpenLocalDocResult } from "app/common/DocListAPI";

export class EncryptedDocComm extends DocComm {
  public override readonly isEncrypted = true;

  constructor(private _encryptedComm: Comm, openResponse: OpenLocalDocResult, docId: string, notifier: Notifier,
    public readonly encryptedSession: EncryptedDocSession) {
    super(_encryptedComm, openResponse, docId, notifier);
    this.autoDispose(encryptedSession);
    this.uploadEncryptedAttachments = (files, target) =>
      this._encryptedComm.trackLocalWork(encryptedSession.uploadAttachments(files, target));
    this.getEncryptedAttachmentUrl = attId => encryptedSession.getAttachmentUrl(attId);
    this.encryption = encryptedSession;
  }

  protected _callDocMethod(name: keyof ActiveDocAPI, ...args: any[]): Promise<any> {
    return this._encryptedComm.trackLocalWork(this.encryptedSession.callMethod(name, ...args));
  }
}
