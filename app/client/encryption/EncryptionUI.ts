/**
 * User interface for encrypted documents' keys: private columns (in the column's settings and
 * headers), and members' access (in the document's settings). Only shown for encrypted
 * documents, through DocComm.encryption (see types.ts).
 */
import { domAsync } from "app/client/lib/domAsync";
import { loadEncryption } from "app/client/lib/imports";
import { makeT } from "app/client/lib/localization";
import { reportError, reportSuccess, reportWarning } from "app/client/models/errors";
import { urlState } from "app/client/models/gristUrlState";
import { textInput } from "app/client/ui/inputs";
import { cssLabel, cssRow } from "app/client/ui/RightPanelStyles";
import { basicButton, primaryButton } from "app/client/ui2018/buttons";
import { labeledSquareCheckbox } from "app/client/ui2018/checkbox";
import { testId, theme } from "app/client/ui2018/cssVars";
import { icon } from "app/client/ui2018/icons";
import { confirmModal, cssModalBody, cssModalButtons, cssModalTitle, modal, saveModal } from "app/client/ui2018/modals";
import { UserAction } from "app/common/DocActions";
import { EncryptionMember } from "app/common/encryption/EncryptionTypes";
import { EncryptionClientConfig } from "app/common/gristUrls";
import { getGristConfig } from "app/common/urlUtils";
import { Document } from "app/common/UserAPI";

import { Computed, dom, DomContents, MultiHolder, Observable, styled } from "grainjs";

import type { GristDoc } from "app/client/components/GristDoc";
import type { EncryptionSummary } from "app/client/encryption/DocConversion";
import type { IDocEncryption, KeyGrantResult } from "app/client/encryption/types";
import type { ColumnRec } from "app/client/models/entities/ColumnRec";

const t = makeT("EncryptionUI");

function getEncryption(gristDoc: GristDoc): IDocEncryption | undefined {
  return gristDoc.docComm.encryption;
}

/** An observable that recomputes whenever keys or private columns change. */
function keysVersion(owner: MultiHolder, encryption: IDocEncryption): Observable<number> {
  const version = Observable.create(owner, 0);
  owner.autoDispose(encryption.keysChanged.addListener(() => version.set(version.get() + 1)));
  return version;
}

/**
 * The "Private column" section of a column's settings: who can read the column, and (for owners)
 * the controls to change it.
 */
export function buildColumnPrivacySection(owner: MultiHolder, gristDoc: GristDoc, column: ColumnRec): DomContents {
  const encryption = getEncryption(gristDoc);
  if (!encryption) { return null; }
  const version = keysVersion(owner, encryption);
  return [
    cssLabel(t("PRIVACY")),
    dom.domComputed((use) => {
      use(version);
      const tableId = use(use(column.table).tableId);
      const colId = use(column.colId);
      const colRef = use(column.id);
      return { scopes: encryption.columnScopes(tableId, colId), colRef, ownScope: encryption.columnOwnScope(colRef) };
    }, ({ scopes, colRef, ownScope }) => {
      if (!colRef) { return null; }
      if (scopes.length === 0) {
        return [
          cssHint(t("All members of the document can read this column.")),
          encryption.isOwner ? cssRow(
            basicButton(icon("Lock"), " ", t("Make private"),
              dom.on("click", () => editAudience(encryption, { colRef, scope: null })),
              testId("column-make-private")),
          ) : null,
        ];
      }
      const readable = scopes.every(scope => encryption.canReadScope(scope));
      if (!ownScope) {
        return cssHint(icon("Lock"), " ",
          t("This formula uses private columns: only members who can read them can see its results."),
          testId("column-private-derived"));
      }
      return [
        cssHint(icon("Lock"), " ", readable ?
          t("Private column: only some members can read it.") :
          t("Private column: you don't have access to its values."),
        testId("column-private")),
        domAsync(encryption.getScopeAudience(ownScope).then(members =>
          cssAudience(members.map(m => cssMember(m.name || m.email, testId("column-audience-member")))),
        )),
        (encryption.isOwner && readable) ? cssRow(
          basicButton(t("Change who can read it"),
            dom.on("click", () => editAudience(encryption, { colRef, scope: ownScope })),
            testId("column-change-audience")),
          basicButton(t("Make public"),
            dom.on("click", () => encryption.makeColumnPublic(colRef).catch(reportError)),
            testId("column-make-public")),
        ) : null,
      ];
    }),
  ];
}

/** Picks the members who can read a private column (making it private if it isn't yet). */
function editAudience(encryption: IDocEncryption, target: { colRef: number, scope: string | null }) {
  saveModal((ctl, owner) => {
    const selected = new Map<number, Observable<boolean>>();
    const members = Observable.create<EncryptionMember[] | null>(owner, null);
    const load = async () => {
      const all = (await encryption.listMembers()).filter(m => m.userId !== encryption.userId);
      const audience = target.scope ? await encryption.getScopeAudience(target.scope) : [];
      for (const m of all) {
        selected.set(m.userId, Observable.create(owner, audience.some(a => a.userId === m.userId)));
      }
      if (!owner.isDisposed()) { members.set(all); }
    };
    load().catch(reportError);
    return {
      title: target.scope ? t("Who can read this column") : t("Make this column private"),
      body: [
        cssHint(t("Only the members you select (and you) will be able to read this column, " +
          "and formulas that use it. Others will see 🔒 in its place.")),
        dom.domComputed(members, list => list === null ? cssHint(t("Loading…")) : list.length === 0 ?
          cssHint(t("There are no other members.")) :
          list.map(m => cssRow(labeledSquareCheckbox(selected.get(m.userId)!,
            `${m.name || m.email} (${m.email})`, testId("audience-member"))))),
      ],
      saveLabel: target.scope ? t("Save") : t("Make private"),
      saveFunc: async () => {
        const userIds = [...selected.entries()].filter(([, obs]) => obs.get()).map(([id]) => id);
        const result = target.scope ?
          await encryption.setScopeAudience(target.scope, userIds) :
          await encryption.makeColumnPrivate(target.colRef, userIds);
        reportSuccess(t("Saved"));
        reportKeyGrant({ granted: [], notReady: result.notReady });
      },
    };
  });
}

/** Tells who got access to keys, and who couldn't (members who haven't enabled encryption). */
export function reportKeyGrant(result: KeyGrantResult) {
  if (result.granted.length > 0) {
    reportSuccess(t("Gave access to {{count}} member(s).", { count: result.granted.length }));
  }
  if (result.notReady.length > 0) {
    reportWarning(t("{{members}} haven't enabled encryption on their account yet: give them access again once " +
      "they have.", { members: result.notReady.map(m => m.name || m.email).join(", ") }));
  }
}

/** A lock in the header of private columns. */
export function buildPrivateColumnMarker(owner: MultiHolder, gristDoc: GristDoc, column: ColumnRec): DomContents {
  const encryption = getEncryption(gristDoc);
  if (!encryption) { return null; }
  const version = keysVersion(owner, encryption);
  const isPrivate = Computed.create(owner, (use) => {
    use(version);
    return encryption.columnScopes(use(use(column.table).tableId), use(column.colId)).length > 0;
  });
  return dom.maybe(isPrivate, () => cssLockIcon("Lock", testId("column-private-marker")));
}

/** The "Encryption" section of the document's settings: members, and their access to keys. */
export function buildEncryptionSettings(owner: MultiHolder, gristDoc: GristDoc): DomContents {
  const encryption = getEncryption(gristDoc);
  if (!encryption) { return null; }
  const version = keysVersion(owner, encryption);
  return cssEncryptionSettings(
    cssHint(icon("Lock"), " ", t("This document is end-to-end encrypted: its content is encrypted in " +
      "members' browsers, and the server can't read it.")),
    dom.domComputed(version, () => domAsync(encryption.listMembers().then(members => [
      cssMembers(members.map(m => cssMemberRow(
        dom("span", m.name || m.email),
        dom("span", m.email),
        dom("span", m.access),
        dom("span", m.keyIds.length > 0 ? t("Can read") : t("Waiting for access")),
        testId("encryption-member"),
      ))),
    ]))),
    encryption.isOwner ? cssRow(
      primaryButton(t("Give access to waiting members"),
        dom.on("click", () => encryption.grantPendingKeys().then(reportKeyGrant).catch(reportError)),
        testId("encryption-grant")),
      basicButton(t("Replace keys"),
        dom.on("click", () => encryption.requestKeyRotation()
          .then(() => reportSuccess(t("Keys replaced.")))
          .catch(reportError)),
        testId("encryption-rotate")),
    ) : null,
    (encryption.isOwner && encryption.canReadAll) ? cssRow(
      basicButton(t("Stop encrypting this document"),
        dom.on("click", () => confirmDecryption(encryption)),
        testId("encryption-decrypt")),
    ) : null,
    testId("encryption-settings"),
  );
}

function confirmDecryption(encryption: IDocEncryption) {
  confirmModal(t("Stop encrypting this document?"), t("Stop encrypting"), () => {
    runWithProgress(t("Making this document a regular one"),
      onProgress => encryption.decryptDocument(onProgress),
      () => window.location.reload());
  }, {
    explanation: cssExplanation(
      dom("p", t("The document becomes a regular one: the server will be able to read it, and all of " +
        "Grist's features become available for it.")),
      dom("p", t("Columns that are private get access rules instead, so that members who couldn't read " +
        "them still can't.")),
      dom("p", t("Earlier (encrypted) versions of it are deleted. Members who have it open see that it's " +
        "in progress, and can't change it until it's done.")),
    ),
  });
}

/**
 * The "Encryption" section of the settings of a regular document (for owners, when encrypted
 * documents are enabled): to encrypt it end to end.
 */
export function buildEncryptDocumentSection(owner: MultiHolder, gristDoc: GristDoc): DomContents {
  const config = getGristConfig().encryption;
  const docModel = gristDoc.docPageModel;
  const doc = docModel.currentDoc.get();
  const userId = docModel.appModel.currentValidUser?.id;
  if (!config || !doc || !userId) { return null; }
  return cssEncryptionSettings(
    cssHint(t("Encrypting this document end to end makes its content readable only in the browsers " +
      "of its members: the server can't read it anymore.")),
    cssRow(
      basicButton(icon("Lock"), " ", t("Encrypt this document"),
        dom.on("click", () => confirmEncryption(gristDoc, doc.id, userId, config)),
        testId("encryption-encrypt")),
    ),
    testId("encryption-settings"),
  );
}

function confirmEncryption(gristDoc: GristDoc, docId: string, userId: number, config: EncryptionClientConfig) {
  confirmModal(t("Encrypt this document end to end?"), t("Encrypt"), () => {
    const comm = gristDoc.app.comm;
    let summary: EncryptionSummary | undefined;
    runWithProgress(t("Encrypting this document"), async (onProgress) => {
      const module = await loadEncryption();
      summary = await module.encryptDocument(comm, docId, userId, config, onProgress,
        vault => module.ensureVaultKeys(vault));
    }, () => showEncryptionSummary(summary));
  }, {
    explanation: cssExplanation(
      dom("p", t("Its content will be encrypted in your browser, and only readable in the browsers of its " +
        "members. They need to enable encryption on their account: those who did get access now, others " +
        "once they have (when an owner opens the document).")),
      dom("p", t("Features that need the server to read the document become unavailable: webhooks, the API " +
        "on its data, server-side exports, and others. Access rules hiding columns from some members " +
        "become private columns (readable by the same members); rules depending on the content (e.g. " +
        "hiding rows) can't be kept, and rules limiting edits are dropped.")),
      dom("p", t("Earlier versions of the document are deleted. Members who have it open see that it's in " +
        "progress, and can't change it until it's done.")),
    ),
  });
}

// After encrypting a document: what changed besides, if anything, then reopening it.
function showEncryptionSummary(summary: EncryptionSummary | undefined) {
  const notes = [
    summary?.privateColumns ? t("{{count}} column(s) hidden by access rules are now private columns.",
      { count: summary.privateColumns }) : null,
    summary?.droppedRules ? t("{{count}} access rule(s) limiting edits were dropped.",
      { count: summary.droppedRules }) : null,
    summary?.waitingMembers.length ? t("{{members}} can't read it until they enable encryption and an owner " +
      "gives them access.", { members: summary.waitingMembers.join(", ") }) : null,
  ].filter(Boolean);
  if (notes.length === 0) {
    window.location.reload();
    return;
  }
  modal(() => [
    cssModalTitle(t("The document is encrypted"), testId("encryption-summary")),
    cssModalBody(notes.map(note => dom("p", note))),
    cssModalButtons(primaryButton(t("Open it"), dom.on("click", () => window.location.reload()),
      testId("encryption-summary-ok"))),
  ], { noClickAway: true, noEscapeKey: true });
}

/**
 * Runs a long task, showing its progress in a dialog that can't be dismissed meanwhile. Calls
 * onDone once it's done; on failure, reports the error.
 */
export function runWithProgress(title: string,
  task: (onProgress: (fraction: number, step: string) => void) => Promise<void>, onDone: () => void) {
  modal((ctl, owner) => {
    const fraction = Observable.create(owner, 0);
    const step = Observable.create(owner, "");
    task((f, s) => { if (!owner.isDisposed()) { fraction.set(f); step.set(s); } })
      .then(() => { ctl.close(); onDone(); })
      .catch((e) => { ctl.close(); reportError(e); });
    return [
      cssModalTitle(title, testId("encryption-progress")),
      cssModalBody(
        cssProgressBar(cssProgressFill(dom.style("width", use => `${Math.round(use(fraction) * 100)}%`))),
        cssHint(dom.text(use => describeStep(use(step)))),
      ),
    ];
  }, { noClickAway: true, noEscapeKey: true });
}

function describeStep(step: string): string {
  switch (step) {
    case "content": return t("Preparing the content…");
    case "attachments": return t("Converting attachments…");
    case "saving": return t("Saving…");
    case "done": return t("Done");
    default: return t("Starting…");
  }
}

/**
 * Copies an encrypted document into a new one (in the same workspace), after asking for its name
 * and whether to copy its data or only its structure. Opens the copy once done.
 */
export function copyEncryptedDocument(gristDoc: GristDoc, doc: Document) {
  const encryption = getEncryption(gristDoc);
  if (!encryption || !doc.workspace) { return; }
  saveModal((ctl, owner) => {
    const name = Observable.create(owner, t("{{name}} (copy)", { name: doc.name }));
    const asTemplate = Observable.create(owner, false);
    return {
      title: t("Duplicate document"),
      body: [
        cssRow(textInput(name, { placeholder: t("Name") }, testId("encrypted-copy-name"))),
        cssRow(labeledSquareCheckbox(asTemplate, t("As template (structure only, without data)"),
          testId("encrypted-copy-template"))),
        cssHint(t("The copy is encrypted end to end too, with keys of its own. Private columns stay private. " +
          "Its members (those of its workspace) can read what they could read in this document.")),
      ],
      saveLabel: t("Duplicate"),
      saveDisabled: Computed.create(owner, use => !use(name).trim()),
      saveFunc: async () => {
        const api = gristDoc.docPageModel.appModel.api;
        const newDocId = await api.newDoc({ name: name.get().trim(), options: { encryption: { version: 1 } } },
          doc.workspace.id);
        let waiting: string[] = [];
        runWithProgress(t("Copying the document"), async (onProgress) => {
          waiting = (await encryption.copyTo(newDocId, { asTemplate: asTemplate.get() }, onProgress)).waitingMembers;
        }, () => {
          urlState().pushUrl({ doc: newDocId }).catch(reportError);
          if (waiting.length > 0) {
            reportWarning(t("{{members}} can't read the copy until they enable encryption and an owner gives " +
              "them access.", { members: waiting.join(", ") }));
          }
        });
      },
    };
  });
}

/**
 * The versions of an encrypted document the server keeps, which owners who can read all of it
 * can restore (for the "Document history" panel).
 */
export function buildEncryptedSnapshots(owner: MultiHolder, gristDoc: GristDoc): DomContents {
  const encryption = getEncryption(gristDoc);
  if (!encryption) { return null; }
  const canRestore = encryption.isOwner && encryption.canReadAll;
  return [
    cssHint(t("Versions of this document are saved regularly (encrypted): the most recent ones are kept.")),
    domAsync(encryption.listSnapshots().then(snapshots => snapshots.map((snapshot, i) => cssSnapshot(
      dom("div",
        dom("div", new Date(snapshot.timeMs).toLocaleString(), i === 0 ? ` (${t("latest")})` : null),
        cssSnapshotDetails(snapshot.userName ? t("Saved by {{name}}", { name: snapshot.userName }) : ""),
      ),
      (canRestore && i > 0) ? basicButton(t("Restore"),
        dom.on("click", () => confirmModal(t("Restore this version?"), t("Restore"),
          () => encryption.restoreSnapshot(snapshot.actionNum),
          { explanation: t("The document will be as it was then: changes since will be undone (they're " +
            "still in the history, as an earlier version). Members who have it open will reload it.") })),
        testId("encrypted-snapshot-restore")) : null,
      testId("encrypted-snapshot"),
    )))),
  ];
}

const cssHint = styled("div", `
  color: ${theme.lightText};
  margin: 8px 16px;
  line-height: 1.4;
`);

const cssAudience = styled("div", `
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin: 0 16px 8px 16px;
`);

const cssMember = styled("span", `
  border-radius: 3px;
  padding: 2px 6px;
  background-color: ${theme.pageBg};
  border: 1px solid ${theme.pagePanelsBorder};
`);

const cssLockIcon = styled(icon, `
  --icon-color: ${theme.lightText};
  width: 12px;
  height: 12px;
  margin-left: 4px;
  flex: none;
`);

const cssEncryptionSettings = styled("div", `
  margin: 8px 0;
`);

const cssMembers = styled("div", `
  display: grid;
  grid-template-columns: auto auto auto auto;
  gap: 4px 16px;
  margin: 8px 16px;
`);

const cssMemberRow = styled("div", `
  display: contents;
`);

const cssExplanation = styled("div", `
  line-height: 1.4;
  & p { margin: 0 0 8px 0; }
`);

const cssProgressBar = styled("div", `
  height: 6px;
  border-radius: 3px;
  margin: 8px 16px;
  background-color: ${theme.pagePanelsBorder};
  overflow: hidden;
`);

const cssProgressFill = styled("div", `
  height: 100%;
  background-color: ${theme.controlPrimaryBg};
  transition: width 0.3s;
`);

const cssSnapshot = styled("div", `
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  margin: 8px 16px;
`);

const cssSnapshotDetails = styled("div", `
  color: ${theme.lightText};
`);

/**
 * While suggesting changes to an encrypted document (members who can't edit it, when it accepts
 * suggestions): sends them, with a description.
 */
export function sendSuggestion(gristDoc: GristDoc) {
  const encryption = getEncryption(gristDoc);
  if (!encryption) { return; }
  if (encryption.pendingSuggestionCount === 0) {
    reportWarning(t("Make your changes first: they'll be sent as a suggestion."));
    return;
  }
  saveModal((ctl, owner) => {
    const desc = Observable.create(owner, "");
    return {
      title: t("Send your suggestion"),
      body: [
        cssHint(t("Your changes ({{count}}) are sent to the members who can edit this document, who may apply " +
          "them. They're undone here meanwhile.", { count: encryption.pendingSuggestionCount })),
        cssTextArea(dom.prop("value", desc), dom.on("input", (e, elem) => desc.set(elem.value)),
          { placeholder: t("What do you suggest, and why? (optional)") }, testId("suggestion-desc")),
      ],
      saveLabel: t("Send"),
      saveFunc: async () => {
        await encryption.submitSuggestion(desc.get().trim());
        reportSuccess(t("Suggestion sent."));
      },
    };
  });
}

export function discardSuggestion(gristDoc: GristDoc) {
  const encryption = getEncryption(gristDoc);
  if (!encryption) { return; }
  confirmModal(t("Discard your changes?"), t("Discard"),
    () => encryption.discardSuggestion(),
    { explanation: t("The changes you made (not sent as a suggestion yet) will be undone.") });
}

/** For members who can edit an encrypted document: the suggestions waiting, to apply or dismiss. */
export function showSuggestions(gristDoc: GristDoc) {
  const encryption = getEncryption(gristDoc);
  if (!encryption) { return; }
  modal((ctl, owner) => {
    const version = Observable.create(owner, 0);
    owner.autoDispose(encryption.suggestionsChanged.addListener(() => version.set(version.get() + 1)));
    const handle = (action: () => Promise<void>) => () => {
      action().then(() => version.set(version.get() + 1)).catch(reportError);
    };
    return [
      cssModalTitle(t("Suggestions"), testId("suggestions")),
      cssModalBody(
        dom.domComputed(version, () => domAsync(encryption.listSuggestions().then(list => list.length === 0 ?
          cssHint(t("There are no suggestions waiting.")) :
          list.map(s => cssSuggestion(
            dom("div",
              dom("b", s.userName || t("A member")), " · ", new Date(s.timeMs).toLocaleString(),
            ),
            s.desc ? dom("div", s.desc, testId("suggestion-text")) : null,
            cssSnapshotDetails(describeUserActions(s.userActions)),
            cssRow(
              encryption.canEdit ? primaryButton(t("Apply"),
                dom.on("click", handle(() => encryption.applySuggestion(s.id))), testId("suggestion-apply")) : null,
              basicButton(encryption.canEdit ? t("Dismiss") : t("Withdraw"),
                dom.on("click", handle(() => encryption.dismissSuggestion(s.id))), testId("suggestion-dismiss")),
            ),
            testId("suggestion"),
          ))))),
      ),
      cssModalButtons(basicButton(t("Close"), dom.on("click", () => ctl.close()))),
    ];
  });
}

/** A short description of what user actions do (e.g. for suggestions). */
export function describeUserActions(actions: UserAction[]): string {
  const counts = new Map<string, number>();
  for (const action of actions) {
    const [name, tableId] = action as [string, string];
    const rows = Array.isArray(action[2]) ? action[2].length : 1;
    const label = typeof tableId === "string" && !tableId.startsWith("_grist") ?
      `${name.replace(/^Bulk/, "")} (${tableId})` : name.replace(/^Bulk/, "");
    counts.set(label, (counts.get(label) || 0) + rows);
  }
  return [...counts.entries()].map(([label, n]) => n > 1 ? `${label} × ${n}` : label).join(", ");
}

const cssTextArea = styled("textarea", `
  width: 100%;
  min-height: 80px;
  margin-top: 8px;
  padding: 8px;
  border-radius: 3px;
  border: 1px solid ${theme.inputBorder};
  background-color: ${theme.inputBg};
  color: ${theme.inputFg};
`);

const cssSuggestion = styled("div", `
  padding: 8px 0;
  border-bottom: 1px solid ${theme.pagePanelsBorder};
  & > div { margin: 4px 0; }
`);
