/**
 * User interface for encrypted documents' keys: private columns (in the column's settings and
 * headers), and members' access (in the document's settings). Only shown for encrypted
 * documents, through DocComm.encryption (see types.ts).
 */
import { cssSmallButton } from "app/client/components/Forms/styles";
import { domAsync } from "app/client/lib/domAsync";
import { loadEncryption } from "app/client/lib/imports";
import { makeT } from "app/client/lib/localization";
import { reportError, reportSuccess, reportWarning } from "app/client/models/errors";
import { urlState } from "app/client/models/gristUrlState";
import { textInput } from "app/client/ui/inputs";
import { cssLabel, cssRow } from "app/client/ui/RightPanelStyles";
import { SectionItem } from "app/client/ui/SettingsLayout";
import { hoverTooltip } from "app/client/ui/tooltips";
import { basicButton, primaryButton, textButton } from "app/client/ui2018/buttons";
import { labeledSquareCheckbox } from "app/client/ui2018/checkbox";
import { colors, testId, theme } from "app/client/ui2018/cssVars";
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
import type { IDocEncryption, KeyGrantResult, WaitingAnswers } from "app/client/encryption/types";
import type { ColumnRec } from "app/client/models/entities/ColumnRec";
import type { TableRec } from "app/client/models/entities/TableRec";
import type { ViewRec } from "app/client/models/entities/ViewRec";
import type { IKeyVault } from "app/common/encryption/EncryptionCrypto";

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
export function buildColumnPrivacySection(owner: MultiHolder, gristDoc: GristDoc, column: ColumnRec,
  options: { isQuestion?: boolean } = {}): DomContents {
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
      const tableRef = use(column.parentId);
      return {
        scopes: encryption.columnScopes(tableId, colId), colRef,
        ownScope: encryption.columnOwnScope(colRef),
        tableScope: tableRef ? encryption.tableScope(tableRef) : null,
      };
    }, ({ scopes, colRef, ownScope, tableScope }) => [
      buildColumnPrivacy(encryption, { scopes, colRef, ownScope, tableScope }),
      // (Forms of encrypted documents encrypt answers for those who can read them.)
      (options.isQuestion && colRef && scopes.length > 0) ?
        cssHint(t("Respondents can still answer it: only members who can read this column can read their answers."),
          testId("question-private")) : null,
    ]),
  ];
}

function buildColumnPrivacy(encryption: IDocEncryption, { scopes, colRef, ownScope, tableScope }: {
  scopes: string[], colRef: number, ownScope: string | null, tableScope: string | null,
}): DomContents {
  if (!colRef) { return null; }
  if (scopes.length === 0) {
    return [
      cssHint(t("All members of the document have access to this column.")),
      encryption.isOwner ? cssRow(
        textButton(t("Make private"),
          dom.on("click", () => editAudience(encryption, { kind: "column", ref: colRef, scope: null })),
          testId("column-make-private")),
      ) : null,
    ];
  }
  // A column of a private table (without a scope of its own) is managed with its table.
  // (Its own members can then only be some of the table's: reading it takes both keys.)
  if (!ownScope && tableScope) {
    return [
      buildPrivacyStatus(encryption, "table", tableScope),
      cssHint(t("It's in a private table: who has access to it is set in the table's settings (Data tab)."),
        testId("column-private-table")),
      (encryption.isOwner && encryption.canReadScope(tableScope)) ? cssRow(
        textButton(t("Restrict to some of them"),
          dom.on("click", () => editAudience(encryption,
            { kind: "column", ref: colRef, scope: null, within: tableScope })),
          testId("column-make-private"))) : null,
    ];
  }
  if (!ownScope) {
    return cssHintWithIcon(cssHintIcon("Lock"),
      dom("div", t("This formula uses private columns: only members who can read them can see its results.")),
      testId("column-private-derived"));
  }
  return [
    buildPrivateTarget(encryption, { kind: "column", ref: colRef, scope: ownScope, within: tableScope }),
    // (Then reading it takes both keys.)
    tableScope ? cssHint(t("It's also in a private table: only members with access to both have access to it."),
      testId("column-private-in-table")) : null,
  ];
}

/**
 * The "Privacy" section of a table's settings, for encrypted documents: who can read the whole
 * table (and, for owners, the controls to change it). Summary tables follow their source.
 */
export function buildTablePrivacySection(owner: MultiHolder, gristDoc: GristDoc, table: TableRec): DomContents {
  const encryption = getEncryption(gristDoc);
  if (!encryption) { return null; }
  const version = keysVersion(owner, encryption);
  return [
    cssLabel(t("PRIVACY")),
    dom.domComputed((use) => {
      use(version);
      const tableRef = use(table.id);
      return { tableRef, scope: tableRef ? encryption.tableScope(tableRef) : null };
    }, ({ tableRef, scope }) => {
      if (!tableRef) { return null; }
      if (!scope) {
        return [
          cssHint(t("All members of the document have access to this table, except its private columns.")),
          encryption.isOwner ? cssRow(
            textButton(t("Make private"),
              dom.on("click", () => editAudience(encryption, { kind: "table", ref: tableRef, scope: null })),
              testId("table-make-private")),
          ) : null,
        ];
      }
      return [
        buildPrivateTarget(encryption, { kind: "table", ref: tableRef, scope }),
        cssHint(t("Its name, its columns and its number of rows stay visible to all members."),
          testId("table-private-visible")),
      ];
    }),
  ];
}

interface PrivacyTarget {
  kind: "column" | "table";
  ref: number;               // colRef or tableRef.
  scope: string | null;      // Null while not private yet.
  within?: string | null;    // For a column of a private table: the table's scope.
}

// What a private column or table shows: who can read it, and (for owners who can) the controls.
function buildPrivateTarget(encryption: IDocEncryption, target: PrivacyTarget & { scope: string }): DomContents {
  const readable = encryption.canReadScope(target.scope);
  const kind = target.kind;
  return [
    buildPrivacyStatus(encryption, kind, target.scope),
    (encryption.isOwner && readable) ? [
      cssRow(textButton(t("Change who has access"),
        dom.on("click", () => editAudience(encryption, target)),
        testId(`${kind}-change-audience`))),
      cssRow(textButton(t("Make public"),
        dom.on("click", () => (kind === "table" ? encryption.makeTablePublic(target.ref) :
          encryption.makeColumnPublic(target.ref)).catch(reportError)),
        testId(`${kind}-make-public`))),
    ] : null,
  ];
}

// "Private column/table", and the members who can read it.
function buildPrivacyStatus(encryption: IDocEncryption, kind: "column" | "table", scope: string): DomContents {
  const readable = encryption.canReadScope(scope);
  return [
    cssHintWithIcon(cssHintIcon("Lock"),
      dom("div", kind === "table" ?
        (readable ? t("Private table: only these members have access to it.") :
          t("Private table: you don't have access to its data.")) :
        (readable ? t("Private column: only these members have access to it.") :
          t("Private column: you don't have access to its values."))),
      testId(`${kind}-private`)),
    domAsync(encryption.getScopeAudience(scope).then(members =>
      cssAudience(members.map(m => cssMember(
        m.userId === encryption.userId ? t("{{name}} (you)", { name: m.name || m.email }) : (m.name || m.email),
        hoverTooltip(m.email),
        testId(`${kind}-audience-member`),
      ))),
    )),
  ];
}

/** Picks the members who can read a private column or table (making it private if it isn't yet). */
function editAudience(encryption: IDocEncryption, target: PrivacyTarget) {
  const isTable = target.kind === "table";
  saveModal((ctl, owner) => {
    const selected = new Map<number, Observable<boolean>>();
    const members = Observable.create<EncryptionMember[] | null>(owner, null);
    const load = async () => {
      // (Owners always have access: they aren't chosen.)
      const all = (target.within ? await encryption.getScopeAudience(target.within) : await encryption.listMembers())
        .filter(m => m.userId !== encryption.userId && m.access !== "owners");
      const audience = target.scope ? await encryption.getScopeAudience(target.scope) : [];
      for (const m of all) {
        selected.set(m.userId, Observable.create(owner, audience.some(a => a.userId === m.userId)));
      }
      if (!owner.isDisposed()) { members.set(all); }
    };
    load().catch(reportError);
    return {
      title: isTable ?
        (target.scope ? t("Who has access to this table") : t("Make this table private")) :
        (target.scope ? t("Who has access to this column") : t("Make this column private")),
      body: [
        cssHint(isTable ?
          t(`Only owners and the members you select will see this table's data and the results of formulas using it, and can change them if their role allows it. Others will see a lock instead, and can't change them. Its name, columns and number of rows stay visible.`) :
          target.within ?
            t(`Among the members with access to the table, only owners and those you select will see this column's values and the results of formulas using them, and can change them if their role allows it. Others will see a lock instead, and can't change them.`) :
            t(`Only owners and the members you select will see this column's values and the results of formulas using them, and can change them if their role allows it. Others will see a lock instead, and can't change them.`)),
        dom.domComputed(members, list => list === null ? cssHint(t("Loading…")) : list.length === 0 ?
          cssHint(t("There are no other members than owners.")) :
          list.map(m => cssRow(labeledSquareCheckbox(selected.get(m.userId)!,
            m.name ? `${m.name} (${m.email})` : m.email, testId("audience-member"))))),
      ],
      saveLabel: target.scope ? t("Save") : t("Make private"),
      saveFunc: async () => {
        const userIds = [...selected.entries()].filter(([, obs]) => obs.get()).map(([id]) => id);
        const result = target.scope ? await encryption.setScopeAudience(target.scope, userIds) :
          isTable ? await encryption.makeTablePrivate(target.ref, userIds) :
            await encryption.makeColumnPrivate(target.ref, userIds);
        reportSuccess(t("Saved"));
        reportKeyGrant({ granted: [], notReady: result.notReady });
      },
    };
  });
}

/**
 * Whether the user enabled encryption on their account, for the account page (see AccountPage),
 * with what can be done about it: enable it (without having to open or encrypt a document), or
 * manage it in the encryption service.
 */
export function watchAccountEncryption(owner: MultiHolder, encryptionUserId: string | undefined) {
  const config = getGristConfig().encryption;
  const status = Observable.create<"loading" | "enabled" | "disabled" | "unavailable">(owner, "loading");
  let vault: IKeyVault | undefined;
  const refresh = async () => {
    vault = vault ?? await (await loadEncryption()).getKeyVault(config!, encryptionUserId ?? null);
    const enabled = await vault.hasKeys();
    if (!owner.isDisposed()) { status.set(enabled ? "enabled" : "disabled"); }
  };
  if (config) {
    refresh().catch((e) => {
      console.warn("[encryption] Could not reach the encryption service", e);
      if (!owner.isDisposed()) { status.set("unavailable"); }
    });
  }
  return {
    status,
    canEnable: () => Boolean(vault?.openOnboarding),
    enable: () => { vault?.openOnboarding?.().then(refresh).catch(reportError); },
    canManage: () => Boolean(vault?.openSettings),
    manage: () => vault?.openSettings?.(),
  };
}

/** Tells who got access to keys, and who couldn't (members who haven't enabled encryption). */
export function reportKeyGrant(result: KeyGrantResult) {
  if (result.granted.length > 0) {
    reportSuccess(t("Gave access to {{count}} member(s).", { count: result.granted.length }));
  }
  if (result.notReady.length > 0) {
    reportWarning(t(`{{members}} haven't enabled encryption on their account yet: give them access again once they have.`, { members: result.notReady.map(m => m.name || m.email).join(", ") }));
  }
}

/**
 * A lock in the header of private columns. Not for columns that are private only as part of a
 * private table: the table's widgets show it once (see buildPrivateTableMarker()).
 */
export function buildPrivateColumnMarker(owner: MultiHolder, gristDoc: GristDoc, column: ColumnRec): DomContents {
  const encryption = getEncryption(gristDoc);
  if (!encryption) { return null; }
  const version = keysVersion(owner, encryption);
  const isPrivate = Computed.create(owner, (use) => {
    use(version);
    const tableRef = use(column.parentId);
    const tableScope = tableRef ? encryption.tableScope(tableRef) : null;
    // (For members who can't read the table, all of it is locked alike.)
    if (tableScope && !encryption.canReadScope(tableScope)) { return false; }
    return encryption.columnScopes(use(use(column.table).tableId), use(column.colId))
      .some(scope => scope !== tableScope);
  });
  return dom.maybe(isPrivate, () => cssLockIcon("Lock", testId("column-private-marker")));
}

/** A lock in the title of widgets of private tables (and in the list of raw data). */
export function buildPrivateTableMarker(owner: MultiHolder, gristDoc: GristDoc, table: TableRec): DomContents {
  const encryption = getEncryption(gristDoc);
  if (!encryption) { return null; }
  const version = keysVersion(owner, encryption);
  const scope = Computed.create(owner, (use) => {
    use(version);
    const tableRef = use(table.id);
    return tableRef ? encryption.tableScope(tableRef) : null;
  });
  return dom.maybe(scope, s => cssTableLockIcon("Lock",
    hoverTooltip(encryption.canReadScope(s) ? t("Private table: only some members have access to it.") :
      t("Private table: you don't have access to its data.")),
    testId("table-private-marker")));
}

/**
 * Under the title of widgets of forms, and of tables forms fill (for members who can edit the
 * document): answers waiting to be added, and why this member can't add them, if they can't.
 */
export function buildWaitingAnswersAlert(owner: MultiHolder, gristDoc: GristDoc, sectionId: number): DomContents {
  const encryption = getEncryption(gristDoc);
  if (!encryption?.canEdit) { return null; }
  const waiting = Observable.create<WaitingAnswers | null>(owner, null);
  let refreshing = false;
  const refresh = () => {
    if (refreshing || owner.isDisposed()) { return; }
    refreshing = true;
    encryption.getWaitingAnswers(sectionId)
      .then((w) => { if (!owner.isDisposed()) { waiting.set(w); } })
      .catch(e => console.warn("[encryption] Could not list form answers waiting", e))
      .finally(() => { refreshing = false; });
  };
  owner.autoDispose(encryption.inboxChanged.addListener(refresh));
  owner.autoDispose(encryption.keysChanged.addListener(refresh));
  // Someone else may add them (with a change to the document), while some are waiting.
  const onDocAction = () => { if (waiting.get()?.count) { refresh(); } };
  gristDoc.on("onDocUserAction", onDocAction);
  owner.onDispose(() => gristDoc.off("onDocUserAction", onDocAction));
  refresh();
  return dom.maybe(use => use(waiting)?.count ? use(waiting) : null, (w) => {
    // (The plural follows `count`; `number` is what's shown, e.g. "200+" when there may be more.)
    const count = w.count;
    const number = w.more ? `${w.count}+` : String(w.count);
    // (Shown as text: i18next's HTML escaping would show apostrophes as "&#39;".)
    const noEscape = { interpolation: { escapeValue: false } };
    // E.g. "the column Staff › Salary, the table Payroll".
    const missing = dom("span", (w.missing || []).flatMap((m, i) => [i > 0 ? ", " : null,
      m.kind === "table" ? t("the table {{name}}", { name: cssColumnName(m.name) }) :
        t("the column {{name}}", { name: cssColumnName(m.name) })]));
    return cssWaitingAnswers(
      cssWaitingAnswers.cls("-busy", !w.reason),
      cssWaitingAnswersIcon(w.reason ? "Warning" : "Info"),
      dom("div",
        w.reason === "keys" ?
          t("{{number}} form answers are waiting. Only editors or owners with access to {{missing}} can add them.",
            { count, number, missing }) :
          w.reason === "blocked" ?
            t("{{number}} form answers are waiting. You can't add them. {{reason}}",
              { count, number, reason: w.message, ...noEscape }) :
            t("{{number}} form answers are waiting. Adding them…", { count, number }),
      ),
      testId("waiting-answers"),
    );
  });
}

/** A lock after the name of pages showing private tables, in the list of pages. */
export function buildPrivatePageMarker(owner: MultiHolder, gristDoc: GristDoc, view: ViewRec): DomContents {
  const encryption = getEncryption(gristDoc);
  if (!encryption) { return null; }
  const version = keysVersion(owner, encryption);
  // (A page may show several tables, in its widgets.)
  const privateTables = Computed.create(owner, (use) => {
    use(version);
    const tableRefs = use(use(view.viewSections).getObservable()).map(section => use(section.tableRef));
    return new Set(tableRefs.filter(tableRef => tableRef && encryption.tableScope(tableRef))).size;
  });
  return dom.maybe(privateTables, count => cssPageLockIcon("Lock",
    hoverTooltip(t("This page shows private tables: only some members have access to them.", { count })),
    testId("page-private-marker")));
}

/** The "Encryption" section of the document's settings: members, and their access to keys. */
export function buildEncryptionSettings(owner: MultiHolder, gristDoc: GristDoc): DomContents {
  const encryption = getEncryption(gristDoc);
  if (!encryption) { return null; }
  return SectionItem({
    id: "encryption-status",
    name: t("End-to-end encryption"),
    description: t("Its content is encrypted in members' browsers: the server can't read it"),
    value: (encryption.isOwner && encryption.canReadAll) ? cssSmallButton(t("Remove encryption"),
      dom.on("click", () => confirmDecryption(encryption)),
      testId("encryption-decrypt")) : cssStatus(icon("Lock"), t("On")),
  });
}

function confirmDecryption(encryption: IDocEncryption) {
  confirmModal(t("Remove encryption from this document?"), t("Remove encryption"), () => {
    runWithProgress(t("Removing encryption"),
      onProgress => encryption.decryptDocument(onProgress),
      () => window.location.reload());
  }, {
    explanation: cssExplanation(
      dom("p", t("The server will be able to read it again.")),
      dom("p", t("Private tables and columns become access rules, so members who couldn't read them still can't.")),
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
  return SectionItem({
    id: "encryption-encrypt",
    name: t("End-to-end encryption"),
    description: t("Make its content readable only in members' browsers: the server can't read it anymore"),
    value: cssSmallButton(t("Encrypt"),
      dom.on("click", () => confirmEncryption(gristDoc, doc.id, userId, config)),
      testId("encryption-encrypt")),
  });
}

// First makes sure the user enabled encryption on their account (as Docs and Drive do), then asks
// to confirm.
function confirmEncryption(gristDoc: GristDoc, docId: string, userId: number, config: EncryptionClientConfig) {
  loadEncryption().then(async (module) => {
    try {
      await module.ensureReadyToEncrypt(gristDoc.app.comm, docId, config);
    } catch (e) {
      // (Giving up the setup isn't an error.)
      if (e instanceof module.SetupCancelledError) { return; }
      throw e;
    }
    askToEncrypt(gristDoc, docId, userId, config);
  }).catch(reportError);
}

function askToEncrypt(gristDoc: GristDoc, docId: string, userId: number, config: EncryptionClientConfig) {
  confirmModal(t("Encrypt this document end to end?"), t("Encrypt"), () => {
    const comm = gristDoc.app.comm;
    let summary: EncryptionSummary | undefined;
    runWithProgress(t("Encrypting this document"), async (onProgress) => {
      const module = await loadEncryption();
      summary = await module.encryptDocument(comm, docId, userId, config, onProgress,
        vault => module.ensureVaultKeys(vault, "encrypt"));
    }, () => showEncryptionSummary(summary));
  }, {
    explanation: cssExplanation(
      dom("p", t("Only its members' browsers will be able to read it, not the server.")),
      dom("p", t(`Webhooks, the API and server-side exports stop working. Access rules hiding columns become private columns; rules hiding rows aren't supported (remove them first).`)),
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
    summary?.waitingMembers.length ? t(`{{members}} can't read it until they enable encryption and an owner gives them access.`, { members: summary.waitingMembers.join(", ") }) : null,
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
        cssHint(t(`The copy is encrypted end to end too, with keys of its own. Private columns stay private. Its members (those of its workspace) can read what they could read in this document.`)),
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
            reportWarning(t(`{{members}} can't read the copy until they enable encryption and an owner gives them access.`, { members: waiting.join(", ") }));
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
          { explanation: t(`The document will be as it was then: changes since will be undone (they're still in the history, as an earlier version). Members who have it open will reload it.`) })),
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

// A hint starting with an icon, aligned with its first line.
const cssHintWithIcon = styled(cssHint, `
  display: flex;
  align-items: flex-start;
  gap: 6px;
`);

const cssHintIcon = styled(icon, `
  flex: none;
  width: 12px;
  height: 12px;
  margin-top: 3px;
  --icon-color: ${theme.lightText};
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

const cssTableLockIcon = styled(icon, `
  --icon-color: ${theme.lightText};
  width: 12px;
  height: 12px;
  margin-right: 4px;
  flex: none;
`);

const cssPageLockIcon = styled(icon, `
  --icon-color: ${theme.lightText};
  width: 12px;
  height: 12px;
  margin: 0 4px;
  flex: none;
`);

const cssStatus = styled("div", `
  display: flex;
  align-items: center;
  gap: 4px;
  color: ${theme.controlPrimaryBg};
  --icon-color: ${theme.controlPrimaryBg};
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
        cssHint(t(`Your changes ({{count}}) are sent to the members who can edit this document, who may apply them. They're undone here meanwhile.`, { count: encryption.pendingSuggestionCount })),
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

const cssWaitingAnswers = styled("div.viewsection_alert", `
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin-bottom: 8px;
  padding: 8px 12px;
  border: 1px solid ${colors.warning};
  border-radius: 4px;
  background-color: color-mix(in srgb, ${colors.warning} 12%, ${theme.mainPanelBg});
  color: ${theme.text};
  line-height: 16px;
  &-busy {
    border-color: ${theme.pagePanelsBorder};
    background-color: ${theme.mainPanelBg};
  }
`);

const cssColumnName = styled("span", `
  font-weight: 600;
  white-space: nowrap;
`);

const cssWaitingAnswersIcon = styled(icon, `
  flex: none;
  --icon-color: ${colors.warning};
  .${cssWaitingAnswers.className}-busy > & {
    --icon-color: ${theme.lightText};
  }
`);
