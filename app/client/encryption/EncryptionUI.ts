/**
 * User interface for encrypted documents' keys: private columns (in the column's settings and
 * headers), and members' access (in the document's settings). Only shown for encrypted
 * documents, through DocComm.encryption (see types.ts).
 */
import { domAsync } from "app/client/lib/domAsync";
import { makeT } from "app/client/lib/localization";
import { reportError, reportSuccess, reportWarning } from "app/client/models/errors";
import { cssLabel, cssRow } from "app/client/ui/RightPanelStyles";
import { basicButton, primaryButton } from "app/client/ui2018/buttons";
import { labeledSquareCheckbox } from "app/client/ui2018/checkbox";
import { testId, theme } from "app/client/ui2018/cssVars";
import { icon } from "app/client/ui2018/icons";
import { saveModal } from "app/client/ui2018/modals";
import { EncryptionMember } from "app/common/encryption/EncryptionTypes";

import { Computed, dom, DomContents, MultiHolder, Observable, styled } from "grainjs";

import type { GristDoc } from "app/client/components/GristDoc";
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
    testId("encryption-settings"),
  );
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
