/**
 * The "Access Rules" page of encrypted documents. The server can't read their data, so it can't
 * apply rules with conditions: what members can read depends on the keys they hold (private
 * tables and columns), and what they can change on their role. This page explains it, and lists
 * private tables and columns with who can read them.
 */
import { allCommands } from "app/client/components/commands";
import { cssSmallButton } from "app/client/components/Forms/styles";
import { domAsync } from "app/client/lib/domAsync";
import { makeT } from "app/client/lib/localization";
import { reportError } from "app/client/models/errors";
import { urlState } from "app/client/models/gristUrlState";
import { cssSettingsPage, SectionCard, SectionItem } from "app/client/ui/SettingsLayout";
import { hoverTooltip } from "app/client/ui/tooltips";
import { textButton } from "app/client/ui2018/buttons";
import { testId, theme } from "app/client/ui2018/cssVars";
import { icon } from "app/client/ui2018/icons";
import { waitObs } from "app/common/gutil";
import { isOwner } from "app/common/roles";

import { dom, DomContents, MultiHolder, Observable, styled } from "grainjs";

import type { GristDoc } from "app/client/components/GristDoc";
import type { IDocEncryption } from "app/client/encryption/types";

const t = makeT("EncryptedAccessRules");

interface PrivateTarget {
  kind: "table" | "column";
  name: string;
  scope: string;
  sectionRef: number;          // The table's raw data widget, to open its settings.
  colRef?: number;
}

export function buildEncryptedAccessRules(owner: MultiHolder, gristDoc: GristDoc): DomContents {
  const encryption = gristDoc.docComm.encryption;
  if (!encryption) { return null; }
  const version = Observable.create(owner, 0);
  owner.autoDispose(encryption.keysChanged.addListener(() => version.set(version.get() + 1)));
  const isDocOwner = isOwner(gristDoc.docPageModel.currentDoc.get());

  return cssPage({ tabIndex: "-1" },
    SectionCard(t("Access rules"), [
      cssIntro(
        dom("p", t(`This document is end-to-end encrypted: the server can't read its data, so it can't apply access rules with conditions.`)),
        dom("p", t(`Owners can make whole tables or columns private: only the members they choose get their keys, to see them and, if their role allows it, change them. What members can change otherwise depends on their role.`)),
      ),
      SectionItem({
        id: "encryption-roles",
        name: t("Roles"),
        description: t(`Viewers can only view. Editors and owners can change what they have access to. Owners manage members and privacy.`),
        value: cssSmallButton(t("Manage users"),
          dom.on("click", () => encryption.reviewMembers()),
          testId("acl-encrypted-manage-users")),
      }),
    ]),
    SectionCard(t("Private tables and columns"), [
      dom.domComputed((use) => {
        use(version);
        const targets: PrivateTarget[] = [];
        for (const table of use(gristDoc.docModel.visibleTables.getObservable())) {
          const tableRef = use(table.id);
          const sectionRef = use(table.rawViewSectionRef);
          const tableName = use(table.tableNameDef);
          const tableScope = encryption.tableScope(tableRef);
          if (tableScope) {
            targets.push({ kind: "table", name: tableName, scope: tableScope, sectionRef });
          }
          for (const column of use(use(table.columns).getObservable())) {
            if (use(column.isHiddenCol)) { continue; }
            const scope = encryption.columnOwnScope(use(column.id));
            if (scope) {
              targets.push({ kind: "column", name: `${tableName} › ${use(column.label)}`, scope, sectionRef,
                colRef: use(column.id) });
            }
          }
        }
        return targets;
      }, targets => targets.length === 0 ?
        cssEmpty(isDocOwner ?
          t(`None: all members have access to the whole document. To make a table or column private, open its settings in the right panel.`) :
          t("None: all members have access to the whole document."),
        testId("acl-encrypted-none")) :
        targets.map(target => buildTarget(gristDoc, encryption, target))),
    ]),
    SectionCard(t("Not available in encrypted documents"), [
      cssIntro(
        dom("p", t("These access rules need the server to read the data:")),
        dom("ul",
          dom("li", t("Hiding some rows or cells, depending on their content")),
          dom("li", t("Conditions on user attributes, or on links shared with others")),
          dom("li", t("Different editing permissions per table or column, and checks of new values")),
          dom("li", t("Viewing the document as another user")),
        ),
        isDocOwner ? dom("p",
          t("To use them, remove encryption from the document in its "),
          textButton(t("settings"), urlState().setLinkUrl({ docPage: "settings" }),
            testId("acl-encrypted-settings")),
          ".",
        ) : null,
      ),
    ]),
    testId("acl-encrypted"),
  );
}

function buildTarget(gristDoc: GristDoc, encryption: IDocEncryption, target: PrivateTarget): DomContents {
  const readable = encryption.canReadScope(target.scope);
  return SectionItem({
    id: `encryption-${target.kind}-${target.colRef ?? target.sectionRef}`,
    name: cssTargetName(cssLock("Lock"), dom("span", target.name), testId("acl-encrypted-target")),
    description: [
      cssKind(target.kind === "table" ? t("Private table") : t("Private column")),
      readable ? domAsync(encryption.getScopeAudience(target.scope).then(members =>
        cssAudience(members.map(m => cssMember(
          m.userId === encryption.userId ? t("{{name}} (you)", { name: m.name || m.email }) : (m.name || m.email),
          hoverTooltip(m.email),
          testId("acl-encrypted-member"),
        ))),
      )) : cssKind(t("You don't have access to it."), testId("acl-encrypted-no-access")),
    ],
    value: cssSmallButton(t("Open settings"),
      dom.on("click", () => openSettings(gristDoc, target).catch(reportError)),
      testId("acl-encrypted-open")),
  });
}

// Opens the table's data (as the Raw data page does), with the right panel showing the table's or
// column's settings.
async function openSettings(gristDoc: GristDoc, target: PrivateTarget) {
  await urlState().pushUrl({ docPage: "data" });
  gristDoc.viewModel.activeSectionId(target.sectionRef);
  const section = gristDoc.docModel.viewSections.getRowModel(target.sectionRef);
  const view = await waitObs(section.viewInstance);
  if (target.colRef) {
    const fieldIndex = section.viewFields.peek().all().findIndex(f => f.colRef.peek() === target.colRef);
    if (fieldIndex >= 0) { view?.setCursorPos({ fieldIndex }); }
    allCommands.fieldTabOpen.run();
  } else {
    allCommands.dataSelectionTabOpen.run();
  }
}

const cssPage = styled(cssSettingsPage, `
  font-size: revert;
`);

const cssIntro = styled("div", `
  line-height: 1.5;
  margin-bottom: 8px;
  & p { margin: 0 0 8px 0; }
  & ul { margin: 0 0 8px 0; padding-left: 20px; }
`);

const cssEmpty = styled("div", `
  color: ${theme.lightText};
  line-height: 1.5;
`);

const cssTargetName = styled("span", `
  display: inline-flex;
  align-items: center;
  gap: 6px;
`);

const cssLock = styled(icon, `
  flex: none;
  width: 12px;
  height: 12px;
  --icon-color: ${theme.lightText};
`);

const cssKind = styled("div", `
  margin-bottom: 4px;
`);

const cssAudience = styled("div", `
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
`);

const cssMember = styled("span", `
  border-radius: 3px;
  padding: 2px 6px;
  background-color: ${theme.pageBg};
  border: 1px solid ${theme.pagePanelsBorder};
  color: ${theme.text};
`);
