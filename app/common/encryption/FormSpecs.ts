/**
 * Forms of encrypted documents, on the side of the document's members (see EncryptedForms.ts):
 * building what respondents get of a form (its "spec": the same as the server builds for regular
 * documents, see DocApi's GET /forms/:vsId), and reading their answers.
 *
 * Forms can fill private columns: their answers can then only be read by members who can read
 * those columns (the form's private key is sealed with their keys, see EncryptedFormKeys). Fields
 * of private columns added since the form was published by such a member are left out until one
 * publishes it again. Formulas are left out, as for regular documents; and so are values of
 * private columns among the choices of references (anyone with the form's link would see them).
 * Files attached in answers are uploaded encrypted by respondents, and added as attachments
 * (encrypted with the keys of their column) along with the answer.
 */
import { TableDataAction, UserAction } from "app/common/DocActions";
import { DocData } from "app/common/DocData";
import { ColumnPrivacy } from "app/common/encryption/ColumnPrivacy";
import {
  decryptFormAnswer, EncryptedFormKeys, FormAnswerFile, FormSpec,
} from "app/common/encryption/EncryptedForms";
import { base64ToBytes } from "app/common/encryption/EncryptionCrypto";
import { DOC_SCOPE, EncryptedInboxEntry } from "app/common/encryption/EncryptionTypes";
import { INITIAL_FIELDS_COUNT } from "app/common/Forms";
import {
  extractTypeFromColType, getReferencedTableId, isBlankValue, isFullReferencingType,
} from "app/common/gristTypes";
import { safeJsonParse } from "app/common/gutil";

/** The form settings kept by a form section (in its shareOptions). */
export interface FormShareOptions {
  form?: boolean;
  publish?: boolean;
  encryptedForm?: EncryptedFormKeys;
}

export function getFormShareOptions(docData: DocData, sectionId: number): FormShareOptions {
  const section = docData.getMetaTable("_grist_Views_section").getRecord(sectionId);
  return safeJsonParse(String(section?.shareOptions || ""), {}) || {};
}

/** Form sections published as encrypted forms. */
export function getPublishedForms(docData: DocData): { sectionId: number, keys: EncryptedFormKeys }[] {
  return docData.getMetaTable("_grist_Views_section").getRecords()
    .map(section => ({ sectionId: section.id, options: safeJsonParse(String(section.shareOptions || ""), {}) || {} }))
    .filter(({ options }) => options.publish && options.encryptedForm)
    .map(({ sectionId, options }) => ({ sectionId, keys: options.encryptedForm }));
}

/**
 * The columns of a form that answers may fill: its fields that aren't formulas, and that aren't
 * private, or are private with scopes among `scopes` (those the form's private key is sealed for).
 */
export function getFormColumns(docData: DocData, privacy: ColumnPrivacy, sectionId: number, scopes: string[] = []) {
  const section = docData.getMetaTable("_grist_Views_section").getRecord(sectionId);
  const table = section && docData.getMetaTable("_grist_Tables").getRecord(section.tableRef);
  if (!section || !table) { return null; }
  const columns = docData.getMetaTable("_grist_Tables_column");
  const fields = docData.getMetaTable("_grist_Views_section_field").filterRecords({ parentId: sectionId })
    .map(field => ({ field, col: columns.getRecord(field.colRef) }))
    .filter(({ col }) => col && !(col.isFormula && col.formula) &&
      privacy.scopesOf(table.tableId, col.colId).every(scope => scopes.includes(scope)));
  return {
    section, table,
    fields: fields as { field: typeof fields[0]["field"], col: NonNullable<typeof fields[0]["col"]> }[],
  };
}

/** The scopes of the private columns a form's fields are for. */
export function getFormScopes(docData: DocData, privacy: ColumnPrivacy, sectionId: number): string[] {
  const section = docData.getMetaTable("_grist_Views_section").getRecord(sectionId);
  const table = section && docData.getMetaTable("_grist_Tables").getRecord(section.tableRef);
  if (!section || !table) { return []; }
  const columns = docData.getMetaTable("_grist_Tables_column");
  const scopes = new Set<string>();
  for (const field of docData.getMetaTable("_grist_Views_section_field").filterRecords({ parentId: sectionId })) {
    const col = columns.getRecord(field.colRef);
    if (!col || (col.isFormula && col.formula)) { continue; }
    for (const scope of privacy.scopesOf(table.tableId, col.colId)) { scopes.add(scope); }
  }
  return [...scopes].sort();
}

/** Builds what respondents get of a form. */
export async function buildFormSpec(docData: DocData, privacy: ColumnPrivacy, sectionId: number,
  keys: EncryptedFormKeys, fetchTable: (tableId: string) => Promise<TableDataAction>): Promise<FormSpec> {
  const formColumns = getFormColumns(docData, privacy, sectionId, keys.scopes);
  if (!formColumns) { throw new Error("Form not found"); }
  const { section, table, fields } = formColumns;
  const columns = docData.getMetaTable("_grist_Tables_column");

  let formLayoutSpec = section.layoutSpec;
  if (!formLayoutSpec) {
    formLayoutSpec = JSON.stringify({
      type: "Layout",
      children: [
        { type: "Label" },
        { type: "Label" },
        {
          type: "Section",
          children: [
            { type: "Label" },
            { type: "Label" },
            ...fields.slice(0, INITIAL_FIELDS_COUNT).map(f => ({ type: "Field", leaf: f.field.id })),
          ],
        },
      ],
    });
  }

  const tables = new Map<string, Promise<TableDataAction>>();
  const getTable = (tableId: string) => {
    if (!tables.has(tableId)) { tables.set(tableId, fetchTable(tableId)); }
    return tables.get(tableId)!;
  };
  const getRefValues = async (col: typeof fields[0]["col"]) => {
    const refTableId = getReferencedTableId(col.type);
    if (!refTableId) { return []; }
    const refCol = col.visibleCol ? columns.getRecord(col.visibleCol) : null;
    if (col.visibleCol && !refCol) { return []; }
    const refColId = refCol?.colId || "id";
    // Values of private columns aren't given to respondents.
    if (refColId !== "id" && privacy.scopesOf(refTableId, refColId).length > 0) { return []; }
    const [, , rowIds, values] = await getTable(refTableId);
    return rowIds.map((rowId, i) => [rowId, refColId === "id" ? rowId : values[refColId]?.[i]] as const)
      .filter(([, value]) => !isBlankValue(value as any));
  };

  const formFieldsById = Object.fromEntries(await Promise.all(fields.map(async ({ field, col }) => {
    const fieldOptions = safeJsonParse(String(field.widgetOptions || ""), {});
    const colOptions = safeJsonParse(String(col.widgetOptions || ""), {});
    const options = { ...colOptions, ...fieldOptions };
    return [field.id, {
      colId: col.colId,
      description: fieldOptions.description || col.description,
      question: options.question || col.label || col.colId,
      options,
      type: extractTypeFromColType(col.type),
      refValues: isFullReferencingType(col.type) ? await getRefValues(col) : null,
    }] as const;
  })));

  const rawSection = docData.getMetaTable("_grist_Views_section").getRecord(table.rawViewSectionRef);
  return {
    v: 1,
    formId: keys.formId,
    publicKey: keys.publicKey,
    form: {
      formFieldsById,
      formLayoutSpec,
      formTableId: table.tableId,
      formTitle: section.title || rawSection?.title || table.tableId,
    },
  };
}

/** What reading answers needs from the member's browser. */
export interface FormAnswerHelpers {
  // The form's private key, if the member can read it (see EncryptedFormKeys).
  getPrivateKey(keys: EncryptedFormKeys): Promise<string | null>;
  // Stores a file attached in an answer as an attachment of the document, encrypted with the key
  // of the given scope: returns its fileIdent (see EncryptedAttachments.ts).
  storeFile(file: FormAnswerFile, scope: string): Promise<string>;
}

/**
 * Reads answers waiting in the inbox: returns the user actions adding those that can be added
 * (for published forms, with values only for the form's fields, and their files as attachments),
 * the inbox entries they're for, and those that can't ever be added (to drop). Answers this member
 * can't read (forms filling private columns they can't read) are left for others.
 */
export async function readFormAnswers(docData: DocData, privacy: ColumnPrivacy, entries: EncryptedInboxEntry[],
  helpers: FormAnswerHelpers): Promise<{ actions: UserAction[], ids: number[], invalid: number[] }> {
  const forms = new Map(getPublishedForms(docData).map(f => [f.keys.formId, f]));
  // Forms unpublished since still take the answers sent before.
  for (const section of docData.getMetaTable("_grist_Views_section").getRecords()) {
    const options: FormShareOptions = safeJsonParse(String(section.shareOptions || ""), {}) || {};
    if (options.encryptedForm && !forms.has(options.encryptedForm.formId)) {
      forms.set(options.encryptedForm.formId, { sectionId: section.id, keys: options.encryptedForm });
    }
  }
  const actions: UserAction[] = [];
  const ids: number[] = [];
  const invalid: number[] = [];
  const privateKeys = new Map<string, string | null>();
  const attachments = docData.getMetaTable("_grist_Attachments");
  let nextAttId = Math.max(0, ...attachments.getRowIds()) + 1;
  for (const entry of entries) {
    const form = forms.get(entry.formId);
    const formColumns = form && getFormColumns(docData, privacy, form.sectionId, form.keys.scopes);
    if (!form || !formColumns) { invalid.push(entry.id); continue; }
    if (!privateKeys.has(form.keys.formId)) {
      privateKeys.set(form.keys.formId, await helpers.getPrivateKey(form.keys));
    }
    const privateKey = privateKeys.get(form.keys.formId);
    if (!privateKey) { continue; }    // For members who can read it.
    const added: UserAction[] = [];
    let colValues: { [colId: string]: any };
    try {
      const answer = await decryptFormAnswer(privateKey, base64ToBytes(entry.payload));
      if (answer.tableId !== formColumns.table.tableId) { throw new Error("Answer for another table"); }
      const byColId = new Map(formColumns.fields.map(f => [f.col.colId, f.col]));
      colValues = Object.fromEntries(Object.entries(answer.colValues).filter(([colId]) => byColId.has(colId)));
      // Files: added as attachments, which cells refer to.
      for (const [colId, value] of Object.entries(colValues)) {
        if (extractTypeFromColType(byColId.get(colId)!.type) !== "Attachments") { continue; }
        if (!Array.isArray(value) || value[0] !== "L") { colValues[colId] = null; continue; }
        const scope = privacy.scopesOf(formColumns.table.tableId, colId)[0] || DOC_SCOPE;
        const attIds: number[] = [];
        for (const ref of value.slice(1)) {
          const file = typeof ref === "number" && ref < 0 ? answer.files?.[-ref - 1] : undefined;
          if (!file) { throw new Error("Invalid file"); }
          const fileIdent = await helpers.storeFile(file, scope);
          const attId = nextAttId++;
          added.push(["AddRecord", "_grist_Attachments", attId, {
            fileName: file.name, fileSize: file.size, fileIdent, timeUploaded: entry.timeMs / 1000,
          }]);
          attIds.push(attId);
        }
        colValues[colId] = ["L", ...attIds];
      }
    } catch (e) {
      invalid.push(entry.id);
      continue;
    }
    actions.push(...added, ["AddRecord", formColumns.table.tableId, null, colValues]);
    ids.push(entry.id);
  }
  return { actions, ids, invalid };
}
