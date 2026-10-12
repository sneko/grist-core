/**
 * Private columns of encrypted documents: columns whose values only some members can read.
 *
 * A column is made private by giving it a scope ("column:<id>"), whose keys only some members
 * hold (see EncryptionTypes.ts). A whole table can be too: all its columns, including those added
 * later, then have the table's scope (and also their own, for those private themselves). Which
 * column or table a scope protects is kept by the server (ScopeBinding), not in the document: any
 * member holding the document key can change the document, but only owners holding a column's key
 * can make it public again. The column's
 * values then travel and get stored encrypted with the scope's key, inside changes and snapshots
 * that are otherwise encrypted with the document key ("sealed", see sealActions()).
 *
 * Formulas reading private columns are private too, with the same scopes: their results reveal
 * what they read. So are the columns a summary table groups by, when they're private in the
 * source table (whether as data, or as formulas reading private columns). Since members missing
 * a scope's key can't read the values such a formula needs, their data engine never computes it
 * ("frozen" column), and they see its results as locked, like the private values themselves.
 * What they can't do follows from this: change a value a formula they can't compute depends on
 * (or add or remove rows in its table, or change the columns and tables it uses), since the
 * formula couldn't be updated; such changes are refused, and must be made by a member who holds
 * the key. Similarly, they can't change private columns, nor their settings.
 *
 * Some metadata reveals private values too, and is sealed like them, cell by cell (see
 * metaCellScopes()): saved filters of private columns (which list values), the choices of
 * private Choice columns, comments on private cells, and the names and sizes of files attached
 * in private columns.
 *
 * Which formulas read which columns is found by looking for column names in formulas. This errs
 * on the side of caution: a formula mentioning a name used by a private column (even of another
 * table) counts as reading it. Formulas can't read columns without naming them: the data engine
 * refuses it (see ScopeMonitor in sandbox/grist/direct_sandbox.py), with the same scopes.
 *
 * Browsers check that changes they receive seal what must be, with the right keys (see
 * checkSealing()), and skip those that don't: a member without a column's key can't write values
 * in it. Sealed values also carry what they are the values of (table, column, rows, and the entry
 * of the history they were sealed for): members holding the key check it when unsealing, so that
 * sealed values can't be moved to other cells, nor replayed in later changes. Those that don't
 * match are locked (as they are for members without the key, who can't check them: all browsers
 * end up with the same document).
 */
import { CellValue, DocAction, TableDataAction } from "app/common/DocActions";
import { parseFileIdent } from "app/common/encryption/EncryptedAttachments";
import { marshalValue, unmarshalValue } from "app/common/encryption/EncryptedPayloads";
import { base64ToBytes, bytesToBase64 } from "app/common/encryption/EncryptionCrypto";
import { isColumnScope, tableTarget } from "app/common/encryption/EncryptionTypes";
import { Keyring, MissingKeyError } from "app/common/encryption/Keyring";
import { isLockedCell, LOCKED_CELL } from "app/common/encryption/LockedCell";
import { getDefaultForType } from "app/common/gristTypes";

import isEqual from "lodash/isEqual";

export { isLockedCell, LOCKED_CELL };

/** Thrown for changes a member isn't allowed to make because of private columns. */
export class EncryptionAccessError extends Error {
  public readonly code = "ENCRYPTION_ACCESS_DENIED";
}

/** Thrown for content that doesn't respect private columns (e.g. made by a modified client). */
export class TamperedContentError extends Error {}

interface ColumnInfo {
  colRef: number;
  tableId: string;
  colId: string;
  type: string;
  isFormula: boolean;
  formula: string;
  // The scopes of the column's own data: its own, and its table's if the table is private.
  ownScopes: string[];
  sourceRef: number;        // For group-by columns of summary tables: the source column.
}

const DATA_ACTIONS = new Set([
  "AddRecord", "BulkAddRecord", "UpdateRecord", "BulkUpdateRecord", "RemoveRecord", "BulkRemoveRecord",
  "ReplaceTableData", "TableData",
]);
const ROW_SET_ACTIONS = new Set(["AddRecord", "BulkAddRecord", "RemoveRecord", "BulkRemoveRecord", "ReplaceTableData"]);
const SINGLE_ROW_ACTIONS = new Set(["AddRecord", "UpdateRecord"]);

// Fields of metadata columns that, when changed for a column used by a formula the member can't
// compute, would change that formula's results.
const COLUMN_DEFINITION_FIELDS = ["colId", "type", "isFormula", "formula", "parentId"];

export class ColumnPrivacy {
  /**
   * Builds the model from the _grist_Tables and _grist_Tables_column metadata tables, and the
   * private columns and tables (target -> scope, see Keyring.bindingsAt() and tableTarget()).
   */
  public static fromMetaTables(tables: TableDataAction, columns: TableDataAction,
    bindings: Map<number, string>): ColumnPrivacy {
    const tableIds = new Map<number, string>();
    tables[2].forEach((rowId, i) => tableIds.set(rowId, tables[3].tableId[i] as string));
    const cols: ColumnInfo[] = [];
    const values = columns[3];
    columns[2].forEach((colRef, i) => {
      const tableId = tableIds.get(values.parentId[i] as number);
      if (!tableId) { return; }
      cols.push({
        colRef,
        tableId,
        colId: values.colId[i] as string,
        type: String(values.type[i] || "Any"),
        isFormula: Boolean(values.isFormula[i]),
        formula: String(values.formula[i] || ""),
        // (A column of a private table, private itself too, needs both keys.)
        ownScopes: [bindings.get(colRef), bindings.get(tableTarget(values.parentId[i] as number))]
          .filter((scope): scope is string => Boolean(scope)).sort(),
        sourceRef: Number(values.summarySourceCol?.[i]) || 0,
      });
    });
    return new ColumnPrivacy(cols);
  }

  private _scopes = new Map<string, string[]>();   // "tableId.colId" -> sorted scopes
  private _byRef = new Map<number, ColumnInfo>();
  private _byKey = new Map<string, ColumnInfo>();
  private _byColId = new Map<string, ColumnInfo[]>();
  private _tokens = new Map<ColumnInfo, Set<string>>();

  constructor(private _cols: ColumnInfo[]) {
    for (const col of _cols) {
      this._byRef.set(col.colRef, col);
      this._byKey.set(key(col.tableId, col.colId), col);
      const sameId = this._byColId.get(col.colId);
      if (sameId) { sameId.push(col); } else { this._byColId.set(col.colId, [col]); }
      if (col.formula) { this._tokens.set(col, getTokens(col.formula)); }
      this._scopes.set(key(col.tableId, col.colId), col.ownScopes);
    }
    // Formulas (including trigger formulas of data columns) reading protected columns are
    // protected too, and so are the group-by columns of summaries of protected columns. Repeat
    // until nothing changes, to follow formulas reading formulas.
    for (let changed = true; changed;) {
      changed = false;
      for (const col of _cols) {
        const tokens = this._tokens.get(col);
        const source = col.sourceRef ? this._byRef.get(col.sourceRef) : undefined;
        if (!tokens && !source) { continue; }
        const scopes = new Set(this.scopesOf(col.tableId, col.colId));
        const before = scopes.size;
        for (const token of tokens || []) {
          for (const other of this._byColId.get(token) || []) {
            if (other !== col) { this.scopesOf(other.tableId, other.colId).forEach(s => scopes.add(s)); }
          }
        }
        if (source) { this.scopesOf(source.tableId, source.colId).forEach(s => scopes.add(s)); }
        if (scopes.size !== before) {
          this._scopes.set(key(col.tableId, col.colId), [...scopes].sort());
          changed = true;
        }
      }
    }
  }

  /** The scopes whose keys are needed to read the column (empty if it isn't protected). */
  public scopesOf(tableId: string, colId: string): string[] {
    return this._scopes.get(key(tableId, colId)) || [];
  }

  /** Same as scopesOf(), for a column given by its row id in _grist_Tables_column. */
  public scopesOfRef(colRef: number): string[] {
    const col = this._byRef.get(colRef);
    return col ? this.scopesOf(col.tableId, col.colId) : [];
  }

  public getColumn(tableId: string, colId: string): ColumnInfo | undefined {
    return this._byKey.get(key(tableId, colId));
  }

  public hasProtectedColumns(): boolean {
    return [...this._scopes.values()].some(scopes => scopes.length > 0);
  }

  /** The scopes in use by the columns of the document. */
  public allScopes(): string[] {
    return [...new Set([...this._scopes.values()].flat())].sort();
  }

  /** The columns a scope applies to. */
  public columnsOfScope(scope: string): { tableId: string, colId: string }[] {
    return this._cols.filter(c => this.scopesOf(c.tableId, c.colId).includes(scope))
      .map(c => ({ tableId: c.tableId, colId: c.colId }));
  }

  /** The protected columns, with their scopes, as the data engine takes them (set_column_scopes). */
  public scopeEntries(): [string, string, string[]][] {
    return this._cols.filter(c => this.scopesOf(c.tableId, c.colId).length > 0)
      .map(c => [c.tableId, c.colId, this.scopesOf(c.tableId, c.colId)]);
  }

  /** Formula columns the member can't compute: their engine mustn't evaluate them. */
  public frozenColumns(canUseScope: (scope: string) => boolean): [string, string][] {
    return this._frozen(canUseScope).map(c => [c.tableId, c.colId]);
  }

  /**
   * Checks that the member may make a change (given as the doc actions their engine produced),
   * throwing EncryptionAccessError if not.
   */
  public checkChange(actions: DocAction[], canUseScope: (scope: string) => boolean) {
    if (!this.hasProtectedColumns()) { return; }
    const isReadable = (tableId: string, colId: string) => this.scopesOf(tableId, colId).every(canUseScope);
    const frozen = this._frozen(canUseScope);
    if (this._cols.every(c => isReadable(c.tableId, c.colId))) { return; }
    const frozenTokens = new Set(frozen.flatMap(c => [...(this._tokens.get(c) || [])]));
    const frozenTables = new Set(frozen.map(c => c.tableId));
    // Whether changing a column (or table) would change what formulas the member can't compute.
    const isUsedByFrozen = (tableId: string, colId?: string) =>
      frozenTokens.has(tableId) || (colId !== undefined && frozenTokens.has(colId));
    const mentionsUnreadable = (formula: unknown) => {
      if (!formula || typeof formula !== "string") { return false; }
      const tokens = getTokens(formula);
      return this._cols.some(c => !isReadable(c.tableId, c.colId) && tokens.has(c.colId));
    };
    const usedByFrozenError = () => new EncryptionAccessError(
      "This is used by a calculation you don't have access to: it has to be changed by a member who " +
      "can read the private columns it uses");

    for (const action of actions) {
      const [name, tableId] = action as [string, string];
      if (tableId === "_grist_Tables_column") {
        const rowIds = getRowIds(action);
        const values: any = (action as any)[3] || {};
        for (const rowId of rowIds) {
          const col = this._byRef.get(rowId);
          if (col && !isReadable(col.tableId, col.colId)) {
            throw new EncryptionAccessError("Only members who can read a private column can change it");
          }
          if (col && isUsedByFrozen(col.tableId, col.colId) &&
            (ROW_SET_ACTIONS.has(name) || COLUMN_DEFINITION_FIELDS.some(f => f in values))) {
            throw usedByFrozenError();
          }
        }
        const formulas = Array.isArray(values.formula) ? values.formula : [values.formula];
        if (formulas.some(mentionsUnreadable)) {
          throw new EncryptionAccessError("You can't use private columns you don't have access to in formulas");
        }
        continue;
      }
      if (tableId.startsWith("_grist")) { continue; }
      if (name === "AddColumn" || name === "ModifyColumn") {
        const colId = action[2] as string;
        if (name === "ModifyColumn" && !isReadable(tableId, colId)) {
          throw new EncryptionAccessError("Only members who can read a private column can change it");
        }
        if (name === "ModifyColumn" && isUsedByFrozen(tableId, colId)) { throw usedByFrozenError(); }
        if (mentionsUnreadable((action as any)[3]?.formula)) {
          throw new EncryptionAccessError("You can't use private columns you don't have access to in formulas");
        }
        continue;
      }
      if (name === "RemoveColumn" || name === "RenameColumn") {
        if (!isReadable(tableId, action[2] as string)) {
          throw new EncryptionAccessError("Only members who can read a private column can change it");
        }
        if (isUsedByFrozen(tableId, action[2] as string)) { throw usedByFrozenError(); }
        continue;
      }
      if (name === "RemoveTable" || name === "RenameTable") {
        if (this._cols.some(c => c.tableId === tableId && !isReadable(c.tableId, c.colId))) {
          throw new EncryptionAccessError("This table has private columns you don't have access to");
        }
        if (isUsedByFrozen(tableId) || frozenTables.has(tableId)) { throw usedByFrozenError(); }
        continue;
      }
      if (!DATA_ACTIONS.has(name)) { continue; }
      for (const colId of Object.keys((action as any)[3] || {})) {
        if (colId === "manualSort") { continue; }
        if (!isReadable(tableId, colId)) {
          throw new EncryptionAccessError("You don't have access to this private column");
        }
        if (frozenTokens.has(colId)) {
          throw new EncryptionAccessError(
            "This value is used by a calculation you don't have access to: it has to be changed " +
            "by a member who can read the private columns it uses");
        }
      }
      if (ROW_SET_ACTIONS.has(name) && (frozenTables.has(tableId) || frozenTokens.has(tableId))) {
        throw new EncryptionAccessError(
          "Rows of this table are used by a calculation you don't have access to: they have to be " +
          "added or removed by a member who can read the private columns it uses");
      }
    }
  }

  private _frozen(canUseScope: (scope: string) => boolean): ColumnInfo[] {
    return this._cols.filter(c => c.isFormula && c.formula &&
      !this.scopesOf(c.tableId, c.colId).every(canUseScope));
  }
}

/**
 * The privacy of columns for a change: a change may make columns private or not, or rename
 * them, so values get sealed with the scopes of their column either before or after the change.
 */
export class ChangePrivacy {
  constructor(public readonly before: ColumnPrivacy, public readonly after: ColumnPrivacy) {}

  public scopesOf(tableId: string, colId: string): string[] {
    const scopes = new Set([...this.before.scopesOf(tableId, colId), ...this.after.scopesOf(tableId, colId)]);
    return [...scopes].sort();
  }

  public scopesOfRef(colRef: number): string[] {
    const scopes = new Set([...this.before.scopesOfRef(colRef), ...this.after.scopesOfRef(colRef)]);
    return [...scopes].sort();
  }

  public colRef(tableId: string, colId: string): number {
    return (this.after.getColumn(tableId, colId) || this.before.getColumn(tableId, colId))?.colRef || 0;
  }

  public hasProtectedColumns() {
    return this.before.hasProtectedColumns() || this.after.hasProtectedColumns();
  }
}

/** A sealed (encrypted) set of values of a protected column. */
export interface SealedBlob {
  keyIds: string[];     // Encrypted with each of these keys in turn.
  data: string;         // Base64 of the encrypted marshalled SealedContent.
  count: number | null; // Number of values, or null for a single value (of single-row actions).
}

/** What a SealedBlob contains. */
interface SealedContent {
  t: string;            // tableId (when sealed).
  c: string;            // colId (when sealed).
  cr: number;           // colRef (0 for metadata cells).
  r: number[];          // rowIds.
  n: number;            // The entry of the history the values were sealed for.
  v: CellValue[];       // The values, for each of the rows.
}

/** How sealed values appear in place of a column's values (or a metadata cell's value). */
export interface SealedValues {
  sealed: SealedBlob;
}

/**
 * How snapshots give a column's values by reference to sealed values (see SealedCells.ts): when
 * made by members who can't read the column, or for cells whose sealed value the snapshot's
 * author couldn't check (locked). Cells without a reference have their value in clear, which for
 * private columns is only allowed for default values (e.g. in rows added by members without
 * the key).
 */
export interface CarriedValues {
  carried: {
    refs: ([number, number] | null)[];   // For each row, [index in the snapshot's blobs, position].
    plain: CellValue[];                  // For each row without a ref, its (default) value.
  };
}

export function isSealed(value: unknown): value is SealedValues {
  return Boolean(value && typeof value === "object" && !Array.isArray(value) && (value as any).sealed);
}

export function isCarried(value: unknown): value is CarriedValues {
  return Boolean(value && typeof value === "object" && !Array.isArray(value) && (value as any).carried);
}

// ---------------------------------------------------------------------------------------------
// Private metadata cells.
// ---------------------------------------------------------------------------------------------

/** The metadata columns whose cells may be private, and what decides it (see metaCellScopes()). */
const PRIVATE_META_FIELDS: { [tableId: string]: { fields: string[], dependsOn: string } } = {
  _grist_Filters: { fields: ["filter"], dependsOn: "colRef" },
  _grist_Views_section_field: { fields: ["filter"], dependsOn: "colRef" },
  _grist_Cells: { fields: ["content"], dependsOn: "colRef" },
  _grist_Tables_column: { fields: ["widgetOptions"], dependsOn: "type" },
  _grist_Attachments: { fields: ["fileName", "fileSize", "imageWidth", "imageHeight"], dependsOn: "fileIdent" },
};

export function hasPrivateMetaFields(tableId: string): boolean {
  return tableId in PRIVATE_META_FIELDS;
}

/** Gives values of metadata rows (as of before a change, or in a snapshot). */
export type MetaLookup = (tableId: string, rowId: number, colId: string) => CellValue | undefined;

/**
 * Follows the values that decide which metadata cells are private (see PRIVATE_META_FIELDS)
 * through the actions of a change: they're looked up in the document as of before the change,
 * unless an action of the change (up to the current one, included) sets them.
 */
export class MetaRows {
  private _overlay = new Map<string, Map<number, CellValue>>();   // "tableId.colId" -> rowId -> value

  constructor(private _lookup: MetaLookup) {}

  public get(tableId: string, rowId: number, colId: string): CellValue | undefined {
    const values = this._overlay.get(key(tableId, colId));
    return (values?.has(rowId)) ? values.get(rowId) : this._lookup(tableId, rowId, colId);
  }

  /** Takes into account an action of the change (in clear or sealed form). */
  public apply(action: any) {
    const [name, tableId] = action as [string, string];
    const spec = PRIVATE_META_FIELDS[tableId];
    if (!spec || !DATA_ACTIONS.has(name)) { return; }
    const values = action[3]?.[spec.dependsOn];
    if (values === undefined) { return; }
    const single = SINGLE_ROW_ACTIONS.has(name);
    const rowIds: number[] = single ? [action[2]] : action[2];
    let overlay = this._overlay.get(key(tableId, spec.dependsOn));
    if (!overlay) { this._overlay.set(key(tableId, spec.dependsOn), overlay = new Map()); }
    rowIds.forEach((rowId, i) => overlay.set(rowId, single ? values : values[i]));
  }
}

/** What metadata privacy needs to know. */
export interface MetaContext {
  rows: MetaRows;
  // The scope of a key (for attachments: the key their file's key is wrapped with).
  keyScope: (keyId: string) => string | undefined;
}

/**
 * The scopes a metadata cell is private with (none if it isn't), given the column privacy:
 *  - a saved filter (in _grist_Filters, or in the older _grist_Views_section_field.filter)
 *    lists values of its column: private if the column is;
 *  - a comment (in _grist_Cells) is about a cell: private if the cell's column is;
 *  - a column's widgetOptions list the choices of Choice columns: private if the column is;
 *  - an attachment's name and size: private if its file is (its key is wrapped with the key
 *    of a private column).
 */
export function metaCellScopes(privacy: { scopesOfRef(colRef: number): string[] }, ctx: MetaContext,
  tableId: string, colId: string, rowId: number): string[] {
  const spec = PRIVATE_META_FIELDS[tableId];
  if (!spec?.fields.includes(colId)) { return []; }
  const value = ctx.rows.get(tableId, rowId, spec.dependsOn);
  switch (tableId) {
    case "_grist_Tables_column":
      return (value === "Choice" || value === "ChoiceList") ? privacy.scopesOfRef(rowId) : [];
    case "_grist_Attachments": {
      const ref = typeof value === "string" ? parseFileIdent(value) : null;
      const scope = ref ? ctx.keyScope(ref.keyId) : undefined;
      return (scope && isColumnScope(scope)) ? [scope] : [];
    }
    default:
      return typeof value === "number" ? privacy.scopesOfRef(value) : [];
  }
}

// Calls callback for each cell given by a data action for a metadata column that may be private.
function forEachMetaCell(action: any, callback: (colId: string, rowId: number, index: number | null) => void) {
  const [name, tableId] = action as [string, string];
  const spec = PRIVATE_META_FIELDS[tableId];
  if (!spec || !DATA_ACTIONS.has(name) || !action[3]) { return; }
  const single = SINGLE_ROW_ACTIONS.has(name);
  const rowIds: number[] = single ? [action[2]] : action[2];
  for (const colId of spec.fields) {
    if (!(colId in action[3])) { continue; }
    rowIds.forEach((rowId, i) => callback(colId, rowId, single ? null : i));
  }
}

/**
 * Checks that the member can read (and so seal) all the private metadata cells in the given
 * actions, throwing EncryptionAccessError otherwise (e.g. removing a page with a saved filter of
 * a private column the member can't read: undoing it would need the filter).
 */
export function checkMetaAccess(actions: DocAction[], privacy: ChangePrivacy, ctx: MetaContext,
  canUseScope: (scope: string) => boolean) {
  for (const action of actions) {
    ctx.rows.apply(action);
    forEachMetaCell(action, (colId, rowId) => {
      if (!metaCellScopes(privacy, ctx, action[1], colId, rowId).every(canUseScope)) {
        throw new EncryptionAccessError("This involves private settings or files you don't have access to");
      }
    });
  }
}

// ---------------------------------------------------------------------------------------------
// Sealing changes.
// ---------------------------------------------------------------------------------------------

/**
 * Encrypts the values of protected columns (and metadata cells) in the given doc actions with
 * the keys of their scopes, as the change numbered actionNum. The rest of the actions is left
 * alone (it gets encrypted as a whole with the document key). Returns new actions; the given
 * ones are unchanged. Actions are taken in order (see MetaRows).
 */
export async function sealActions(actions: DocAction[], privacy: ChangePrivacy, keyring: Keyring,
  actionNum: number, ctx: MetaContext): Promise<any[]> {
  const result: any[] = [];
  for (const action of actions) {
    ctx.rows.apply(action);
    result.push(await sealAction(action, privacy, keyring, actionNum, ctx));
  }
  return result;
}

async function sealAction(action: DocAction, privacy: ChangePrivacy, keyring: Keyring, actionNum: number,
  ctx: MetaContext): Promise<any> {
  const [name, tableId] = action as [string, string];
  if (!DATA_ACTIONS.has(name) || !(action as any)[3]) { return action; }
  const columns: Record<string, any> = (action as any)[3];
  const single = SINGLE_ROW_ACTIONS.has(name);
  const rowIds = single ? [action[2] as number] : action[2] as number[];
  let sealedColumns: Record<string, any> | null = null;
  if (tableId.startsWith("_grist")) {
    // Metadata: cell by cell.
    const sealCell = async (colId: string, rowId: number, value: CellValue) => {
      const scopes = metaCellScopes(privacy, ctx, tableId, colId, rowId);
      if (scopes.length === 0) { return value; }
      return {
        sealed: await sealValues(keyring, scopes.map(scope => keyring.currentKeyId(scope)), {
          t: tableId, c: colId, cr: 0, r: [rowId], n: actionNum, v: [value],
        }, true),
      } as SealedValues;
    };
    for (const [colId, values] of Object.entries(columns)) {
      if (!PRIVATE_META_FIELDS[tableId]?.fields.includes(colId)) { continue; }
      const sealed = single ? await sealCell(colId, rowIds[0], values) :
        await Promise.all((values as CellValue[]).map((v, i) => sealCell(colId, rowIds[i], v)));
      if (!isEqual(sealed, values)) {
        sealedColumns = sealedColumns || { ...columns };
        sealedColumns[colId] = sealed;
      }
    }
  } else {
    if (!privacy.hasProtectedColumns()) { return action; }
    for (const [colId, values] of Object.entries(columns)) {
      const scopes = privacy.scopesOf(tableId, colId);
      if (scopes.length === 0) { continue; }
      sealedColumns = sealedColumns || { ...columns };
      sealedColumns[colId] = {
        sealed: await sealValues(keyring, scopes.map(scope => keyring.currentKeyId(scope)), {
          t: tableId, c: colId, cr: privacy.colRef(tableId, colId), r: rowIds, n: actionNum,
          v: single ? [values] : values,
        }, single),
      } as SealedValues;
    }
  }
  return sealedColumns ? [...(action as any).slice(0, 3), sealedColumns] : action;
}

/**
 * Checks that a change (the doc actions of change actionNum, as received) seals the values it
 * must, with the right keys, and only those: throws TamperedContentError otherwise. Actions are
 * taken in order (see MetaRows).
 */
export function checkSealing(actions: any[], privacy: ChangePrivacy, keyIdAt: (scope: string) => string | null,
  ctx: MetaContext) {
  const checkKeys = (what: string, blob: SealedBlob, scopes: string[]) => {
    const expected = scopes.map(keyIdAt);
    if (!isEqual([...blob.keyIds].sort(), [...expected].sort())) {
      throw new TamperedContentError(`${what} sealed with the wrong keys`);
    }
  };
  for (const action of actions) {
    ctx.rows.apply(action);
    const [name, tableId] = action as [string, string];
    if (!DATA_ACTIONS.has(name) || !action[3]) { continue; }
    const single = SINGLE_ROW_ACTIONS.has(name);
    if (tableId.startsWith("_grist")) {
      for (const [colId, values] of Object.entries(action[3] as Record<string, unknown>)) {
        const isMeta = Boolean(PRIVATE_META_FIELDS[tableId]?.fields.includes(colId));
        const rowIds: number[] = single ? [action[2]] : action[2];
        const cells: unknown[] = single ? [values] : (Array.isArray(values) ? values : []);
        if (!single && !Array.isArray(values)) {
          throw new TamperedContentError(`Unexpected values in ${tableId}.${colId}`);
        }
        rowIds.forEach((rowId, i) => {
          const scopes = isMeta ? metaCellScopes(privacy, ctx, tableId, colId, rowId) : [];
          const what = `${tableId}.${colId} (row ${rowId})`;
          if (scopes.length === 0) {
            if (isSealed(cells[i])) { throw new TamperedContentError(`Unexpected sealed value in ${what}`); }
            return;
          }
          if (!isSealed(cells[i])) { throw new TamperedContentError(`Unsealed private value in ${what}`); }
          if ((cells[i]).sealed.count !== null) {
            throw new TamperedContentError(`Wrong number of sealed values in ${what}`);
          }
          checkKeys(what, (cells[i]).sealed, scopes);
        });
      }
      continue;
    }
    for (const [colId, values] of Object.entries(action[3] as Record<string, unknown>)) {
      const scopes = privacy.scopesOf(tableId, colId);
      if (scopes.length === 0) {
        if (isSealed(values)) { throw new TamperedContentError(`Unexpected sealed values in ${tableId}.${colId}`); }
        continue;
      }
      if (!isSealed(values)) { throw new TamperedContentError(`Unsealed private values in ${tableId}.${colId}`); }
      if (values.sealed.count !== (single ? null : (action[2] as number[]).length)) {
        throw new TamperedContentError(`Wrong number of sealed values in ${tableId}.${colId}`);
      }
      checkKeys(`Values of ${tableId}.${colId}`, values.sealed, scopes);
    }
  }
}

/**
 * Reverses sealActions() for change actionNum: decrypts sealed values the member can read, and
 * replaces those they can't with LOCKED_CELL. Sealed values that aren't what they're presented
 * as are locked too, and reported with onTampered().
 */
export async function unsealActions(actions: any[], keyring: Keyring, actionNum: number,
  onTampered: (message: string) => void = () => {}): Promise<DocAction[]> {
  const opener = makeOpener(keyring);
  return Promise.all(actions.map(async (action) => {
    const columns = action?.[3];
    if (!columns || typeof columns !== "object" || Array.isArray(columns)) { return action; }
    const [name, tableId] = action as [string, string];
    const single = SINGLE_ROW_ACTIONS.has(name);
    const rowIds = single ? [action[2]] : action[2];
    const isMetaTable = tableId.startsWith("_grist");
    if (!Object.values(columns).some(v => isSealed(v) || (isMetaTable && Array.isArray(v) && v.some(isSealed)))) {
      return action;
    }
    const result: Record<string, any> = {};
    for (const [colId, values] of Object.entries(columns)) {
      if (isMetaTable) {
        // Metadata: cell by cell.
        const openCell = async (cell: unknown, rowId: number) => {
          if (!isSealed(cell)) { return cell; }
          return openCheckedCell(opener, cell.sealed, { t: tableId, c: colId, r: rowId, exactN: actionNum },
            onTampered);
        };
        result[colId] = single ? await openCell(values, rowIds[0]) :
          (Array.isArray(values) ? await Promise.all(values.map((v, i) => openCell(v, rowIds[i]))) : values);
        continue;
      }
      if (!isSealed(values)) { result[colId] = values; continue; }
      const locked = single ? LOCKED_CELL : new Array(rowIds.length).fill(LOCKED_CELL);
      let content: SealedContent | null;
      try {
        content = await opener(values.sealed);
      } catch (e) {
        if (e instanceof MissingKeyError) { throw e; }
        onTampered(`Invalid sealed values in ${tableId}.${colId}`);
        result[colId] = locked;
        continue;
      }
      if (!content) {
        result[colId] = locked;
      } else if (content.t !== tableId || content.c !== colId || content.n !== actionNum ||
        !isEqual(content.r, rowIds)) {
        onTampered(`Sealed values don't belong to ${tableId}.${colId}`);
        result[colId] = locked;
      } else {
        result[colId] = single ? content.v[0] : content.v;
      }
    }
    return [...action.slice(0, 3), result] as DocAction;
  }));
}

// Opens a sealed metadata cell, checking it belongs to the cell (and was sealed for change
// exactN, or for one up to maxN, for snapshots). Returns LOCKED_CELL if it can't be read.
async function openCheckedCell(opener: (blob: SealedBlob) => Promise<SealedContent | null>, blob: SealedBlob,
  expected: { t: string, c: string, r: number, exactN?: number, maxN?: number },
  onTampered: (message: string) => void): Promise<CellValue> {
  let content: SealedContent | null;
  try {
    content = await opener(blob);
  } catch (e) {
    if (e instanceof MissingKeyError) { throw e; }
    onTampered(`Invalid sealed value in ${expected.t}.${expected.c}`);
    return LOCKED_CELL;
  }
  if (!content) { return LOCKED_CELL; }
  if (content.t !== expected.t || content.c !== expected.c || content.r.length !== 1 || content.r[0] !== expected.r ||
    (expected.exactN !== undefined && content.n !== expected.exactN) ||
    (expected.maxN !== undefined && content.n > expected.maxN)) {
    onTampered(`Sealed value doesn't belong to ${expected.t}.${expected.c} (row ${expected.r})`);
    return LOCKED_CELL;
  }
  return content.v[0];
}

// ---------------------------------------------------------------------------------------------
// Sealing snapshots.
// ---------------------------------------------------------------------------------------------

/** Blobs of a snapshot, each included once. */
export class BlobTable {
  public readonly blobs: SealedBlob[] = [];
  private _index = new Map<SealedBlob, number>();

  public indexOf(blob: SealedBlob): number {
    let index = this._index.get(blob);
    if (index === undefined) {
      index = this.blobs.push(blob) - 1;
      this._index.set(blob, index);
    }
    return index;
  }
}

/** What sealing a snapshot needs to know about the sealed values the member received. */
export interface SnapshotCarrier {
  /**
   * A column's values, by reference to the sealed values received (see SealedCells.export()),
   * for columns the member can't read. Throws CannotCarryError if that's not possible.
   */
  carryColumn(tableId: string, colId: string, rowIds: number[], values: CellValue[], blobs: BlobTable): CarriedValues;
  /** The sealed value received for a cell, if any. */
  sealedCell(tableId: string, colId: string, rowId: number): { blob: SealedBlob, pos: number } | undefined;
  /** Throws CannotCarryError: for a private value the member can't seal nor carry. */
  cannotCarry(message: string): never;
}

/**
 * Seals protected columns and metadata cells in a snapshot's tables, as of actionNum. Values
 * the member can't seal (they don't hold the current keys of their scopes) are given by
 * reference to the sealed values they received (see SnapshotCarrier). So are locked values in
 * columns the member can read (their sealed values didn't check out: they stay as they are).
 */
export async function sealTables(tables: { [tableId: string]: TableDataAction }, privacy: ColumnPrivacy,
  keyring: Keyring, actionNum: number, blobs: BlobTable, ctx: MetaContext, carrier: SnapshotCarrier,
): Promise<{ [tableId: string]: any }> {
  const result: { [tableId: string]: any } = {};
  for (const [tableId, tableData] of Object.entries(tables)) {
    const [, , rowIds, columns] = tableData;
    let sealedColumns: Record<string, any> | null = null;
    if (tableId.startsWith("_grist")) {
      for (const colId of PRIVATE_META_FIELDS[tableId]?.fields || []) {
        const values = columns[colId];
        if (!values) { continue; }
        const cells: any[] = [];
        let changed = false;
        for (const [i, rowId] of rowIds.entries()) {
          const scopes = metaCellScopes(privacy, ctx, tableId, colId, rowId);
          if (scopes.length === 0) { cells.push(values[i]); continue; }
          changed = true;
          if (scopes.every(scope => keyring.canUseScope(scope)) && !isLockedCell(values[i])) {
            cells.push({
              sealed: await sealValues(keyring, scopes.map(scope => keyring.currentKeyId(scope)), {
                t: tableId, c: colId, cr: 0, r: [rowId], n: actionNum, v: [values[i]],
              }, true),
            } as SealedValues);
            continue;
          }
          const received = carrier.sealedCell(tableId, colId, rowId);
          if (received) {
            cells.push({ sealed: received.blob } as SealedValues);
          } else if (isDefaultMetaValue(values[i])) {
            cells.push(values[i]);
          } else {
            carrier.cannotCarry(`No sealed value for ${tableId}.${colId} in row ${rowId}`);
          }
        }
        if (changed) {
          sealedColumns = sealedColumns || { ...columns };
          sealedColumns[colId] = cells;
        }
      }
    } else {
      for (const [colId, values] of Object.entries(columns)) {
        const scopes = privacy.scopesOf(tableId, colId);
        if (scopes.length === 0) { continue; }
        sealedColumns = sealedColumns || { ...columns };
        if (!scopes.every(scope => keyring.canUseScope(scope))) {
          sealedColumns[colId] = carrier.carryColumn(tableId, colId, rowIds, values, blobs);
          continue;
        }
        const sealed: SealedValues = {
          sealed: await sealValues(keyring, scopes.map(scope => keyring.currentKeyId(scope)), {
            t: tableId, c: colId, cr: privacy.getColumn(tableId, colId)?.colRef || 0, r: rowIds, n: actionNum,
            v: values,
          }, false),
        };
        const lockedRows = rowIds.filter((rowId, i) => isLockedCell(values[i]) &&
          carrier.sealedCell(tableId, colId, rowId));
        if (lockedRows.length === 0) {
          sealedColumns[colId] = sealed;
        } else {
          // Locked cells keep the sealed values they have; the others refer to the new ones.
          const index = blobs.indexOf(sealed.sealed);
          sealedColumns[colId] = {
            carried: {
              refs: rowIds.map((rowId, pos) => {
                const received = isLockedCell(values[pos]) ? carrier.sealedCell(tableId, colId, rowId) : undefined;
                return received ? [blobs.indexOf(received.blob), received.pos] : [index, pos];
              }),
              plain: rowIds.map(() => null),
            },
          } as CarriedValues;
        }
      }
    }
    result[tableId] = sealedColumns ? [tableData[0], tableId, rowIds, sealedColumns] : tableData;
  }
  return result;
}

/**
 * Reverses sealTables() for a snapshot as of actionNum, whose columns' privacy is given. Values
 * that should be sealed but aren't, or whose seal doesn't match, are replaced with LOCKED_CELL
 * (they can only come from a modified client), and reported with onTampered().
 */
export async function unsealTables(tables: { [tableId: string]: any }, blobs: SealedBlob[], keyring: Keyring,
  privacy: ColumnPrivacy, actionNum: number, onTampered: (message: string) => void,
): Promise<{ [tableId: string]: TableDataAction }> {
  const opener = makeOpener(keyring);
  const open = (blob: SealedBlob | undefined) => blob ? opener(blob).catch(() => null) : Promise.resolve(null);
  // Which metadata cells are private is decided by the snapshot's own metadata.
  const ctx: MetaContext = {
    rows: new MetaRows((tableId, rowId, colId) => {
      const table = tables[tableId];
      const index = table?.[2]?.indexOf(rowId);
      return (index !== undefined && index >= 0) ? table[3][colId]?.[index] : undefined;
    }),
    keyScope: keyId => keyring.getKey(keyId)?.scope,
  };
  const result: { [tableId: string]: TableDataAction } = {};
  for (const [tableId, tableData] of Object.entries(tables)) {
    const [, , rowIds, columns] = tableData as [string, string, number[], Record<string, any>];
    const unsealed: Record<string, CellValue[]> = {};
    for (const [colId, values] of Object.entries(columns)) {
      if (tableId.startsWith("_grist")) {
        if (!PRIVATE_META_FIELDS[tableId]?.fields.includes(colId)) {
          unsealed[colId] = values;
          continue;
        }
        const cells: CellValue[] = [];
        for (const [i, rowId] of rowIds.entries()) {
          const cell = Array.isArray(values) ? values[i] : undefined;
          const scopes = metaCellScopes(privacy, ctx, tableId, colId, rowId);
          const what = `${tableId}.${colId} (row ${rowId})`;
          if (scopes.length === 0) {
            if (isSealed(cell)) { onTampered(`${what}: unexpected sealed value`); cells.push(LOCKED_CELL); continue; }
            cells.push(cell as CellValue);
          } else if (isSealed(cell)) {
            if (!hasScopes(keyring, cell.sealed, scopes)) { onTampered(`${what}: wrong keys`); cells.push(LOCKED_CELL); continue; }
            cells.push(await openCheckedCell(opener, cell.sealed, { t: tableId, c: colId, r: rowId, maxN: actionNum },
              onTampered));
          } else if (isDefaultMetaValue(cell)) {
            cells.push(cell as CellValue);
          } else {
            onTampered(`${what}: private value given in clear`);
            cells.push(LOCKED_CELL);
          }
        }
        unsealed[colId] = cells;
        continue;
      }
      const scopes = privacy.scopesOf(tableId, colId);
      const col = privacy.getColumn(tableId, colId);
      const locked = () => rowIds.map(() => LOCKED_CELL as CellValue);
      const tampered = (what: string) => { onTampered(`${tableId}.${colId}: ${what}`); return locked(); };
      if (scopes.length === 0) {
        unsealed[colId] = (isSealed(values) || isCarried(values)) ? tampered("unexpected sealed values") : values;
      } else if (isSealed(values)) {
        if (!hasScopes(keyring, values.sealed, scopes)) { unsealed[colId] = tampered("wrong keys"); continue; }
        const content = await open(values.sealed);
        if (!content) { unsealed[colId] = locked(); continue; }
        unsealed[colId] = (content.cr !== col?.colRef || content.n > actionNum || !isEqual(content.r, rowIds)) ?
          tampered("sealed values don't belong there") : content.v;
      } else if (isCarried(values)) {
        const { refs, plain } = values.carried;
        const defaultValue = getDefaultForType(col?.type || "Any");
        const cells: CellValue[] = [];
        for (const [i, rowId] of rowIds.entries()) {
          const ref = refs[i];
          if (!ref) {
            // Only default values may be given in clear (see SealedCells.export()).
            cells.push(isEqual(plain[i], defaultValue) ? plain[i] : LOCKED_CELL);
            if (!isEqual(plain[i], defaultValue)) { onTampered(`${tableId}.${colId}: value given in clear`); }
            continue;
          }
          const blob = blobs[ref[0]];
          if (!blob || !hasScopes(keyring, blob, scopes)) {
            onTampered(`${tableId}.${colId}: wrong keys`);
            cells.push(LOCKED_CELL);
            continue;
          }
          const content = await open(blob);
          if (!content) { cells.push(LOCKED_CELL); continue; }
          const pos = ref[1];
          if (content.cr !== col?.colRef || content.n > actionNum || content.r[pos] !== rowId) {
            onTampered(`${tableId}.${colId}: sealed value doesn't belong there`);
            cells.push(LOCKED_CELL);
          } else {
            cells.push(content.v[pos]);
          }
        }
        unsealed[colId] = cells;
      } else {
        unsealed[colId] = tampered("private values given in clear");
      }
    }
    result[tableId] = [(tableData)[0], tableId, rowIds, unsealed] as TableDataAction;
  }
  return result;
}

// Values a private metadata cell may have in clear: those that reveal nothing.
function isDefaultMetaValue(value: unknown): boolean {
  return value === "" || value === 0 || value === null || value === undefined;
}

// Whether a blob is sealed with keys of exactly the given scopes (keys may be older ones).
function hasScopes(keyring: Keyring, blob: SealedBlob, scopes: string[]): boolean {
  const blobScopes = blob.keyIds.map(keyId => keyring.getKey(keyId)?.scope);
  return isEqual([...blobScopes].sort(), [...scopes].sort());
}

async function sealValues(keyring: Keyring, keyIds: string[], content: SealedContent,
  single: boolean): Promise<SealedBlob> {
  return {
    keyIds,
    data: bytesToBase64(await keyring.encryptWithAll(keyIds, marshalValue(content))),
    count: single ? null : content.v.length,
  };
}

/**
 * Returns a function decrypting blobs, or returning null if the member doesn't hold all their
 * keys. Each blob is decrypted once (the same one may be referred to many times in a snapshot).
 */
function makeOpener(keyring: Keyring): (blob: SealedBlob) => Promise<SealedContent | null> {
  const opened = new Map<SealedBlob, Promise<SealedContent | null>>();
  return (blob: SealedBlob) => {
    let result = opened.get(blob);
    if (!result) { opened.set(blob, result = openBlob(keyring, blob)); }
    return result;
  };
}

/** Decrypts a blob, or returns null if the member doesn't hold all its keys. */
async function openBlob(keyring: Keyring, blob: SealedBlob): Promise<SealedContent | null> {
  if (!blob || !Array.isArray(blob.keyIds) || typeof blob.data !== "string") {
    throw new TamperedContentError("Invalid sealed values");
  }
  // A key unknown so far may be new: in that case, check whether we got a copy of it.
  await keyring.refreshIfUnknown(blob.keyIds).catch(() => {});
  if (!blob.keyIds.every(keyId => keyring.holds(keyId))) { return null; }
  const content = unmarshalValue(await keyring.decryptWithAll(blob.keyIds, base64ToBytes(blob.data)));
  if (!content || typeof content !== "object" || !Array.isArray(content.r) || !Array.isArray(content.v) ||
    content.r.length !== content.v.length) {
    throw new TamperedContentError("Invalid sealed values");
  }
  return content;
}

function getRowIds(action: DocAction): number[] {
  const rowIds = (action as any)[2];
  return Array.isArray(rowIds) ? rowIds : (typeof rowIds === "number" ? [rowIds] : []);
}

/**
 * The names a formula may use. Python normalizes identifiers (NFKC), so that e.g. "ｓalary"
 * reads "salary": normalize the same way.
 */
function getTokens(formula: string): Set<string> {
  return new Set(formula.normalize("NFKC").match(/[A-Za-z_][A-Za-z0-9_]*/g) || []);
}

function key(tableId: string, colId: string) {
  return `${tableId}.${colId}`;
}
