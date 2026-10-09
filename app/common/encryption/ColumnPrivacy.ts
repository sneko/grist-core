/**
 * Private columns of encrypted documents: columns whose values only some members can read.
 *
 * A column is made private by giving it a scope ("column:<id>"), whose keys only some members
 * hold (see EncryptionTypes.ts). Which column a scope protects is kept by the server
 * (ScopeBinding), not in the document: any member holding the document key can change the
 * document, but only owners holding a column's key can make it public again. The column's
 * values then travel and get stored encrypted with the scope's key, inside changes and snapshots
 * that are otherwise encrypted with the document key ("sealed", see sealActions()).
 *
 * Formulas reading private columns are private too, with the same scopes: their results reveal
 * what they read. So are the columns a summary table groups by, when they're private in the
 * source table. Since members missing a scope's key can't read the values such a formula needs,
 * their data engine never computes it ("frozen" column), and they see its results as locked,
 * like the private values themselves. What they can't do follows from this: change a value a
 * formula they can't compute depends on (or add or remove rows in its table), since the formula
 * couldn't be updated; such changes are refused, and must be made by a member who holds the key.
 * Similarly, they can't change private columns, nor their settings.
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
import { base64ToBytes, bytesToBase64 } from "app/common/encryption/EncryptionCrypto";
import { Keyring, MissingKeyError } from "app/common/encryption/Keyring";
import { isLockedCell, LOCKED_CELL } from "app/common/encryption/LockedCell";
import { getDefaultForType } from "app/common/gristTypes";
import * as marshal from "app/common/marshal";

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
  ownScope: string | null;
}

const DATA_ACTIONS = new Set([
  "AddRecord", "BulkAddRecord", "UpdateRecord", "BulkUpdateRecord", "RemoveRecord", "BulkRemoveRecord",
  "ReplaceTableData", "TableData",
]);
const ROW_SET_ACTIONS = new Set(["AddRecord", "BulkAddRecord", "RemoveRecord", "BulkRemoveRecord", "ReplaceTableData"]);
const SINGLE_ROW_ACTIONS = new Set(["AddRecord", "UpdateRecord"]);

export class ColumnPrivacy {
  /**
   * Builds the model from the _grist_Tables and _grist_Tables_column metadata tables, and the
   * private columns (colRef -> scope, see Keyring.bindingsAt()).
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
      // A summary table's group-by columns hold the values of the source columns.
      const sourceRef = values.summarySourceCol?.[i] as number | undefined;
      cols.push({
        colRef,
        tableId,
        colId: values.colId[i] as string,
        type: String(values.type[i] || "Any"),
        isFormula: Boolean(values.isFormula[i]),
        formula: String(values.formula[i] || ""),
        ownScope: bindings.get(colRef) ?? (sourceRef ? bindings.get(sourceRef) : undefined) ?? null,
      });
    });
    return new ColumnPrivacy(cols);
  }

  private _scopes = new Map<string, string[]>();   // "tableId.colId" -> sorted scopes
  private _byRef = new Map<number, ColumnInfo>();
  private _byKey = new Map<string, ColumnInfo>();
  private _tokens = new Map<ColumnInfo, Set<string>>();

  constructor(private _cols: ColumnInfo[]) {
    for (const col of _cols) {
      this._byRef.set(col.colRef, col);
      this._byKey.set(key(col.tableId, col.colId), col);
      if (col.formula) { this._tokens.set(col, getTokens(col.formula)); }
      this._scopes.set(key(col.tableId, col.colId), col.ownScope ? [col.ownScope] : []);
    }
    // Formulas (including trigger formulas of data columns) reading protected columns are
    // protected too. Repeat until nothing changes, to follow formulas reading formulas.
    for (let changed = true; changed;) {
      changed = false;
      for (const col of _cols) {
        const tokens = this._tokens.get(col);
        if (!tokens) { continue; }
        const scopes = new Set(this.scopesOf(col.tableId, col.colId));
        const before = scopes.size;
        for (const other of _cols) {
          if (other !== col && tokens.has(other.colId)) {
            for (const scope of this.scopesOf(other.tableId, other.colId)) { scopes.add(scope); }
          }
        }
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
    const mentionsUnreadable = (formula: unknown) => {
      if (!formula || typeof formula !== "string") { return false; }
      const tokens = getTokens(formula);
      return this._cols.some(c => !isReadable(c.tableId, c.colId) && tokens.has(c.colId));
    };

    for (const action of actions) {
      const [name, tableId] = action as [string, string];
      if (tableId === "_grist_Tables_column") {
        const rowIds = getRowIds(action);
        for (const rowId of rowIds) {
          const col = this._byRef.get(rowId);
          if (col && !isReadable(col.tableId, col.colId)) {
            throw new EncryptionAccessError("Only members who can read a private column can change it");
          }
        }
        const values: any = (action as any)[3] || {};
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
        if (mentionsUnreadable((action as any)[3]?.formula)) {
          throw new EncryptionAccessError("You can't use private columns you don't have access to in formulas");
        }
        continue;
      }
      if (name === "RemoveColumn" || name === "RenameColumn") {
        if (!isReadable(tableId, action[2] as string)) {
          throw new EncryptionAccessError("Only members who can read a private column can change it");
        }
        continue;
      }
      if (name === "RemoveTable" || name === "RenameTable") {
        if (this._cols.some(c => c.tableId === tableId && !isReadable(c.tableId, c.colId))) {
          throw new EncryptionAccessError("This table has private columns you don't have access to");
        }
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
  cr: number;           // colRef.
  r: number[];          // rowIds.
  n: number;            // The entry of the history the values were sealed for.
  v: CellValue[];       // The values, for each of the rows.
}

/** How sealed values appear in place of a column's values, in actions and snapshots. */
export interface SealedValues {
  sealed: SealedBlob;
}

/**
 * How snapshots made by members who can't read a column give its values: as the sealed values
 * they received, by reference (see SealedCells.ts), and for cells for which they don't have any,
 * the column's default value (e.g. in rows they added).
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

/**
 * Encrypts the values of protected columns in the given doc actions with the keys of their
 * scopes, as the change numbered actionNum. The rest of the actions is left alone (it gets
 * encrypted as a whole with the document key). Returns new actions; the given ones are unchanged.
 */
export async function sealActions(actions: DocAction[], privacy: ChangePrivacy, keyring: Keyring,
  actionNum: number): Promise<any[]> {
  if (!privacy.hasProtectedColumns()) { return actions; }
  return Promise.all(actions.map(async (action) => {
    const [name, tableId] = action as [string, string];
    if (!DATA_ACTIONS.has(name) || tableId.startsWith("_grist") || !(action as any)[3]) { return action; }
    const columns: Record<string, any> = (action as any)[3];
    const single = SINGLE_ROW_ACTIONS.has(name);
    const rowIds = single ? [action[2] as number] : action[2] as number[];
    let sealedColumns: Record<string, any> | null = null;
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
    return sealedColumns ? [...(action as any).slice(0, 3), sealedColumns] : action;
  }));
}

/**
 * Checks that a change (the doc actions of change actionNum, as received) seals the values it
 * must, with the right keys, and only those: throws TamperedContentError otherwise.
 */
export function checkSealing(actions: any[], privacy: ChangePrivacy, keyIdAt: (scope: string) => string | null) {
  for (const action of actions) {
    const [name, tableId] = action as [string, string];
    if (!DATA_ACTIONS.has(name) || tableId.startsWith("_grist") || !action[3]) { continue; }
    for (const [colId, values] of Object.entries(action[3] as Record<string, unknown>)) {
      const scopes = privacy.scopesOf(tableId, colId);
      if (scopes.length === 0) {
        if (isSealed(values)) { throw new TamperedContentError(`Unexpected sealed values in ${tableId}.${colId}`); }
        continue;
      }
      if (!isSealed(values)) { throw new TamperedContentError(`Unsealed private values in ${tableId}.${colId}`); }
      const single = SINGLE_ROW_ACTIONS.has(name);
      if (values.sealed.count !== (single ? null : (action[2] as number[]).length)) {
        throw new TamperedContentError(`Wrong number of sealed values in ${tableId}.${colId}`);
      }
      const expected = scopes.map(keyIdAt);
      if (!isEqual([...values.sealed.keyIds].sort(), [...expected].sort())) {
        throw new TamperedContentError(`Values of ${tableId}.${colId} sealed with the wrong keys`);
      }
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
  return Promise.all(actions.map(async (action) => {
    const columns = action?.[3];
    if (!columns || typeof columns !== "object" || Array.isArray(columns) ||
      !Object.values(columns).some(isSealed)) {
      return action;
    }
    const [name, tableId] = action as [string, string];
    const single = SINGLE_ROW_ACTIONS.has(name);
    const rowIds = single ? [action[2]] : action[2];
    const result: Record<string, any> = {};
    for (const [colId, values] of Object.entries(columns)) {
      if (!isSealed(values)) { result[colId] = values; continue; }
      const locked = single ? LOCKED_CELL : new Array(rowIds.length).fill(LOCKED_CELL);
      let content: SealedContent | null;
      try {
        content = await openBlob(keyring, values.sealed);
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

/**
 * Seals protected columns in a snapshot's tables, as of actionNum. Columns the member can't read
 * (they don't hold the current keys of their scopes) get their values from getCarried(), which
 * returns the sealed values they received (see SealedCells.ts), or throws if it can't.
 */
export async function sealTables(tables: { [tableId: string]: TableDataAction }, privacy: ColumnPrivacy,
  keyring: Keyring, actionNum: number, blobs: BlobTable,
  getCarried: (tableId: string, colId: string, rowIds: number[], values: CellValue[]) => CarriedValues,
): Promise<{ [tableId: string]: any }> {
  const result: { [tableId: string]: any } = {};
  for (const [tableId, tableData] of Object.entries(tables)) {
    const [, , rowIds, columns] = tableData;
    let sealedColumns: Record<string, any> | null = null;
    if (!tableId.startsWith("_grist")) {
      for (const [colId, values] of Object.entries(columns)) {
        const scopes = privacy.scopesOf(tableId, colId);
        if (scopes.length === 0) { continue; }
        sealedColumns = sealedColumns || { ...columns };
        if (scopes.every(scope => keyring.canUseScope(scope))) {
          sealedColumns[colId] = {
            sealed: await sealValues(keyring, scopes.map(scope => keyring.currentKeyId(scope)), {
              t: tableId, c: colId, cr: privacy.getColumn(tableId, colId)?.colRef || 0, r: rowIds, n: actionNum,
              v: values,
            }, false),
          } as SealedValues;
        } else {
          sealedColumns[colId] = getCarried(tableId, colId, rowIds, values);
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
  const opened = new Map<SealedBlob, SealedContent | null>();
  const open = async (blob: SealedBlob | undefined) => {
    if (!blob) { return null; }
    if (!opened.has(blob)) { opened.set(blob, await openBlob(keyring, blob).catch(() => null)); }
    return opened.get(blob)!;
  };
  const result: { [tableId: string]: TableDataAction } = {};
  for (const [tableId, tableData] of Object.entries(tables)) {
    const [, , rowIds, columns] = tableData as [string, string, number[], Record<string, any>];
    const unsealed: Record<string, CellValue[]> = {};
    for (const [colId, values] of Object.entries(columns)) {
      const scopes = tableId.startsWith("_grist") ? [] : privacy.scopesOf(tableId, colId);
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

/** Decrypts a blob, or returns null if the member doesn't hold all its keys. */
async function openBlob(keyring: Keyring, blob: SealedBlob): Promise<SealedContent | null> {
  // A key unknown so far may be new: in that case, check whether we got a copy of it.
  if (blob.keyIds.some(keyId => !keyring.getKey(keyId))) { await keyring.refresh().catch(() => {}); }
  if (!blob.keyIds.every(keyId => keyring.holds(keyId))) { return null; }
  const content = marshal.loads(await keyring.decryptWithAll(blob.keyIds, base64ToBytes(blob.data)),
    { bufferToString: true });
  if (!content || typeof content !== "object" || !Array.isArray(content.r) || !Array.isArray(content.v) ||
    content.r.length !== content.v.length) {
    throw new TamperedContentError("Invalid sealed values");
  }
  return content;
}

function marshalValue(value: unknown): Uint8Array {
  const marshaller = new marshal.Marshaller({ stringToBuffer: false, version: 2 });
  marshaller.marshal(value);
  return marshaller.dump();
}

function getRowIds(action: DocAction): number[] {
  const rowIds = (action as any)[2];
  return Array.isArray(rowIds) ? rowIds : (typeof rowIds === "number" ? [rowIds] : []);
}

function getTokens(formula: string): Set<string> {
  return new Set(formula.match(/[A-Za-z_][A-Za-z0-9_]*/g) || []);
}

function key(tableId: string, colId: string) {
  return `${tableId}.${colId}`;
}
