/**
 * Where the sealed values of private cells are (see ColumnPrivacy.ts), as received in changes and
 * snapshots: so that members who can't read some private columns can still save snapshots of the
 * whole document. Their snapshots give the values of those columns by reference to the sealed
 * values they received (CarriedValues), which they can pass on without being able to read them;
 * readers check that each sealed value belongs to its cell. This is the document's previous state
 * patched with the changes since, for the cells the member can't read.
 *
 * This follows the changes as they apply to the document (rows added and removed, columns and
 * tables renamed or removed), in the form they were shared in (with sealed values).
 */
import { CellValue } from "app/common/DocActions";
import {
  BlobTable, CarriedValues, isCarried, isSealed, SealedBlob,
} from "app/common/encryption/ColumnPrivacy";
import { isLockedCell } from "app/common/encryption/LockedCell";
import { getDefaultForType } from "app/common/gristTypes";

import isEqual from "lodash/isEqual";

interface CellRef {
  blob: SealedBlob;
  pos: number;
}

/** Thrown when a snapshot can't include a column the member can't read. */
export class CannotCarryError extends Error {}

export class SealedCells {
  // For each table, for each column, where each row's sealed value is.
  private _tables = new Map<string, Map<string, Map<number, CellRef>>>();

  public clear() {
    this._tables.clear();
  }

  /** Starts from a snapshot's tables (in their shared form). */
  public loadSnapshot(tables: { [tableId: string]: any }, blobs: SealedBlob[]) {
    this.clear();
    for (const [tableId, tableData] of Object.entries(tables)) {
      const [, , rowIds, columns] = tableData as [string, string, number[], Record<string, unknown>];
      for (const [colId, values] of Object.entries(columns)) {
        if (isSealed(values)) {
          const cells = this._column(tableId, colId);
          rowIds.forEach((rowId, pos) => cells.set(rowId, { blob: values.sealed, pos }));
        } else if (isCarried(values)) {
          const cells = this._column(tableId, colId);
          values.carried.refs.forEach((ref, i) => {
            if (ref && blobs[ref[0]]) { cells.set(rowIds[i], { blob: blobs[ref[0]], pos: ref[1] }); }
          });
        }
      }
    }
  }

  /** Follows the doc actions of a change (in their shared form, with sealed values). */
  public applyActions(actions: any[]) {
    for (const action of actions) { this._applyAction(action); }
  }

  /**
   * Returns a column's values for a snapshot, by reference to their sealed values. Cells without
   * any must have their default value (e.g. rows the member added): anything else would be
   * values the member can see but not seal (e.g. right after the column became private), and the
   * snapshot can't be made (others will make it).
   */
  public export(tableId: string, colId: string, colType: string, rowIds: number[], values: CellValue[],
    blobs: BlobTable): CarriedValues {
    const cells = this._tables.get(tableId)?.get(colId);
    const defaultValue = getDefaultForType(colType);
    const refs: ([number, number] | null)[] = [];
    const plain: CellValue[] = [];
    for (const [i, rowId] of rowIds.entries()) {
      const ref = cells?.get(rowId);
      if (ref) {
        refs.push([blobs.indexOf(ref.blob), ref.pos]);
        plain.push(null);
      } else if (!isLockedCell(values[i]) && isEqual(values[i], defaultValue)) {
        refs.push(null);
        plain.push(values[i]);
      } else {
        throw new CannotCarryError(`No sealed value for ${tableId}.${colId} in row ${rowId}`);
      }
    }
    return { carried: { refs, plain } };
  }

  private _column(tableId: string, colId: string): Map<number, CellRef> {
    let table = this._tables.get(tableId);
    if (!table) { this._tables.set(tableId, table = new Map()); }
    let cells = table.get(colId);
    if (!cells) { table.set(colId, cells = new Map()); }
    return cells;
  }

  private _applyAction(action: any) {
    const [name, tableId] = action as [string, string];
    const table = this._tables.get(tableId);
    switch (name) {
      case "AddRecord": case "BulkAddRecord": case "UpdateRecord": case "BulkUpdateRecord":
      case "ReplaceTableData": case "TableData": {
        const single = (name === "AddRecord" || name === "UpdateRecord");
        const rowIds: number[] = single ? [action[2]] : action[2];
        const columns: Record<string, unknown> = action[3] || {};
        if (name === "ReplaceTableData" || name === "TableData") {
          this._tables.delete(tableId);
        } else if (table && (name === "AddRecord" || name === "BulkAddRecord")) {
          // New rows get default values in columns the action doesn't give.
          for (const [colId, cells] of table) {
            if (!(colId in columns)) { for (const rowId of rowIds) { cells.delete(rowId); } }
          }
        }
        for (const [colId, values] of Object.entries(columns)) {
          if (isSealed(values)) {
            const cells = this._column(tableId, colId);
            rowIds.forEach((rowId, pos) => cells.set(rowId, { blob: values.sealed, pos }));
          } else {
            const cells = this._tables.get(tableId)?.get(colId);
            if (cells) { for (const rowId of rowIds) { cells.delete(rowId); } }
          }
        }
        break;
      }
      case "RemoveRecord": case "BulkRemoveRecord": {
        const rowIds: number[] = name === "RemoveRecord" ? [action[2]] : action[2];
        for (const cells of table?.values() || []) {
          for (const rowId of rowIds) { cells.delete(rowId); }
        }
        break;
      }
      case "RemoveColumn":
        table?.delete(action[2]);
        break;
      case "RenameColumn": {
        const cells = table?.get(action[2]);
        if (table && cells) { table.delete(action[2]); table.set(action[3], cells); }
        break;
      }
      case "RemoveTable":
        this._tables.delete(tableId);
        break;
      case "RenameTable":
        if (table) { this._tables.delete(tableId); this._tables.set(action[2], table); }
        break;
    }
  }
}
