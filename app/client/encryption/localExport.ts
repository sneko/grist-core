/**
 * Exports of end-to-end encrypted documents. The server can't produce them (it can't read the
 * data), so they are built in the browser, from the data shown in a widget: its rows in the
 * order and with the filters shown, and its columns formatted as shown (except for numbers and
 * true/false values, which Excel workbooks keep as such).
 */
import { CopySelection } from "app/client/components/CopySelection";
import { CellValue } from "app/common/DocActions";

import type { GristDoc } from "app/client/components/GristDoc";
import type { ViewSectionRec } from "app/client/models/entities/ViewSectionRec";

export type LocalExportFormat = "csv" | "tsv" | "xlsx";

const DELIMITERS: Record<"csv" | "tsv", string> = { csv: ",", tsv: "\t" };

const MIME_TYPES: Record<LocalExportFormat, string> = {
  csv: "text/csv;charset=utf-8",
  tsv: "text/tab-separated-values;charset=utf-8",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
};

/** Returns the content of a widget, as shown: its header, and its rows. */
export function getSectionContent(gristDoc: GristDoc, section: ViewSectionRec,
  options: { typed?: boolean } = {}): { header: string[], rows: CellValue[][] } {
  const view = section.viewInstance.peek();
  if (!view) { throw new Error("This widget can't be exported"); }
  const tableId = section.table.peek().tableId.peek();
  const tableData = gristDoc.docData.getTable(tableId);
  if (!tableData) { throw new Error(`Table ${tableId} is not loaded`); }
  const rowIds = view.sortedRows.getKoArray().peek().filter((r): r is number => typeof r === "number");
  const fields = section.viewFields.peek().peek();
  const selection = new CopySelection(tableData, rowIds, fields, {});
  const types = fields.map(f => f.column.peek().pureType.peek());
  const colIds = fields.map(f => f.colId.peek());
  return {
    header: fields.map(f => f.label.peek()),
    rows: rowIds.map(rowId => selection.columns.map((col, i) => {
      if (options.typed) {
        const value = tableData.getValue(rowId, colIds[i]);
        if ((types[i] === "Numeric" || types[i] === "Int") && typeof value === "number") { return value; }
        if (types[i] === "Bool" && typeof value === "boolean") { return value; }
      }
      return col.fmtGetter(rowId);
    })),
  };
}

/** Returns the content of a widget, as shown, formatted as CSV or TSV. */
export function exportSection(gristDoc: GristDoc, section: ViewSectionRec, format: "csv" | "tsv"): string {
  const { header, rows } = getSectionContent(gristDoc, section);
  const delimiter = DELIMITERS[format];
  return [header, ...rows].map(row => row.map(value => encodeValue(String(value), delimiter)).join(delimiter))
    .join("\r\n") + "\r\n";
}

/** Downloads the content of a widget (by default, the active one), as shown. */
export async function downloadSection(gristDoc: GristDoc, format: LocalExportFormat,
  section: ViewSectionRec = gristDoc.viewModel.activeSection.peek()) {
  const docName = gristDoc.docPageModel.currentDocTitle.get() || "document";
  const sectionName = section.titleDef.peek() || section.table.peek().tableId.peek();
  let parts: BlobPart[];
  if (format === "xlsx") {
    const encryption = gristDoc.docComm.encryption;
    if (!encryption) { throw new Error("Only available for encrypted documents"); }
    const { header, rows } = getSectionContent(gristDoc, section, { typed: true });
    parts = [await encryption.exportXlsx([[sectionName, header, rows]]) as BlobPart];
  } else {
    // A BOM lets spreadsheet software recognize UTF-8.
    parts = ["﻿", exportSection(gristDoc, section, format)];
  }
  const url = URL.createObjectURL(new Blob(parts, { type: MIME_TYPES[format] }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `${docName} - ${sectionName}.${format}`.replace(/[\\/:*?"<>|]/g, "_");
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

function encodeValue(value: string, delimiter: string): string {
  if (value.includes(delimiter) || /["\r\n]/.test(value)) {
    return `"${value.replace(/"/g, "\"\"")}"`;
  }
  return value;
}
