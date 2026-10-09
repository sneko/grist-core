/**
 * Exports of end-to-end encrypted documents. The server can't produce them (it can't read the
 * data), so they are built in the browser, from the data shown in a widget: its rows in the
 * order and with the filters shown, and its columns formatted as shown.
 */
import { CopySelection } from "app/client/components/CopySelection";

import type { GristDoc } from "app/client/components/GristDoc";
import type { ViewSectionRec } from "app/client/models/entities/ViewSectionRec";

export type LocalExportFormat = "csv" | "tsv";

const DELIMITERS: Record<LocalExportFormat, string> = { csv: ",", tsv: "\t" };

/** Returns the content of a widget, as shown, formatted as CSV or TSV. */
export function exportSection(gristDoc: GristDoc, section: ViewSectionRec, format: LocalExportFormat): string {
  const view = section.viewInstance.peek();
  if (!view) { throw new Error("This widget can't be exported"); }
  const tableId = section.table.peek().tableId.peek();
  const tableData = gristDoc.docData.getTable(tableId);
  if (!tableData) { throw new Error(`Table ${tableId} is not loaded`); }
  const rowIds = view.sortedRows.getKoArray().peek().filter((r): r is number => typeof r === "number");
  const fields = section.viewFields.peek().peek();
  const selection = new CopySelection(tableData, rowIds, fields, {});
  const rows = [
    fields.map(f => f.label.peek()),
    ...rowIds.map(rowId => selection.columns.map(col => col.fmtGetter(rowId))),
  ];
  const delimiter = DELIMITERS[format];
  return rows.map(row => row.map(value => encodeValue(value, delimiter)).join(delimiter)).join("\r\n") + "\r\n";
}

/** Downloads the content of the active widget, as shown. */
export function downloadActiveSection(gristDoc: GristDoc, format: LocalExportFormat) {
  const section = gristDoc.viewModel.activeSection.peek();
  const content = exportSection(gristDoc, section, format);
  const docName = gristDoc.docPageModel.currentDocTitle.get() || "document";
  const sectionName = section.titleDef.peek() || section.table.peek().tableId.peek();
  const mimeType = format === "csv" ? "text/csv" : "text/tab-separated-values";
  // A BOM lets spreadsheet software recognize UTF-8.
  const blob = new Blob(["﻿", content], { type: `${mimeType};charset=utf-8` });
  const url = URL.createObjectURL(blob);
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
