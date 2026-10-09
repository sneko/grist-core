/**
 * Imports files into encrypted documents. For regular documents, files are uploaded to the
 * server, which parses them; encrypted documents can't let the server see them, so files are
 * parsed in the browser, by the same parsers (those of the data engine, which runs there), and
 * added as new tables like the server would.
 */
import { ApplyUAResult } from "app/common/ActiveDocAPI";
import { CellValue, UserAction } from "app/common/DocActions";
import { DocData } from "app/common/DocData";
import { IMPORT_DIR } from "app/common/encryption/PyodideEngine";
import { localTimestampToUTC } from "app/common/RelativeDates";
import { guessColInfoForImports } from "app/common/ValueGuesser";
import { ParseFileResult } from "app/plugin/FileParserAPI";
import { GristColumn } from "app/plugin/GristTable";

/** The engine features needed to parse files. */
export interface ImportEngine {
  writeFile(path: string, data: Uint8Array): Promise<void> | void;
  removeFile(path: string): Promise<void> | void;
  call(funcName: string, ...args: any[]): Promise<any>;
}

const PARSERS: Record<string, string> = {
  csv: "csv_parser.parseFile",
  tsv: "csv_parser.parseFile",
  txt: "csv_parser.parseFile",
  dsv: "csv_parser.parseFile",
  xlsx: "xls_parser.parseFile",
  xlsm: "xls_parser.parseFile",
  json: "json_parser.parseFile",
};

/** Parses a file with the engine's import parsers. */
export async function parseFileLocally(engine: ImportEngine, fileName: string,
  data: Uint8Array): Promise<ParseFileResult> {
  const ext = fileName.split(".").pop()?.toLowerCase() || "";
  const parser = PARSERS[ext];
  if (!parser) { throw new Error(`Importing ${ext ? `.${ext}` : "these"} files is not supported`); }
  const name = `${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`;
  await engine.writeFile(`${IMPORT_DIR}/${name}`, data);
  // Encoding detection can be unreliable for short files: when the file is valid UTF-8, say so.
  const options = (parser === PARSERS.csv && isValidUtf8(data)) ? { encoding: "utf-8" } : {};
  try {
    return await engine.call(parser, { path: name, origName: fileName }, options);
  } finally {
    await engine.removeFile(`${IMPORT_DIR}/${name}`);
  }
}

/**
 * Adds parsed tables to the document, as new tables, guessing column types as the server does
 * for imports (see ActiveDocImport). Returns the ids of the new tables.
 */
export async function addParsedTables(
  parsed: ParseFileResult, fileName: string, docData: DocData,
  applyUserActions: (actions: UserAction[]) => Promise<ApplyUAResult>,
): Promise<string[]> {
  const tableIds: string[] = [];
  const baseName = fileName.replace(/\.[^.]*$/, "").trim() || "Imported";
  for (const table of parsed.tables) {
    const tableData = table.table_data.map(col => [...col]) as CellValue[][];
    const columns = cleanColumns(table.column_metadata, tableData, docData);
    const name = table.table_name ? `${baseName} - ${table.table_name}` : baseName;
    const added = await applyUserActions([["AddTable", toTableId(name), columns]]);
    const { table_id: tableId, columns: colIds } = added.retValues[0];
    const numRows = tableData[0]?.length || 0;
    if (numRows > 0) {
      const values = Object.fromEntries(colIds.map((colId: string, i: number) => [colId, tableData[i]]));
      await applyUserActions([["BulkAddRecord", tableId, new Array(numRows).fill(null), values]]);
    }
    tableIds.push(tableId);
  }
  return tableIds;
}

function isValidUtf8(data: Uint8Array): boolean {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(data);
    return true;
  } catch (e) {
    return false;
  }
}

// As cleanColumnMetadata() in ActiveDocImport.
function cleanColumns(columns: GristColumn[], tableData: CellValue[][], docData: DocData) {
  const timezone = docData.docInfo().timezone;
  return columns.map((c, index) => {
    const newCol: any = { ...c, isFormula: false };
    if (c.id) { newCol.label = c.id; }
    if (c.type === "Any") {
      const { values, colMetadata } = guessColInfoForImports(tableData[index], docData);
      tableData[index] = values;
      if (colMetadata) { Object.assign(newCol, colMetadata); }
    }
    if (c.type === "DateTime" && timezone) {
      newCol.type = `DateTime:${timezone}`;
      tableData[index] = tableData[index].map(v => typeof v === "number" ? localTimestampToUTC(v, timezone) : v);
    }
    return newCol;
  });
}

// Table ids get sanitized by the engine; this only makes them look like the file's name.
function toTableId(name: string): string {
  const id = name.replace(/[^A-Za-z0-9_]+/g, "_").replace(/^_+|_+$/g, "");
  return id ? id.charAt(0).toUpperCase() + id.slice(1) : "Imported";
}
