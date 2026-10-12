/**
 * When an encrypted document becomes a regular one (see app/client/encryption/DocConversion.ts),
 * its private columns and tables become columns and tables hidden by access rules from the
 * members who couldn't read them, so that they still can't.
 */
import { UserAction } from "app/common/DocActions";
import { DocData } from "app/common/DocData";
import { ColumnPrivacy } from "app/common/encryption/ColumnPrivacy";
import { EncryptionMember } from "app/common/encryption/EncryptionTypes";
import { Keyring } from "app/common/encryption/Keyring";

/**
 * The user actions adding access rules that hide what's private from members who can't read it:
 * for each column whose values are private (private columns, and formulas using them), only
 * members holding all the keys needed to read it can read it (or change it).
 */
export function makeAccessRuleActions(docData: DocData, privacy: ColumnPrivacy, keyring: Keyring,
  members: EncryptionMember[]): ((previous: any[]) => UserAction[])[] {
  const readers = (scopes: string[]) => members.filter(m => scopes.every((scope) => {
    const key = keyring.currentKey(scope);
    return key && m.keyIds.includes(key.keyId);
  }));
  // Private tables become tables hidden as a whole (rows included), and can't be changed by others.
  const tableScopes = new Map<number, string>();
  for (const table of docData.getMetaTable("_grist_Tables").getRecords()) {
    const scope = keyring.currentScopeOfTable(table.id);
    if (scope) { tableScopes.set(table.id, scope); }
  }
  // Group columns by table and by who can read them.
  const groups = new Map<string, {
    tableId: string, colIds: string[], readers: EncryptionMember[], wholeTable?: boolean,
  }>();
  for (const [tableRef, scope] of tableScopes) {
    const tableId = docData.getMetaTable("_grist_Tables").getValue(tableRef, "tableId") as string;
    groups.set(`${tableId} *`, { tableId, colIds: ["*"], readers: readers([scope]), wholeTable: true });
  }
  for (const column of docData.getMetaTable("_grist_Tables_column").getRecords()) {
    const table = docData.getMetaTable("_grist_Tables").getRecord(column.parentId);
    if (!table) { continue; }
    // (Columns of a private table only need a rule of their own if they need more keys.)
    const tableScope = tableScopes.get(table.id);
    const scopes = privacy.scopesOf(table.tableId, column.colId).filter(scope => scope !== tableScope);
    if (scopes.length === 0) { continue; }
    const allowed = readers(scopes);
    const key = `${table.tableId} ${allowed.map(m => m.userId).sort((a, b) => a - b).join(",")}`;
    const group = groups.get(key) || { tableId: table.tableId, colIds: [], readers: allowed };
    group.colIds.push(column.colId);
    groups.set(key, group);
  }
  if (groups.size === 0) { return []; }
  const list = [...groups.values()];
  return [
    () => [["BulkAddRecord", "_grist_ACLResources", list.map(() => null), {
      tableId: list.map(g => g.tableId),
      colIds: list.map(g => g.colIds.join(",")),
    }]],
    (previous: any[]) => {
      const resourceIds: number[] = previous[0];
      return [["BulkAddRecord", "_grist_ACLRules", list.map(() => null), {
        resource: resourceIds,
        aclFormula: list.map(g => g.readers.length === 0 ? "True" :
          `user.UserID not in [${g.readers.map(m => m.userId).join(", ")}]`),
        permissionsText: list.map(g => g.wholeTable ? "-CRUD" : "-RU"),
        rulePos: list.map((_, i) => i + 1),
        memo: list.map(g => `${g.wholeTable ? "Private table" : "Private column"} ` +
          `(readable by ${g.readers.map(m => m.name || m.email).join(", ") || "nobody"})`),
      }]];
    },
  ];
}
