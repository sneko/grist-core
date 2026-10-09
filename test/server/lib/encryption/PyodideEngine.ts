/**
 * Tests the in-process Pyodide data engine that browsers run for end-to-end encrypted documents.
 */
import { PyodideEngine } from "app/common/encryption/PyodideEngine";
import { User } from "app/common/User";
import { getGristEngineArchive } from "app/server/lib/encryption/engineAssets";
import { createNodePyodideEngine } from "app/server/lib/encryption/NodePyodideEngine";

import * as zlib from "zlib";

import { assert } from "chai";

describe("encryption/PyodideEngine", function() {
  this.timeout(120000);

  let engine: PyodideEngine;

  before(async function() {
    engine = await createNodePyodideEngine();
  });

  it("ships the engine without its tests", async function() {
    const tarball = zlib.gunzipSync(await getGristEngineArchive()).toString("latin1");
    assert.include(tarball, "grist/engine.py");
    assert.include(tarball, "grist/direct_sandbox.py");
    assert.include(tarball, "grist/tzdata.data");
    assert.include(tarball, "grist/imports/import_csv.py");
    assert.notInclude(tarball, "grist/test_engine.py");
    assert.notInclude(tarball, "grist/imports/import_csv_test.py");
  });

  it("creates a document and computes formulas", async function() {
    await engine.call("load_empty");
    await engine.call("apply_user_actions", [["InitNewDoc"]]);
    const res = await engine.call("apply_user_actions", [
      ["AddTable", "People", [
        { id: "Name", type: "Text", isFormula: false },
        { id: "Age", type: "Numeric", isFormula: false },
        { id: "Upper", type: "Any", isFormula: true, formula: "$Name.upper()" },
      ]],
      ["BulkAddRecord", "People", [null, null], { Name: ["alice", "bob"], Age: [30, 25] }],
    ], new User({ Email: "alice@example.com", Name: "Alice", Access: "owners", UserID: 1 }).toJSON());
    assert.deepEqual(res.retValues[1], [1, 2]);
    const table = await engine.call("fetch_table", "People");
    assert.deepEqual(table[2], [1, 2]);
    assert.deepEqual(table[3].Upper, ["ALICE", "BOB"]);
    assert.deepEqual(table[3].Age, [30, 25]);
  });

  it("calls back into JS to guess column types", async function() {
    // Writing into empty "Any" columns makes the engine guess a type via guessColInfo.
    await engine.call("apply_user_actions", [["AddEmptyTable", null]]);
    await engine.call("apply_user_actions", [["AddRecord", "Table1", null, { A: "12", B: "2024-01-15" }]]);
    const cols = await engine.call("fetch_table", "_grist_Tables_column");
    const colIdx = cols[3].colId.indexOf("A");
    assert.equal(cols[3].type[colIdx], "Numeric");
    const table = await engine.call("fetch_table", "Table1");
    assert.deepEqual(table[3].A, [12]);
  });

  it("reports engine errors as exceptions", async function() {
    await assert.isRejected(engine.call("apply_user_actions", [["AddRecord", "NoSuchTable", null, {}]]),
      /\[Sandbox\] KeyError/);
    await assert.isRejected(engine.call("no_such_function"), /\[Sandbox\] KeyError/);
  });

  it("can reload a document from all its tables and replay changes exactly", async function() {
    const snapshot = await engine.call("fetch_all_tables");
    assert.includeMembers(Object.keys(snapshot), ["_grist_Tables", "_grist_DocInfo", "People", "Table1"]);

    // A second engine loads the snapshot.
    const engine2 = await createNodePyodideEngine();
    const others: string[] = await engine2.call("load_meta_tables_repr",
      snapshot._grist_Tables, snapshot._grist_Tables_column);
    for (const tableId of others) {
      await engine2.call("load_table_repr", snapshot[tableId]);
    }
    await engine2.call("calculate_exactly");
    assert.deepEqual(await engine2.call("fetch_all_tables"), snapshot);

    // A change computed by the first engine (including a volatile formula) is replayed by the
    // second one, which must end up with exactly the same values rather than recomputing them.
    const change = await engine.call("apply_user_actions", [
      ["AddColumn", "People", "Rand", { type: "Any", isFormula: true, formula: "RANDBETWEEN(1, 1000000)" }],
      ["AddRecord", "People", null, { Name: "carol", Age: 41 }],
    ]);
    const stored = change.stored.map((env: [number, any]) => env[1]);
    await engine2.call("apply_doc_actions_exactly", stored);
    assert.deepEqual(await engine2.call("fetch_table", "People"), await engine.call("fetch_table", "People"));

    // Formulas added by a replayed change still track their dependencies (the engine learns
    // them by evaluating formulas, which replaying mustn't skip).
    const added = await engine.call("apply_user_actions", [["AddColumn", "People", "Initials",
      { type: "Any", isFormula: true, formula: "$Name[:2]" }]]);
    await engine2.call("apply_doc_actions_exactly", added.stored.map((env: [number, any]) => env[1]));
    const edited = await engine2.call("apply_user_actions", [["UpdateRecord", "People", 3, { Name: "dave" }]]);
    assert.deepInclude(edited.stored.map((env: [number, any]) => env[1]),
      ["UpdateRecord", "People", 3, { Initials: "da" }]);
    await engine2.call("apply_user_actions", [["ApplyUndoActions", edited.undo.map((env: [number, any]) => env[1])]]);
    await engine2.call("apply_user_actions", [["ApplyUndoActions", added.undo.map((env: [number, any]) => env[1])]]);

    // Undoing it on the second engine restores the snapshot's data.
    const undo = change.undo.map((env: [number, any]) => env[1]);
    await engine2.call("apply_user_actions", [["ApplyUndoActions", undo]]);
    assert.deepEqual(await engine2.call("fetch_table", "People"), snapshot.People);
  });
});
