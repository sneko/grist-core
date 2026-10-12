import * as gu from "test/nbrowser/gristUtils";
import { setupTestSuite } from "test/nbrowser/testUtils";

import { assert, Key } from "mocha-webdriver";

describe("RenameColumnBack", function() {
  this.timeout(30000);
  const cleanup = setupTestSuite();

  it("keeps a column editable when renamed back to its suggested id", async function() {
    // A column added with a name gets a suggested id first (here "D"), then is renamed: row
    // models created meanwhile used to keep a broken "D" once the column was renamed back to it.
    const session = await gu.session().teamSite.login();
    await session.tempNewDoc(cleanup, "RenameColumnBack");
    await gu.getCell({ col: "A", rowNum: 1 }).click();
    await gu.enterCell("a1", Key.ENTER, "a2");
    await gu.waitForServer();
    await gu.addColumn("random one", "Integer");
    await gu.renameColumn("random one", "D");
    await gu.waitForServer();
    await gu.waitToPass(async () => assert.include(await gu.getColumnNames(), "D"));
    await gu.getCell({ col: "D", rowNum: 1 }).click();
    await gu.enterCell("42");
    await gu.waitForServer();
    assert.equal(await gu.getCell({ col: "D", rowNum: 1 }).getText(), "42");
    await gu.checkForErrors();
  });
});
