/**
 * Creates the in-process Pyodide data engine (the one browsers run for end-to-end encrypted
 * documents) under Node, from the same assets the server serves to browsers. Used in tests.
 */
import { engineExports } from "app/common/encryption/engineExports";
import { PyodideEngine } from "app/common/encryption/PyodideEngine";
import {
  getGristEngineArchive, getPyodidePackageNames, getPyodidePackagesDir, getPyodideRuntimeDir,
} from "app/server/lib/encryption/engineAssets";
import log from "app/server/lib/log";

import * as path from "path";

import * as fse from "fs-extra";

export async function createNodePyodideEngine(options: { verbose?: boolean } = {}): Promise<PyodideEngine> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { loadPyodide } = require(getPyodideRuntimeDir());
  const pyodide = await loadPyodide();
  const packagesDir = getPyodidePackagesDir();
  const packages = await Promise.all((await getPyodidePackageNames()).map(async p =>
    new Uint8Array(await fse.readFile(path.join(packagesDir, p)))));
  return PyodideEngine.create(pyodide, {
    packages,
    gristArchive: await getGristEngineArchive(),
    exports: engineExports,
    log: options.verbose ? (...args) => log.info("[encryption engine]", ...args) : undefined,
  });
}
