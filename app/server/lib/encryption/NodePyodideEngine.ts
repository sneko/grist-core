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

export async function createNodePyodideEngine(options: { verbose?: boolean } = {}): Promise<PyodideEngine> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { loadPyodide } = require(getPyodideRuntimeDir());
  const pyodide = await loadPyodide();
  const packagesDir = getPyodidePackagesDir();
  // Pyodide names a wheel after the last "/"-separated part of its path.
  const packages = (await getPyodidePackageNames()).map(p => path.join(packagesDir, p).split(path.sep).join("/"));
  return PyodideEngine.create(pyodide, {
    packages,
    gristArchive: await getGristEngineArchive(),
    exports: engineExports,
    log: options.verbose ? (...args) => log.info("[encryption engine]", ...args) : undefined,
  });
}
