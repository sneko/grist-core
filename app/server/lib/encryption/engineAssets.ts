/**
 * Serves what a browser needs to run the data engine itself, for end-to-end encrypted documents:
 * the Pyodide runtime, the Python packages the engine depends on, and the engine's own code
 * (sandbox/grist) as a tarball.
 *
 * Everything is served under a versioned path, so that it can be cached by browsers for as long
 * as the server version doesn't change. Only the small manifest is served without caching.
 */
import { EngineManifest } from "app/common/encryption/EncryptionTypes";
import { getAppPathTo, getAppRoot } from "app/server/lib/places";

import * as crypto from "crypto";
import * as path from "path";

import * as express from "express";
import * as fse from "fs-extra";
import * as tar from "tar";

export const ENCRYPTION_ENGINE_PATH = "/encryption-engine";

// Files of the pyodide npm package that the browser needs.
const PYODIDE_RUNTIME_FILES = [
  "pyodide.js", "pyodide.mjs", "pyodide.asm.js", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json",
];

function getSandboxDir() {
  return getAppPathTo(getAppRoot(), "sandbox");
}

export function getPyodideRuntimeDir() {
  return path.join(getSandboxDir(), "pyodide", "worker", "node_modules", "pyodide");
}

export function getPyodidePackagesDir() {
  return path.join(getSandboxDir(), "pyodide", "_build", "packages");
}

/** Lists the wheels the engine needs (the same list the server-side pyodide sandbox uses). */
export async function getPyodidePackageNames(): Promise<string[]> {
  return fse.readJson(path.join(getSandboxDir(), "pyodide", "package_filenames.json"));
}

/** Whether a file in sandbox/grist is part of the engine (rather than its tests). */
function isEngineFile(relPath: string): boolean {
  const parts = relPath.split(/[\\/]/);
  const base = parts[parts.length - 1];
  if (parts.some(p => p === "__pycache__" || p === "fixtures" || p === "bench")) { return false; }
  if (base.startsWith("test") || base.endsWith("_test.py")) { return false; }
  return base.endsWith(".py") || base === "tzdata.data" || !base.includes(".");
}

let _archive: Promise<Buffer> | undefined;

/**
 * Returns a gzipped tarball of the engine code, with a top-level "grist" directory. It is built
 * once per process.
 */
export function getGristEngineArchive(): Promise<Buffer> {
  if (!_archive) {
    _archive = (async () => {
      const chunks: Buffer[] = [];
      const stream = tar.create({
        gzip: true,
        cwd: getSandboxDir(),
        portable: true,
        // Fixed mtimes make the archive (and so the asset version) reproducible.
        mtime: new Date(0),
        filter: (p: string) => isEngineFile(path.relative("grist", p) || p),
      }, ["grist"]);
      for await (const chunk of stream as AsyncIterable<Buffer>) { chunks.push(Buffer.from(chunk)); }
      return Buffer.concat(chunks);
    })();
    _archive.catch(() => { _archive = undefined; });
  }
  return _archive;
}

let _manifest: Promise<EngineManifest> | undefined;

/**
 * Returns the list of packages and a version that changes whenever any engine asset does: a hash
 * of the contents of all of them. Browsers rely on it to cache the assets for good (their URLs
 * include it), and to reuse the memory snapshot of the engine they saved (see engineWorker.ts).
 */
export function getEngineManifest(): Promise<EngineManifest> {
  if (!_manifest) {
    _manifest = (async () => {
      const packages = await getPyodidePackageNames();
      const hash = crypto.createHash("sha256");
      const addFile = async (name: string, file: string) => {
        hash.update(`${name}\n`);
        hash.update(await fse.readFile(file));
      };
      for (const file of PYODIDE_RUNTIME_FILES) {
        await addFile(`pyodide/${file}`, path.join(getPyodideRuntimeDir(), file));
      }
      for (const p of packages) {
        await addFile(`packages/${p}`, path.join(getPyodidePackagesDir(), p));
      }
      hash.update("grist.tar.gz\n");
      hash.update(await getGristEngineArchive());
      const version = hash.digest("hex").slice(0, 16);
      return { version, packages };
    })();
    _manifest.catch(() => { _manifest = undefined; });
  }
  return _manifest;
}

const IMMUTABLE = "public, max-age=31536000, immutable";

/**
 * Adds the endpoints serving engine assets to the given app:
 *   GET /encryption-engine/manifest.json
 *   GET /encryption-engine/:version/pyodide/:file
 *   GET /encryption-engine/:version/packages/:file
 *   GET /encryption-engine/:version/grist.tar.gz
 */
export function addEncryptionEngineEndpoints(app: express.Application) {
  const router = express.Router();

  router.get("/manifest.json", async (_req, res) => {
    res.set("Cache-Control", "no-cache");
    res.json(await getEngineManifest());
  });

  // Assets are only served under the current version, so that a cached copy is never stale.
  const checkVersion: express.RequestHandler = async (req, res, next) => {
    const { version } = await getEngineManifest();
    if (req.params.version !== version) {
      res.status(404).json({ error: "Unknown engine version" });
      return;
    }
    res.set("Cache-Control", IMMUTABLE);
    next();
  };

  router.get("/:version/pyodide/:file", checkVersion, (req, res) => {
    const file = req.params.file;
    if (!PYODIDE_RUNTIME_FILES.includes(file)) {
      res.status(404).json({ error: "Not found" });
      return;
    }
    res.sendFile(path.join(getPyodideRuntimeDir(), file));
  });

  router.get("/:version/packages/:file", checkVersion, async (req, res) => {
    const file = req.params.file;
    if (!(await getPyodidePackageNames()).includes(file)) {
      res.status(404).json({ error: "Not found" });
      return;
    }
    res.sendFile(path.join(getPyodidePackagesDir(), file));
  });

  router.get("/:version/grist.tar.gz", checkVersion, async (_req, res) => {
    res.type("application/gzip").send(await getGristEngineArchive());
  });

  app.use(ENCRYPTION_ENGINE_PATH, (req, res, next) => {
    router(req, res, (err?: any) => {
      if (err) {
        res.status(500).json({ error: String(err) });
      } else {
        next();
      }
    });
  });
}
