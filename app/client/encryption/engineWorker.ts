/**
 * Web Worker running the data engine (Python, in Pyodide) for an end-to-end encrypted document.
 * It is built as its own bundle (see buildtools/webpack.config.js) and driven by WorkerEngine.
 *
 * Messages in:  {type: "init", engineBaseUrl} then {type: "call", id, funcName, args}
 * Messages out: {type: "ready"} or {type: "initError", error}, then {id, result} or {id, error}
 */
import { EngineManifest } from "app/common/encryption/EncryptionTypes";
import { engineExports } from "app/common/encryption/engineExports";
import { PyodideEngine } from "app/common/encryption/PyodideEngine";

// The worker global scope (typed loosely: the client is compiled against DOM typings).
declare const self: any;

let engine: PyodideEngine | null = null;

async function init(engineBaseUrl: string) {
  const manifestResp = await fetch(`${engineBaseUrl}/manifest.json`);
  if (!manifestResp.ok) { throw new Error(`Cannot load engine manifest: ${manifestResp.status}`); }
  const manifest: EngineManifest = await manifestResp.json();
  const base = `${engineBaseUrl}/${manifest.version}`;
  self.importScripts(`${base}/pyodide/pyodide.js`);
  const pyodide = await self.loadPyodide!({ indexURL: `${base}/pyodide/` });
  const archiveResp = await fetch(`${base}/grist.tar.gz`);
  if (!archiveResp.ok) { throw new Error(`Cannot load engine code: ${archiveResp.status}`); }
  engine = await PyodideEngine.create(pyodide, {
    packages: manifest.packages.map(p => `${base}/packages/${p}`),
    gristArchive: new Uint8Array(await archiveResp.arrayBuffer()),
    exports: engineExports,
    log: (...args) => console.debug("[encryption engine]", ...args),
  });
}

self.onmessage = async (event: MessageEvent) => {
  const msg = event.data;
  if (msg.type === "init") {
    try {
      await init(msg.engineBaseUrl);
      self.postMessage({ type: "ready" });
    } catch (e) {
      self.postMessage({ type: "initError", error: String(e?.message || e) });
    }
  } else if (msg.type === "writeFile" || msg.type === "removeFile") {
    try {
      if (!engine) { throw new Error("Engine not ready"); }
      if (msg.type === "writeFile") {
        engine.writeFile(msg.path, msg.data);
      } else {
        engine.removeFile(msg.path);
      }
      self.postMessage({ id: msg.id, result: null });
    } catch (e) {
      self.postMessage({ id: msg.id, error: String(e?.message || e) });
    }
  } else if (msg.type === "call") {
    try {
      if (!engine) { throw new Error("Engine not ready"); }
      const result = engine.callSync(msg.funcName, ...msg.args);
      self.postMessage({ id: msg.id, result });
    } catch (e) {
      self.postMessage({ id: msg.id, error: String(e?.message || e) });
    }
  }
};
