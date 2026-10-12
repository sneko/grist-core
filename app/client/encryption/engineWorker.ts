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

// How long each step of starting took (sent along with "ready").
const timings: { step: string, ms: number }[] = [];
let lastStep = performance.now();
function step(name: string) {
  const now = performance.now();
  timings.push({ step: name, ms: Math.round(now - lastStep) });
  lastStep = now;
}

async function init(engineBaseUrl: string) {
  step("start worker");
  const manifestResp = await fetch(`${engineBaseUrl}/manifest.json`);
  if (!manifestResp.ok) { throw new Error(`Cannot load engine manifest: ${manifestResp.status}`); }
  const manifest: EngineManifest = await manifestResp.json();
  const base = `${engineBaseUrl}/${manifest.version}`;
  self.importScripts(`${base}/pyodide/pyodide.js`);
  step("load Pyodide script");
  const snapshots = await SnapshotStore.open(`${base}/memory-snapshot`);
  const [packages, gristArchive, snapshot] = await Promise.all([
    Promise.all(manifest.packages.map(p => fetchBytes(`${base}/packages/${p}`))),
    fetchBytes(`${base}/grist.tar.gz`),
    snapshots?.load(),
  ]);
  step(`fetch packages and Grist's code${snapshot ? ", and Python's saved memory" : ""}`);
  const options = {
    onStep: step,
    packages,
    gristArchive,
    exports: engineExports,
    log: (...args: any[]) => console.debug("[encryption engine]", ...args),
  };

  if (snapshot) {
    try {
      const pyodide = await self.loadPyodide!({ indexURL: `${base}/pyodide/`, _loadSnapshot: snapshot });
      step("restore Python (WebAssembly) from saved memory");
      engine = await PyodideEngine.create(pyodide, { ...options, restored: true });
      return;
    } catch (e) {
      // E.g. a browser change: start normally, and save a new one.
      console.warn("[encryption engine] Could not restore Python's saved memory", e);
      await snapshots?.drop();
    }
  }
  const pyodide = await self.loadPyodide!({ indexURL: `${base}/pyodide/`, _makeSnapshot: Boolean(snapshots) });
  step("start Python (WebAssembly)");
  engine = await PyodideEngine.create(pyodide, {
    ...options,
    // Next time, start from Python's memory as it is now (saved without waiting).
    beforeSandbox: snapshots ? () => snapshots.save(pyodide.makeMemorySnapshot()) : undefined,
  });
}

async function fetchBytes(url: string): Promise<Uint8Array> {
  const resp = await fetch(url);
  if (!resp.ok) { throw new Error(`Cannot load ${url}: ${resp.status}`); }
  return new Uint8Array(await resp.arrayBuffer());
}

/**
 * Python's memory once the engine's modules are imported (a Pyodide "memory snapshot"), kept in
 * the browser's cache storage: restoring it skips most of starting the engine. It's saved per
 * engine version (part of its URL), keeping only the current one. Without cache storage (e.g.
 * outside secure contexts), the engine just starts normally.
 */
class SnapshotStore {
  public static async open(url: string): Promise<SnapshotStore | null> {
    try {
      return new SnapshotStore(await self.caches.open(SNAPSHOT_CACHE), url);
    } catch (e) {
      return null;
    }
  }

  private constructor(private _cache: Cache, private _url: string) {}

  public async load(): Promise<Uint8Array | undefined> {
    try {
      const resp = await this._cache.match(this._url);
      return resp ? new Uint8Array(await resp.arrayBuffer()) : undefined;
    } catch (e) {
      return undefined;
    }
  }

  public save(snapshot: Uint8Array) {
    (async () => {
      for (const request of await this._cache.keys()) {
        if (request.url !== this._url) { await this._cache.delete(request); }
      }
      await this._cache.put(this._url, new Response(new Blob([snapshot as Uint8Array<ArrayBuffer>]),
        { headers: { "Content-Type": "application/octet-stream" } }));
    })().catch(e => console.warn("[encryption engine] Could not save Python's memory", e));
  }

  public async drop() {
    await this._cache.delete(this._url).catch(() => {});
  }
}

const SNAPSHOT_CACHE = "grist-encryption-engine";

self.onmessage = async (event: MessageEvent) => {
  const msg = event.data;
  if (msg.type === "init") {
    try {
      await init(msg.engineBaseUrl);
      self.postMessage({ type: "ready", timings });
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
