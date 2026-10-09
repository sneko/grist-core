/**
 * Hosts Grist's Python data engine inside a Pyodide instance, in the same thread as the caller.
 *
 * This is how end-to-end encrypted documents get their engine: the server never sees their data,
 * so the engine runs where the data is decrypted, i.e. in the browser (in a Web Worker, see
 * app/client/encryption/engineWorker.ts). The same class runs under Node in tests.
 *
 * Calls are marshalled exactly as NSandbox marshals them over pipes, and are handled on the
 * Python side by sandbox/grist/direct_sandbox.py.
 */
import * as marshal from "app/common/marshal";

/**
 * The subset of the Pyodide API that we use. It is declared here rather than imported, since the
 * pyodide package is not a dependency of the main build: it is loaded at runtime.
 */
export interface PyodideLike {
  FS: { writeFile(path: string, data: Uint8Array): void, unlink(path: string): void, mkdirTree(path: string): void };
  loadPackage(names: string | string[], options?: {
    messageCallback?: (msg: string) => void,
    errorCallback?: (msg: string) => void,
  }): Promise<unknown[]>;
  unpackArchive(buffer: ArrayBuffer | Uint8Array, format: string, options?: { extractDir?: string }): void;
  runPython(code: string): any;
  setStderr?(options: { batched: (msg: string) => void }): void;
  setStdout?(options: { batched: (msg: string) => void }): void;
}

/**
 * Functions the engine may call back into (via call_external in Python). They must be
 * synchronous: the engine blocks while waiting for them.
 */
export type EngineExports = Record<string, (...args: any[]) => any>;

export interface PyodideEngineOptions {
  /** Wheels to load, as URLs (in the browser) or file paths (under Node). */
  packages: string[];
  /** A gzipped tarball of sandbox/grist, containing a top-level "grist" directory. */
  gristArchive: Uint8Array;
  /** Functions the engine may call, such as guessColInfo and convertFromColumn. */
  exports: EngineExports;
  log?: (...args: any[]) => void;
}

/**
 * Anything that can run engine functions. PyodideEngine implements it directly; the browser uses
 * a proxy to an engine running in a Web Worker.
 */
export interface IDataEngine {
  call(funcName: string, ...args: any[]): Promise<any>;
}

// Where files to import are placed for the engine's import parsers (see imports/import_utils.py).
export const IMPORT_DIR = "/import";

// Message codes, as in app/server/lib/sandboxUtil.ts and sandbox/grist/sandbox.py.
const DATA = true;
const EXC = false;

export class PyodideEngine implements IDataEngine {
  public static async create(pyodide: PyodideLike, options: PyodideEngineOptions): Promise<PyodideEngine> {
    const log = options.log || (() => {});
    pyodide.setStderr?.({ batched: msg => log("[py]", msg) });
    pyodide.setStdout?.({ batched: msg => log("[py]", msg) });
    const loaded = await pyodide.loadPackage(options.packages, {
      messageCallback: msg => log("[package]", msg),
      errorCallback: msg => log("[package error]", msg),
    });
    // loadPackage resolves even when it loaded nothing; catch that here rather than through an
    // ImportError from deep inside the engine.
    if (loaded.length !== options.packages.length) {
      throw new Error(`Pyodide loaded ${loaded.length} of ${options.packages.length} packages`);
    }
    // Pyodide only accepts plain typed arrays (not e.g. Node's Buffer subclass).
    const archive = new Uint8Array(options.gristArchive.buffer, options.gristArchive.byteOffset,
      options.gristArchive.byteLength);
    pyodide.unpackArchive(archive, "gztar", { extractDir: "/" });
    // main.py appends a relative "thirdparty" path, so run from the engine's directory.
    pyodide.runPython(`
import os, sys
sys.path.append('/grist')
os.chdir('/grist')
os.environ['IMPORTDIR'] = '${IMPORT_DIR}'
`);
    pyodide.FS.mkdirTree(IMPORT_DIR);
    const createSandbox = pyodide.runPython("import direct_sandbox\ndirect_sandbox.create");
    const engine = new PyodideEngine(pyodide, options.exports, log);
    const sandbox = createSandbox(engine._callExternal.bind(engine));
    createSandbox.destroy?.();
    engine._pyCall = sandbox.call;
    return engine;
  }

  private _pyCall: (buf: Uint8Array) => any;

  private constructor(private _pyodide: PyodideLike, private _exports: EngineExports,
    private _log: (...args: any[]) => void) {}

  /**
   * Calls an engine function, e.g. call("apply_user_actions", [["AddTable", ...]]). The call runs
   * synchronously; it returns a promise only to share the interface with asynchronous engines.
   */
  public async call(funcName: string, ...args: any[]): Promise<any> {
    return this.callSync(funcName, ...args);
  }

  /** Places a file in the engine's file system (e.g. for its import parsers, under IMPORT_DIR). */
  public writeFile(path: string, data: Uint8Array) {
    this._pyodide.FS.writeFile(path, data);
  }

  public removeFile(path: string) {
    this._pyodide.FS.unlink(path);
  }

  public callSync(funcName: string, ...args: any[]): any {
    const marshaller = new marshal.Marshaller({ stringToBuffer: false, version: 2 });
    marshaller.marshal([funcName, ...args]);
    const resultProxy = this._pyCall(marshaller.dump());
    let bytes: Uint8Array;
    try {
      bytes = resultProxy.toJs();
    } finally {
      resultProxy.destroy?.();
    }
    const [code, data] = marshal.loads(bytes, { bufferToString: true });
    if (code === DATA) { return data; }
    if (code === EXC) { throw new Error(`[Sandbox] ${data}`); }
    throw new Error(`[Sandbox] unexpected response code ${code}`);
  }

  /**
   * Called synchronously from Python with a marshalled [funcName, ...args]; returns a marshalled
   * (msgCode, data) pair.
   */
  private _callExternal(bufProxy: any): Uint8Array {
    let buf: Uint8Array;
    try {
      buf = bufProxy.toJs();
    } finally {
      bufProxy.destroy?.();
    }
    const marshaller = new marshal.Marshaller({ stringToBuffer: false, version: 2 });
    try {
      const [funcName, ...args] = marshal.loads(buf, { bufferToString: true });
      const func = this._exports[funcName];
      if (!func) { throw new Error(`No such exported function: ${funcName}`); }
      const result = func(...args);
      if (result && typeof result.then === "function") {
        throw new Error(`Exported function ${funcName} must be synchronous`);
      }
      marshaller.marshal([DATA, result]);
    } catch (e) {
      this._log("[engine] call_external failed", e);
      marshaller.marshal([EXC, String(e)]);
    }
    return marshaller.dump();
  }
}
