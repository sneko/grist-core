/**
 * The data engine of an end-to-end encrypted document, running in a Web Worker (see
 * engineWorker.ts), so that loading and computing don't block the page.
 */
import { IDataEngine } from "app/common/encryption/PyodideEngine";

const WORKER_BUNDLE = "encryptionEngineWorker.bundle.js";

export class WorkerEngine implements IDataEngine {
  /**
   * Starts the worker and waits for the engine to be loaded. Engine assets are cached by the
   * browser for as long as the server version doesn't change.
   */
  public static async create(): Promise<WorkerEngine> {
    const worker = await createWorker(new URL(WORKER_BUNDLE, document.baseURI).href);
    const engine = new WorkerEngine(worker);
    try {
      await engine._init(`${window.location.origin}/encryption-engine`);
    } catch (e) {
      engine.terminate();
      throw e;
    }
    return engine;
  }

  private _nextId = 1;
  private _pending = new Map<number, { resolve: (v: any) => void, reject: (e: Error) => void }>();
  private _ready?: { resolve: () => void, reject: (e: Error) => void };
  private _terminated = false;

  private constructor(private _worker: Worker) {
    _worker.onmessage = (event: MessageEvent) => this._onMessage(event.data);
    _worker.onerror = (event: ErrorEvent) => this._fail(new Error(`Engine worker failed: ${event.message}`));
  }

  public call(funcName: string, ...args: any[]): Promise<any> {
    return this._request({ type: "call", funcName, args });
  }

  /** Places a file in the engine's file system (e.g. to import it). */
  public writeFile(path: string, data: Uint8Array): Promise<void> {
    return this._request({ type: "writeFile", path, data });
  }

  public removeFile(path: string): Promise<void> {
    return this._request({ type: "removeFile", path });
  }

  public terminate() {
    if (this._terminated) { return; }
    this._terminated = true;
    this._worker.terminate();
    this._fail(new Error("Engine stopped"));
  }

  private _request(message: object): Promise<any> {
    // (A terminated worker would never answer.)
    if (this._terminated) { return Promise.reject(new Error("Engine stopped")); }
    const id = this._nextId++;
    return new Promise((resolve, reject) => {
      this._pending.set(id, { resolve, reject });
      this._worker.postMessage({ ...message, id });
    });
  }

  private _init(engineBaseUrl: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this._ready = { resolve, reject };
      this._worker.postMessage({ type: "init", engineBaseUrl });
    });
  }

  private _onMessage(msg: any) {
    if (msg.type === "ready") {
      this._ready?.resolve();
    } else if (msg.type === "initError") {
      this._ready?.reject(new Error(`Could not load the data engine: ${msg.error}`));
    } else {
      const pending = this._pending.get(msg.id);
      if (!pending) { return; }
      this._pending.delete(msg.id);
      if ("error" in msg) {
        pending.reject(new Error(msg.error));
      } else {
        pending.resolve(msg.result);
      }
    }
  }

  private _fail(err: Error) {
    this._ready?.reject(err);
    for (const pending of this._pending.values()) { pending.reject(err); }
    this._pending.clear();
  }
}

async function createWorker(url: string): Promise<Worker> {
  if (new URL(url).origin === window.location.origin) {
    return new Worker(url);
  }
  // Static assets may be served from another origin (e.g. a CDN), which workers can't be
  // started from directly; go through a same-origin blob URL instead.
  const resp = await fetch(url);
  if (!resp.ok) { throw new Error(`Could not load the data engine: ${resp.status}`); }
  const blobUrl = URL.createObjectURL(new Blob([await resp.text()], { type: "text/javascript" }));
  try {
    return new Worker(blobUrl);
  } finally {
    // The worker has its script once started.
    setTimeout(() => URL.revokeObjectURL(blobUrl), 60000);
  }
}
