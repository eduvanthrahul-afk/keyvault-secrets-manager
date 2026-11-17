import { setArgon2Implementation, type KdfParams } from '@keyvault/crypto';

let worker: Worker | null = null;
let seq = 0;
const pending = new Map<number, { resolve: (k: Uint8Array) => void; reject: (e: Error) => void }>();

function getWorker(): Worker {
  if (!worker) {
    worker = new Worker(new URL('./kdf.worker.ts', import.meta.url), { type: 'module' });
    worker.onmessage = (e: MessageEvent<{ id: number; key?: Uint8Array; error?: string }>) => {
      const p = pending.get(e.data.id);
      if (!p) return;
      pending.delete(e.data.id);
      if (e.data.key) p.resolve(new Uint8Array(e.data.key));
      else p.reject(new Error(e.data.error ?? 'Key derivation failed'));
    };
  }
  return worker;
}

/** Route every Argon2id call made by @keyvault/crypto through the worker. */
export function installWorkerKdf(): void {
  if (typeof Worker === 'undefined') return;
  setArgon2Implementation(
    (password: string, salt: Uint8Array, params: KdfParams) =>
      new Promise<Uint8Array>((resolve, reject) => {
        const id = ++seq;
        pending.set(id, { resolve, reject });
        getWorker().postMessage({ id, password, salt, params });
      }),
  );
}
