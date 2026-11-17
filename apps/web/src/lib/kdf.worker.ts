/// <reference lib="webworker" />
// Runs Argon2id off the main thread. Receives the password, returns the 32-byte master key.
import { argon2Local, assertSafeKdf, type KdfParams } from '@keyvault/crypto';

self.onmessage = async (e: MessageEvent<{ id: number; password: string; salt: Uint8Array; params: KdfParams }>) => {
  const { id, password, salt, params } = e.data;
  try {
    assertSafeKdf(params);
    const key = await argon2Local(password, salt, params);
    (self as unknown as Worker).postMessage({ id, key }, [key.buffer]);
  } catch (err) {
    (self as unknown as Worker).postMessage({ id, error: (err as Error).message });
  }
};
