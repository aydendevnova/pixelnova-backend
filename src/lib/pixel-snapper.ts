// pixel-snapper.ts
// Native Node.js WASM loader for spritefusion_pixel_snapper
// Replicates the minimal glue code from the ESM wrapper for CJS compatibility

import { readFileSync } from "fs";
import { join } from "path";

let wasm: any = null;

function getUint8ArrayMemory(): Uint8Array {
  return new Uint8Array(wasm.memory.buffer);
}

function getStringFromWasm(ptr: number, len: number): string {
  ptr = ptr >>> 0;
  const bytes = getUint8ArrayMemory().subarray(ptr, ptr + len);
  return new TextDecoder("utf-8").decode(bytes);
}

function passArray8ToWasm(arg: Uint8Array): [number, number] {
  const ptr = (wasm.__wbindgen_malloc(arg.length, 1) as number) >>> 0;
  getUint8ArrayMemory().set(arg, ptr);
  return [ptr, arg.length];
}

function getArrayU8FromWasm(ptr: number, len: number): Uint8Array {
  ptr = ptr >>> 0;
  return getUint8ArrayMemory().subarray(ptr, ptr + len);
}

function takeFromExternrefTable(idx: number): any {
  const table = wasm.__wbindgen_externrefs as WebAssembly.Table;
  const value = table.get(idx);
  wasm.__externref_table_dealloc(idx);
  return value;
}

function initializeWasm(): void {
  if (wasm) return;

  const wasmPath = join(
    process.cwd(),
    "public",
    "spritefusion_pixel_snapper_bg.wasm"
  );
  const wasmBytes = readFileSync(wasmPath);

  const imports: WebAssembly.Imports = {
    wbg: {
      __wbg___wbindgen_throw_b855445ff6a94295: (
        arg0: number,
        arg1: number
      ) => {
        throw new Error(getStringFromWasm(arg0, arg1));
      },
      __wbindgen_cast_2241b6af4c4b2941: (arg0: number, arg1: number) => {
        return getStringFromWasm(arg0, arg1);
      },
      __wbindgen_init_externref_table: () => {
        const table = wasm.__wbindgen_externrefs as WebAssembly.Table;
        const offset = table.grow(4);
        table.set(0, undefined);
        table.set(offset + 0, undefined);
        table.set(offset + 1, null);
        table.set(offset + 2, true);
        table.set(offset + 3, false);
      },
    },
  };

  const wasmModule = new WebAssembly.Module(wasmBytes);
  const instance = new WebAssembly.Instance(wasmModule, imports);
  wasm = instance.exports;

  // Initialize the WASM module (sets up externref table, etc.)
  (wasm.__wbindgen_start as Function)();

  console.log("Pixel snapper WASM module initialized");
}

/**
 * Process an image through the spritefusion pixel snapper WASM module.
 * The module performs color quantization (k-means), edge profile detection,
 * grid estimation, and resampling to produce clean pixel art.
 *
 * @param imageBuffer - Raw image bytes (PNG format)
 * @param kColors - Number of colors for quantization (default: 16)
 * @returns Processed PNG image as Buffer
 */
/**
 * Process an image through the spritefusion pixel snapper WASM module.
 * The module performs color quantization (k-means), edge profile detection,
 * grid estimation, and resampling to produce clean pixel art.
 *
 * @param imageBuffer - Raw image bytes (PNG format)
 * @param kColors - Number of colors for quantization (default: 16)
 * @param targetSegments - Target grid segments per axis, controls output fidelity (default: 64)
 * @returns Processed PNG image as Buffer
 */
export function processWithPixelSnapper(
  imageBuffer: Buffer,
  kColors?: number,
  targetSegments?: number
): Buffer {
  initializeWasm();

  const inputBytes = new Uint8Array(imageBuffer);
  const [ptr, len] = passArray8ToWasm(inputBytes);

  // 0x100000001 signals "None" (use default) for Option<u32> in wasm-bindgen
  const kColorsArg =
    kColors != null ? kColors >>> 0 : 0x100000001;
  const targetSegmentsArg =
    targetSegments != null ? targetSegments >>> 0 : 0x100000001;
  const ret = wasm.process_image(ptr, len, kColorsArg, targetSegmentsArg);

  if (ret[3]) {
    throw new Error(
      String(takeFromExternrefTable(ret[2]) ?? "WASM processing failed")
    );
  }

  const outputBytes = getArrayU8FromWasm(ret[0], ret[1]).slice();
  wasm.__wbindgen_free(ret[0], ret[1], 1);

  return Buffer.from(outputBytes);
}
