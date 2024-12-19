import fs from "fs";
import path from "path";

let wasmInstance: any = null;

export async function initWasm() {
  if (wasmInstance) return wasmInstance;

  // Read the wasm_exec.js file
  const wasmExecPath = path.join(__dirname, "../../wasm/public/wasm_exec.js");
  const wasmPath = path.join(__dirname, "../../wasm/public/main.wasm");

  // Execute wasm_exec.js to define Go globally
  eval(fs.readFileSync(wasmExecPath, "utf8"));

  // Load the wasm module
  const wasmCode = fs.readFileSync(wasmPath);

  // Create a new instance
  const go = new (global as any).Go();
  const result = await WebAssembly.instantiate(wasmCode, go.importObject);

  wasmInstance = result.instance;
  go.run(wasmInstance);

  return wasmInstance;
}
