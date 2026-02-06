declare global {
  interface Window {
    downscaleImage: (imageData: string, grid: number) => any;
    estimateGridSize: (imageData: string) => any;
  }
}

declare class Go {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}
