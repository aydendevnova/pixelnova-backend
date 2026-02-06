// pixel-art-tools.ts
import { InferenceClient } from "@huggingface/inference";
import { writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import sharp from "sharp";

if (!process.env.HF_TOKEN) {
  throw new Error("HF_TOKEN is not set");
}

const hf = new InferenceClient(process.env.HF_TOKEN);

export async function generatePixelSprite(prompt: string) {
  const fullPrompt = prompt.includes("Retro Pixel")
    ? prompt
    : `Retro Pixel ${prompt}`;

  const response = (await hf.textToImage({
    model: "prithivMLmods/Retro-Pixel-Flux-LoRA", // LoRA + SDXL 1.0 are auto-fused
    inputs: fullPrompt,
    parameters: {
      // num_inference_steps: 8, // keep latency ≈ 1.8 s
      // guidance_scale: 1.5,
      seed: new Date().getTime(),
      negative_prompt: "3d render, realistic, blurry, noisy, photographic", // common clean-up
    },
  })) as unknown as Blob;

  // Convert response to Buffer
  const arrayBuffer = await response.arrayBuffer();
  const buffer = Buffer.from(arrayBuffer);

  return buffer;
}

interface Color {
  r: number;
  g: number;
  b: number;
  a: number;
}

// Quick select algorithm for finding median without full sort
function quickSelect(arr: number[], k: number): number {
  if (arr.length === 1) return arr[0];

  const pivot = arr[Math.floor(Math.random() * arr.length)];
  const left = arr.filter((x) => x < pivot);
  const equal = arr.filter((x) => x === pivot);
  const right = arr.filter((x) => x > pivot);

  if (k < left.length) {
    return quickSelect(left, k);
  } else if (k < left.length + equal.length) {
    return pivot;
  } else {
    return quickSelect(right, k - left.length - equal.length);
  }
}

function calculateMedianColor(
  pixels: Buffer,
  width: number,
  channels: number,
  startX: number,
  startY: number,
  cellWidth: number,
  cellHeight: number
): Color {
  // Ensure we stay within bounds
  const endY = Math.min(startY + cellHeight, width);
  const endX = Math.min(startX + cellWidth, width);

  // Pre-calculate array size
  const cellSize = (endX - startX) * (endY - startY);
  if (cellSize === 0) return { r: 0, g: 0, b: 0, a: 255 };

  // Pre-allocate arrays
  const rs = new Array(cellSize);
  const gs = new Array(cellSize);
  const bs = new Array(cellSize);
  const as = new Array(cellSize);

  // Collect colors using single loop and direct indexing
  let idx = 0;
  for (let y = startY; y < endY; y++) {
    const rowOffset = y * width * channels;
    for (let x = startX; x < endX; x++) {
      const i = rowOffset + x * channels;
      rs[idx] = pixels[i];
      gs[idx] = pixels[i + 1];
      bs[idx] = pixels[i + 2];
      as[idx] = channels === 4 ? pixels[i + 3] : 255;
      idx++;
    }
  }

  // Find median using quick select
  const medianIndex = Math.floor(cellSize / 2);
  return {
    r: quickSelect(rs, medianIndex),
    g: quickSelect(gs, medianIndex),
    b: quickSelect(bs, medianIndex),
    a: quickSelect(as, medianIndex),
  };
}

async function customDownscale(
  imageBuffer: Buffer,
  targetSize: number
): Promise<Buffer> {
  // Get original image dimensions
  const metadata = await sharp(imageBuffer).metadata();
  if (!metadata.width || !metadata.height) {
    throw new Error("Could not get image dimensions");
  }

  // Calculate target dimensions while maintaining aspect ratio
  const aspectRatio = metadata.width / metadata.height;
  let targetWidth = targetSize;
  let targetHeight = targetSize;

  if (aspectRatio > 1) {
    // Image is wider than tall
    targetHeight = Math.round(targetSize / aspectRatio);
  } else if (aspectRatio < 1) {
    // Image is taller than wide
    targetWidth = Math.round(targetSize * aspectRatio);
  }

  // Process image in a single Sharp pipeline for initial operations
  const { data, info } = await sharp(imageBuffer)
    .png({
      colors: 32,
      dither: 0,
      palette: true,
    })
    .resize(targetWidth * 2, targetHeight * 2, {
      fit: "fill", // Use fill to maintain aspect ratio without cropping
    })
    .raw()
    .toBuffer({ resolveWithObject: true });

  // Calculate cell dimensions
  const cellSize = 2; // Since we resized to 2x target size
  const width = targetWidth * 2;
  const height = targetHeight * 2;

  // Create output buffer
  const outputPixels = Buffer.alloc(targetWidth * targetHeight * 4);

  // Process each cell
  for (let y = 0; y < targetHeight; y++) {
    for (let x = 0; x < targetWidth; x++) {
      // Calculate median color for this cell
      const medianColor = calculateMedianColor(
        data,
        width,
        info.channels,
        x * cellSize,
        y * cellSize,
        cellSize,
        cellSize
      );

      // Set output pixel
      const i = (y * targetWidth + x) * 4;
      outputPixels[i] = medianColor.r;
      outputPixels[i + 1] = medianColor.g;
      outputPixels[i + 2] = medianColor.b;
      outputPixels[i + 3] = medianColor.a;
    }
  }

  // Final PNG conversion
  return sharp(outputPixels, {
    raw: {
      width: targetWidth,
      height: targetHeight,
      channels: 4,
    },
  })
    .png({
      colors: 32,
      dither: 0,
      palette: true,
    })
    .toBuffer();
}

// Function to downscale image
export async function downscaleImage(
  imageBuffer: Buffer,
  resolution: number
): Promise<Buffer> {
  try {
    return customDownscale(imageBuffer, resolution);
  } catch (error) {
    console.error("Error processing image:", error);
    throw error;
  }
}
