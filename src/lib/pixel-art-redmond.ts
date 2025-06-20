// pixelArtRedmond.ts
import { InferenceClient } from "@huggingface/inference";
import { writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import sharp from "sharp";

if (!process.env.HF_TOKEN) {
  throw new Error("HF_TOKEN is not set");
}

const hf = new InferenceClient(process.env.HF_TOKEN);

export async function generatePixelSprite(
  prompt: string,
  size = 128 // final sprite edge in px
) {
  // PixelArt.Redmond was trained with the trigger `PixArFK`
  const fullPrompt = prompt.includes("Retro Pixel")
    ? prompt
    : `Retro Pixel ${prompt}`;

  const response = (await hf.textToImage({
    model: "prithivMLmods/Retro-Pixel-Flux-LoRA", // LoRA + SDXL 1.0 are auto-fused
    inputs: fullPrompt,
    parameters: {
      // num_inference_steps: 8, // keep latency ≈ 1.8 s
      // guidance_scale: 1.5,
      negative_prompt: "3d render, realistic, blurry, noisy, photographic", // common clean-up
    },
  })) as unknown as Blob;

  // Convert response to Buffer
  const arrayBuffer = await response.arrayBuffer();
  const buffer = Buffer.from(arrayBuffer);

  return buffer;
}

// Function to downscale image
export async function downscaleImage8x(imageBuffer: Buffer): Promise<Buffer> {
  try {
    const metadata = await sharp(imageBuffer).metadata();

    if (!metadata.width || !metadata.height) {
      throw new Error("Could not determine image dimensions");
    }

    // Resize to 64x64 regardless of input size
    const processedBuffer = await sharp(imageBuffer)
      .resize(64, 64, {
        kernel: "nearest",
        fit: "cover",
        position: "center",
      })
      // Quantize colors - reduce to a smaller palette without dithering
      .png({
        colors: 40, // Reduce to X colors - good balance for pixel art
        dither: 0, // No dithering to maintain crisp edges
        palette: true, // Use palette-based quantization
      })
      .toBuffer();

    return processedBuffer;
  } catch (error) {
    console.error("Error processing image:", error);
    throw error;
  }
}
