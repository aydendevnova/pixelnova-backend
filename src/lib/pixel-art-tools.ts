// pixel-art-tools.ts
import { InferenceClient } from "@huggingface/inference";

if (!process.env.HF_TOKEN) {
  throw new Error("HF_TOKEN is not set");
}

const hf = new InferenceClient(process.env.HF_TOKEN);

export async function generatePixelSprite(prompt: string) {
  const fullPrompt = prompt.includes("Retro Pixel")
    ? prompt
    : `Retro Pixel ${prompt}`;

  const response = (await hf.textToImage({
    model: "prithivMLmods/Retro-Pixel-Flux-LoRA",
    inputs: fullPrompt,
    parameters: {
      seed: new Date().getTime(),
      negative_prompt: "3d render, realistic, blurry, noisy, photographic",
    },
  })) as unknown as Blob;

  const arrayBuffer = await response.arrayBuffer();
  const buffer = Buffer.from(arrayBuffer);

  return buffer;
}
