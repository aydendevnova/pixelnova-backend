// pixel-art-tools.ts
import { InferenceClient } from "@huggingface/inference";

if (!process.env.HF_TOKEN) {
  throw new Error("HF_TOKEN is not set");
}

const hf = new InferenceClient(process.env.HF_TOKEN);

const MODELS = [{
  name: "Retro Pixel Flux LoRA",
  model: "prithivMLmods/Retro-Pixel-Flux-LoRA",
  triggerWords: "Retro Pixel",
  needsDownscale: true,
}, 
{
  name: "Flux 1 LoRA Modern Pixel Art",
  model: "UmeAiRT/FLUX.1-dev-LoRA-Modern_Pixel_art",
  triggerWords: "Flux 1 LoRA Modern Pixel Art",
  needsDownscale: true,
}]

export async function generatePixelSprite(prompt: string, model = 0) {
  const fullPrompt = prompt.includes(MODELS[model].triggerWords)
    ? prompt
    : `${MODELS[model].triggerWords} ${prompt}`;

  const modelData = MODELS[model];

  const response = (await hf.textToImage({
    model: modelData.model,
    inputs: fullPrompt,
    parameters: {
      seed: new Date().getTime(),
      negative_prompt: "3d render, realistic, blurry, noisy, photographic",
    },
  })) as unknown as Blob;

  const arrayBuffer = await response.arrayBuffer();
  const buffer = Buffer.from(arrayBuffer);

  return { buffer, needsDownscale: modelData.needsDownscale };
}
