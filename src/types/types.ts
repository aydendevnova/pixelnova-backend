import { z } from "zod";

export const usernameRegex = /^[a-zA-Z0-9_]+$/;

export const fullNameRegex = /^[a-zA-Z0-9 ]+$/;

export const checkUsernameSchema = z.object({
  username: z
    .string()
    .regex(
      usernameRegex,
      "Username can only contain letters, numbers and underscores"
    )
    .min(3)
    .max(20),
});

export const updateAccountSchema = z.object({
  fullName: z
    .string()
    .regex(
      fullNameRegex,
      "Full name can only contain letters, numbers and spaces"
    )
    .min(2)
    .max(50)
    .optional(),
  username: z
    .string()
    .regex(
      usernameRegex,
      "Username can only contain letters, numbers and underscores"
    )
    .min(3)
    .max(20)
    .optional(),
  website: z.string().url().optional(),
});

export type UpdateAccountBody = z.infer<typeof updateAccountSchema> & {
  image?: File;
};

export type CheckUsernameBody = z.infer<typeof checkUsernameSchema>;

export type EstimateGridSizeBody = {
  image: File;
};

export type EstimateGridSizeResponse = {
  gridSize: number;
};

export type DownscaleResponse = {
  results: {
    grid: number;
    image: string;
  }[];
};

export type DownscaleImageBody = {
  image: File;
};
