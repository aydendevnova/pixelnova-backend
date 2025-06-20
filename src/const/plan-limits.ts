import { Database } from "../lib/types_db";

export type UserTier = Database["public"]["Enums"]["user_tier"];

export const PLAN_LIMITS = {
  NONE: {
    MAX_GENERATIONS: 4,
    MAX_CONVERSIONS: 10,
  },
  PRO: {
    MAX_GENERATIONS: 150,
    MAX_CONVERSIONS: Infinity, // Unlimited conversions for PRO
  },
} as const;

export function getMaxGenerations(tier: UserTier): number {
  return PLAN_LIMITS[tier].MAX_GENERATIONS;
}

export function getMaxConversions(tier: UserTier): number {
  return PLAN_LIMITS[tier].MAX_CONVERSIONS;
}
