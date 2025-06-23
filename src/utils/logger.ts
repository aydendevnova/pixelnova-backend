import { SupabaseClient } from "@supabase/supabase-js";
import { Database } from "../lib/types_db";

export type LogLevel = "info" | "warn" | "error" | "debug";

// Define all possible log types
export enum LogType {
  // Account related
  ACCOUNT_UPDATE = "account_update",
  ACCOUNT_UPDATE_ERROR = "account_update_error",

  // Authentication
  LOGIN = "login",
  LOGOUT = "logout",
  AUTH_ERROR = "auth_error",

  // Subscription/Payment
  SUBSCRIPTION_RENEWED = "subscription_renewed",
  SUBSCRIPTION_CANCELLED = "subscription_cancelled",
  SUBSCRIPTION_ERROR = "subscription_error",
  CHECKOUT = "checkout",
  CHECKOUT_ERROR = "checkout_error",
  CHECKOUT_SESSION_CREATED = "checkout_session_created",

  BILLING_PORTAL_ERROR = "billing_portal_error",

  // Generation/Conversion
  PIXEL_ART_GENERATION = "pixel_art_generation",
  PIXEL_ART_GENERATION_SUCCESS = "pixel_art_generation_success",
  PIXEL_ART_GENERATION_ERROR = "pixel_art_generation_error",
  GENERATION_LIMIT_REACHED = "generation_limit_reached",

  // Avatar
  AVATAR_UPLOAD = "avatar_upload",
  AVATAR_UPLOAD_SUCCESS = "avatar_upload_success",
  AVATAR_UPLOAD_ERROR = "avatar_upload_error",

  // Tier
  TIER_UPDATED = "tier_updated",

  // Content Moderation
  BLACKLISTED_PROMPT = "blacklisted_prompt",
  BLACKLISTED_CONTENT = "blacklisted_content",

  // System
  SYSTEM_ERROR = "system_error",
  API_ERROR = "api_error",
}

interface LogMetadata {
  userId?: string;
  path?: string;
  method?: string;
  [key: string]: any;
}

interface LogEntry {
  type: LogType;
  level: LogLevel;
  message: string;
  metadata?: LogMetadata;
}

class Logger {
  private isDevelopment: boolean;

  constructor() {
    this.isDevelopment = process.env.NODE_ENV === "development";
  }

  private formatMessage(entry: LogEntry): string {
    const timestamp = new Date().toISOString();
    return JSON.stringify({
      timestamp,
      level: entry.level,
      type: entry.type,
      message: entry.message,
      ...entry.metadata,
      environment: this.isDevelopment ? "development" : "production",
    });
  }

  async log(entry: LogEntry, supabase?: SupabaseClient<Database>) {
    const formattedLog = this.formatMessage(entry);

    // Console output
    switch (entry.level) {
      case "error":
        console.error(formattedLog);
        break;
      case "warn":
        console.warn(formattedLog);
        break;
      case "info":
        console.log(formattedLog);
        break;
      case "debug":
        if (this.isDevelopment) {
          console.debug(formattedLog);
        }
        break;
    }

    // If Supabase client is provided, also log to database
    if (supabase) {
      try {
        await supabase.from("logs").insert({
          type: entry.type,
          level: entry.level,
          message: entry.message,
          metadata: entry.metadata ? JSON.stringify(entry.metadata) : null,
          user_id: entry.metadata?.userId,
        });
      } catch (err) {
        // If database logging fails, at least console log it
        console.error("Failed to write log to database:", err);
      }
    }
  }

  // Convenience methods for different log levels
  async info(
    type: LogType,
    message: string,
    metadata?: LogMetadata,
    supabase?: SupabaseClient<Database>
  ) {
    return this.log({ type, level: "info", message, metadata }, supabase);
  }

  async warn(
    type: LogType,
    message: string,
    metadata?: LogMetadata,
    supabase?: SupabaseClient<Database>
  ) {
    return this.log({ type, level: "warn", message, metadata }, supabase);
  }

  async error(
    type: LogType,
    message: string,
    metadata?: LogMetadata,
    supabase?: SupabaseClient<Database>
  ) {
    return this.log({ type, level: "error", message, metadata }, supabase);
  }

  async debug(
    type: LogType,
    message: string,
    metadata?: LogMetadata,
    supabase?: SupabaseClient<Database>
  ) {
    return this.log({ type, level: "debug", message, metadata }, supabase);
  }
}

// Create a singleton instance
export const logger = new Logger();

// Error classes for different types of errors
export class APIError extends Error {
  constructor(
    public statusCode: number,
    message: string,
    public metadata?: Record<string, any>
  ) {
    super(message);
    this.name = "APIError";
  }
}

export class ValidationError extends APIError {
  constructor(message: string, metadata?: Record<string, any>) {
    super(400, message, metadata);
    this.name = "ValidationError";
  }
}

export class AuthenticationError extends APIError {
  constructor(
    message: string = "Unauthorized",
    metadata?: Record<string, any>
  ) {
    super(401, message, metadata);
    this.name = "AuthenticationError";
  }
}

export class ForbiddenError extends APIError {
  constructor(message: string = "Forbidden", metadata?: Record<string, any>) {
    super(403, message, metadata);
    this.name = "ForbiddenError";
  }
}

// Error handler middleware
export const errorHandler = (err: Error, req: any, res: any, next: any) => {
  if (err instanceof APIError) {
    // Log API errors with their specific status codes
    logger.error(LogType.API_ERROR, err.message, {
      statusCode: err.statusCode,
      path: req.path,
      method: req.method,
      userId: req.user?.id,
      ...err.metadata,
    });

    // Send error response without internal details
    res.status(err.statusCode).json({
      error: err.message,
    });
  } else {
    // Log unexpected errors
    logger.error(LogType.SYSTEM_ERROR, "Internal server error", {
      error: err.message,
      stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
      path: req.path,
      method: req.method,
      userId: req.user?.id,
    });

    // Send generic error message to client
    res.status(500).json({
      error: "An unexpected error occurred",
    });
  }
};
