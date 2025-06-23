import helmet from "helmet";
import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import multer from "multer";
import { createClient, SupabaseClient } from "@supabase/supabase-js";
import {
  logger as loggerInstanceUseFunctionNotThis,
  errorHandler,
  APIError,
  ValidationError,
  AuthenticationError,
  ForbiddenError,
  LogLevel,
  LogType,
} from "./utils/logger";
dotenv.config();

// Environment variables validation
const requiredEnvVars = [
  "HF_TOKEN",
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY",
  "STRIPE_WEBHOOK_SECRET",
  "STRIPE_SECRET_KEY",
  "STRIPE_PRICE_ID_PRO",
];

requiredEnvVars.forEach((varName) => {
  if (!process.env[varName]) {
    throw new Error(`${varName} is not set`);
  }
});

// if (!process.env.OPEN_API_KEY) {
//   throw new Error("OPEN_API_KEY is not set");
// }

import { BLACKLISTED_WORDS } from "./const/blacklisted-words";
import { BLACKLISTED_SITES } from "./const/blacklisted-sites";
import { checkUsernameSchema, updateAccountSchema } from "./types/types";

import rateLimit from "express-rate-limit";
import { type Database } from "./lib/types_db";

import { stripe } from "./utils/stripe";
import { downscaleImage, generatePixelSprite } from "./lib/pixel-art-tools";
import sharp from "sharp";
import { getMaxConversions, getMaxGenerations } from "./const/plan-limits";

const supabaseAdmin = createClient<Database>(
  process.env.SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

// Reusable logging function
async function log(
  level: LogLevel,
  type: LogType,
  message: string,
  metadata?: Record<string, any>,
  user_id?: string
) {
  try {
    await loggerInstanceUseFunctionNotThis[level](
      type,
      message,
      { ...metadata, userId: user_id },
      supabaseAdmin
    );
  } catch (err) {
    console.error("Failed to insert log", {
      error: err instanceof Error ? err.message : "Unknown error",
      type,
      userId: user_id,
    });
  }
}

const app = express();
app.set("trust proxy", 1);

app.use(helmet());

const upload = multer({
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    const validMimeTypes = ["image/jpeg", "image/png", "image/webp"];
    if (!validMimeTypes.includes(file.mimetype)) {
      cb(new Error("Invalid file type"));
      return;
    }
    cb(null, true);
  },
});

// Environment variables
const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  // OPEN_API_KEY,
  PORT = 8787,
} = process.env;

if (process.env.NODE_ENV === "production") {
  // CORS configuration
  app.use(
    cors({
      origin: [
        "https://editor.pixelnova.app", // Cloudflare Pages domain
        "https://pixelnova.app",
      ],
      methods: ["GET", "POST", "PUT", "OPTIONS", "PATCH", "DELETE"],
      allowedHeaders: [
        "Content-Type",
        "Authorization",
        "stripe-signature",
        "X-Forwarded-For",
      ],
    })
  );
} else {
  // CORS configuration
  app.use(
    cors({
      origin: ["http://localhost:3000", "http://192.168.12.102:3000"],
      methods: ["GET", "POST", "PUT", "OPTIONS", "PATCH", "DELETE"],
      allowedHeaders: [
        "Content-Type",
        "Authorization",
        "stripe-signature",
        "X-Forwarded-For",
      ],
    })
  );
}

// Always allow webhook requests to bypass rate limiting
app.use((req, res, next) => {
  if (
    req.path === "/api/webhook" ||
    req.path === "/api/update-conversion-count"
  ) {
    return next();
  }
  return apiLimiter(req, res, next);
});

app.post(
  "/api/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
        log(
          "error",
          LogType.SYSTEM_ERROR,
          "Missing Supabase configuration in webhook"
        );
        throw new APIError(500, "Server configuration error");
      }
      if (!process.env.STRIPE_WEBHOOK_SECRET) {
        log(
          "error",
          LogType.SYSTEM_ERROR,
          "Missing Stripe webhook secret in webhook"
        );
        throw new APIError(500, "Missing Stripe webhook secret");
      }

      const signature = req.headers["stripe-signature"];
      if (!signature) {
        throw new ValidationError("Missing Stripe signature");
      }

      const event = stripe.webhooks.constructEvent(
        req.body,
        signature,
        process.env.STRIPE_WEBHOOK_SECRET
      );

      const supabase = createClient<Database>(
        process.env.SUPABASE_URL,
        process.env.SUPABASE_SERVICE_ROLE_KEY,
        {
          auth: {
            autoRefreshToken: false,
            persistSession: false,
          },
        }
      );

      // Add idempotency check
      const eventId = event.id;
      const { data: existingEvent } = await supabase
        .from("stripe_events")
        .select("id")
        .eq("stripe_event_id", eventId)
        .single();

      if (existingEvent) {
        log(
          "info",
          LogType.SUBSCRIPTION_RENEWED,
          `Stripe event already processed: event id: ${eventId} for user ${event.account}`,
          { eventId, account: event.account }
        );
        return res.status(200).json({ received: true });
      }

      // Process the event
      try {
        await processStripeEvent(event, supabase);
        // Record successful processing
        await supabase.from("stripe_events").insert({
          stripe_event_id: eventId,
          type: event.type,
          processed_at: new Date().toISOString(),
          error_message: null,
        });
      } catch (e) {
        await log(
          "error",
          LogType.SUBSCRIPTION_ERROR,
          `Stripe event processing error: event id: ${eventId} for user ${
            event.account
          }. Error: ${e instanceof Error ? e.message : "Unknown error"}`,
          { userId: event.account }
        );
        throw new APIError(500, "Failed to process Stripe event");
      }

      res.status(200).json({ received: true });
    } catch (err) {
      if (err instanceof APIError) {
        throw err;
      }
      log(
        "error",
        LogType.SYSTEM_ERROR,
        `Webhook processing error: ${
          err instanceof Error ? err.message : "Unknown error"
        }`
      );
      throw new APIError(500, "Webhook processing failed");
    }
  }
);

// Helper function to handle protected routes
const withAuth = async (req: express.Request) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    throw new AuthenticationError("Missing or invalid authorization header");
  }

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    log("error", LogType.SYSTEM_ERROR, "Missing Supabase configuration");
    throw new APIError(500, "Server configuration error");
  }

  const supabase = createClient<Database>(
    SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false,
      },
    }
  );

  const token = authHeader.split(" ")[1];
  const {
    data: { user },
    error: userError,
  } = await supabase.auth.getUser(token);

  if (userError || !user) {
    throw new AuthenticationError(userError?.message || "User not found");
  }

  return { user, supabase };
};

app.get("/", (_, res) => {
  res.json({ status: "ok" });
});

// Routes
app.get("/api/health", (_, res) => {
  res.json({ status: "ok" });
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Limit each IP to 200 requests per windowMs
  message: { error: "Too many requests, please try again later." },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// Apply to all routes
app.use(apiLimiter);

// Stricter limit for image generation
const aiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 250, // Limit each IP to certain requests per hour
  standardHeaders: true,
  legacyHeaders: false,
});

app.patch(
  "/api/update-account",
  express.json({ type: "application/json" }),
  upload.single("image"),
  (req, res) => {
    (async () => {
      const { user, supabase } = await withAuth(req);
      try {
        const { fullName, username, website } = req.body;

        // Log attempt
        log(
          "info",
          LogType.ACCOUNT_UPDATE,
          `Update account request. Changes: ${JSON.stringify({
            fullName: fullName || undefined,
            username: username || undefined,
            website: website || undefined,
            hasNewAvatar: !!req.file,
          })}`,
          { userId: user.id }
        );

        const result = updateAccountSchema.safeParse({
          fullName,
          username,
          website,
        });

        if (!result.success) {
          return res.status(400).json({
            error: "Invalid input format",
            details: result.error.format(),
          });
        }

        const { data: profile, error: profileError } = await supabase
          .from("profiles")
          .select("*")
          .eq("id", user.id)
          .single();

        if (profileError || !profile) {
          throw profileError || new Error("Profile not found");
        }

        const usernameSanitized = username?.toLowerCase().trim();
        const websiteSanitized = website?.toLowerCase().trim();

        // Check blacklisted usernames and sites
        if (
          usernameSanitized &&
          (BLACKLISTED_WORDS.includes(usernameSanitized) ||
            BLACKLISTED_SITES.some((site) => usernameSanitized.includes(site)))
        ) {
          log(
            "warn",
            LogType.ACCOUNT_UPDATE_ERROR,
            `Attempted to update to blacklisted username: ${usernameSanitized}`,
            { userId: user.id }
          );
          return res.status(400).json({ error: "Username is blacklisted" });
        }

        // Check username availability
        if (usernameSanitized && usernameSanitized !== profile.username) {
          const { data: existingUser } = await supabase
            .from("profiles")
            .select("username")
            .eq("username", usernameSanitized)
            .single();

          if (existingUser) {
            return res.status(400).json({ error: "Username is already taken" });
          }
        }

        if (
          websiteSanitized &&
          BLACKLISTED_SITES.some((site) => websiteSanitized.includes(site))
        ) {
          log(
            "warn",
            LogType.ACCOUNT_UPDATE_ERROR,
            `Attempted to update to blacklisted site: ${websiteSanitized}`,
            { userId: user.id }
          );
          return res.status(400).json({ error: "Website is blacklisted" });
        }

        let avatar_url = profile.avatar_url;

        // Handle image upload if present
        if (req.file) {
          try {
            // Process the image - resize and optimize
            const processedImage = await sharp(req.file.buffer)
              .resize(256, 256, {
                fit: "cover",
                position: "center",
              })
              .webp({ quality: 80 })
              .toBuffer();

            // Upload to Supabase storage
            const fileName = `${user.id}/${Date.now()}.webp`;
            const { data: uploadData, error: uploadError } =
              await supabase.storage
                .from("avatars")
                .upload(fileName, processedImage, {
                  contentType: "image/webp",
                  upsert: true,
                });

            if (uploadError) {
              throw uploadError;
            }

            // Get the public URL
            const {
              data: { publicUrl },
            } = supabase.storage.from("avatars").getPublicUrl(fileName);

            avatar_url = publicUrl;
          } catch (error) {
            console.error("Image processing error:", error);
            return res.status(500).json({
              error: "Failed to process image",
              message: error instanceof Error ? error.message : "Unknown error",
            });
          }
        }

        // Update profile
        const { error: updateError } = await supabase
          .from("profiles")
          .update({
            full_name: fullName?.trim() ?? profile.full_name,
            username: usernameSanitized ?? profile.username,
            website: websiteSanitized ?? profile.website,
            avatar_url,
            updated_at: new Date().toISOString(),
          })
          .eq("id", user.id);

        if (updateError) {
          throw updateError;
        }

        // Log successful avatar upload
        if (req.file) {
          log(
            "info",
            LogType.AVATAR_UPLOAD_SUCCESS,
            `Successfully uploaded new avatar: ${avatar_url}`,
            { userId: user.id, avatarUrl: avatar_url }
          );
        }

        return res.status(200).json({ success: true, avatar_url });
      } catch (err) {
        const supabase = createClient<Database>(
          process.env.SUPABASE_URL!,
          process.env.SUPABASE_SERVICE_ROLE_KEY!
        );

        // Log error
        log(
          "error",
          LogType.ACCOUNT_UPDATE_ERROR,
          `Error updating account: ${JSON.stringify(err)}`,
          { userId: user.id }
        );

        console.error("Update account error:", err);
        res.status(500).json({
          error: "Failed to update account",
          message: err instanceof Error ? err.message : "Unknown error",
        });
      }
    })();
  }
);

app.post(
  "/api/check-username",
  express.json({ type: "application/json" }),
  (req: express.Request, res: express.Response) => {
    (async () => {
      try {
        const body = req.body;
        const result = checkUsernameSchema.safeParse(body);

        if (!result.success) {
          return res.status(400).json({
            error: "Invalid username format",
            details: result.error.format(),
          });
        }

        const sanitizedUsername = result.data.username.toLowerCase().trim();

        // Check if username is blacklisted
        if (
          BLACKLISTED_WORDS.includes(sanitizedUsername) ||
          BLACKLISTED_SITES.some((site) => sanitizedUsername.includes(site))
        ) {
          return res.status(400).json({ available: false, blacklisted: true });
        }

        if (
          !process.env.SUPABASE_URL ||
          !process.env.SUPABASE_SERVICE_ROLE_KEY
        ) {
          log("error", LogType.SYSTEM_ERROR, "Missing Supabase configuration");
          throw new Error("Missing Supabase configuration");
        }

        const supabase = createClient<Database>(
          process.env.SUPABASE_URL,
          process.env.SUPABASE_SERVICE_ROLE_KEY,
          {
            auth: {
              autoRefreshToken: false,
              persistSession: false,
            },
          }
        );

        const { data, error } = await supabase
          .from("profiles")
          .select("username")
          .eq("username", sanitizedUsername);

        if (error) {
          throw error;
        }

        const usernameExists = data && data.length > 0;

        return res.status(200).json({
          available: !usernameExists,
          blacklisted: false,
        });
      } catch (err) {
        console.error("Check username error:", err);
        res.status(500).json({
          error: "Failed to check username",
          message: err instanceof Error ? err.message : "Unknown error",
        });
      }
    })();
  }
);

app.post("/api/reduce-colors", upload.single("image"), async (req, res) => {
  let user;
  let supabase;
  try {
    if (!req.file) {
      throw new ValidationError("No image file provided");
    }

    const auth = await withAuth(req);
    user = auth.user;
    supabase = auth.supabase;

    await log("info", LogType.PIXEL_ART_GENERATION, "Color reduction request", {
      userId: user.id,
      fileSize: req.file.size,
    });

    // Get factor from request body
    let factor = 96; // default value
    try {
      if (req.body.factor) {
        const parsed = parseInt(req.body.factor);
        if (!isNaN(parsed) && parsed > 0 && parsed <= 256) {
          factor = parsed;
        }
      }
    } catch (err) {
      log(
        "warn",
        LogType.SYSTEM_ERROR,
        `Invalid factor provided: ${req.body.factor} for user ${user.id}`,
        { userId: user.id }
      );
      // Continue with default value
    }

    // Get user profile to check limits
    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", user.id)
      .single();

    if (profileError || !profile) {
      throw new APIError(404, "Profile not found");
    }

    // Check if user has reached their conversion limit
    const maxConversions = getMaxConversions(profile.tier);
    if (profile.conversion_count >= maxConversions) {
      await log(
        "warn",
        LogType.GENERATION_LIMIT_REACHED,
        `Conversion limit reached for user ${user.id}. Current count: ${profile.conversion_count}. Max count: ${maxConversions}`,
        {
          userId: user.id,
          limit: maxConversions,
          current: profile.conversion_count,
        }
      );

      throw new ForbiddenError("Conversion limit reached", {
        limit: maxConversions,
        current: profile.conversion_count,
      });
    }

    // Process the image
    const processedBuffer = await sharp(req.file.buffer)
      .png({
        colors: factor,
        dither: 0,
        compressionLevel: 0,
        palette: true,
        effort: 2,
      })
      .toBuffer();

    const base64Image = processedBuffer.toString("base64");

    res.json({
      image: `data:image/png;base64,${base64Image}`,
      maxConversions,
      currentCount: profile.conversion_count,
    });
  } catch (err) {
    if (err instanceof APIError) {
      throw err;
    }

    await log(
      "error",
      LogType.SYSTEM_ERROR,
      `Color reduction error: ${
        err instanceof Error ? err.message : "Unknown error"
      } for user ${user?.id}`,
      { userId: user?.id }
    );

    throw new APIError(500, "Failed to process image");
  }
});

// New endpoint to update conversion count
app.post("/api/update-conversion-count", async (req, res) => {
  try {
    const { user, supabase } = await withAuth(req);

    // Get user profile
    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", user.id)
      .single();

    if (profileError || !profile) {
      throw profileError || new Error("Profile not found");
    }

    // Check if user has reached their conversion limit
    const maxConversions = getMaxConversions(profile.tier);
    if (profile.conversion_count >= maxConversions) {
      return res.status(403).json({
        error: "Conversion limit reached",
        limit: maxConversions,
        current: profile.conversion_count,
      });
    }

    // Increment both conversion counters
    const { error: updateError } = await supabase
      .from("profiles")
      .update({
        conversion_count: (profile.conversion_count ?? 0) + 1,
        conversion_count_lifetime: (profile.conversion_count_lifetime ?? 0) + 1,
        updated_at: new Date().toISOString(),
      })
      .eq("id", user.id);

    if (updateError) {
      throw updateError;
    }

    res.json({
      success: true,
      newCount: (profile.conversion_count ?? 0) + 1,
      maxConversions,
    });
  } catch (err) {
    console.error("Update conversion count error:", err);
    res.status(500).json({
      error: "Failed to update conversion count",
      message: err instanceof Error ? err.message : "Unknown error",
    });
  }
});

// // Add credits check middleware for protected operations
// const withCredits = async (req: express.Request, cost: number) => {
//   const { user, supabase } = await withAuth(req);

//   const { data: profile, error } = await supabase
//     .from("profiles")
//     .select("credits")
//     .eq("id", user.id)
//     .single();

//   if (error) throw error;
//   if (!profile) {
//     throw new Error("Profile not found");
//   }

//   return { user, supabase, credits: profile.generation_count };
// };

app.get("/api/protected", async (req, res) => {
  try {
    const { user } = await withAuth(req);
    res.status(200).json(user);
  } catch (err) {
    console.error("Protected route error:", err);
    res.status(401).json({
      error: "Unauthorized",
      message: err instanceof Error ? err.message : "Unknown error",
    });
  }
});

async function processStripeEvent(
  event: any,
  supabase: SupabaseClient<Database>
) {
  switch (event.type) {
    case "invoice.paid": {
      const invoice = event.data.object;

      log(
        "info",
        LogType.SUBSCRIPTION_RENEWED,
        `An invoice was paid: ${JSON.stringify(invoice, null, 2)}`
      );

      // Only process if this is a subscription invoice
      if (invoice.subscription) {
        // Get the customer ID
        const { data: customer, error: customerError } = await supabase
          .from("stripe_customers")
          .select("user_id")
          .eq("subscription_id", invoice.subscription)
          .single();

        if (customerError || !customer) {
          log("error", LogType.SUBSCRIPTION_ERROR, "Error finding customer:", {
            error: customerError,
            subscriptionId: invoice.subscription,
          });
          log(
            "error",
            LogType.SUBSCRIPTION_ERROR,
            `Error finding customer: ${customerError} for subscription ${
              invoice.subscription
            } for user ${JSON.stringify(customer)}`
          );
          throw new Error("Customer not found");
        }

        // Reset generation and conversion counts, but keep lifetime counts
        const { error: updateError } = await supabase
          .from("profiles")
          .update({
            generation_count: 0,
            conversion_count: 0,
            updated_at: new Date().toISOString(),
          })
          .eq("id", customer.user_id);

        if (updateError) {
          log("error", LogType.SUBSCRIPTION_ERROR, "Error resetting counts:", {
            error: updateError,
            userId: customer.user_id,
          });
          log(
            "error",
            LogType.SUBSCRIPTION_ERROR,
            `Error resetting counts: ${updateError} for user ${customer.user_id}`
          );
          throw updateError;
        }

        try {
          log(
            "info",
            LogType.SUBSCRIPTION_RENEWED,
            `User ${customer.user_id} subscription renewed, reset generation and conversion counts.`
          );
        } catch (error) {
          log(
            "error",
            LogType.SUBSCRIPTION_ERROR,
            "Error logging subscription renewal:",
            {
              error: error instanceof Error ? error.message : "Unknown error",
              userId: customer.user_id,
            }
          );
        }
      }
      break;
    }
    case "checkout.session.completed": {
      const session = event.data.object;

      log("info", LogType.SUBSCRIPTION_RENEWED, "Checkout session completed:", {
        session: JSON.stringify(session, null, 2),
      });

      const userId = session.metadata?.user_id;

      if (!userId) {
        log("error", LogType.SUBSCRIPTION_ERROR, "Missing user_id");
        throw new Error("Missing user_id");
      }

      const priceId = session.metadata?.price_id;
      if (!priceId) {
        log(
          "error",
          LogType.CHECKOUT_ERROR,
          "Checkout completed: Missing price id",
          { userId }
        );
        log(
          "error",
          LogType.CHECKOUT_ERROR,
          `Checkout completed: Missing price id: ${JSON.stringify(
            session.metadata
          )} for user ${userId}`
        );
        throw new Error("Missing price id");
      }

      let tier: Database["public"]["Enums"]["user_tier"] = "NONE";

      if (priceId === process.env.STRIPE_PRICE_ID_PRO) {
        tier = "PRO";
      } else {
        log(
          "error",
          LogType.CHECKOUT_ERROR,
          "Checkout completed: Invalid price id",
          { userId }
        );
        log(
          "error",
          LogType.CHECKOUT_ERROR,
          `Invalid price id: ${JSON.stringify(session.metadata)}`
        );
        throw new Error("Invalid price id");
      }

      // Update their tier
      const { error: updateError } = await supabase
        .from("profiles")
        .update({
          tier: tier,
          updated_at: new Date().toISOString(),
        })
        .eq("id", userId);

      if (updateError) {
        log(
          "error",
          LogType.SUBSCRIPTION_ERROR,
          "Checkout completed: Error updating tier:",
          {
            error:
              updateError instanceof Error
                ? updateError.message
                : "Unknown error",
            userId,
          }
        );
        log(
          "info",
          LogType.TIER_UPDATED,
          `User ${userId} updated tier to ${tier}.`
        );
        throw updateError;
      } else {
        try {
          log(
            "info",
            LogType.TIER_UPDATED,
            `User ${userId} updated tier to ${tier}.`
          );
        } catch (error) {
          log(
            "error",
            LogType.SUBSCRIPTION_ERROR,
            "Error logging tier update:",
            {
              error: error instanceof Error ? error.message : "Unknown error",
              userId,
            }
          );
        }
      }

      // Use a transaction to ensure data consistency
      const { error } = await supabase.from("stripe_customers").upsert({
        stripe_customer_id: session.customer as string | null,
        user_id: userId,
        plan_active: true,
        subscription_id: session.subscription as string | null,
        latest_address: session.customer_details?.address,
        latest_currency: session.customer_details?.address?.country,
      });

      if (error) {
        log(
          "error",
          LogType.SUBSCRIPTION_ERROR,
          "Error updating stripe_customers:",
          {
            error: error instanceof Error ? error.message : "Unknown error",
            userId,
          }
        );
        log(
          "error",
          LogType.SUBSCRIPTION_ERROR,
          `Error updating stripe_customers: ${JSON.stringify(
            error
          )} for user ${userId}`
        );
        throw error;
      }
      break;
    }
    case "customer.subscription.deleted": {
      const subscription = event.data.object;

      // Find the user associated with this subscription
      const { data: customer, error: customerError } = await supabase
        .from("stripe_customers")
        .select("user_id")
        .eq("subscription_id", subscription.id)
        .single();

      if (customerError || !customer) {
        log("error", LogType.SUBSCRIPTION_ERROR, "Error finding customer:", {
          error:
            customerError instanceof Error
              ? customerError.message
              : "Unknown error",
          subscriptionId: subscription.id,
        });
        log(
          "error",
          LogType.SUBSCRIPTION_ERROR,
          `Error finding customer: ${customerError} for subscription ${subscription.id}`
        );
        throw new Error("Customer not found");
      }

      // Update user's tier to NONE
      const { error: updateError } = await supabase
        .from("profiles")
        .update({
          tier: "NONE",
          updated_at: new Date().toISOString(),
        })
        .eq("id", customer.user_id);

      if (updateError) {
        log("error", LogType.SUBSCRIPTION_ERROR, "Error updating tier:", {
          error:
            updateError instanceof Error
              ? updateError.message
              : "Unknown error",
          userId: customer.user_id,
        });
        log(
          "error",
          LogType.SUBSCRIPTION_ERROR,
          `Error updating tier: ${updateError} for user ${customer.user_id}`
        );
        throw updateError;
      }

      // Update stripe_customers table
      const { error: customerUpdateError } = await supabase
        .from("stripe_customers")
        .update({
          plan_active: false,
          subscription_id: null,
        })
        .eq("user_id", customer.user_id);

      if (customerUpdateError) {
        log(
          "error",
          LogType.SUBSCRIPTION_ERROR,
          "Error updating stripe_customers:",
          {
            error:
              customerUpdateError instanceof Error
                ? customerUpdateError.message
                : "Unknown error",
            userId: customer.user_id,
          }
        );
        log(
          "error",
          LogType.SUBSCRIPTION_ERROR,
          `Error updating stripe_customers: ${customerUpdateError} for user ${customer.user_id}`
        );
        throw customerUpdateError;
      }

      try {
        log(
          "info",
          LogType.TIER_UPDATED,
          `User ${customer.user_id} subscription cancelled, tier set to NONE.`
        );
      } catch (error) {
        log("error", LogType.SUBSCRIPTION_ERROR, "Error logging tier update:", {
          error: error instanceof Error ? error.message : "Unknown error",
          userId: customer.user_id,
        });
      }
      break;
    }
  }
}

app.post(
  "/api/checkout",
  express.json({ type: "application/json" }),
  async (req, res) => {
    let user;
    let supabase;
    try {
      const { priceId } = req.body;
      const auth = await withAuth(req);
      user = auth.user;
      supabase = auth.supabase;

      // Log checkout attempt
      log(
        "info",
        LogType.CHECKOUT,
        `Checkout request with priceId: ${priceId}`,
        { userId: user.id, priceId }
      );

      if (!priceId) {
        log("error", LogType.CHECKOUT_ERROR, "Missing price ID", {
          userId: user.id,
        });
        return res.status(400).json({ error: "Invalid request" });
      }

      if (!user) {
        log("error", LogType.AUTH_ERROR, "User not found", { priceId });
        return res.status(401).json({ error: "User not found" });
      }

      // verify price ID is valid
      const price = await stripe.prices.retrieve(priceId);
      if (!price) {
        log("error", LogType.CHECKOUT_ERROR, `Invalid price ID: ${priceId}`, {
          userId: user.id,
          priceId,
        });
        return res.status(400).json({ error: "Invalid price ID" });
      }

      const session = await stripe.checkout.sessions.create({
        metadata: {
          user_id: user.id,
          price_id: priceId,
        },
        customer_email: user.email,
        payment_method_types: ["card"],
        line_items: [
          {
            price: priceId,
            quantity: 1,
          },
        ],
        mode: "subscription",
        success_url: `${req.headers.origin}/success`,
        cancel_url: `${req.headers.origin}/cancel`,
      });

      // Log successful checkout session creation
      log(
        "info",
        LogType.CHECKOUT_SESSION_CREATED,
        `Successfully created checkout session. Session ID: ${session.id}`,
        { userId: user.id, sessionId: session.id }
      );

      return res.json({ id: session.id });
    } catch (e) {
      // Log error
      if (supabase) {
        log(
          "error",
          LogType.CHECKOUT_ERROR,
          `Error creating checkout session: ${
            e instanceof Error ? e.message : "Unknown error"
          }`,
          { userId: user?.id }
        );
      }
      log("error", LogType.SYSTEM_ERROR, "Error creating checkout session:", {
        error: e instanceof Error ? e.message : "Unknown error",
        userId: user?.id,
      });
      return res.status(500).json({ error: e });
    }
  }
);

// API endpoint to generate and process image
app.post(
  "/api/generate-pixel-art",
  express.json({ type: "application/json" }),
  aiLimiter,
  async (req, res) => {
    let user;
    let supabase;
    try {
      const auth = await withAuth(req);
      user = auth.user;
      supabase = auth.supabase;

      if (!user) {
        return res.status(401).json({ error: "User not found" });
      }

      // Get user profile to check limits
      const { data: profile, error: profileError } = await supabase
        .from("profiles")
        .select("*")
        .eq("id", user.id)
        .single();

      if (profileError || !profile) {
        throw profileError || new Error("Profile not found");
      }

      // Check if user has reached their generation limit
      const maxGenerations = getMaxGenerations(profile.tier);
      if (profile.generation_count >= maxGenerations) {
        // Log limit reached
        log(
          "warn",
          LogType.GENERATION_LIMIT_REACHED,
          `Hit generation limit. Limit: ${maxGenerations}, Count: ${profile.generation_count}`,
          {
            userId: user.id,
            limit: maxGenerations,
            count: profile.generation_count,
          }
        );
        return res.status(403).json({
          error: "Generation limit reached",
          limit: maxGenerations,
          current: profile.generation_count,
        });
      }

      let resolution = 128;
      try {
        const t_res = parseInt(req.body.resolution);
        if ([64, 96, 128].includes(t_res)) {
          resolution = t_res;
        }
      } catch (e) {
        log("error", LogType.SYSTEM_ERROR, "Error parsing resolution:", {
          error: e instanceof Error ? e.message : "Unknown error",
          userId: user?.id,
        });
      }

      let prompt = req.body.prompt || "Astronaut riding a horse";
      prompt += ` ${resolution}x${resolution} ${resolution} x ${resolution}`;
      if (resolution === 64) {
        prompt += " low resolution ";
      }

      // Log attempt
      log(
        "info",
        LogType.PIXEL_ART_GENERATION,
        `Generate pixel art request. Resolution: ${
          req.body.resolution
        }, Prompt: ${req.body.prompt || ""}`,
        {
          userId: user.id,
          resolution: req.body.resolution,
          prompt: req.body.prompt,
        }
      );

      // Log blacklisted words
      if (
        BLACKLISTED_WORDS.some((word) =>
          prompt.toLowerCase().split(/\s+/).includes(word.toLowerCase())
        )
      ) {
        log(
          "warn",
          LogType.BLACKLISTED_PROMPT,
          `Used blacklisted words in prompt: ${prompt}`,
          { userId: user.id, prompt }
        );
        return res.status(400).json({
          error: "Prompt contains blacklisted words potentially against TOS.",
        });
      }

      // Generate the image
      const imgBuffer = await generatePixelSprite(prompt);

      // Process the image - only color reduction, no downscaling
      const processedImage = await sharp(imgBuffer)
        .png({
          colors: 16,
          dither: 0,
          compressionLevel: 0,
          palette: true,
        })
        .toBuffer();

      // downscale
      const downscaledImage = await downscaleImage(processedImage, resolution);

      // Save to supabase storage without awaiting
      const promise = supabase.storage
        .from("pixel-art")
        .upload(`${user.id}/${Date.now()}.png`, downscaledImage);

      // increment generations
      await supabase
        .from("profiles")
        .update({ generation_count: profile.generation_count + 1 })
        .eq("id", user.id);

      // Send the processed image
      res.set("Content-Type", "image/png");
      res.send(downscaledImage);
    } catch (error) {
      // Log error
      if (supabase) {
        log(
          "error",
          LogType.PIXEL_ART_GENERATION_ERROR,
          `Error generating pixel art: ${
            error instanceof Error ? error.message : "Unknown error"
          }`,
          { userId: user?.id }
        );
      }
      log("error", LogType.SYSTEM_ERROR, "Error:", {
        error: error instanceof Error ? error.message : "Unknown error",
        userId: user?.id,
      });
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error occurred";
      res.status(500).json({ error: errorMessage });
    }
  }
);

app.post(
  "/api/create-portal-session",
  express.json({ type: "application/json" }),
  async (req, res) => {
    try {
      const { user, supabase } = await withAuth(req);
      if (!user) {
        return res.status(401).json({ error: "Not authenticated" });
      }

      // Get the customer ID from our database
      const { data: customer, error: customerError } = await supabase
        .from("stripe_customers")
        .select("stripe_customer_id")
        .eq("user_id", user.id)
        .single();

      if (customerError || !customer?.stripe_customer_id) {
        log(
          "error",
          LogType.BILLING_PORTAL_ERROR,
          `No associated Stripe customer found for user ${user.id} ${
            customerError ? JSON.stringify(customerError) : ""
          } `,
          { userId: user.id },
          user.id
        );
        return res
          .status(404)
          .json({ error: "No associated Stripe customer found" });
      }

      // Create a Stripe Portal session
      const portalSession = await stripe.billingPortal.sessions.create({
        customer: customer.stripe_customer_id,
        return_url: `${req.headers.origin}/pricing`,
      });

      return res.json({ url: portalSession.url });
    } catch (error) {
      log(
        "error",
        LogType.BILLING_PORTAL_ERROR,
        `Error creating Stripe portal session: ${
          error instanceof Error ? error.message : "Unknown error"
        }`
      );
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

// async function processTestImage(gamePath: string): Promise<Buffer> {
//   try {
//     const startTime = Date.now();
//     // Read the input image
//     // use fs to read the image
//     const inputImage = await fs.readFile(
//       path.join(__dirname, "generated-images", gamePath)
//     );
//     // const inputImage = await sharp(gamePath);
//     const metadata = await sharp(inputImage).metadata();

//     if (!metadata.width || !metadata.height) {
//       throw new Error("Could not get image dimensions");
//     }

//     const downscaledImage = await downscaleImage(inputImage, 128);

//     // Save to disk with game path-based filename
//     const outputPath = path.join(
//       __dirname,
//       "generated-images",
//       `${gamePath}-downscaled.png`
//     );
//     await sharp(downscaledImage).toFile(outputPath);

//     const endTime = Date.now();
//     console.log(`Time elapsed: ${endTime - startTime}ms`);
//     console.log("downscaledImage", outputPath);

//     return downscaledImage;
//   } catch (error) {
//     console.error("Error processing test image:", error);
//     throw error;
//   }
// }

// processTestImage("/test-1750625857434.png");

// Apply error handling middleware last
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
