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

import { stripe } from "./utils/stripe";
import { downscaleImage, generatePixelSprite } from "./lib/pixel-art-tools";
import sharp from "sharp";
import { getMaxConversions, getMaxGenerations } from "./const/plan-limits";
import { Database } from "./lib/types_db";

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
      error:
        err instanceof Error
          ? err.message
          : "Unknown error: " + JSON.stringify(err),
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
          }. Error: ${
            e instanceof Error
              ? e.message
              : "Unknown error: " + JSON.stringify(e)
          }`,
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
          err instanceof Error
            ? err.message
            : "Unknown error: " + JSON.stringify(err)
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
          {},
          user.id
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
            {},
            user.id
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
            {},
            user.id
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
              message:
                error instanceof Error
                  ? error.message
                  : "Unknown error: " + JSON.stringify(error),
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
            { avatarUrl: avatar_url },
            user.id
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
          {},
          user.id
        );

        console.error("Update account error:", err);
        res.status(500).json({
          error: "Failed to update account",
          message:
            err instanceof Error
              ? err.message
              : "Unknown error: " + JSON.stringify(err),
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
          message:
            err instanceof Error
              ? err.message
              : "Unknown error: " + JSON.stringify(err),
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

    await log(
      "info",
      LogType.PIXEL_ART_GENERATION,
      "Color reduction request",
      {
        fileSize: req.file.size,
      },
      user.id
    );

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
        {
          factor: req.body.factor,
        },
        user.id
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
          limit: maxConversions,
          current: profile.conversion_count,
        },
        user.id
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
        err instanceof Error
          ? err.message
          : "Unknown error: " + JSON.stringify(err)
      } for user ${user?.id}`,
      {},
      user?.id
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
      message:
        err instanceof Error
          ? err.message
          : "Unknown error: " + JSON.stringify(err),
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
      message:
        err instanceof Error
          ? err.message
          : "Unknown error: " + JSON.stringify(err),
    });
  }
});

// New endpoint to fetch logs (admin only)
app.get("/api/admin/logs", async (req, res) => {
  try {
    const { user, supabase } = await withAuth(req);

    // Check if user is admin
    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", user.id)
      .single();

    if (profileError || !profile?.is_admin) {
      throw new ForbiddenError("Admin access required");
    }

    // Get query parameters for pagination and filtering
    const page = parseInt(req.query.page as string) || 1;
    const limit = parseInt(req.query.limit as string) || 100;
    const offset = (page - 1) * limit;
    const userId = req.query.userId as string;
    const level = req.query.level as string;
    const sortBy = (req.query.sortBy as string) || "created_at";
    const sortOrder = (req.query.sortOrder as "asc" | "desc") || "desc";

    // Build the query
    let query = supabase.from("logs").select("*", { count: "exact" });

    // Apply filters
    if (userId) {
      query = query.eq("user_id", userId);
    }
    if (level) {
      query = query.eq("level", level);
    }

    // Apply sorting
    query = query.order(sortBy, { ascending: sortOrder === "asc" });

    // Apply pagination
    query = query.range(offset, offset + limit - 1);

    // Execute query
    const { data: logs, error: logsError, count } = await query;

    if (logsError) {
      throw logsError;
    }

    // If userId is provided, fetch user profile
    let userProfile = null;
    if (userId) {
      const { data: profileData } = await supabase
        .from("profiles")
        .select("*")
        .eq("id", userId)
        .single();
      userProfile = profileData;
    }

    // Get unique user IDs from logs
    const userIds = [
      ...new Set(logs?.map((log) => log.user_id).filter(Boolean)),
    ];

    // Fetch all relevant user profiles in one query
    const { data: userProfiles } = await supabase
      .from("profiles")
      .select("*")
      .in("id", userIds);

    // Create a map of user profiles
    const userProfilesMap = (userProfiles || []).reduce((acc, profile) => {
      acc[profile.id] = profile;
      return acc;
    }, {} as Record<string, any>);

    res.json({
      logs,
      userProfiles: userProfilesMap,
      selectedUserProfile: userProfile,
      pagination: {
        page,
        limit,
        total: count || 0,
        totalPages: Math.ceil((count || 0) / limit),
      },
    });
  } catch (err) {
    if (err instanceof ForbiddenError) {
      res.status(403).json({
        error: "Forbidden",
        message: err.message,
      });
      return;
    }

    console.error("Admin logs fetch error:", err);
    res.status(500).json({
      error: "Internal server error",
      message:
        err instanceof Error
          ? err.message
          : "Unknown error: " + JSON.stringify(err),
    });
  }
});

async function processStripeEvent(
  event: any,
  supabase: SupabaseClient<Database>
) {
  switch (event.type) {
    // Resets a user's generation and conversion counts, even upon first subscription.
    case "invoice.payment_succeeded": {
      const invoice = event.data.object;
      if (
        invoice.billing_reason === "subscription_create" ||
        invoice.billing_reason === "subscription_cycle"
      ) {
        log(
          "info",
          LogType.SUBSCRIPTION_RENEWED,
          `An invoice payment succeeded: ${JSON.stringify(invoice, null, 2)}`
        );

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
          log(
            "error",
            LogType.SUBSCRIPTION_ERROR,
            "Error resetting counts:",
            {
              error: updateError,
              userId: customer.user_id,
            },
            customer.user_id
          );
          log(
            "error",
            LogType.SUBSCRIPTION_ERROR,
            `Error resetting counts: ${updateError} for user ${customer.user_id}`,
            {},
            customer.user_id
          );
          throw updateError;
        }

        try {
          log(
            "info",
            LogType.SUBSCRIPTION_RENEWED,
            `User ${customer.user_id} subscription renewed, reset generation and conversion counts.`,
            {},
            customer.user_id
          );
        } catch (error) {
          log(
            "error",
            LogType.SUBSCRIPTION_ERROR,
            "Error logging subscription renewal:",
            {
              error:
                error instanceof Error
                  ? error.message
                  : "Unknown error: " + JSON.stringify(error),
              userId: customer.user_id,
            },
            customer.user_id
          );
        }
      } else {
        log(
          "warn",
          LogType.SUBSCRIPTION_ERROR,
          "I don't know what to do? Invoice is not of subscription_create or subscription_cycle",
          {
            error: invoice.billing_reason,
            userId: JSON.stringify(invoice.customer),
          }
        );
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
          `Checkout completed: Missing price id: ${JSON.stringify(
            session.metadata
          )} for user ${userId}`,
          { metadata: JSON.stringify(session.metadata) },
          userId
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
          { userId },
          userId
        );
        log(
          "error",
          LogType.CHECKOUT_ERROR,
          `Invalid price id: ${JSON.stringify(session.metadata)}`,
          { metadata: JSON.stringify(session.metadata) },
          userId
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
                : "Unknown error: " + JSON.stringify(updateError),
            userId,
          },
          userId
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
            `User ${userId} updated tier to ${tier}.`,
            { userId, tier },
            userId
          );
        } catch (error) {
          log(
            "error",
            LogType.SUBSCRIPTION_ERROR,
            "Error logging tier update:",
            {
              error:
                error instanceof Error
                  ? error.message
                  : "Unknown error: " + JSON.stringify(error),
              userId,
            },
            userId
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
            error:
              error instanceof Error
                ? error.message
                : "Unknown error: " + JSON.stringify(error),
            userId,
          },
          userId
        );
        log(
          "error",
          LogType.SUBSCRIPTION_ERROR,
          `Error updating stripe_customers: ${JSON.stringify(
            error
          )} for user ${userId}`,
          { userId },
          userId
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
        log(
          "error",
          LogType.STRIPE_SUBSCRIPTION_CANCELLED,
          "Error finding customer:",
          {
            error:
              customerError instanceof Error
                ? customerError.message
                : "Unknown error: " + JSON.stringify(customerError),
            subscriptionId: subscription.id,
          }
        );
        log(
          "error",
          LogType.STRIPE_SUBSCRIPTION_CANCELLED,
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
        log(
          "error",
          LogType.STRIPE_SUBSCRIPTION_CANCELLED,
          "Error updating tier:",
          {
            error:
              updateError instanceof Error
                ? updateError.message
                : "Unknown error: " + JSON.stringify(updateError),
            userId: customer.user_id,
          },
          customer.user_id
        );
        log(
          "error",
          LogType.STRIPE_SUBSCRIPTION_CANCELLED,
          `Error updating tier: ${updateError} for user ${customer.user_id}`,
          { userId: customer.user_id },
          customer.user_id
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
          LogType.STRIPE_SUBSCRIPTION_CANCELLED,
          "Error updating stripe_customers:",
          {
            error:
              customerUpdateError instanceof Error
                ? customerUpdateError.message
                : "Unknown error: " + JSON.stringify(customerUpdateError),
            userId: customer.user_id,
          },
          customer.user_id
        );
        log(
          "error",
          LogType.STRIPE_SUBSCRIPTION_CANCELLED,
          `Error updating stripe_customers: ${customerUpdateError} for user ${customer.user_id}`
        );
        throw customerUpdateError;
      }

      try {
        log(
          "info",
          LogType.TIER_UPDATED,
          `User ${customer.user_id} subscription cancelled, tier set to NONE.`,
          { userId: customer.user_id },
          customer.user_id
        );
      } catch (error) {
        log(
          "error",
          LogType.STRIPE_SUBSCRIPTION_CANCELLED,
          "Error logging tier update:",
          {
            error:
              error instanceof Error
                ? error.message
                : "Unknown error: " + JSON.stringify(error),
            userId: customer.user_id,
          },
          customer.user_id
        );
      }
      break;
    }
    case "customer.subscription.updated": {
      const subscription = event.data.object;

      // Find the user associated with this subscription
      const { data: customer, error: customerError } = await supabase
        .from("stripe_customers")
        .select("user_id")
        .eq("subscription_id", subscription.id)
        .single();

      if (customerError || !customer) {
        log(
          "error",
          LogType.STRIPE_SUBSCRIPTION_UPDATED,
          "Error finding customer for subscription update:",
          {
            error:
              customerError instanceof Error
                ? customerError.message
                : "Unknown error: " + JSON.stringify(customerError),
            subscriptionId: subscription.id,
          }
        );
        throw new Error("Customer not found");
      }

      // Handle different subscription states
      switch (subscription.status) {
        case "active":
          // Ensure user has PRO access
          await supabase
            .from("profiles")
            .update({
              tier: "PRO",
              updated_at: new Date().toISOString(),
            })
            .eq("id", customer.user_id);

          log(
            "info",
            LogType.STRIPE_SUBSCRIPTION_UPDATED,
            `User ${customer.user_id} subscription is active, tier set/confirmed as PRO.`,
            { userId: customer.user_id },
            customer.user_id
          );
          break;

        case "past_due":
          // Log the past due status but don't change tier yet
          log(
            "warn",
            LogType.STRIPE_SUBSCRIPTION_UPDATED,
            `User ${customer.user_id} subscription is past due.`,
            {
              userId: customer.user_id,
              subscriptionId: subscription.id,
              status: subscription.status,
            },
            customer.user_id
          );
          break;

        case "unpaid":
        case "canceled":
        case "paused":
          // Downgrade user to NONE for these states
          await supabase
            .from("profiles")
            .update({
              tier: "NONE",
              updated_at: new Date().toISOString(),
            })
            .eq("id", customer.user_id);

          // Update stripe_customers table to reflect inactive plan
          await supabase
            .from("stripe_customers")
            .update({
              plan_active: false,
            })
            .eq("user_id", customer.user_id);

          log(
            "info",
            LogType.STRIPE_SUBSCRIPTION_UPDATED,
            `User ${customer.user_id} subscription status changed to ${subscription.status}, tier set to NONE.`,
            {
              userId: customer.user_id,
              subscriptionId: subscription.id,
              status: subscription.status,
              tier: "NONE",
            },
            customer.user_id
          );
          break;

        default:
          log(
            "warn",
            LogType.SUBSCRIPTION_ERROR,
            `Unhandled subscription status ${subscription.status} for user ${customer.user_id}`,
            { userId: customer.user_id },
            customer.user_id
          );
      }

      // If trial was extended, log it
      if (subscription.trial_end) {
        const trialEnd = new Date(subscription.trial_end * 1000);
        log(
          "info",
          LogType.SUBSCRIPTION_RENEWED,
          `User ${
            customer.user_id
          } trial extended to ${trialEnd.toISOString()}`,
          { userId: customer.user_id },
          customer.user_id
        );
      }
      break;
    }
    case "customer.deleted": {
      const customer = event.data.object;

      // Find the user associated with this Stripe customer
      const { data: stripeCustomer, error: customerError } = await supabase
        .from("stripe_customers")
        .select("user_id")
        .eq("stripe_customer_id", customer.id)
        .single();

      if (customerError || !stripeCustomer) {
        log(
          "error",
          LogType.STRIPE_DELETE_USER_ERROR,
          "Error finding customer:",
          {
            error:
              customerError instanceof Error
                ? customerError.message
                : "Unknown error: " + JSON.stringify(customerError),
            stripeCustomerId: customer.id,
          }
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
        .eq("id", stripeCustomer.user_id);

      if (updateError) {
        log(
          "error",
          LogType.STRIPE_DELETE_USER_ERROR,
          "Error updating tier:",
          {
            error:
              updateError instanceof Error
                ? updateError.message
                : "Unknown error: " + JSON.stringify(updateError),
            userId: stripeCustomer.user_id,
          },
          stripeCustomer.user_id
        );
        throw updateError;
      }

      // Delete the stripe_customers record
      const { error: deleteError } = await supabase
        .from("stripe_customers")
        .delete()
        .eq("stripe_customer_id", customer.id);

      if (deleteError) {
        log(
          "error",
          LogType.STRIPE_DELETE_USER_ERROR,
          "Error deleting stripe_customer record:",
          {
            error:
              deleteError instanceof Error
                ? deleteError.message
                : "Unknown error: " + JSON.stringify(deleteError),
            userId: stripeCustomer.user_id,
            stripeCustomerId: customer.id,
          },
          stripeCustomer.user_id
        );
        throw deleteError;
      }

      try {
        log(
          "info",
          LogType.TIER_UPDATED,
          `User ${stripeCustomer.user_id} Stripe customer deleted, tier set to NONE and stripe_customer record removed.`,
          { userId: stripeCustomer.user_id },
          stripeCustomer.user_id
        );
      } catch (error) {
        log(
          "error",
          LogType.STRIPE_DELETE_USER_ERROR,
          "Error logging customer deletion:",
          {
            error:
              error instanceof Error
                ? error.message
                : "Unknown error: " + JSON.stringify(error),
            userId: stripeCustomer.user_id,
          },
          stripeCustomer.user_id
        );
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
        log(
          "error",
          LogType.CHECKOUT_ERROR,
          `Invalid price ID: ${priceId}`,
          {
            userId: user.id,
            priceId,
          },
          user.id
        );
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
        allow_promotion_codes: true,
      });

      // Log successful checkout session creation
      log(
        "info",
        LogType.CHECKOUT_SESSION_CREATED,
        `Successfully created checkout session. Session ID: ${session.id}`,
        { userId: user.id, sessionId: session.id },
        user.id
      );

      return res.json({ id: session.id });
    } catch (e) {
      // Log error
      if (supabase) {
        log(
          "error",
          LogType.CHECKOUT_ERROR,
          `Error creating checkout session: ${
            e instanceof Error
              ? e.message
              : "Unknown error: " + JSON.stringify(e)
          }`,
          { userId: user?.id },
          user?.id
        );
      }
      log(
        "error",
        LogType.SYSTEM_ERROR,
        "Error creating checkout session:",
        {
          error:
            e instanceof Error
              ? e.message
              : "Unknown error: " + JSON.stringify(e),
          userId: user?.id,
        },
        user?.id
      );
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
            limit: maxGenerations,
            count: profile.generation_count,
          },
          user.id
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
        if ([64, 96, 128, 256].includes(t_res)) {
          resolution = t_res;
        }
      } catch (e) {
        log(
          "error",
          LogType.SYSTEM_ERROR,
          "Error parsing resolution:",
          {
            error:
              e instanceof Error
                ? e.message
                : "Unknown error: " + JSON.stringify(e),
          },
          user.id
        );
      }

      let prompt = req.body.prompt || "Astronaut riding a horse";
      prompt += ` ${resolution}x${resolution} ${resolution} x ${resolution}`;
      if (resolution === 64) {
        prompt += " low resolution ";
      } else if (resolution === 256) {
        prompt += " high resolution ";
      }

      // Log attempt
      log(
        "info",
        LogType.PIXEL_ART_GENERATION,
        `Generate pixel art request. Resolution: ${
          req.body.resolution
        }, Prompt: ${req.body.prompt || ""}`,
        {
          resolution: req.body.resolution,
          prompt: req.body.prompt,
        },
        user.id
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
          { prompt },
          user.id
        );
        return res.status(400).json({
          error: "Prompt contains blacklisted words potentially against TOS.",
        });
      }

      // Generate the image
      const imgBuffer = await generatePixelSprite(prompt);

      // Process the image - only color reduction, no downscaling
      const processedImage = await sharp(imgBuffer)
        .modulate({
          saturation: 1.2, // Increase saturation by 20%
        })
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
        .update({
          generation_count: profile.generation_count + 1,
          generation_count_lifetime: profile.generation_count_lifetime + 1,
        })
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
            error instanceof Error
              ? error.message
              : "Unknown error: " + JSON.stringify(error)
          }`,
          {},
          user?.id
        );
      }
      log(
        "error",
        LogType.SYSTEM_ERROR,
        "Error:",
        {
          error:
            error instanceof Error
              ? error.message
              : "Unknown error: " + JSON.stringify(error),
        },
        user?.id
      );
      const errorMessage =
        error instanceof Error
          ? error.message
          : "Unknown error occurred: " + JSON.stringify(error);
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
          {},
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
          error instanceof Error
            ? error.message
            : "Unknown error: " + JSON.stringify(error)
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
