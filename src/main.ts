import dotenv from "dotenv";

dotenv.config();

if (!process.env.HF_TOKEN) {
  throw new Error("HF_TOKEN is not set");
}

if (!process.env.OPEN_API_KEY) {
  throw new Error("OPEN_API_KEY is not set");
}

if (!process.env.SUPABASE_URL) {
  throw new Error("SUPABASE_URL is not set");
}

if (!process.env.SUPABASE_SERVICE_ROLE_KEY) {
  throw new Error("SUPABASE_SERVICE_ROLE_KEY is not set");
}

if (!process.env.STRIPE_WEBHOOK_SECRET) {
  throw new Error("STRIPE_WEBHOOK_SECRET is not set");
}

if (!process.env.STRIPE_SECRET_KEY) {
  throw new Error("STRIPE_SECRET_KEY is not set");
}

if (!process.env.STRIPE_PRICE_ID_PRO) {
  throw new Error("STRIPE_PRICE_ID_PRO is not set");
}

import express from "express";
import cors from "cors";
import multer from "multer";
import { createClient, SupabaseClient } from "@supabase/supabase-js";

import { BLACKLISTED_USERNAMES } from "./const/blacklisted-usernames";
import { BLACKLISTED_SITES } from "./const/blacklisted-sites";
import { checkUsernameSchema, updateAccountSchema } from "./types/types";

import OpenAI from "openai";
import rateLimit from "express-rate-limit";
import crypto from "crypto";
import { nonceCache } from "./utils/nonce-cache";
import { type Database } from "./lib/types_db";

import { stripe } from "./utils/stripe";
import { downscaleImage8x, generatePixelSprite } from "./lib/pixel-art-redmond";

const app = express();
app.set("trust proxy", 1);

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
  OPEN_API_KEY,
  PORT = 8787,
} = process.env;

const openai = new OpenAI({
  apiKey: OPEN_API_KEY,
});

// CORS configuration
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "http://192.168.12.102:3000",
      "https://editor.pixelnova.app", // Cloudflare Pages domain
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

// Always allow webhook requests to bypass rate limiting
app.use((req, res, next) => {
  if (req.path === "/api/webhook") {
    return next();
  }
  return apiLimiter(req, res, next);
});

app.post(
  "/api/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    // Process the webhook asynchronously
    try {
      if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
        throw new Error("Missing Supabase configuration");
      }
      if (!process.env.STRIPE_WEBHOOK_SECRET) {
        throw new Error("Missing Stripe webhook secret");
      }

      const signature = req.headers["stripe-signature"];
      if (!signature) {
        throw new Error("Missing signature");
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
        await supabase.from("logs").insert({
          type: "stripe_event_already_processed",
          message: `Event ${eventId} already processed in DB. This may be a duplicate and the user will have extra credits.`,
        });
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
        await supabase.from("logs").insert({
          type: "stripe_event_processing_error",
          message: `Error processing event ${eventId}: ${e}`,
        });
      }

      // Return a 200 response quickly to acknowledge receipt
      res.status(200).json({ received: true });
    } catch (err) {
      console.error("Webhook processing error:", err);
      // Consider implementing error reporting service here

      res.status(500).json({ received: false });
    }
  }
);

function generateImageKey(
  userId: string,
  timestamp: number,
  serverNonce: string
): string {
  // Super simple key generation for testing
  const data = `${userId}:${timestamp}:${serverNonce}`;
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    hash = (hash << 5) - hash + data.charCodeAt(i);
    hash = hash & hash; // Convert to 32-bit integer
  }
  return Math.abs(hash).toString(16).padStart(8, "0");
}

// Helper function to handle protected routes
const withAuth = async (req: express.Request) => {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith("Bearer ")) {
    throw new Error("Unauthorized");
  }

  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    throw new Error("Missing Supabase configuration");
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
    throw userError || new Error("User not found");
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

const PIXEL_ART_INJECTION =
  "You are a pixel art sprite creator. You make an image with a white background. Pixels are sharp and square. Make ";

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
  max: 70, // Limit each IP to 70 requests per hour
  standardHeaders: true,
  legacyHeaders: false,
});

app.post(
  "/api/generate-image",
  express.json({ type: "application/json" }),
  aiLimiter,
  async (req, res) => {
    try {
      const { prompt } = req.body;

      if (!prompt) {
        return res.status(400).json({ error: "Prompt is required" });
      }

      const response = await openai.images.generate({
        model: "dall-e-3",
        prompt: `${PIXEL_ART_INJECTION} ${prompt}`,
        n: 1,
        size: "1024x1024",
      });

      const imageUrl = response.data?.[0]?.url;
      if (!imageUrl) {
        return res.status(500).json({ error: "Failed to generate image URL" });
      }

      // Fetch the image from the URL
      const imageResponse = await fetch(imageUrl);
      if (!imageResponse.ok) {
        throw new Error("Failed to fetch image from OpenAI");
      }

      const imageBuffer = await imageResponse.arrayBuffer();

      // Set appropriate headers and send the image buffer
      res.setHeader("Content-Type", "image/png");
      res.setHeader(
        "Content-Disposition",
        'attachment; filename="generated-image.png"'
      );
      res.send(Buffer.from(imageBuffer));
    } catch (error) {
      console.error("Error generating image:", error);
      return res.status(500).json({ error: "Failed to generate image" });
    }
  }
);

app.patch(
  "/api/update-account",
  express.json({ type: "application/json" }),
  upload.single("image"),
  (req, res) => {
    (async () => {
      try {
        const { user, supabase } = await withAuth(req);
        const { fullName, username, website } = req.body;

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
          (BLACKLISTED_USERNAMES.includes(usernameSanitized) ||
            BLACKLISTED_SITES.some((site) => usernameSanitized.includes(site)))
        ) {
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
          return res.status(400).json({ error: "Website is blacklisted" });
        }

        // Update profile
        const { error: updateError } = await supabase
          .from("profiles")
          .update({
            full_name: fullName?.trim() ?? profile.full_name,
            username: usernameSanitized ?? profile.username,
            website: websiteSanitized ?? profile.website,
            updated_at: new Date().toISOString(),
          })
          .eq("id", user.id);

        if (updateError) {
          throw updateError;
        }

        return res.status(200).json({ success: true });
      } catch (err) {
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
          BLACKLISTED_USERNAMES.includes(sanitizedUsername) ||
          BLACKLISTED_SITES.some((site) => sanitizedUsername.includes(site))
        ) {
          return res.status(400).json({ available: false, blacklisted: true });
        }

        if (
          !process.env.SUPABASE_URL ||
          !process.env.SUPABASE_SERVICE_ROLE_KEY
        ) {
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

// Generate a secure nonce for each request
function generateServerNonce(): string {
  return crypto.randomBytes(32).toString("hex");
}

// Replace the existing /api/estimate-grid-size endpoint
app.post(
  "/api/estimate-grid-size",
  express.json({ type: "application/json" }),
  async (req, res) => {
    try {
      const { user } = await withAuth(req);
      const timestamp = Math.floor(Date.now() / 1000);
      const serverNonce = generateServerNonce();

      await nonceCache.cacheNonce(user.id, serverNonce, 30); // 30 second TTL

      const key = generateImageKey(user.id, timestamp, serverNonce);

      res.status(200).json({
        a: key,
        b: timestamp,
        c: serverNonce,
        authorized: true,
      });
    } catch (err) {
      console.error("Estimate grid size error:", err);
      res.status(500).json({
        error: "Failed to estimate grid size",
        message: err instanceof Error ? err.message : "Unknown error",
      });
    }
  }
);

app.post(
  "/api/downscale-image",
  express.json({ type: "application/json" }),
  async (req, res) => {
    try {
      const { user, supabase } = await withAuth(req);
      const timestamp = Math.floor(Date.now() / 1000);
      const serverNonce = generateServerNonce();

      // Store nonce in Redis or similar with short TTL
      await nonceCache.cacheNonce(user.id, serverNonce, 30); // 30 second TTL

      const key = generateImageKey(user.id, timestamp, serverNonce);
      res.json({
        a: key,
        b: timestamp,
        c: serverNonce,
      });

      // await spendCredits(user.id, supabase, 5);
      // increment generation count
      // get profile
      const { data: profile, error: profileError } = await supabase
        .from("profiles")
        .select("generation_count")
        .eq("id", user.id)
        .single();
      if (profileError) {
        throw profileError;
      }
      if (!profile) {
        throw new Error("Profile not found");
      }
      // increment generation count
      const { error: updateError } = await supabase
        .from("profiles")
        .update({ generation_count: (profile?.generation_count ?? 0) + 1 })
        .eq("id", user.id);
      if (updateError) {
        throw updateError;
      }
    } catch (err) {
      console.error("Downscale image error:", err);
      res.status(500).json({
        error: "Failed to downscale image",
        message: err instanceof Error ? err.message : "Unknown error",
      });
    }
  }
);

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

async function spendCredits(
  userId: string,
  supabase: SupabaseClient,
  amount: number,
  existingCredits?: number | null | undefined
) {
  let baseCredits = existingCredits ?? 0;
  if (!baseCredits) {
    // fetch profile
    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("credits")
      .eq("id", userId)
      .single();
    if (profileError) {
      console.error("Error fetching user profile:", profileError);
      throw new Error(`Failed to fetch user profile: ${profileError.message}`);
    }
    baseCredits = profile?.credits ?? 0;
  }
  // Deduct credits
  const { error: deductError } = await supabase
    .from("profiles")
    .update({
      credits: baseCredits - amount,
      updated_at: new Date().toISOString(),
    })
    .eq("id", userId);

  if (deductError) {
    console.error("Error deducting credits:", deductError);
    throw deductError;
  }
}

app.post(
  "/api/generate-image",
  express.json({ type: "application/json" }),
  async (req, res) => {
    try {
      const { user, supabase } = await withAuth(req);
      const { prompt } = req.body;

      return res.status(400).json({ error: "Not implemented" });

      // if (!prompt) {
      //   return res.status(400).json({ error: "Prompt is required" });
      // }

      // const response = await openai.images.generate({
      //   model: "dall-e-3",
      //   prompt: `${PIXEL_ART_INJECTION} ${prompt}`,
      //   n: 1,
      //   size: "1024x1024",
      // });

      // const imageUrl = response.data?.[0]?.url;
      // if (!imageUrl) {
      //   return res.status(500).json({ error: "Failed to generate image URL" });
      // }

      // // Fetch the image from the URL
      // const imageResponse = await fetch(imageUrl);
      // if (!imageResponse.ok) {
      //   throw new Error("Failed to fetch image from OpenAI");
      // }

      // const imageBuffer = await imageResponse.arrayBuffer();

      // await spendCredits(user.id, supabase, 40);

      // // Set appropriate headers and send the image buffer
      // res.setHeader("Content-Type", "image/png");
      // res.setHeader(
      //   "Content-Disposition",
      //   'attachment; filename="generated-image.png"'
      // );
      // res.send(Buffer.from(imageBuffer));
    } catch (error) {
      console.error("Error generating image:", error);
      return res.status(500).json({ error: "Failed to generate image" });
    }
  }
);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

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
    case "checkout.session.completed": {
      const session = event.data.object;
      console.log("session");
      console.log(session);

      const userId = session.metadata?.user_id;

      if (!userId) {
        console.error("Missing user_id");
        throw new Error("Missing user_id");
      }

      const priceId = session.metadata?.price_id;
      if (!priceId) {
        console.error("Missing price id");
        throw new Error("Missing price id");
      }

      let amount = 0;
      let tier: Database["public"]["Enums"]["user_tier"] = "NONE";

      if (priceId === process.env.STRIPE_PRICE_ID_STARTER) {
        amount = 2000;
        tier = "NONE";
      } else if (priceId === process.env.STRIPE_PRICE_ID_PRO) {
        amount = 5000;
        tier = "PRO";
      } else {
        console.error("Invalid price id");
        throw new Error("Invalid price id");
      }

      // get their credits
      const { data: profile, error: profileError } = await supabase
        .from("profiles")
        .select("generation_count")
        .eq("id", userId)
        .single();

      if (profileError) {
        console.error("Error fetching user profile:", profileError);
        throw new Error(
          `Failed to fetch user profile: ${profileError.message}`
        );
      }

      if (!profile) {
        console.error("User profile not found");
        throw new Error("User profile not found");
      }

      const existingCredits = profile.generation_count ?? 0;

      // Update their credits and tier
      const { error: updateError } = await supabase
        .from("profiles")
        .update({
          generation_count: existingCredits + amount,
          tier: tier,
          updated_at: new Date().toISOString(),
        })
        .eq("id", userId);

      if (updateError) {
        console.error("Error updating credits:", updateError);
        throw updateError;
      } else {
        try {
          await supabase.from("logs").insert({
            type: "credit_added",
            message: `User ${userId} purchased ${amount} credits and set tier to ${tier}.`,
          });
        } catch (error) {
          console.error("Error logging credit purchase:", error);
        }
      }

      // Use a transaction to ensure data consistency
      const { error } = await supabase.from("stripe_customers").upsert({
        stripe_customer_id: session.customer as string | null,
        user_id: userId,
        plan_active: true,
        latest_address: session.customer_details?.address,
        latest_currency: session.customer_details?.address?.country,
      });

      if (error) {
        console.error("Error updating stripe_customers:", error);
        throw error;
      }
      break;
    }
  }
}

app.post(
  "/api/checkout",
  express.json({ type: "application/json" }),
  async (req, res) => {
    try {
      const { priceId } = req.body;
      if (!priceId) {
        return res.status(400).json({ error: "Invalid request" });
      }

      const { user } = await withAuth(req);
      if (!user) {
        return res.status(401).json({ error: "User not found" });
      }

      // verify price ID is valid
      const price = await stripe.prices.retrieve(priceId);
      if (!price) {
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
        mode: "payment",
        success_url: `${req.headers.origin}/success`,
        cancel_url: `${req.headers.origin}/cancel`,
      });

      return res.json({ id: session.id });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: e });
    }
  }
);

// API endpoint to generate and process image
app.post("/generate-pixel-art", async (req, res) => {
  // require auth
  const { user } = await withAuth(req);
  if (!user) {
    return res.status(401).json({ error: "User not found" });
  }

  //TODO: Check their subscription status and total generations for the month

  try {
    const prompt = req.body.prompt || "Astronaut riding a horse";
    const steps = req.body.steps || 5;

    const imgBuffer = await generatePixelSprite(prompt, steps);
    const processedImage = await downscaleImage8x(imgBuffer);

    // save to supabase storage
    // TODO: Save to user storage
    // const { data, error } = await supabase.storage
    // .from("pixel-art")
    // .upload(`${user.id}/${Date.now()}.png`, processedImage);

    // Send the processed image
    res.set("Content-Type", "image/png");
    res.send(processedImage);
  } catch (error) {
    console.error("Error:", error);
    const errorMessage =
      error instanceof Error ? error.message : "Unknown error occurred";
    res.status(500).json({ error: errorMessage });
  }
});
