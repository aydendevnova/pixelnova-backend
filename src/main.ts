import express from "express";
import cors from "cors";
import multer from "multer";
import { createClient, SupabaseClient } from "@supabase/supabase-js";

import { BLACKLISTED_USERNAMES } from "./const/blacklisted-usernames";
import { BLACKLISTED_SITES } from "./const/blacklisted-sites";
import { checkUsernameSchema, updateAccountSchema } from "./types/types";
import dotenv from "dotenv";

import OpenAI from "openai";
import rateLimit from "express-rate-limit";
import crypto from "crypto";
import { nonceCache } from "./utils/nonce-cache";
import { type Database } from "./lib/types_db";

dotenv.config();
// Must come after dotenv.config()
import { stripe } from "./utils/stripe";

const app = express();
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
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

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
        console.log(`Event ${eventId} already processed, skipping`);
        return;
      }

      // Process the event
      await processStripeEvent(event, supabase);

      // Record successful processing
      await supabase.from("stripe_events").insert({
        stripe_event_id: eventId,
        type: event.type,
        processed_at: new Date().toISOString(),
        error_message: null,
      });

      // Return a 200 response quickly to acknowledge receipt
      res.status(200).json({ received: true });
    } catch (err) {
      console.error("Webhook processing error:", err);
      // Consider implementing error reporting service here

      res.status(500).json({ received: false });
    }
  }
);

const MAGIC_PRIME = 0x1f7b3c5d;

function generateImageKey(
  userId: string,
  timestamp: number,
  serverNonce: string
): string {
  // Simple concatenation
  const data = `${userId}:${timestamp}:${serverNonce}`;

  // First hash
  const h1 = crypto.createHash("sha256");
  h1.update(data);
  const hash1 = Buffer.from(h1.digest());

  // XOR each byte with our magic number
  for (let i = 0; i < hash1.length; i++) {
    hash1[i] ^= (MAGIC_PRIME >> i % 8) & 0xff;
  }

  // Second hash
  const h2 = crypto.createHash("sha256");
  h2.update(hash1);
  const result = h2.digest("hex");

  return result;
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
  max: 100, // Limit each IP to 100 requests per windowMs
  message: { error: "Too many requests, please try again later." },
});

// Apply to all routes
app.use(apiLimiter);

// Stricter limit for image generation
const aiLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit each IP to 10 requests per hour
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
      await withCredits(req, 5);
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

      await spendCredits(user.id, supabase, 5);
    } catch (err) {
      console.error("Downscale image error:", err);
      res.status(500).json({
        error: "Failed to downscale image",
        message: err instanceof Error ? err.message : "Unknown error",
      });
    }
  }
);

// Add credits check middleware for protected operations
const withCredits = async (req: express.Request, cost: number) => {
  const { user, supabase } = await withAuth(req);

  const { data: profile, error } = await supabase
    .from("profiles")
    .select("credits")
    .eq("id", user.id)
    .single();

  if (error) throw error;
  if (!profile || profile.credits < cost) {
    throw new Error("Insufficient credits");
  }

  return { user, supabase, credits: profile.credits };
};

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
      await withCredits(req, 40); // Cost: 40 credits
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

      await spendCredits(user.id, supabase, 40);

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
      if (priceId === process.env.STRIPE_PRICE_ID_STARTER) {
        amount = 2000;
      } else if (priceId === process.env.STRIPE_PRICE_ID_PRO) {
        amount = 5000;
      } else {
        console.error("Invalid price id");
        throw new Error("Invalid price id");
      }

      // get their credits
      const { data: profile, error: profileError } = await supabase
        .from("profiles")
        .select("credits")
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

      const existingCredits = profile.credits ?? 0;

      // Update their credits
      const { error: updateError } = await supabase
        .from("profiles")
        .update({
          credits: existingCredits + amount,
        })
        .eq("id", userId);

      if (updateError) {
        console.error("Error updating credits:", updateError);
        throw updateError;
      } else {
        try {
          await supabase.from("logs").insert({
            type: "credit_added",
            message: `User ${userId} purchased ${amount} credits.`,
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
