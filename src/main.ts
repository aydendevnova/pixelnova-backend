import helmet from "helmet";
import dotenv from "dotenv";
import express from "express";
import cors from "cors";
import multer from "multer";
import { createClient } from "@supabase/supabase-js";
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
const requiredEnvVars = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"];

requiredEnvVars.forEach((varName) => {
  if (!process.env[varName]) {
    throw new Error(`${varName} is not set`);
  }
});

import { BLACKLISTED_WORDS } from "./const/blacklisted-words";
import { BLACKLISTED_SITES } from "./const/blacklisted-sites";
import { checkUsernameSchema, updateAccountSchema } from "./types/types";

import rateLimit from "express-rate-limit";

import { processWithPixelSnapper } from "./lib/pixel-snapper";
import sharp from "sharp";
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
        "X-Forwarded-For",
      ],
    })
  );
}

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

// Convert image to pixel art using WASM pixel snapper
app.post("/api/convert-image", upload.single("image"), async (req, res) => {
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
      "Convert image request",
      {
        fileSize: req.file.size,
      },
      user.id
    );

    // Parse k_colors from request body (optional, default 16)
    let kColors = 16;
    try {
      if (req.body.kColors) {
        const parsed = parseInt(req.body.kColors);
        if (!isNaN(parsed) && parsed > 0 && parsed <= 256) {
          kColors = parsed;
        }
      }
    } catch (err) {
      // Continue with default value
    }

    // Parse targetSegments - 0 = auto-detect (WASM decides grid), >0 = forced grid segments
    let targetSegments = 0;
    try {
      if (req.body.targetSegments) {
        const parsed = parseInt(req.body.targetSegments);
        if (!isNaN(parsed) && parsed >= 0 && parsed <= 512) {
          targetSegments = parsed;
        }
      }
    } catch (err) {
      // Continue with default (auto-detect)
    }

    // Ensure input has enough resolution for the target grid density
    // Auto-detect uses 512 baseline; forced mode needs at least 4 source pixels per grid cell
    const maxSize = targetSegments > 0 ? Math.max(512, targetSegments * 4) : 512;

    // Get user profile for usage tracking. Conversions are free and unlimited.
    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", user.id)
      .single();

    if (profileError || !profile) {
      throw new APIError(404, "Profile not found");
    }

    // Resize input to a consistent working size for WASM processing
    const resizedBuffer = await sharp(req.file.buffer)
      .resize(maxSize, maxSize, {
        fit: "inside",
        withoutEnlargement: true,
      })
      .png()
      .toBuffer();

    // Process through WASM pixel snapper
    // targetSegments=0 means auto-detect; >0 forces output grid density
    const processedBuffer = processWithPixelSnapper(
      resizedBuffer,
      kColors,
      targetSegments > 0 ? targetSegments : undefined
    );

    // Increment conversion counters
    const { error: updateError } = await supabase
      .from("profiles")
      .update({
        conversion_count: (profile.conversion_count ?? 0) + 1,
        conversion_count_lifetime:
          (profile.conversion_count_lifetime ?? 0) + 1,
        updated_at: new Date().toISOString(),
      })
      .eq("id", user.id);

    if (updateError) {
      await log(
        "error",
        LogType.SYSTEM_ERROR,
        `Failed to update conversion count for user ${user.id}`,
        { error: updateError },
        user.id
      );
    }

    const base64Image = processedBuffer.toString("base64");

    res.json({
      image: `data:image/png;base64,${base64Image}`,
      currentCount: (profile.conversion_count ?? 0) + 1,
    });
  } catch (err) {
    if (err instanceof APIError) {
      throw err;
    }

    await log(
      "error",
      LogType.SYSTEM_ERROR,
      `Convert image error: ${
        err instanceof Error
          ? err.message
          : "Unknown error: " + JSON.stringify(err)
      } for user ${user?.id}`,
      {},
      user?.id
    );

    throw new APIError(500, "Failed to convert image");
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
      ...new Set(
        logs?.flatMap((log) => (log.user_id ? [log.user_id] : [])) ?? []
      ),
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

// Apply error handling middleware last
app.use(errorHandler);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
