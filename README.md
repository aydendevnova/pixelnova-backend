# PixelNova Backend

Express.js backend API for PixelNova, a pixel art generation and conversion platform. Handles AI image generation via HuggingFace, image processing with Sharp, Stripe subscription management, and user authentication through Supabase. Deployed on Fly.io.

For screenshots, app details, and the full user experience, see the [frontend repository](https://github.com/aydendevnova/pixelnova-frontend) or visit [pixelnova.app](https://pixelnova.app).

## Overview

This backend provides REST API endpoints for pixel art generation, image color reduction/downscaling, user account management, and subscription billing. It enforces usage quotas based on user tier (NONE/PRO), processes Stripe webhooks for subscription lifecycle events, and manages user profiles with blacklist filtering and rate limiting.

Image generation uses HuggingFace's inference API to produce pixel art sprites from text prompts. The color reduction endpoint quantizes uploaded images to a specified palette size using Sharp's PNG quantization. All authenticated routes validate JWT tokens via Supabase and track usage limits stored in PostgreSQL.

## Tech Stack

**Backend Framework & Language**

- TypeScript
- Node.js
- Express.js

**Database & Auth**

- Supabase (PostgreSQL, Auth, Storage)

**Image Processing & AI**

- Sharp (image manipulation, color quantization, downscaling)
- HuggingFace Inference API (pixel art generation)

**Payments & Subscriptions**

- Stripe (checkout, webhooks, billing portal)

**Security & Rate Limiting**

- Helmet (security headers)
- express-rate-limit (API throttling)
- CORS (cross-origin configuration)

**File Handling**

- Multer (multipart/form-data uploads)

**Validation**

- Zod (schema validation)

**Deployment**

- Fly.io (Docker-based deployment)

## Features

- AI-powered pixel art generation with configurable resolution (64x64 to 256x256)
- Image color reduction/palette quantization with adjustable color count
- JWT-based authentication and authorization via Supabase
- Stripe subscription management (checkout, webhooks, billing portal)
- Usage quota enforcement (generation and conversion limits by tier)
- Profile management (username, avatar, website with blacklist filtering)
- Comprehensive logging system with admin dashboard support
- Rate limiting for API routes and AI operations
- Image storage in Supabase storage buckets
- Webhook idempotency checks for reliable Stripe event processing

## Setup / Installation

```bash
# Install dependencies
npm install

# Environment variables required (see .env.example):
# HF_TOKEN - HuggingFace API token
# SUPABASE_URL - Supabase project URL
# SUPABASE_SERVICE_ROLE_KEY - Supabase service role key
# STRIPE_WEBHOOK_SECRET - Stripe webhook signing secret
# STRIPE_SECRET_KEY - Stripe secret key
# STRIPE_PRICE_ID_PRO - Stripe price ID for PRO plan
# PORT - Server port (default: 8787)

# Development
npm run dev

# Build
npm run build

# Production
npm start

# Deploy to Fly.io
fly deploy
```

## API Endpoints

**Public**

- `GET /` - Health check
- `GET /api/health` - Health check
- `POST /api/webhook` - Stripe webhook handler
- `POST /api/check-username` - Check username availability

**Authenticated**

- `GET /api/protected` - Verify auth token
- `PATCH /api/update-account` - Update profile (multipart/form-data)
- `POST /api/reduce-colors` - Image color reduction (multipart/form-data)
- `POST /api/update-conversion-count` - Increment conversion counter
- `POST /api/generate-pixel-art` - AI pixel art generation
- `POST /api/checkout` - Create Stripe checkout session
- `POST /api/create-portal-session` - Create Stripe billing portal session

**Admin**

- `GET /api/admin/logs` - Fetch system logs with filtering/pagination

## Deployment

Deployed on Fly.io using Docker. See `fly.toml` for configuration. The app runs on port 8787 with 512MB RAM and 1 shared CPU in the `iad` (Virginia) region.

```bash
fly deploy
```

For detailed deployment configuration, see `fly-deploy.md` and `server-docker.md`.
