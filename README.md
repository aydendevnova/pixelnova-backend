# Pixel Nova Studio Backend

Express.js backend API for Pixel Nova Studio, a free pixel art toolkit. Handles image processing with Sharp, pixel-perfect conversion via WASM, and user authentication through Supabase. Deployed on Fly.io.

For screenshots, app details, and the full user experience, see the [frontend repository](https://github.com/aydendevnova/pixelnova-frontend) or visit [pixelnova.app](https://pixelnova.app).

## Overview

This backend provides REST API endpoints for converting images to pixel art and for user account management. All authenticated routes validate JWT tokens via Supabase.

The conversion endpoint runs uploaded images through a WASM pixel snapper that aligns pixels to a consistent grid and quantizes colors to a strict palette. Every feature is free and unmetered.

## Tech Stack

**Backend Framework & Language**

- TypeScript
- Node.js
- Express.js

**Database & Auth**

- Supabase (PostgreSQL, Auth, Storage)

**Image Processing**

- Sharp (image manipulation, resizing)
- SpriteFusion Pixel Snapper (WASM grid snapping and color quantization)

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

- Image to pixel art conversion with adjustable color count and grid density
- JWT-based authentication and authorization via Supabase
- Profile management (username, avatar, website with blacklist filtering)
- Comprehensive logging system with admin dashboard support
- Rate limiting for API routes
- Image storage in Supabase storage buckets

## Setup / Installation

```bash
# Install dependencies
npm install

# Environment variables required (see .env.example):
# SUPABASE_URL - Supabase project URL
# SUPABASE_SERVICE_ROLE_KEY - Supabase service role key
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
- `POST /api/check-username` - Check username availability

**Authenticated**

- `GET /api/protected` - Verify auth token
- `PATCH /api/update-account` - Update profile (multipart/form-data)
- `POST /api/convert-image` - Convert image to pixel art using WASM pixel snapper

**Admin**

- `GET /api/admin/logs` - Fetch system logs with filtering/pagination

## Deployment

Deployed on Fly.io using Docker. See `fly.toml` for configuration. The app runs on port 8787 with 512MB RAM and 1 shared CPU in the `iad` (Virginia) region.

```bash
fly deploy
```

For detailed deployment configuration, see `fly-deploy.md` and `server-docker.md`.

## License

This project is licensed under the [Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License (CC BY-NC-SA 4.0)](https://creativecommons.org/licenses/by-nc-sa/4.0/).

See the [LICENSE](LICENSE) file for the full text.

## Third-Party Attributions

### SpriteFusion Pixel Snapper

Used to convert uploaded images into true pixel art. The WASM module snaps pixels to a consistent grid and quantizes colors to a strict palette. This project uses a modified version of this code.

- **Author:** Hugo Duprez
- **Repository:** [github.com/Hugo-Dz/spritefusion-pixel-snapper](https://github.com/Hugo-Dz/spritefusion-pixel-snapper)
- **License:** MIT License
- **Website:** [spritefusion.com/pixel-snapper](https://www.spritefusion.com/pixel-snapper)
