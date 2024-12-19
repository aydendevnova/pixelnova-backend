# Build stage for WASM
FROM golang:1.23.4-alpine AS wasm-builder
WORKDIR /app/wasm
COPY wasm/ .
RUN apk add --no-cache bash && \
    chmod +x build-wasm.sh && \
    GOOS=js GOARCH=wasm go build -o public/main.wasm && \
    cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" public/

# Build stage for Node.js
FROM node:20-slim AS builder
WORKDIR /app

# Copy package files and install dependencies
COPY package*.json ./
COPY tsconfig.json ./
RUN npm ci

# Copy source code and types
COPY src/ ./src/
COPY --from=wasm-builder /app/wasm/public ./wasm/public

# Build TypeScript
RUN npm run build

# Production stage
FROM node:20-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8787

# Copy built files and dependencies
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/wasm/public ./wasm/public
COPY package*.json ./

# Install production dependencies only
RUN npm ci --production

EXPOSE 8787
CMD ["node", "dist/main.js"]