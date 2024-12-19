#!/bin/bash

# Create directories if they don't exist
mkdir -p public

# Navigate to wasm directory
cd wasm

# Set Go environment variables for WebAssembly compilation
# GOOS=js tells Go to compile for JavaScript environment
# GOARCH=wasm tells Go to compile to WebAssembly
export GOOS=js
export GOARCH=wasm

# Build the WebAssembly module
echo "Building WebAssembly module..."
go build -o public/main.wasm

# Copy the WebAssembly support JavaScript file
echo "Copying WebAssembly support files..."
cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" public/

echo "Build complete! Check the public directory for main.wasm and wasm_exec.js" 