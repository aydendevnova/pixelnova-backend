//go:build js && wasm
// +build js,wasm

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"io"
	"pixlabs/wasm/util"
	"strings"

	// Explicitly import decoders
	_ "image/jpeg"
	_ "image/png"

	_ "golang.org/x/image/webp"

	// ignore error - available in wasm
	"syscall/js"
)

func init() {
	// Register WebP format
	image.RegisterFormat("webp", "RIFF",
		func(r io.Reader) (image.Image, error) {
			img, _, err := image.Decode(r)
			return img, err
		},
		func(r io.Reader) (image.Config, error) {
			config, _, err := image.DecodeConfig(r)
			return config, err
		})
}

func main() {
	c := make(chan struct{})
	
	// Register functions to be called from JavaScript
	js.Global().Set("downscaleImage", js.FuncOf(downscaleImage))
	js.Global().Set("estimateGridSize", js.FuncOf(estimateGridSize))
	
	<-c
}

func downscaleImage(this js.Value, args []js.Value) interface{} {
	// Get base64 image data from JavaScript
	imageData := args[0].String()
	grid := args[1].Int()
	
	// Remove data:image/... prefix if present
	originalFormat := ""
	switch {
	case strings.HasPrefix(imageData, "data:image/webp;base64,"):
		originalFormat = "webp"
		imageData = strings.TrimPrefix(imageData, "data:image/webp;base64,")
	case strings.HasPrefix(imageData, "data:image/png;base64,"):
		originalFormat = "png"
		imageData = strings.TrimPrefix(imageData, "data:image/png;base64,")
	case strings.HasPrefix(imageData, "data:image/jpeg;base64,"):
		originalFormat = "jpeg"
		imageData = strings.TrimPrefix(imageData, "data:image/jpeg;base64,")
	case strings.HasPrefix(imageData, "data:image/jpg;base64,"):
		originalFormat = "jpeg"
		imageData = strings.TrimPrefix(imageData, "data:image/jpg;base64,")
	default:
		return map[string]interface{}{
			"error": "Unsupported image format",
		}
	}
	
	// Decode base64 image
	decodedData, err := base64.StdEncoding.DecodeString(imageData)
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Base64 decode error: %v", err),
		}
	}
	
	reader := bytes.NewReader(decodedData)
	img, format, err := image.Decode(reader)
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Image decode error: %v (original format: %s, detected format: %s)", err, originalFormat, format),
		}
	}

	// Process image using downscaleImage function
	result, err := util.DownscaleImageUtil(img, grid, 32, true, 32, "kmeans")
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Processing error: %v", err),
		}
	}

	return map[string]interface{}{
		"results": []interface{}{
			map[string]interface{}{
				"image": result.Image,
				"grid":  result.Grid,
			},
		},
	}
}

func estimateGridSize(this js.Value, args []js.Value) interface{} {
	// Get base64 image data from JavaScript
	imageData := args[0].String()
	
	// Remove data:image/... prefix if present
	originalFormat := ""
	switch {
	case strings.HasPrefix(imageData, "data:image/webp;base64,"):
		originalFormat = "webp"
		imageData = strings.TrimPrefix(imageData, "data:image/webp;base64,")
	case strings.HasPrefix(imageData, "data:image/png;base64,"):
		originalFormat = "png"
		imageData = strings.TrimPrefix(imageData, "data:image/png;base64,")
	case strings.HasPrefix(imageData, "data:image/jpeg;base64,"):
		originalFormat = "jpeg"
		imageData = strings.TrimPrefix(imageData, "data:image/jpeg;base64,")
	case strings.HasPrefix(imageData, "data:image/jpg;base64,"):
		originalFormat = "jpeg"
		imageData = strings.TrimPrefix(imageData, "data:image/jpg;base64,")
	default:
		return map[string]interface{}{
			"error": "Unsupported image format",
		}
	}
	
	// Decode base64 image
	decodedData, err := base64.StdEncoding.DecodeString(imageData)
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Base64 decode error: %v", err),
		}
	}
	
	reader := bytes.NewReader(decodedData)
	img, format, err := image.Decode(reader)
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Image decode error: %v (original format: %s, detected format: %s)", err, originalFormat, format),
		}
	}

	// Process image
	gridSize, err := util.EstimateGridSizeUtil(img)
	if err != nil {
		return map[string]interface{}{
			"error": fmt.Sprintf("Processing error: %v", err),
		}
	}

	return map[string]interface{}{
		"gridSize": gridSize,
	}
}