package util

import (
	"image"

	"math"
)

type EstimateGridRequest struct {
	Image string `json:"image"`
}

type EstimateGridResponse struct {
	GridSize int `json:"gridSize"`
}

func EstimateGridSizeUtil(img image.Image) (int, error) {
	
	bounds := img.Bounds()
	width := bounds.Max.X - bounds.Min.X
	height := bounds.Max.Y - bounds.Min.Y

	// Convert to grayscale and get raw pixel data
	grayData := make([]uint8, width*height)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			// Convert to grayscale using standard luminance formula
			gray := uint8((0.299*float64(r) + 0.587*float64(g) + 0.114*float64(b)) / 256)
			grayData[y*width+x] = gray
		}
	}

	// Edge detection
	edgeCount := 0
	threshold := uint8(24)

	// Iterate through pixels (excluding borders)
	for y := 1; y < height-1; y++ {
		for x := 1; x < width-1; x++ {
			up := grayData[(y-1)*width+x]
			down := grayData[(y+1)*width+x]
			left := grayData[y*width+(x-1)]
			right := grayData[y*width+(x+1)]

			verticalGradient := absDiff(up, down)
			horizontalGradient := absDiff(left, right)

			if verticalGradient > threshold || horizontalGradient > threshold {
				edgeCount++
			}
		}
	}

	// Calculate edge density
	totalPixels := width * height
	edgeDensity := float64(edgeCount) / float64(totalPixels)

	// Base grid size
	baseGridSize := 12.0

	// Calculate density factor
	densityFactor := math.Pow(edgeDensity*100, 0.6)

	// Calculate suggested grid size
	maxDimension := math.Max(float64(width), float64(height))
	suggestedGrid := math.Round(
		baseGridSize *
			(1 + densityFactor) *
			math.Log10(maxDimension/200),
	)

	// Clamp and double the grid size
	finalGrid := int(math.Max(8, math.Min(512, suggestedGrid*2)))

	return finalGrid, nil
}

func absDiff(a, b uint8) uint8 {
	if a > b {
		return a - b
	}
	return b - a
}
