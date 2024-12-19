package util

import (
	"bytes"
	"encoding/base64"

	// "fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"sort"
)



type ProcessImageResult struct {
	Grid  int    `json:"grid"`
	Image string `json:"image"`
}

type DownscaleResponse struct {
	Results []ProcessImageResult `json:"results"`
}

func DownscaleImageUtil(img image.Image, grid int, colorTolerance int, colorQuantization bool, maxColors int, quantizationType string) (ProcessImageResult, error) {
	bounds := img.Bounds()
	width := bounds.Max.X - bounds.Min.X
	height := bounds.Max.Y - bounds.Min.Y

	// Pre-calculate dimensions
	gridWidth := grid
	gridHeight := int(math.Round(float64(height) * float64(gridWidth) / float64(width)))
	cellWidth := float64(width) / float64(gridWidth)
	cellHeight := float64(height) / float64(gridHeight)

	// Initialize color quantizer once if needed
	var dominantColors []color.Color
	var kmeans *KMeansColorQuantizer
	if colorQuantization && quantizationType == "kmeans" {
		kmeans = NewKMeansColorQuantizer(maxColors, 20)
		dominantColors = kmeans.FindDominantColors(img)
	}

	// Pre-allocate output image
	output := image.NewRGBA(image.Rect(0, 0, gridWidth, gridHeight))

	// Pre-allocate slices for color components
	maxCellSize := int(math.Ceil(cellWidth) * math.Ceil(cellHeight))
	rs := make([]uint32, 0, maxCellSize)
	gs := make([]uint32, 0, maxCellSize)
	bs := make([]uint32, 0, maxCellSize)
	as := make([]uint32, 0, maxCellSize)

	// Process each cell
	for y := 0; y < gridHeight; y++ {
		startY := int(math.Floor(float64(y) * cellHeight))
		endY := int(math.Floor(float64(y+1) * cellHeight))

		for x := 0; x < gridWidth; x++ {
			startX := int(math.Floor(float64(x) * cellWidth))
			endX := int(math.Floor(float64(x+1) * cellWidth))

			// Clear slices without reallocating
			rs = rs[:0]
			gs = gs[:0]
			bs = bs[:0]
			as = as[:0]

			// Sample colors from cell
			for cy := startY; cy < endY; cy++ {
				for cx := startX; cx < endX; cx++ {
					r, g, b, a := img.At(cx, cy).RGBA()
					rs = append(rs, r)
					gs = append(gs, g)
					bs = append(bs, b)
					as = append(as, a)
				}
			}

			// Find median color
			medianIndex := len(rs) / 2
			sort.Slice(rs, func(i, j int) bool { return rs[i] < rs[j] })
			sort.Slice(gs, func(i, j int) bool { return gs[i] < gs[j] })
			sort.Slice(bs, func(i, j int) bool { return bs[i] < bs[j] })
			sort.Slice(as, func(i, j int) bool { return as[i] < as[j] })

			medianColor := color.RGBA{
				R: uint8(rs[medianIndex] >> 8),
				G: uint8(gs[medianIndex] >> 8),
				B: uint8(bs[medianIndex] >> 8),
				A: uint8(as[medianIndex] >> 8),
			}

			// Apply color quantization if needed
			if colorQuantization && len(dominantColors) > 0 && quantizationType == "kmeans" {
				medianColor = kmeans.FindClosestColor(medianColor, dominantColors).(color.RGBA)
			}

			output.Set(x, y, medianColor)
		}
	}

	// Encode output image
	var buf bytes.Buffer
	if err := png.Encode(&buf, output); err != nil {
		return ProcessImageResult{}, err
	}

	base64Image := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

	return ProcessImageResult{
		Grid:  grid,
		Image: base64Image,
	}, nil
}

func processImageColors(img image.Image, colorQuantization bool, colorTolerance int, maxColors int, quantizationType string) (ProcessImageResult, error) {
	bounds := img.Bounds()
	return DownscaleImageUtil(img, bounds.Max.X, colorTolerance, colorQuantization, maxColors, quantizationType)
}