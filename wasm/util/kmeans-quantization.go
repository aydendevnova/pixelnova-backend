package util

import (
	"image"
	"image/color"
	"math"
)

const MAX_K_MEANS_PIXELS = 50000

type KMeansColorQuantizer struct {
	maxColors     int
	maxIterations int
	rngSeed       int64
}

func NewKMeansColorQuantizer(maxColors int, maxIterations int) *KMeansColorQuantizer {
	return &KMeansColorQuantizer{
		maxColors:     maxColors,
		maxIterations: maxIterations,
		rngSeed:      1234, // Initial seed
	}
}

func (k *KMeansColorQuantizer) random() float64 {
	k.rngSeed = (k.rngSeed*9301 + 49297) % 233280
	return float64(k.rngSeed) / 233280
}

func (k *KMeansColorQuantizer) arraysEqual(a1, a2 []int) bool {
	if len(a1) != len(a2) {
		return false
	}
	for i := 0; i < len(a1); i++ {
		if a1[i] != a2[i] {
			return false
		}
	}
	return true
}

func (k *KMeansColorQuantizer) calculateCentroid(cluster [][]int) []int {
	if len(cluster) == 0 || len(cluster[0]) == 0 {
		return []int{}
	}

	dimensions := len(cluster[0])
	centroid := make([]float64, dimensions)

	for i := 0; i < len(cluster); i++ {
		point := cluster[i]
		for j := 0; j < dimensions; j++ {
			centroid[j] += (float64(point[j]) - centroid[j]) / float64(i+1)
		}
	}

	result := make([]int, dimensions)
	for i := range centroid {
		result[i] = int(math.Round(centroid[i]))
	}
	return result
}

func (k *KMeansColorQuantizer) nearestNeighbor(point []int, neighbors [][]int) int {
	bestDist := math.MaxFloat64
	bestIndex := -1

	for i, neighbor := range neighbors {
		var dist float64
		for j := range point {
			diff := float64(point[j] - neighbor[j])
			dist += diff * diff
		}
		if dist < bestDist {
			bestDist = dist
			bestIndex = i
		}
	}

	return bestIndex
}

func (k *KMeansColorQuantizer) FindDominantColors(img image.Image) []color.Color {
	bounds := img.Bounds()
	width := bounds.Max.X - bounds.Min.X
	height := bounds.Max.Y - bounds.Min.Y

	// Convert image to RGB points
	dataset := make([][]int, 0)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			r, g, b, _ := img.At(x, y).RGBA()
			dataset = append(dataset, []int{int(r >> 8), int(g >> 8), int(b >> 8)})
		}
	}

	// Subsample if dataset is too large
	if len(dataset) > MAX_K_MEANS_PIXELS {
		stride := int(math.Ceil(float64(len(dataset)) / float64(MAX_K_MEANS_PIXELS)))
		sampledDataset := make([][]int, 0)
		for i := 0; i < len(dataset); i += stride {
			sampledDataset = append(sampledDataset, dataset[i])
		}
		dataset = sampledDataset
	}

	// Initialize centroids randomly
	kk := min(k.maxColors, len(dataset))
	centroids := make([][]int, kk)
	for i := 0; i < kk; i++ {
		idx := int(k.random() * float64(len(dataset)))
		centroids[i] = make([]int, len(dataset[0]))
		copy(centroids[i], dataset[idx])
	}

	// K-means iteration
	for iteration := 0; iteration < k.maxIterations; iteration++ {
		clusters := make([][][]int, kk)
		for i := range clusters {
			clusters[i] = make([][]int, 0)
		}

		// Assign points to nearest centroid
		for _, point := range dataset {
			nearestCentroidIndex := k.nearestNeighbor(point, centroids)
			clusters[nearestCentroidIndex] = append(clusters[nearestCentroidIndex], point)
		}

		// Update centroids
		converged := true
		for i := 0; i < kk; i++ {
			cluster := clusters[i]
			var newCentroid []int
			if len(cluster) > 0 {
				newCentroid = k.calculateCentroid(cluster)
			} else {
				idx := int(k.random() * float64(len(dataset)))
				newCentroid = make([]int, len(dataset[0]))
				copy(newCentroid, dataset[idx])
			}

			converged = converged && k.arraysEqual(newCentroid, centroids[i])
			centroids[i] = newCentroid
		}

		if converged {
			break
		}
	}

	// Convert centroids to color.Color
	colors := make([]color.Color, len(centroids))
	for i, c := range centroids {
		colors[i] = color.RGBA{
			R: uint8(c[0]),
			G: uint8(c[1]),
			B: uint8(c[2]),
			A: 255,
		}
	}

	return colors
}

func (k *KMeansColorQuantizer) FindClosestColor(c color.Color, dominantColors []color.Color) color.Color {
	r1, g1, b1, _ := c.RGBA()
	r1 >>= 8
	g1 >>= 8
	b1 >>= 8

	minDistance := math.MaxFloat64
	var closestColor color.Color = dominantColors[0]

	for _, dc := range dominantColors {
		r2, g2, b2, _ := dc.RGBA()
		r2 >>= 8
		g2 >>= 8
		b2 >>= 8

		distance := k.colorDistance([]int{int(r1), int(g1), int(b1)}, []int{int(r2), int(g2), int(b2)})
		if distance < minDistance {
			minDistance = distance
			closestColor = dc
		}
	}

	return closestColor
}

func (k *KMeansColorQuantizer) colorDistance(color1, color2 []int) float64 {
	var distance float64
	for i := 0; i < len(color1); i++ {
		diff := float64(color1[i] - color2[i])
		distance += diff * diff
	}
	return distance
} 