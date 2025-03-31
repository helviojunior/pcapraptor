/*
 * PACP - PCAP manipulation tool in Golang
 * Copyright (c) 2025 Helvio Junior <helvio_junior [at] hotmail [dot] com>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package tools

import (
	"time"

	"math/rand"
)

// SliceHasStr checks if a slice has a string
func SliceHasStr(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}

	return false
}

// SliceHasInt checks if a slice has an int
func SliceHasInt(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}

	return false
}

// UniqueIntSlice returns a slice of unique ints
func UniqueIntSlice(slice []int) []int {
	seen := make(map[int]bool)
	result := []int{}

	for _, num := range slice {
		if !seen[num] {
			seen[num] = true
			result = append(result, num)
		}
	}

	return result
}

// ShuffleStr shuffles a slice of strings
func ShuffleStr(slice []string) {
	source := rand.NewSource(time.Now().UnixNano())
	rng := rand.New(source)

	// Fisher-Yates shuffle algorithm
	for i := len(slice) - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		slice[i], slice[j] = slice[j], slice[i]
	}
}
