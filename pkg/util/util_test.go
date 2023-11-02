package util

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDedup(t *testing.T) {
	a := []int{0, 1, 2, 3, 1, 4, 5, 9, 16, 9, 12, 9, 9, 9, 13, 12, 15, 17, 15}
	b := Dedup(a)

	require.Equal(t, len(b), 12, "the deduplicated list should have 12 elements")
}
