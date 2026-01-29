package capacity

import (
	"math"
	"testing"
)

func TestMul(t *testing.T) {
	tests := []struct {
		name string
		a, b int
		want int
	}{
		{"simple", 3, 4, 12},
		{"zero a", 0, 5, 0},
		{"zero b", 5, 0, 0},
		{"negative", -1, 5, 0},
		{"at limit", math.MaxInt / 2, 2, (math.MaxInt / 2) * 2},
		{"overflow", math.MaxInt/2 + 1, 2, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Mul(tt.a, tt.b); got != tt.want {
				t.Errorf("Mul(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestAdd(t *testing.T) {
	tests := []struct {
		name string
		a, b int
		want int
	}{
		{"simple", 3, 4, 7},
		{"zero a", 0, 5, 5},
		{"zero b", 5, 0, 5},
		{"negative", -1, 5, 0},
		{"at limit", math.MaxInt - 1, 1, math.MaxInt},
		{"overflow", math.MaxInt, 1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Add(tt.a, tt.b); got != tt.want {
				t.Errorf("Add(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
