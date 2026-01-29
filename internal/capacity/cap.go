package capacity

import "math"

// Mul returns a*b if it doesn't overflow, otherwise 0.
func Mul(a, b int) int {
	if a <= 0 || b <= 0 {
		return 0
	}
	if a > math.MaxInt/b {
		return 0
	}
	return a * b
}

// Add returns a+b if it doesn't overflow, otherwise 0.
func Add(a, b int) int {
	if a < 0 || b < 0 {
		return 0
	}
	if a > math.MaxInt-b {
		return 0
	}
	return a + b
}
