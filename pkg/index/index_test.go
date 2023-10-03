package index

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIndex_LoadIndex(t *testing.T) {
	idx, err := New(WithExpectedArch("x86_64"))
	assert.NoError(t, err)

	err = idx.LoadIndex("https://packages.wolfi.dev/os")
	assert.NoError(t, err)

	assert.NotEmpty(t, idx.Index.Packages)
}
