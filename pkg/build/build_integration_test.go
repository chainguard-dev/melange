//go:build integration
// +build integration

package build

import (
	"context"
	"path/filepath"
	"testing"

	"chainguard.dev/melange/pkg/container/docker"
)

func TestBuild_BuildPackage(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "crane.yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join("testdata", "build_configs", tt.name)

			ctx := context.Background()
			r, err := docker.NewRunner(ctx) // TODO: is access to Docker a safe assumption in CI?
			if err != nil {
				t.Fatalf("creating docker runner: %v", err)
			}

			b, err := New(
				ctx,
				WithConfig(p),
				WithConfigFileRepositoryURL("https://github.com/wolfi-dev/os"),
				WithConfigFileRepositoryCommit("abcdef"),
				WithRunner(r),
				WithNamespace("wolfi"),
			)
			if err != nil {
				t.Fatal(err)
			}

			if err := b.BuildPackage(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}
