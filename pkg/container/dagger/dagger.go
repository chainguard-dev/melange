// Copyright 2023 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dagger

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_oci "chainguard.dev/apko/pkg/build/oci"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/container"
	"dagger.io/dagger"
	"github.com/chainguard-dev/clog"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"go.opentelemetry.io/otel"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

const (
	DaggerName   = "dagger"
	imageTarName = "image.tar"
)

type daggerRunner struct {
	client    *dagger.Client
	container *dagger.Container
	tmpDir    string
}

// NewRunner returns a Dagger Runner implementation.
func NewRunner(ctx context.Context) (container.Runner, error) {
	// initialize Dagger client
	client, err := dagger.Connect(ctx, dagger.WithLogOutput(os.Stderr))
	if err != nil {
		return nil, err
	}
	tmpDir, err := os.MkdirTemp("", "melange-dagger-")
	if err != nil {
		return nil, err
	}
	return &daggerRunner{
		client: client,
		tmpDir: tmpDir,
	}, nil
}

func (d *daggerRunner) Close() error {
	return errors.Join(d.client.Close(), os.RemoveAll(d.tmpDir))
}

// Name name of the runner
func (d *daggerRunner) Name() string {
	return DaggerName
}

// Run runs a Dagger task given a Config and command string.
func (d *daggerRunner) Run(ctx context.Context, cfg *container.Config, envOverride map[string]string, args ...string) error {
	_, span := otel.Tracer("melange").Start(ctx, "dagger.Run")
	defer span.End()

	// Add env in a deterministic order.
	for _, envs := range []map[string]string{cfg.Environment, envOverride} {
		keys := maps.Keys(envs)
		slices.Sort(keys)
		for _, key := range keys {
			val := envs[key]
			d.container = d.container.WithEnvVariable(key, val)
		}
	}

	d.container = d.container.WithExec(args, dagger.ContainerWithExecOpts{})

	var err error
	// Force execution
	d.container, err = d.container.Sync(ctx)
	return err
}

// TestUsability implements Runner.
func (d *daggerRunner) TestUsability(ctx context.Context) bool {
	// TODO: d.client.CheckVersionCompatibility()
	return true
}

// OCIImageLoader used to load OCI images in, if needed. dagger does not need it.
func (d *daggerRunner) OCIImageLoader() container.Loader {
	return &daggerLoader{
		client: d.client,
		tmpDir: d.tmpDir,
	}
}

// TempDir returns the base for temporary directory. For dagger, this is empty.
func (d *daggerRunner) TempDir() string {
	return ""
}

// StartPod kicks off the build.
func (d *daggerRunner) StartPod(ctx context.Context, cfg *container.Config) error {
	log := clog.FromContext(ctx)
	_, span := otel.Tracer("melange").Start(ctx, "dagger.StartPod")
	defer span.End()

	// Initialize the Container from disk
	imgPath := filepath.Join(d.tmpDir, imageTarName)
	d.container = d.client.Container().Import(d.client.Host().File(imgPath))

	// Add our cache dir
	d.container = d.container.WithMountedCache("/var/cache/melange/", d.client.CacheVolume("build-cache"))

	for _, mnt := range cfg.Mounts {

		// We skip mounting in some files that we don't need in this mode
		if mnt.Source == container.DefaultResolvConfPath {
			continue
		}

		// check if its a file or a directory
		fi, err := os.Stat(mnt.Source)
		if err != nil {
			return err
		}

		log.Infof("mounting %s to %s", mnt.Source, mnt.Destination)

		if fi.IsDir() {
			host := d.client.Host().Directory(mnt.Source)
			d.container = d.container.WithMountedDirectory(mnt.Destination, host)
		} else {
			host := d.client.Host().File(mnt.Source)
			d.container = d.container.WithMountedFile(mnt.Destination, host)
		}
	}

	script := "[ -x /sbin/ldconfig ] && /sbin/ldconfig /lib || true"
	d.container = d.container.WithExec([]string{"/bin/sh", "-c", script})
	return nil
}

// TerminatePod implements Runner.
func (d *daggerRunner) TerminatePod(ctx context.Context, cfg *container.Config) error {
	return nil
}

// WorkspaceTar implements Runner.
func (d *daggerRunner) WorkspaceTar(ctx context.Context, cfg *container.Config) (io.ReadCloser, error) {
	clog.FromContext(ctx).Infof("Exporting dagger workspace to %s", cfg.WorkspaceDir)

	ctx, span := otel.Tracer("melange").Start(ctx, "dagger.Export")
	defer span.End()

	output := d.container.Directory("/home/build/melange-out")

	if _, err := output.Export(ctx, cfg.WorkspaceDir+"/melange-out"); err != nil {
		return nil, err
	}

	return nil, nil
}

type daggerLoader struct {
	tmpDir string
	client *dagger.Client
}

func (d *daggerLoader) LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (string, error) {
	ctx, span := otel.Tracer("melange").Start(ctx, "dagger.LoadImage")
	defer span.End()

	creationTime, err := bc.GetBuildDateEpoch()
	if err != nil {
		return "", err
	}

	img, err := apko_oci.BuildImageFromLayer(ctx, empty.Image, layer, bc.ImageConfiguration(), creationTime, arch)
	if err != nil {
		return "", err
	}

	ref, err := name.ParseReference("melange:latest")
	if err != nil {
		return "", err
	}

	tarPath := filepath.Join(d.tmpDir, imageTarName)
	if err := tarball.WriteToFile(tarPath, ref, img); err != nil {
		return "", err
	}
	return ref.String(), nil
}

func (d *daggerLoader) RemoveImage(ctx context.Context, ref string) error {
	return os.Remove(filepath.Join(d.tmpDir, imageTarName))
}
