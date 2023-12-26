// Copyright 2022 Chainguard, Inc.
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

package container

import (
	"context"
	"io"
	"os"
	"path/filepath"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_oci "chainguard.dev/apko/pkg/build/oci"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/log"
	"dagger.io/dagger"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"go.opentelemetry.io/otel"
)

const DaggerName = "dagger"
const imageTarName = "image.tar"

type daggerRunner struct {
	logger    log.Logger
	client    *dagger.Client
	container *dagger.Container
	tmpDir    string
}

// DaggerRunner returns a Dagger Runner implementation.
func DaggerRunner(ctx context.Context, logger log.Logger) (Runner, error) {
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
		logger: logger,
		client: client,
		tmpDir: tmpDir,
	}, nil
}

// Name name of the runner
func (bw *daggerRunner) Name() string {
	return DaggerName
}

// Run runs a Dagger task given a Config and command string.
func (d *daggerRunner) Run(ctx context.Context, cfg *Config, args ...string) error {
	_, span := otel.Tracer("melange").Start(ctx, "dagger.Run")
	defer span.End()

	for key, val := range cfg.Environment {
		d.container = d.container.WithEnvVariable(key, val)
	}
	d.container = d.container.WithExec(args, dagger.ContainerWithExecOpts{})

	var err error
	// Force execution
	d.container, err = d.container.Sync(ctx)
	return err
}

// TestUsability determines if the Bubblewrap runner can be used
// as a container runner.
func (d *daggerRunner) TestUsability(ctx context.Context) bool {
	return true
}

// OCIImageLoader used to load OCI images in, if needed. dagger does not need it.
func (d *daggerRunner) OCIImageLoader() Loader {
	return &daggerLoader{
		client: d.client,
		tmpDir: d.tmpDir,
	}
}

// TempDir returns the base for temporary directory. For dagger, this is empty.
func (d *daggerRunner) TempDir() string {
	return ""
}

// StartPod starts a pod if necessary.  On Bubblewrap, we just run
// ldconfig to prime ld.so.cache for glibc < 2.37 builds.
func (d *daggerRunner) StartPod(ctx context.Context, cfg *Config) error {
	_, span := otel.Tracer("melange").Start(ctx, "dagger.StartPod")
	defer span.End()

	// Initialize the Container from disk
	imgPath := filepath.Join(d.tmpDir, imageTarName)
	d.container = d.client.Container().Import(d.client.Host().File(imgPath))

	// Add our cache dir
	d.container = d.container.WithMountedCache("/var/cache/melange/", d.client.CacheVolume("build-cache"))

	for _, mnt := range cfg.Mounts {

		// We skip mounting in some files that we don't need in this mode
		if mnt.Source == "/etc/resolv.conf" {
			continue
		}

		// check if its a file or a directory
		fi, err := os.Stat(mnt.Source)
		if err != nil {
			return err
		}

		d.logger.Infof("mounting %s to %s", mnt.Source, mnt.Destination)

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

// TerminatePod terminates a pod if necessary.  Not implemented
// for Bubblewrap runners.
func (d *daggerRunner) TerminatePod(ctx context.Context, cfg *Config) error {
	return nil
}

func (d *daggerRunner) WorkspaceTar(ctx context.Context, cfg *Config) (io.ReadCloser, error) {
	return nil, nil
}

// WorkspaceTar implements Runner
func (d *daggerRunner) Export(ctx context.Context, p string) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "docker.Export")
	defer span.End()
	output := d.container.Directory("/home/build/melange-out")
	if _, err := output.Export(ctx, p+"/melange-out"); err != nil {
		return err
	}
	return nil
}

type daggerLoader struct {
	tmpDir string
	client *dagger.Client
}

func (d *daggerLoader) LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (string, error) {
	ctx, span := otel.Tracer("melange").Start(ctx, "docker.LoadImage")
	defer span.End()

	creationTime, err := bc.GetBuildDateEpoch()
	if err != nil {
		return "", err
	}

	img, err := apko_oci.BuildImageFromLayer(layer, bc.ImageConfiguration(), creationTime, arch, bc.Logger())
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
