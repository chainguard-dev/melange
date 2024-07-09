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

package docker

import (
	"context"
	"fmt"
	"io"
	"os"

	"go.opentelemetry.io/otel"
	"golang.org/x/sync/errgroup"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_oci "chainguard.dev/apko/pkg/build/oci"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/internal/contextreader"
	"chainguard.dev/melange/internal/logwriter"
	mcontainer "chainguard.dev/melange/pkg/container"
	"github.com/chainguard-dev/clog"
	"github.com/docker/cli/cli/streams"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	image_spec "github.com/opencontainers/image-spec/specs-go/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

var _ mcontainer.Debugger = (*docker)(nil)

const (
	DockerName = "docker"

	runnerWorkdir = "/home/build"
)

// docker is a Runner implementation that uses the docker library.
type docker struct {
	cli *client.Client
}

// NewRunner returns a Docker Runner implementation.
func NewRunner(ctx context.Context) (mcontainer.Runner, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}

	return &docker{
		cli: cli,
	}, nil
}

func (dk *docker) Name() string {
	return DockerName
}

func (dk *docker) Close() error {
	return dk.cli.Close()
}

// StartPod starts a pod for supporting a Docker task, if
// necessary.
func (dk *docker) StartPod(ctx context.Context, cfg *mcontainer.Config) error {
	log := clog.FromContext(ctx)

	ctx, span := otel.Tracer("melange").Start(ctx, "docker.StartPod")
	defer span.End()

	mounts := []mount.Mount{}
	for _, bind := range cfg.Mounts {
		// We skip mounting in some files that we don't need in this mode
		if bind.Source == mcontainer.DefaultResolvConfPath {
			continue
		}

		mounts = append(mounts, mount.Mount{
			Type:   mount.TypeBind,
			Source: bind.Source,
			Target: bind.Destination,
		})
	}

	hostConfig := &container.HostConfig{
		Mounts:    mounts,
		Resources: container.Resources{},
	}

	if cfg.CPU != "" {
		res, err := resource.ParseQuantity(cfg.CPU)
		if err != nil {
			return fmt.Errorf("parsing CPU resource: %w", err)
		}
		hostConfig.Resources.NanoCPUs = int64(res.AsApproximateFloat64() * 1000000000)
	}
	if cfg.Memory != "" {
		res, err := resource.ParseQuantity(cfg.Memory)
		if err != nil {
			return fmt.Errorf("parsing memory resource: %w", err)
		}
		hostConfig.Resources.Memory = res.Value()
	}

	platform := &image_spec.Platform{
		Architecture: cfg.Arch.String(),
		OS:           "linux",
	}

	// ldconfig is run to prime ld.so.cache for glibc packages which require it.
	resp, err := dk.cli.ContainerCreate(ctx, &container.Config{
		Image: cfg.ImgRef,
		Cmd:   []string{"/bin/sh", "-c", "[ -x /sbin/ldconfig ] && /sbin/ldconfig /lib || true\nwhile true; do sleep 5; done"},
		Tty:   false,
		Labels: map[string]string{
			"dev.chainguard.melange":         "true",
			"dev.chainguard.melange.package": cfg.PackageName,
		},
	}, hostConfig, nil, platform, "")
	if err != nil {
		return err
	}

	if err := dk.cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
		return err
	}

	cfg.PodID = resp.ID
	log.Debugf("pod %s started", cfg.PodID)

	return nil
}

// TerminatePod terminates a pod for supporting a Docker task,
// if necessary.
func (dk *docker) TerminatePod(ctx context.Context, cfg *mcontainer.Config) error {
	log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "docker.TerminatePod")
	defer span.End()

	if cfg.PodID == "" {
		return fmt.Errorf("pod not running")
	}

	if err := dk.cli.ContainerRemove(ctx, cfg.PodID, container.RemoveOptions{
		Force: true,
	}); err != nil {
		return err
	}

	log.Infof("pod %s terminated", cfg.PodID)

	return nil
}

// TestUsability determines if the Docker runner can be used
// as a container runner.
func (dk *docker) TestUsability(ctx context.Context) bool {
	log := clog.FromContext(ctx)
	if _, err := dk.cli.Ping(ctx); err != nil {
		log.Infof("cannot use docker for containers: %v", err)
		return false
	}

	return true
}

// OCIImageLoader create a loader to load an OCI image into the docker daemon.
func (dk *docker) OCIImageLoader() mcontainer.Loader {
	return &dockerLoader{
		cli: dk.cli,
	}
}

// TempDir returns the base for temporary directory. For docker
// this is whatever the system provides.
func (dk *docker) TempDir() string {
	return ""
}

// waitForCommand waits for a command to complete in the pod.
func (dk *docker) waitForCommand(ctx context.Context, r io.Reader) error {
	// log := clog.FromContext(ctx)
	ctx, span := otel.Tracer("melange").Start(ctx, "waitForCommand")
	defer span.End()

	log := clog.FromContext(ctx)
	stdout, stderr := logwriter.New(log.Info), logwriter.New(log.Warn)
	defer stdout.Close()
	defer stderr.Close()

	// Wrap this in a contextReader so we respond to cancel.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ctxr := contextreader.New(ctx, r)

	_, err := stdcopy.StdCopy(stdout, stderr, ctxr)
	return err
}

// Run runs a Docker task given a Config and command string.
// The resultant filesystem can be read from the io.ReadCloser
func (dk *docker) Run(ctx context.Context, cfg *mcontainer.Config, envOverride map[string]string, args ...string) error {
	if cfg.PodID == "" {
		return fmt.Errorf("pod not running")
	}

	environ := []string{}
	for k, v := range cfg.Environment {
		environ = append(environ, fmt.Sprintf("%s=%s", k, v))
	}
	for k, v := range envOverride {
		environ = append(environ, fmt.Sprintf("%s=%s", k, v))
	}

	taskIDResp, err := dk.cli.ContainerExecCreate(ctx, cfg.PodID, container.ExecOptions{
		User:         cfg.RunAs,
		Cmd:          args,
		WorkingDir:   runnerWorkdir,
		Env:          environ,
		Tty:          false,
		AttachStderr: true,
		AttachStdout: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create exec task inside pod: %w", err)
	}

	attachResp, err := dk.cli.ContainerExecAttach(ctx, taskIDResp.ID, container.ExecStartOptions{
		Tty: false,
	})
	if err != nil {
		return fmt.Errorf("failed to attach to exec task: %w", err)
	}
	defer attachResp.Close()

	if err := dk.waitForCommand(ctx, attachResp.Reader); err != nil {
		return err
	}

	inspectResp, err := dk.cli.ContainerExecInspect(ctx, taskIDResp.ID)
	if err != nil {
		return fmt.Errorf("failed to get exit code from task: %w", err)
	}

	switch inspectResp.ExitCode {
	case 0:
		return nil
	default:
		return fmt.Errorf("task exited with code %d", inspectResp.ExitCode)
	}
}

func (dk *docker) Debug(ctx context.Context, cfg *mcontainer.Config, envOverride map[string]string, args ...string) error {
	if cfg.PodID == "" {
		return fmt.Errorf("pod not running")
	}

	environ := []string{}
	for k, v := range cfg.Environment {
		environ = append(environ, fmt.Sprintf("%s=%s", k, v))
	}
	for k, v := range envOverride {
		environ = append(environ, fmt.Sprintf("%s=%s", k, v))
	}

	outterm := streams.NewOut(os.Stdout)
	h, w := outterm.GetTtySize()
	size := [2]uint{h, w}

	taskIDResp, err := dk.cli.ContainerExecCreate(ctx, cfg.PodID, container.ExecOptions{
		Cmd:          args,
		WorkingDir:   runnerWorkdir,
		Env:          environ,
		Tty:          true,
		ConsoleSize:  &size,
		AttachStdin:  true,
		AttachStderr: true,
		AttachStdout: true,
	})
	if err != nil {
		return fmt.Errorf("failed to create debug exec task inside pod: %w", err)
	}

	attachResp, err := dk.cli.ContainerExecAttach(ctx, taskIDResp.ID, container.ExecStartOptions{
		ConsoleSize: &size,
		Tty:         true,
	})
	if err != nil {
		return fmt.Errorf("failed to attach to exec task: %w", err)
	}
	defer attachResp.Close()

	if err := outterm.SetRawTerminal(); err != nil {
		return fmt.Errorf("set raw out: %w", err)
	}
	defer outterm.RestoreTerminal()

	// When the container exits, we call cancelin() to stop Copy()ing from stdin.
	inctx, cancelin := context.WithCancel(ctx)

	var g errgroup.Group

	// Wire up stdin to into a tty into the Attach connection.
	g.Go(func() error {
		interm := streams.NewIn(os.Stdin)
		if err := interm.SetRawTerminal(); err != nil {
			return fmt.Errorf("set raw in: %w", err)
		}
		defer interm.RestoreTerminal()

		// Allows us to cancel the Read().
		ctxr := contextreader.New(inctx, interm)

		if _, err := io.Copy(attachResp.Conn, ctxr); err != nil {
			return fmt.Errorf("copy in : %w", err)
		}

		return nil
	})

	// Copy from the Attach reader to stdout tty.
	g.Go(func() error {
		defer cancelin()

		if _, err := io.Copy(outterm, attachResp.Reader); err != nil {
			return fmt.Errorf("copy out: %w", err)
		}

		return nil
	})

	if err := g.Wait(); err != nil {
		return err
	}

	// Poll docker once per second to see if the container has exited yet.
	inspectResp, err := dk.cli.ContainerExecInspect(ctx, taskIDResp.ID)
	if err != nil {
		return fmt.Errorf("failed to get exit code from task: %w", err)
	}
	if inspectResp.Running {
		return fmt.Errorf("container still running")
	}
	switch inspectResp.ExitCode {
	case 0:
		return nil
	default:
		return fmt.Errorf("task exited with code %d", inspectResp.ExitCode)
	}
}

// WorkspaceTar implements Runner
// This is a noop for Docker, which uses bind-mounts to manage the workspace
func (dk *docker) WorkspaceTar(ctx context.Context, cfg *mcontainer.Config) (io.ReadCloser, error) {
	return nil, nil
}

type dockerLoader struct {
	cli *client.Client
}

func (d *dockerLoader) LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (string, error) {
	ctx, span := otel.Tracer("melange").Start(ctx, "docker.LoadImage")
	defer span.End()

	creationTime, err := bc.GetBuildDateEpoch()
	if err != nil {
		return "", err
	}

	img, err := apko_oci.BuildImageFromLayer(ctx, empty.Image, layer, bc.ImageConfiguration(), creationTime, arch)
	if err != nil {
		return "", err
	}

	ref, err := apko_oci.LoadImage(ctx, img, []string{"melange:latest"})
	if err != nil {
		return "", err
	}
	return ref.String(), nil
}

func (d *dockerLoader) RemoveImage(ctx context.Context, ref string) error {
	log := clog.FromContext(ctx)
	log.Infof("deleting image %s", ref)
	resps, err := d.cli.ImageRemove(ctx, ref, image.RemoveOptions{
		Force:         true,
		PruneChildren: true,
	})
	if err != nil {
		return err
	}

	for _, resp := range resps {
		if resp.Untagged != "" {
			log.Infof("untagged %s", resp.Untagged)
		}
		if resp.Deleted != "" {
			log.Infof("deleted %s", resp.Deleted)
		}
	}

	return nil
}
