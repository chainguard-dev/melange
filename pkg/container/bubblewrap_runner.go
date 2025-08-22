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
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"chainguard.dev/melange/internal/logwriter"
	"golang.org/x/sys/unix"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	moby "github.com/moby/moby/oci/caps"
	"go.opentelemetry.io/otel"
)

var _ Debugger = (*bubblewrap)(nil)

const (
	BubblewrapName = "bubblewrap"
	buildUserID    = "1000"
)

type bubblewrap struct {
	remove bool // if true, clean up temp dirs on close.
}

// BubblewrapRunner returns a Bubblewrap Runner implementation.
func BubblewrapRunner(remove bool) Runner {
	return &bubblewrap{remove: remove}
}

func (bw *bubblewrap) Close() error {
	return nil
}

// Name of the runner.
func (bw *bubblewrap) Name() string {
	return BubblewrapName
}

// Run runs a Bubblewrap task given a Config and command string.
func (bw *bubblewrap) Run(ctx context.Context, cfg *Config, envOverride map[string]string, args ...string) error {
	execCmd := bw.cmd(ctx, cfg, false, envOverride, args...)

	log := clog.FromContext(ctx)
	stdout, stderr := logwriter.New(log.Info), logwriter.New(log.Warn)
	defer stdout.Close()
	defer stderr.Close()

	execCmd.Stdout = stdout
	execCmd.Stderr = stderr

	return execCmd.Run()
}

func (bw *bubblewrap) testUnshareUser(ctx context.Context) error {
	execCmd := exec.CommandContext(ctx, "bwrap", "--unshare-user", "true")
	execCmd.Env = append(os.Environ(), "LANG=C")
	out, err := execCmd.CombinedOutput()
	if err == nil {
		return nil
	}

	if !bytes.Contains(out, []byte("setting up uid map")) {
		return nil
	}

	return fmt.Errorf("%s\n",
		strings.Join([]string{
			"Unable to execute 'bwrap --unshare-user true'.",
			"Command failed with: ",
			"  " + string(out),
			"See https://github.com/chainguard-dev/melange/issues/1508 for fix",
		}, "\n"))
}

func (bw *bubblewrap) cmd(ctx context.Context, cfg *Config, debug bool, envOverride map[string]string, args ...string) *exec.Cmd {
	baseargs := []string{}

	// always be sure to mount the / first!
	baseargs = append(baseargs, "--bind", cfg.ImgRef, "/")

	for _, bind := range cfg.Mounts {
		baseargs = append(baseargs, "--bind", bind.Source, bind.Destination)
	}
	// add the ref of the directory

	baseargs = append(baseargs, "--unshare-pid", "--die-with-parent",
		"--dev", "/dev",
		"--proc", "/proc",
		"--ro-bind", "/sys", "/sys",
		"--chdir", runnerWorkdir,
		"--clearenv")

	// If we need to run as an user, we run as that user.
	if cfg.RunAsUID != "" {
		gid := cfg.RunAsGID
		if gid == "" {
			// no gid given, fall back to UID, may fail
			// if GID == UID doesn't exist in the environment
			gid = cfg.RunAsUID
		}
		baseargs = append(baseargs, "--unshare-user")
		baseargs = append(baseargs, "--uid", cfg.RunAsUID)
		baseargs = append(baseargs, "--gid", gid)
		// Else if we're not using melange as root, we force the use of the
		// Apko build user. This avoids problems on machines where default
		// regular user is NOT 1000.
	} else if os.Getuid() > 0 {
		baseargs = append(baseargs, "--unshare-user")
		baseargs = append(baseargs, "--uid", buildUserID)
		baseargs = append(baseargs, "--gid", buildUserID)
	}

	// Add Docker runner-parity kernel capabilities to the container.
	for _, c := range moby.DefaultCapabilities() {
		baseargs = append(baseargs, "--cap-add", c)
	}
	// Add additional process kernel capabilities to the container as configured.
	if cfg.Capabilities.Add != nil {
		for _, c := range cfg.Capabilities.Add {
			baseargs = append(baseargs, "--cap-add", c)
		}
	}
	// Drop process kernel capabilities from the container as configured.
	if cfg.Capabilities.Drop != nil {
		for _, c := range cfg.Capabilities.Drop {
			baseargs = append(baseargs, "--cap-drop", c)
		}
	}

	if !debug {
		// This flag breaks job control, which we only care about for --interactive debugging.
		// So we usually include it, but if we're about to debug, don't set it.
		baseargs = append(baseargs, "--new-session")
	}

	if !cfg.Capabilities.Networking {
		baseargs = append(baseargs, "--unshare-net")
	}

	for k, v := range cfg.Environment {
		baseargs = append(baseargs, "--setenv", k, v)
	}
	for k, v := range envOverride {
		baseargs = append(baseargs, "--setenv", k, v)
	}

	args = append(baseargs, args...)
	execCmd := exec.CommandContext(ctx, "bwrap", args...)

	clog.FromContext(ctx).Debugf("executing: %s", strings.Join(execCmd.Args, " "))

	return execCmd
}

func (bw *bubblewrap) Debug(ctx context.Context, cfg *Config, envOverride map[string]string, args ...string) error {
	execCmd := bw.cmd(ctx, cfg, true, envOverride, args...)

	execCmd.Stdout = os.Stdout
	execCmd.Stderr = os.Stderr
	execCmd.Stdin = os.Stdin

	return execCmd.Run()
}

// TestUsability determines if the Bubblewrap runner can be used
// as a container runner.
func (bw *bubblewrap) TestUsability(ctx context.Context) bool {
	log := clog.FromContext(ctx)
	if _, err := exec.LookPath("bwrap"); err != nil {
		log.Warnf("cannot use bubblewrap for containers: bwrap not found on $PATH")
		return false
	}

	if err := bw.testUnshareUser(ctx); err != nil {
		log.Warnf("%s", err)
		return false
	}

	return true
}

// OCIImageLoader used to load OCI images in, if needed. bubblewrap does not need it.
func (bw *bubblewrap) OCIImageLoader() Loader {
	return &bubblewrapOCILoader{remove: bw.remove}
}

// TempDir returns the base for temporary directory. For bubblewrap, this is empty.
func (bw *bubblewrap) TempDir() string {
	return ""
}

// StartPod starts a pod if necessary.  On Bubblewrap, we just run
// ldconfig to prime ld.so.cache for glibc < 2.37 builds.
func (bw *bubblewrap) StartPod(ctx context.Context, cfg *Config) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "bubblewrap.StartPod")
	defer span.End()

	script := "[ -x /sbin/ldconfig ] && /sbin/ldconfig /lib || true"
	return bw.Run(ctx, cfg, nil, "/bin/sh", "-c", script)
}

// TerminatePod terminates a pod if necessary.  Not implemented
// for Bubblewrap runners.
func (bw *bubblewrap) TerminatePod(ctx context.Context, cfg *Config) error {
	return nil
}

// WorkspaceTar implements Runner
// This is a noop for Bubblewrap, which uses bind-mounts to manage the workspace
func (bw *bubblewrap) WorkspaceTar(ctx context.Context, cfg *Config, extraFiles []string) (io.ReadCloser, error) {
	return nil, nil
}

// GetReleaseData returns the OS information (os-release contents) for the Bubblewrap runner.
func (bw *bubblewrap) GetReleaseData(ctx context.Context, cfg *Config) (*apko_build.ReleaseData, error) {
	// Read the os-release through a bubblewrap command
	execCmd := bw.cmd(ctx, cfg, false, nil, "cat", "/etc/os-release")

	log := clog.FromContext(ctx)
	stderr := logwriter.New(log.Warn)
	defer stderr.Close()
	var buf bytes.Buffer
	bufWriter := bufio.NewWriter(&buf)
	defer bufWriter.Flush()

	execCmd.Stdout = bufWriter
	execCmd.Stderr = stderr
	err := execCmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to read os-release: %w", err)
	}

	return apko_build.ParseReleaseData(&buf)
}

type bubblewrapOCILoader struct {
	remove   bool
	guestDir string
}

func (b *bubblewrapOCILoader) LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (ref string, err error) {
	_, span := otel.Tracer("melange").Start(ctx, "bubblewrap.LoadImage")
	defer span.End()

	// bubblewrap does not have the idea of container images or layers or such, just
	// straight out chroot, so we create the guest dir
	guestDir, err := os.MkdirTemp("", "bubblewrap-guest-*")
	if err != nil {
		return ref, fmt.Errorf("failed to create guest dir: %w", err)
	}
	b.guestDir = guestDir
	rc, err := layer.Uncompressed()
	if err != nil {
		return ref, fmt.Errorf("failed to read layer tarball: %w", err)
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		fullname := filepath.Join(guestDir, hdr.Name)
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(fullname, hdr.FileInfo().Mode().Perm()); err != nil {
				return ref, fmt.Errorf("failed to create directory %s: %w", fullname, err)
			}
			continue
		case tar.TypeReg:
			f, err := os.OpenFile(fullname, os.O_CREATE|os.O_WRONLY, hdr.FileInfo().Mode().Perm())
			if err != nil {
				return ref, fmt.Errorf("failed to create file %s: %w", fullname, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				return ref, fmt.Errorf("failed to copy file %s: %w", fullname, err)
			}
			f.Close()
		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, filepath.Join(guestDir, hdr.Name)); err != nil {
				return ref, fmt.Errorf("failed to create symlink %s: %w", fullname, err)
			}
		case tar.TypeLink:
			if err := os.Link(filepath.Join(guestDir, hdr.Linkname), filepath.Join(guestDir, hdr.Name)); err != nil {
				return ref, fmt.Errorf("failed to create hardlink %s: %w", fullname, err)
			}
		default:
			// TODO: Is this correct? We are loading these into the directory, so character devices and such
			// do not really matter to us, but maybe they should?
			continue
		}

		for k, v := range hdr.PAXRecords {
			if !strings.HasPrefix(k, "SCHILY.xattr.") {
				continue
			}
			attrName := strings.TrimPrefix(k, "SCHILY.xattr.")
			if err := unix.Setxattr(fullname, attrName, []byte(v), 0); err != nil {
				return ref, fmt.Errorf("unable to set xattr %s on %s: %w", attrName, hdr.Name, err)
			}
		}
	}
	return guestDir, nil
}

func (b *bubblewrapOCILoader) RemoveImage(ctx context.Context, ref string) error {
	clog.FromContext(ctx).Debugf("removing image path %s", ref)
	if b.remove {
		os.RemoveAll(b.guestDir)
	}
	return os.RemoveAll(ref)
}
