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
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_oci "chainguard.dev/apko/pkg/build/oci"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/options"
	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/lima-vm/lima/pkg/limayaml"
	limastore "github.com/lima-vm/lima/pkg/store"
	"go.opentelemetry.io/otel"
)

const (
	melangeVMName         = "melange-builder"
	melangeWritableParent = "/tmp/melange"
	// containerImageName name to use; this MUST be the fully qualified name, because we intend to work directly with containerd in the future
	containerImageName = "index.docker.io/library/melange:latest"

	LimaName = "lima"
)

//go:embed lima.yaml
var config []byte

var nerdctlLoadRE = regexp.MustCompile(`unpacking (\S+) \((sha256:[a-f0-9]+)\)`)

type lima struct {
}

// LimaRunner returns a lima with nerdctl Runner implementation.
// It uses the limactl CLI to manage the VM, and lima CLI to
// execute commands inside the VM.
// This could be replaced at some point by a lima library, when such a thing exists.
// For now, most commands that we use - limactl start, limactl stop, limactl delete,
// limactl list, lima nerctl run - are implemented as logic in github.com/lima-vm/lima/cmd
// rather than as a library surface.
func LimaRunner(ctx context.Context) (Runner, error) {
	l := &lima{}
	// make sure our VM is running
	if err := l.startVM(ctx); err != nil {
		return nil, err
	}

	return l, nil
}

func (l *lima) Name() string {
	return LimaName
}

// TODO: check that guest dir is correct

// OCIImageLoader create a loader to load an OCI image into the docker daemon.
func (l *lima) OCIImageLoader() Loader {
	return &limaOCILoader{
		lima: l,
	}
}

// TempDir returns the base for temporary directory. For lima
// this is /tmp/melange, as that is what is mounted r/w into the melange-builder VM.
func (l *lima) TempDir() string {
	return melangeWritableParent
}

// Run runs a lima task given a Config and command string.
func (l *lima) Run(ctx context.Context, cfg *Config, args ...string) error {
	if cfg.PodID == "" {
		return fmt.Errorf("pod not running")
	}

	// TODO(epsilon-phase): building as the user "build" was removed from lima runner
	// for consistency with other runners and to ensure that packages can be generated with files
	// that have owners other than root. We should explore using fakeroot or similar tricks for these use-cases.
	baseargs := []string{"exec", "-w", runnerWorkdir}
	for k, v := range cfg.Environment {
		baseargs = append(baseargs, "-e", fmt.Sprintf("%s=%s", k, v))
	}
	baseargs = append(baseargs, cfg.PodID)
	baseargs = append(baseargs, args...)

	err := l.nerdctl(ctx, melangeVMName, nil, nil, nil, baseargs...)
	return err
}

// StartPod starts a pod for supporting a lima task.
func (l *lima) StartPod(ctx context.Context, cfg *Config) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "lima.StartPod")
	defer span.End()

	// make sure our VM is running
	if err := l.startVM(ctx); err != nil {
		return err
	}

	args := []string{"run", "--detach"}
	for _, bind := range cfg.Mounts {
		args = append(args, "--volume", fmt.Sprintf("%s:%s", bind.Source, bind.Destination))
	}

	if !cfg.Capabilities.Networking {
		args = append(args, "--network=none")
	}

	for k, v := range cfg.Environment {
		args = append(args, "--env", fmt.Sprintf("%s=%s", k, v))
	}
	args = append(args, fmt.Sprintf("--platform=%s", cfg.Arch.String()))

	cmd := []string{"/bin/sh", "-c", "while true; do sleep 5; done"}

	digest, err := digestFromRef(cfg.ImgRef)
	if err != nil {
		return err
	}
	args = append(args, digest)

	args = append(args, cmd...)

	var buf bytes.Buffer
	if err := l.nerdctl(ctx, melangeVMName, nil, &buf, nil, args...); err != nil {
		return err
	}
	cfg.PodID = strings.TrimSpace(buf.String())

	return nil
}

// TerminatePod terminates a pod for supporting a Docker task,
// if necessary.
func (l *lima) TerminatePod(ctx context.Context, cfg *Config) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "lima.TerminatePod")
	defer span.End()

	name := cfg.PodID
	// first check the state of the pod
	containers, err := l.listContainers(ctx, name)
	if err != nil {
		return err
	}
	// if container was not found, nothing to terminate
	if len(containers) < 1 {
		return nil
	}
	return l.removeContainer(ctx, name, true)
}

// TestUsability determines if the lima runner can be used
// as a container runner.
func (l *lima) TestUsability(ctx context.Context) bool {
	_, err := l.list(ctx, "")
	return err == nil
}

// startVM starts the melange-builder VM
func (l *lima) startVM(ctx context.Context) error {
	// inspect existing runners
	vms, err := l.list(ctx, melangeVMName)
	if err != nil {
		return err
	}
	if len(vms) < 1 {
		return l.start(ctx, melangeVMName, false)
	}
	vminfo := vms[0]
	instanceConfig := path.Join(vminfo.Dir, "lima.yaml")
	b, err := os.ReadFile(instanceConfig)
	if err != nil {
		return fmt.Errorf("failed to read lima config %s: %w", instanceConfig, err)
	}
	y, err := limayaml.Load(b, instanceConfig)
	if err != nil {
		return fmt.Errorf("failed to load lima config: %w", err)
	}
	var mountGood bool
	for _, m := range y.Mounts {
		// we do not care about non-writable mounts
		if m.Writable != nil && !*m.Writable {
			continue
		}
		if m.Location == melangeWritableParent {
			mountGood = true
		}
	}
	if !mountGood {
		return fmt.Errorf("unable to find writable mount under %s", melangeWritableParent)
	}
	// make sure it is started
	if vminfo.Status != "Running" {
		err = l.start(ctx, melangeVMName, true)
		if err != nil {
			return err
		}
	}
	if err := l.limashell(ctx, melangeVMName, nil, nil, nil, "sudo", "systemctl", "start", "containerd"); err != nil {
		return fmt.Errorf("failed to start containerd in root for binfmt: %w", err)
	}
	if err := l.sudoNerdctl(ctx, melangeVMName, nil, nil, nil, "run", "--privileged", "--rm", "tonistiigi/binfmt:qemu-v7.0.0-28", "--install", "all"); err != nil {
		return fmt.Errorf("failed to run binfmt container: %w", err)
	}
	if err := l.limashell(ctx, melangeVMName, nil, nil, nil, "sudo", "systemctl", "stop", "containerd"); err != nil {
		return fmt.Errorf("failed to stop containerd in root for binfmt: %w", err)
	}
	return nil
}

// nolint: unused
// terminateVM terminates the melange builder VM.
func (l *lima) terminateVM(ctx context.Context, cfg *Config) error {
	name := melangeVMName
	// inspect existing runners
	vms, err := l.list(ctx, name)
	if err != nil {
		return err
	}
	// it was found, so remove it
	if len(vms) < 1 {
		return nil
	}
	vminfo := vms[0]

	// make sure it is started
	if vminfo.Status != "Stopped" {
		if err := l.stop(ctx, name); err != nil {
			return err
		}
	}
	return l.delete(ctx, name)
}

func (l *lima) WorkspaceTar(ctx context.Context, cfg *Config) (io.ReadCloser, error) {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()

		if err := l.nerdctl(ctx, melangeVMName, nil, pw, nil, "exec", "-i", cfg.PodID, "tar", "czf", "-", "-C", runnerWorkdir, "melange-out"); err != nil {
			pw.CloseWithError(fmt.Errorf("failed to tar workspace: %w", err))
		}
	}()

	return pr, nil
}

// these private functions handle some reusable code to avoid duplication.

// limactl issues limactl commands to work with VMs
func (l *lima) limactl(ctx context.Context, stdin io.Reader, stdout io.Writer, stderr io.Writer, args ...string) error {
	log := clog.FromContext(ctx)

	baseargs := args
	log.Infof("limactl %v", baseargs)
	cmd := exec.CommandContext(ctx, "limactl", baseargs...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	cmd.Stdout = os.Stdout
	if stdout != nil {
		cmd.Stdout = stdout
	}
	cmd.Stderr = os.Stderr
	if stderr != nil {
		cmd.Stderr = stderr
	}

	return cmd.Run()
}

// limashell issues shelled commands to work inside a VM
func (l *lima) limashell(ctx context.Context, name string, stdin io.Reader, stdout io.Writer, stderr io.Writer, args ...string) error {
	baseargs := []string{"shell", "--workdir", melangeWritableParent, name}
	baseargs = append(baseargs, args...)
	return l.limactl(ctx, stdin, stdout, stderr, baseargs...)
}

// list returns a list of lima VMs, each as a map of key/value pairs.
func (l *lima) list(ctx context.Context, name string) ([]*limastore.Instance, error) {
	args := []string{"list"}
	if name != "" {
		args = append(args, name)
	}
	args = append(args, "--json")
	var buf bytes.Buffer
	if err := l.limactl(ctx, nil, &buf, nil, args...); err != nil {
		return nil, fmt.Errorf("failed to list existing lima VMs: %w", err)
	}
	// parse to look for a runner whose name matches our name
	var vmlist []*limastore.Instance
	dec := json.NewDecoder(&buf)
	for {
		var vminfo limastore.Instance
		if err := dec.Decode(&vminfo); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to parse lima list output: %w", err)
		}
		vmlist = append(vmlist, &vminfo)
	}
	return vmlist, nil
}

// nolint: unused
// stop stops a named VM
func (l *lima) stop(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("no name provided")
	}
	return l.limactl(ctx, nil, nil, nil, "stop", name)
}

// start starts a new lima VM
func (l *lima) start(ctx context.Context, name string, exists bool) error {
	// inspect existing runners
	buf := bytes.NewReader(nil)
	args := []string{"start", "--name", name, "--tty=false"}

	if !exists {
		buf = bytes.NewReader(config)
		args = append(args, "-")
	}
	return l.limactl(ctx, buf, nil, nil, args...)
}

// nolint: unused
// delete deletes a stopped VM
func (l *lima) delete(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("no name provided")
	}
	return l.limactl(ctx, nil, nil, nil, "delete", name)
}

// nerdctl issues nerdctl commands to work with containers inside a VM
func (l *lima) nerdctl(ctx context.Context, name string, stdin io.Reader, stdout io.Writer, stderr io.Writer, args ...string) error {
	baseargs := []string{"nerdctl"}
	baseargs = append(baseargs, args...)
	return l.limashell(ctx, melangeVMName, stdin, stdout, stderr, baseargs...)
}

// sudoNerdctl issues nerdctl commands to work with containers inside a VM
func (l *lima) sudoNerdctl(ctx context.Context, name string, stdin io.Reader, stdout io.Writer, stderr io.Writer, args ...string) error {
	baseargs := []string{"sudo", "nerdctl"}
	baseargs = append(baseargs, args...)
	return l.limashell(ctx, melangeVMName, stdin, stdout, stderr, baseargs...)
}

// nolint: unused
// startContainer stops a running container
func (l *lima) startContainer(ctx context.Context, image string, background bool, args []string) (string, error) {
	nerdctlArgs := []string{"run"}
	if background {
		nerdctlArgs = append(nerdctlArgs, "--detach")
	}
	nerdctlArgs = append(nerdctlArgs, image)
	nerdctlArgs = append(nerdctlArgs, args...)
	var buf bytes.Buffer
	err := l.nerdctl(ctx, melangeVMName, nil, &buf, nil, nerdctlArgs...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

// nolint: unused
// stopContainer stops a running container
func (l *lima) stopContainer(ctx context.Context, name string) error {
	return l.nerdctl(ctx, melangeVMName, nil, nil, nil, "stop", name)
}

// removeContainer removes a container. It should be stopped already, or provide the force option
func (l *lima) removeContainer(ctx context.Context, name string, force bool) error {
	args := []string{"rm", name}
	if force {
		args = append(args, "--force")
	}
	return l.nerdctl(ctx, melangeVMName, nil, nil, nil, args...)
}

// listContainers lists all containers. If ID is provided, restricted to that name
func (l *lima) listContainers(ctx context.Context, id string) ([]map[string]string, error) {
	args := []string{"container", "list", "-a", "--format", "json"}
	if id != "" {
		args = append(args, "--filter", fmt.Sprintf("id=%s", id))
	}

	var buf bytes.Buffer
	err := l.nerdctl(ctx, melangeVMName, nil, &buf, nil, args...)
	if err != nil {
		return nil, err
	}
	var containers []map[string]string
	dec := json.NewDecoder(&buf)
	for {
		var container map[string]string
		if err := dec.Decode(&container); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to parse container list output: %w", err)
		}
		containers = append(containers, container)
	}
	return containers, nil
}

type limaOCILoader struct {
	lima *lima
}

func (l limaOCILoader) LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (ref string, err error) {
	ctx, span := otel.Tracer("melange").Start(ctx, "lima.LoadImage")
	defer span.End()

	// convert the layer into an image
	tmp, err := os.MkdirTemp("", "")
	if err != nil {
		return "", err
	}

	outputTarGZ := filepath.Join(tmp, "oci_image.tar.gz")

	// This is a bit janky but BuildImageTarballFromLayer expects an Options.
	creationTime, err := bc.GetBuildDateEpoch()
	if err != nil {
		return "", err
	}
	bopt := options.Options{
		SourceDateEpoch: creationTime,
		Arch:            arch,
	}

	if err := apko_oci.BuildImageTarballFromLayer(ctx,
		containerImageName, layer, outputTarGZ, bc.ImageConfiguration(), bopt); err != nil {
		return ref, fmt.Errorf("failed to build OCI image: %w", err)
	}
	f, err := os.Open(outputTarGZ)
	if err != nil {
		return ref, fmt.Errorf("failed to open OCI image: %w", err)
	}
	defer f.Close()
	defer os.Remove(outputTarGZ)

	// load the image into containerd via nerdctl. We would like to use the containerd client library directly,
	// but the socket is available only on the VM, which we need to access via ssh.
	var buf, errBuf bytes.Buffer
	if err := l.lima.nerdctl(ctx, melangeVMName, f, &buf, &errBuf, "image", "load", fmt.Sprintf("--platform=%s", arch)); err != nil {
		return ref, fmt.Errorf("failed to load image into containerd: %w %s", err, errBuf.Bytes())
	}

	// TODO: It would be much better if we could figure out the digest from the input tar
	out := buf.String()
	matches := nerdctlLoadRE.FindStringSubmatch(out)
	if len(matches) != 3 {
		return ref, fmt.Errorf("failed to find digest for loaded image: %s", out)
	}
	return fmt.Sprintf("%s@%s", matches[1], matches[2]), nil
}
