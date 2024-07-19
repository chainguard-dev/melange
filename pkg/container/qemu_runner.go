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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/internal/logwriter"
	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/ssh"
)

var _ Debugger = (*qemu)(nil)

const QemuName = "qemu"

const (
	PrivateKeyFile    = "id_rsa_wolfi"
	PublicKeyFile     = PrivateKeyFile + ".pub"
	SSHPortRangeStart = 10000
	SSHPortRangeEnd   = 50000
)

type qemu struct{}

// QemuRunner returns a Qemu Runner implementation.
func QemuRunner() Runner {
	return &qemu{}
}

func (bw *qemu) Close() error {
	return nil
}

// Name name of the runner
func (bw *qemu) Name() string {
	return QemuName
}

// Run runs a Qemu task given a Config and command string.
func (bw *qemu) Run(ctx context.Context, cfg *Config, envOverride map[string]string, args ...string) error {
	log := clog.FromContext(ctx)
	stdout, stderr := logwriter.New(log.Info), logwriter.New(log.Warn)
	defer stdout.Close()
	defer stderr.Close()

	err := sendSSHCommand(ctx,
		"root",
		"localhost",
		cfg.PodID,
		filepath.Join(cfg.ImgRef, PrivateKeyFile),
		cfg,
		envOverride,
		stderr,
		stdout,
		args,
	)
	if err != nil {
		return err
	}

	return nil
}

func (bw *qemu) Debug(ctx context.Context, cfg *Config, envOverride map[string]string, args ...string) error {
	return bw.Run(ctx, cfg, envOverride, args...)
}

// TestUsability determines if the Qemu runner can be used
// as a microvm runner.
func (bw *qemu) TestUsability(ctx context.Context) bool {
	log := clog.FromContext(ctx)
	if _, err := exec.LookPath("qemu-system-x86_64"); err != nil {
		log.Warnf("cannot use qemu for microvms: qemu-system-x86_64 not found on $PATH")
		return false
	}

	return true
}

// OCIImageLoader used to load OCI images in, if needed. qemu does not need it.
func (bw *qemu) OCIImageLoader() Loader {
	return &qemuOCILoader{}
}

// TempDir returns the base for temporary directory. For qemu, this is empty.
func (bw *qemu) TempDir() string {
	return ""
}

// StartPod starts a pod if necessary.
func (bw *qemu) StartPod(ctx context.Context, cfg *Config) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "qemu.StartPod")
	defer span.End()

	sshPort, err := randpomPortN()
	if err != nil {
		return err
	}

	cfg.PodID = strconv.Itoa(sshPort)

	return createMicroVM(ctx, cfg)
}

// TerminatePod terminates a pod if necessary.  Not implemented
// for Qemu runners.
func (bw *qemu) TerminatePod(ctx context.Context, cfg *Config) error {
	err := sendSSHCommand(ctx,
		"root",
		"localhost",
		cfg.PodID,
		filepath.Join(cfg.ImgRef, PrivateKeyFile),
		cfg,
		nil,
		nil,
		nil,
		[]string{"shutdown -h +10&"},
	)
	if err != nil {
		return err
	}

	return nil
}

// WorkspaceTar implements Runner
func (bw *qemu) WorkspaceTar(ctx context.Context, cfg *Config) (io.ReadCloser, error) {
	clog.FromContext(ctx).Infof("compressing remote workspace")
	err := sendSSHCommand(ctx,
		"root",
		"localhost",
		cfg.PodID,
		filepath.Join(cfg.ImgRef, PrivateKeyFile),
		cfg,
		nil,
		nil,
		nil,
		[]string{"cd /home/build && tar cvzf melange-out.tar.gz melange-out"},
	)
	if err != nil {
		return nil, err
	}

	clog.FromContext(ctx).Infof("fetching remote workspace")
	file, err := os.OpenFile(filepath.Join(cfg.WorkspaceDir, "melange-out.tar.gz"), os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	err = sendSSHCommand(ctx,
		"root",
		"localhost",
		cfg.PodID,
		filepath.Join(cfg.ImgRef, PrivateKeyFile),
		cfg,
		nil,
		nil,
		file,
		[]string{"cat /home/build/melange-out.tar.gz"},
	)
	if err != nil {
		return nil, err
	}

	return os.Open(filepath.Join(cfg.WorkspaceDir, "melange-out.tar.gz"))
}

type qemuOCILoader struct{}

func (b qemuOCILoader) LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (ref string, err error) {
	_, span := otel.Tracer("melange").Start(ctx, "qemu.LoadImage")
	defer span.End()

	// qemu does not have the idea of container images or layers or such, just
	// straight out rootfs, so we create the guest dir
	guestDir, err := os.MkdirTemp("", "melange-guest-*")
	if err != nil {
		return ref, fmt.Errorf("failed to create guest dir: %w", err)
	}
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
	}
	return guestDir, nil
}

func (b qemuOCILoader) RemoveImage(ctx context.Context, ref string) error {
	clog.FromContext(ctx).Infof("removing image path %s", ref)
	return os.RemoveAll(ref)
}

func createMicroVM(ctx context.Context, cfg *Config) error {
	rootfs := cfg.ImgRef
	baseargs := []string{}

	// always be sure to create the VM rootfs first!
	kernelPath, rootfsInitrdPath, err := createRootfs(ctx, rootfs)
	if err != nil {
		clog.FromContext(ctx).Errorf("could not prepare rootfs: %v", err)
		return err
	}

	baseargs = append(baseargs, "-m", getAvailableMemoryKB())
	baseargs = append(baseargs, "-smp", fmt.Sprintf("%d", runtime.NumCPU()))
	baseargs = append(baseargs, "-cpu", "host")
	baseargs = append(baseargs, "-enable-kvm")
	baseargs = append(baseargs, "-daemonize")
	baseargs = append(baseargs, "-nic", "user,hostfwd=tcp::"+cfg.PodID+"-:22")
	baseargs = append(baseargs, "-kernel", kernelPath)
	baseargs = append(baseargs, "-initrd", rootfsInitrdPath)
	baseargs = append(baseargs, "-append", "console=ttyS0 quiet")

	injectFstab := ""

	clog.FromContext(ctx).Info("qemu: generating qemu command...")
	for count, bind := range cfg.Mounts {
		// we skip file mounts, it doesn't work for qemu
		fileInfo, err := os.Stat(bind.Source)
		if err != nil {
			return err
		}

		if !fileInfo.IsDir() {
			continue
		}

		// we skip mounting the workspace
		// we build locally and retrieve it with WorkspaceTar
		if strings.Contains(bind.Source, "workspace") {
			continue
		}

		mountTag := strings.ReplaceAll(bind.Source, "/", "")

		if len(mountTag) > 30 {
			mountTag = mountTag[:30]
		}

		baseargs = append(baseargs, "-fsdev", "local,security_model=mapped,id=fsdev"+strconv.Itoa(count)+",path="+bind.Source)
		baseargs = append(baseargs, "-device", "virtio-9p-pci,id=fs"+strconv.Itoa(count)+",fsdev=fsdev"+strconv.Itoa(count)+",mount_tag="+mountTag)

		injectFstab = injectFstab + "\n" + mountTag + " " + bind.Destination + " 9p  trans=virtio,version=9p2000.L   0   0"
	}

	execCmd := exec.CommandContext(ctx, "qemu-system-x86_64", baseargs...)
	clog.FromContext(ctx).Infof("qemu: executing - %s", strings.Join(execCmd.Args, " "))

	err = execCmd.Run()
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: failed to run qemu command: %v", err)
		return err
	}

	sshCmd := `echo "` + injectFstab + `" >> /etc/fstab
cat /etc/fstab | cut -d' ' -f2 | xargs mkdir -p
mount -a
[ -x /sbin/ldconfig ] && /sbin/ldconfig /lib || true`

	clog.FromContext(ctx).Info("qemu: injecting fstab...")
	err = sendSSHCommand(ctx,
		"root",
		"localhost",
		cfg.PodID,
		filepath.Join(cfg.ImgRef, PrivateKeyFile),
		cfg,
		nil,
		nil,
		nil,
		[]string{sshCmd},
	)
	return err
}

func createRootfs(ctx context.Context, rootfs string) (string, string, error) {
	err := os.Chmod(rootfs, 0755)
	if err != nil {
		return "", "", err
	}

	mkdirPaths := []string{
		"dev",
		"etc/systemd/network",
		"etc/systemd/system",
		"home",
		"opt",
		"proc",
		"root",
		"root/.ssh",
		"run",
		"tmp",
		"var",
		"var/empty",
		"var/run",
	}
	for _, path := range mkdirPaths {
		_ = os.MkdirAll(filepath.Join(rootfs, path), 0o755)
	}

	err = os.Symlink("/dev/null", filepath.Join(rootfs, "etc/systemd/system/systemd-logind.service"))
	if err != nil {
		return "", "", err
	}

	err = os.Symlink("/usr/lib/systemd/systemd", filepath.Join(rootfs, "init"))
	if err != nil {
		return "", "", err
	}

	err = os.Symlink("/usr/share/zoneinfo/UTC", filepath.Join(rootfs, "etc/localtime"))
	if err != nil {
		return "", "", err
	}

	err = replaceStringInFile(filepath.Join(rootfs, "usr/lib/systemd/system/serial-getty@.service"),
		"(?m)^ExecStart=.*",
		"ExecStart=/bin/sh -c \"/usr/bin/ssh-keygen -A; /usr/sbin/sshd -D\"")
	if err != nil {
		return "", "", err
	}

	err = replaceStringInFile(filepath.Join(rootfs, "usr/lib/systemd/system/systemd-vconsole-setup.service"),
		"(?m)^ExecStart=.*",
		"ExecStart=/bin/true")
	if err != nil {
		return "", "", err
	}

	err = replaceStringInFile(filepath.Join(rootfs, "etc/hosts"),
		" localhost ",
		" localhost wolfi-qemu ")
	if err != nil {
		return "", "", err
	}

	err = os.WriteFile(filepath.Join(rootfs, "etc/hostname"),
		[]byte("wolfi-qemu"),
		0644)
	if err != nil {
		return "", "", err
	}

	// allow passing env variables to ssh commands
	sshdConfig, err := os.OpenFile(filepath.Join(rootfs, "etc/ssh/sshd_config"), os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return "", "", err
	}
	// Append the string to the file
	_, err = sshdConfig.WriteString(`AcceptEnv *`)
	if err != nil {
		return "", "", err
	}

	err = os.WriteFile(filepath.Join(rootfs, "etc/systemd/network/20-wired.network"),
		[]byte(`[Match]
Name=en*
[Network]
Address=10.0.2.15/24
Gateway=10.0.2.2
DNS=1.1.1.1`),
		0644)
	if err != nil {
		return "", "", err
	}

	err = generateSSHKeys(ctx, rootfs)
	if err != nil {
		return "", "", err
	}

	err = os.Rename(filepath.Join(rootfs, PublicKeyFile), filepath.Join(rootfs, "root/.ssh/authorized_keys"))
	if err != nil {
		return "", "", err
	}

	// fix permissions ofr .ssh and authorized keys files
	err = os.Chmod(filepath.Join(rootfs, "root/.ssh"), 0700)
	if err != nil {
		return "", "", err
	}
	err = os.Chmod(filepath.Join(rootfs, "root/.ssh/authorized_keys"), 0400)
	if err != nil {
		return "", "", err
	}

	initramfs, err := generateInitrd(ctx, rootfs)
	if err != nil {
		return "", "", err
	}

	kernel := filepath.Join(rootfs, "boot", "vmlinuz")

	return kernel, initramfs, nil
}

func generateInitrd(ctx context.Context, rootfs string) (string, error) {
	clog.FromContext(ctx).Info("qemu: building initramfs...")

	// ( cd /tmp/initramfs/rootfs && find . >../files )
	findFileOutput, err := os.CreateTemp("", "")
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: rootfs file fidning output file failed: %v", err)
		return "", err
	}
	defer findFileOutput.Close()
	defer os.Remove(findFileOutput.Name())

	findFiles := exec.Command("find", ".")
	findFiles.Dir = rootfs
	findFiles.Stdout = findFileOutput

	clog.FromContext(ctx).Info("qemu: finding rootfs files...")
	err = findFiles.Run()
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: rootfs file fidning failed: %v", err)
		return "", err
	}

	initramfs, err := os.Create(filepath.Join(rootfs, "initramfs.cpio.gz"))
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: initramfs file creation failed: %v", err)
		return "", err
	}
	defer initramfs.Close()

	content, _ := os.ReadFile(findFileOutput.Name())
	buffer := bytes.Buffer{}
	buffer.Write(content)

	// ( cd /tmp/initramfs/rootfs && cpio --format=newc -o ) </tmp/initramfs/files | gzip --to-stdout > /initramfs.$(uname -m).cpio.gz
	cpioCmd := exec.Command("cpio", "--format=newc", "-o", "-R", "0:0")

	cpioCmd.Stdin = &buffer
	// cpioCmd.Stdout = initramfs
	cpioCmd.Dir = rootfs

	gzipCmd := exec.Command("gzip", "--to-stdout")
	gzipCmd.Stdout = initramfs

	// Pipe cmd1 to cmd2
	gzipCmd.Stdin, err = cpioCmd.StdoutPipe()
	if err != nil {
		return "", err
	}

	// Start cmd2 first to avoid deadlock
	if err := gzipCmd.Start(); err != nil {
		return "", err
	}

	clog.FromContext(ctx).Info("qemu: compressing rootfs...")
	// Then start cmd1
	if err := cpioCmd.Run(); err != nil {
		clog.FromContext(ctx).Errorf("qemu: initramfs cpio command failed: %v", err)
		return "", err
	}

	// Wait for cmd2 to finish
	if err := gzipCmd.Wait(); err != nil {
		clog.FromContext(ctx).Errorf("qemu: initramfs gzip command failed: %v", err)
		return "", err
	}

	clog.FromContext(ctx).Info("qemu: initramfs ready")
	return initramfs.Name(), nil
}

func sendSSHCommand(ctx context.Context, user, host, port, privatekey string, cfg *Config, extraVars map[string]string, stderr, stdout io.Writer, command []string) error {
	server := host + ":" + port

	key, err := os.ReadFile(privatekey)
	if err != nil {
		clog.FromContext(ctx).Errorf("Unable to read private key: %v", err)
		return err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		clog.FromContext(ctx).Errorf("Unable to parse private key: %v", err)
		return err
	}

	// Create SSH client configuration
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // equivalent to StrictHostKeyChecking=no
	}

	// Connect to the SSH server
	client, err := ssh.Dial("tcp", server, config)
	if err != nil {
		clog.FromContext(ctx).Errorf("Failed to dial: %s", err)
		return err
	}
	defer client.Close()

	// Create a session
	session, err := client.NewSession()
	if err != nil {
		clog.FromContext(ctx).Errorf("Failed to create session: %s", err)
		return err
	}
	defer session.Close()

	for k, v := range cfg.Environment {
		err = session.Setenv(k, v)
		if err != nil {
			return err
		}
	}

	for k, v := range extraVars {
		err = session.Setenv(k, v)
		if err != nil {
			return err
		}
	}

	session.Stderr = stderr
	session.Stdout = stdout
	err = session.Run(strings.Join(command, " "))
	if err != nil {
		clog.FromContext(ctx).Errorf("Failed to run command: %s", err)
		return err
	}

	return nil
}

func generateSSHKeys(ctx context.Context, rootfs string) error {
	clog.FromContext(ctx).Info("qemu: generating ssh key pairs for ephemeral VM...")
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: ssh keygen failed: %v", err)
		return err
	}

	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	err = os.WriteFile(filepath.Join(rootfs, PrivateKeyFile), pem.EncodeToMemory(&privBlock), 0600)
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: ssh keygen failed: %v", err)
		return err
	}

	publicRsaKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: ssh keygen failed: %v", err)
		return err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)
	err = os.WriteFile(filepath.Join(rootfs, PublicKeyFile), pubKeyBytes, 0600)
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: ssh keygen failed: %v", err)
		return err
	}

	return nil
}

func randpomPortN() (int, error) {
	for port := SSHPortRangeStart; port <= SSHPortRangeEnd; port++ {
		address := fmt.Sprintf("localhost:%d", port)
		listener, err := net.Listen("tcp", address)
		if err == nil {
			listener.Close()
			return port, nil
		}
	}

	return 0, fmt.Errorf("no open port found in range %d-%d", SSHPortRangeStart, SSHPortRangeEnd)
}

func getAvailableMemoryKB() string {
	mem := "16000000"
	f, e := os.Open("/proc/meminfo")
	if e != nil {
		return mem
	}

	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		var n int
		if nItems, _ := fmt.Sscanf(s.Text(), "MemTotal: %d kB", &n); nItems == 1 {
			mem = strconv.Itoa(n)
			return mem
		}
	}

	return mem
}

func replaceStringInFile(inputFile, pattern, replace string) error {
	file, err := os.ReadFile(inputFile)
	if err != nil {
		return err
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	replaced := re.ReplaceAllString(string(file), replace)

	return os.WriteFile(inputFile, []byte(replaced), 0644)
}