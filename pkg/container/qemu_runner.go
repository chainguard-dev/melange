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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"chainguard.dev/apko/pkg/apk/expandapk"
	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/internal/logwriter"
	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/ssh"
)

//go:embed qemu_init.sh
var qemuInit []byte

var _ Debugger = (*qemu)(nil)

const QemuName = "qemu"

const (
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

	// default to root user but if a different user is specified
	// we will use the embedded build:1000:1000 user
	user := "root"
	if cfg.RunAs != "" {
		user = "build"
	}

	err := sendSSHCommand(ctx,
		user,
		"localhost",
		cfg.SSHPort,
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

	qemuBin := "qemu-system-x86_64"
	if runtime.GOARCH == "arm64" {
		qemuBin = "qemu-system-aarch64"
	}

	if _, err := exec.LookPath(qemuBin); err != nil {
		log.Warnf("cannot use qemu for microvms: %s not found on $PATH", qemuBin)
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

	cfg.SSHPort = strconv.Itoa(sshPort)

	return createMicroVM(ctx, cfg)
}

// TerminatePod terminates a pod if necessary.  Not implemented
// for Qemu runners.
func (bw *qemu) TerminatePod(ctx context.Context, cfg *Config) error {
	clog.FromContext(ctx).Info("qemu: sending shutdown signal")
	err := sendSSHCommand(ctx,
		"root",
		"localhost",
		cfg.SSHPort,
		cfg,
		nil,
		nil,
		nil,
		[]string{"echo s > /proc/sysrq-trigger && echo o > /proc/sysrq-trigger&"},
	)
	if err != nil {
		return err
	}

	return nil
}

// WorkspaceTar implements Runner
func (bw *qemu) WorkspaceTar(ctx context.Context, cfg *Config) (io.ReadCloser, error) {
	// default to root user but if a different user is specified
	// we will use the embedded build:1000:1000 user
	user := "root"
	if cfg.RunAs != "" {
		user = "build"
	}

	clog.FromContext(ctx).Infof("compressing remote workspace")
	err := sendSSHCommand(ctx,
		user,
		"localhost",
		cfg.SSHPort,
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
		user,
		"localhost",
		cfg.SSHPort,
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
	kernelPath, rootfsInitrdPath, err := createRootfs(ctx, cfg, rootfs)
	if err != nil {
		clog.FromContext(ctx).Errorf("could not prepare rootfs: %v", err)
		return err
	}

	// load microvm profile and bios, shave some milliseconds from boot
	// using this will make a complete boot->initrd (with working network) In ~700ms
	// instead of ~900ms.
	if _, err := os.Stat("/usr/share/qemu/bios-microvm.bin"); err == nil {
		// only enable pcie for network, enable RTC for kernel, disable i8254PIT, i8259PIC and serial port
		baseargs = append(baseargs, "-machine", "microvm,rtc=on,pcie=on,pit=off,pic=off,isa-serial=off")
		baseargs = append(baseargs, "-bios", "/usr/share/qemu/bios-microvm.bin")
	}

	if cfg.Memory != "" {
		baseargs = append(baseargs, "-m", cfg.Memory)
	} else {
		baseargs = append(baseargs, "-m", getAvailableMemoryKB())
	}

	if cfg.CPU != "" {
		baseargs = append(baseargs, "-cpu", cfg.CPU)
	} else {
		baseargs = append(baseargs, "-cpu", "host")
	}

	// use kvm on linux, and Hypervisor.framework on macOS
	if runtime.GOOS == "linux" {
		baseargs = append(baseargs, "-enable-kvm")
	} else if runtime.GOOS == "darwin" {
		baseargs = append(baseargs, "-accel", "hvf")
	}

	baseargs = append(baseargs, "-smp", fmt.Sprintf("%d", runtime.NumCPU()))
	baseargs = append(baseargs, "-daemonize")
	baseargs = append(baseargs, "-display", "none")
	baseargs = append(baseargs, "-no-reboot")
	baseargs = append(baseargs, "-no-user-config")
	baseargs = append(baseargs, "-nodefaults")
	baseargs = append(baseargs, "-parallel", "none")
	baseargs = append(baseargs, "-serial", "none")
	baseargs = append(baseargs, "-vga", "none")
	// use -netdev + -device instead of -nic, as this is better supported by microvm machine type
	baseargs = append(baseargs, "-netdev", "user,id=id1,hostfwd=tcp::"+cfg.SSHPort+"-:22")
	baseargs = append(baseargs, "-device", "virtio-net-pci,netdev=id1")
	baseargs = append(baseargs, "-kernel", kernelPath)
	baseargs = append(baseargs, "-initrd", rootfsInitrdPath)
	baseargs = append(baseargs, "-append", "quiet nomodeset panic=-1")

	injectFstab := ""

	// we will *not* mount workspace using qemu, this will use 9pfs which is network-based, and will
	// kill all performances (lots of small files)
	// instead we will copy back the finished workspace artifacts when done.
	// this dramatically improves compile time, making them comparable to bwrap or docker runners.
	clog.FromContext(ctx).Info("qemu: generating qemu command...")
	clog.FromContext(ctx).Debug("qemu: generating mount list")
	for count, bind := range cfg.Mounts {
		// we skip file mounts, it doesn't work for qemu
		fileInfo, err := os.Stat(bind.Source)
		if err != nil {
			return err
		}

		if !fileInfo.IsDir() {
			clog.FromContext(ctx).Debugf("qemu: skipping file mount: %s", bind.Source)
			continue
		}

		// we skip mounting the workspace
		// we build locally and retrieve it with WorkspaceTar
		if strings.Contains(bind.Source, "workspace") {
			clog.FromContext(ctx).Debugf("qemu: skipping workspace mount: %s", bind.Source)
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

	qemuBin := "qemu-system-x86_64"
	if runtime.GOARCH == "arm64" {
		qemuBin = "qemu-system-aarch64"
	}

	execCmd := exec.CommandContext(ctx, qemuBin, baseargs...)
	clog.FromContext(ctx).Infof("qemu: executing - %s", strings.Join(execCmd.Args, " "))

	output, err := execCmd.CombinedOutput()
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: failed to run qemu command: %v - %s", err, string(output))
		return err
	}

	sshCmd := `echo "` + injectFstab + `" >> /etc/fstab
cat /etc/fstab | cut -d' ' -f2 | xargs mkdir -p
mount -a
[ -x /sbin/ldconfig ] && /sbin/ldconfig /lib || true`

	clog.FromContext(ctx).Info("qemu: injecting fstab...")
	clog.FromContext(ctx).Debugf("qemu: injecting fstab - %s", sshCmd)
	err = sendSSHCommand(ctx,
		"root",
		"localhost",
		cfg.SSHPort,
		cfg,
		nil,
		nil,
		nil,
		[]string{sshCmd},
	)
	return err
}

func createRootfs(ctx context.Context, cfg *Config, rootfs string) (string, string, error) {
	err := os.Chmod(rootfs, 0755)
	if err != nil {
		return "", "", err
	}

	mkdirPaths := []string{
		"dev",
		"home",
		"home/build/.ssh",
		"proc",
		"root",
		"root/.ssh",
		"run",
		"sys",
		"var",
		"var/empty",
	}
	clog.FromContext(ctx).Debug("qemu: creating basic rootfs directories")
	for _, path := range mkdirPaths {
		_ = os.MkdirAll(filepath.Join(rootfs, path), 0o755)
	}

	mkdirPaths = []string{
		"opt",
		"tmp",
		"var/cache",
		"var/run",
	}
	clog.FromContext(ctx).Debug("qemu: creating basic word writable rootfs directories")
	for _, path := range mkdirPaths {
		_ = os.Mkdir(filepath.Join(rootfs, path), 0o777)
	}
	for _, path := range mkdirPaths {
		_ = os.Chmod(filepath.Join(rootfs, path), 0o777)
	}

	// inject /init from ./qemu_init.sh, previously this was using
	// systemd, we now use this minimal init as we only need:
	//   - basic mount points
	//   - setup static network
	//   - start sshd
	clog.FromContext(ctx).Debug("qemu: injecting /init")
	err = os.WriteFile(filepath.Join(rootfs, "init"),
		qemuInit,
		0755)
	if err != nil {
		return "", "", err
	}

	clog.FromContext(ctx).Debug("qemu: setup default timezone")
	err = os.Symlink("/usr/share/zoneinfo/UTC", filepath.Join(rootfs, "etc/localtime"))
	if err != nil {
		return "", "", err
	}

	clog.FromContext(ctx).Debug("qemu: setup /etc/hosts")
	err = replaceStringInFile(filepath.Join(rootfs, "etc/hosts"),
		" localhost ",
		" localhost wolfi-qemu ")
	if err != nil {
		return "", "", err
	}

	clog.FromContext(ctx).Debug("qemu: setup hostname")
	err = os.WriteFile(filepath.Join(rootfs, "etc/hostname"),
		[]byte("wolfi-qemu"),
		0644)
	if err != nil {
		return "", "", err
	}

	clog.FromContext(ctx).Debug("qemu: setup DNS")
	err = os.WriteFile(filepath.Join(rootfs, "etc/resolv.conf"),
		[]byte("nameserver 1.1.1.1"),
		0644)
	if err != nil {
		return "", "", err
	}

	// allow passing env variables to ssh commands
	clog.FromContext(ctx).Debug("qemu: ssh - acceptenv")
	sshdConfig, err := os.OpenFile(filepath.Join(rootfs, "etc/ssh/sshd_config"), os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return "", "", err
	}
	_, err = sshdConfig.WriteString(`AcceptEnv *`)
	if err != nil {
		return "", "", err
	}
	defer sshdConfig.Close()

	clog.FromContext(ctx).Debug("qemu: ssh - create ssh key pair")
	pubKeyBytes, err := generateSSHKeys(ctx, cfg, rootfs)
	if err != nil {
		return "", "", err
	}

	clog.FromContext(ctx).Debug("qemu: ssh - inject authorized_keys - root")
	err = os.WriteFile(filepath.Join(rootfs, "root/.ssh/authorized_keys"), pubKeyBytes, 0400)
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: ssh pubkey write failed: %v", err)
		return "", "", err
	}

	clog.FromContext(ctx).Debug("qemu: ssh - fix dir permissions - root")
	err = os.Chmod(filepath.Join(rootfs, "root/.ssh"), 0700)
	if err != nil {
		return "", "", err
	}

	clog.FromContext(ctx).Debug("qemu: ssh - inject authorized_keys - build user")
	err = os.WriteFile(filepath.Join(rootfs, "home/build/.ssh/authorized_keys"), pubKeyBytes, 0400)
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: ssh pubkey write failed: %v", err)
		return "", "", err
	}

	clog.FromContext(ctx).Debug("qemu: ssh - fix dir permissions - build user")
	err = os.Chmod(filepath.Join(rootfs, "home/build/.ssh"), 0700)
	if err != nil {
		return "", "", err
	}

	clog.FromContext(ctx).Debug("qemu: setting up kernel for vm")
	kernel, err := generateVmlinuz(ctx, rootfs)
	if err != nil {
		return "", "", err
	}

	clog.FromContext(ctx).Debug("qemu: generating initramfs...")
	initramfs, err := generateInitrd(ctx, rootfs)
	if err != nil {
		return "", "", err
	}

	return kernel, initramfs, nil
}

func generateVmlinuz(ctx context.Context, rootfs string) (string, error) {
	clog.FromContext(ctx).Info("qemu: detecting kernel")
	if _, err := os.Stat("/boot/vmlinuz"); err == nil {
		clog.FromContext(ctx).Info("qemu: vmlinuz detected, reusing it")
		return "/boot/vmlinuz", nil
	}

	clog.FromContext(ctx).Info("qemu: detecting kernel")
	if _, err := os.Stat("/boot/vmlinuz-virt"); err == nil {
		clog.FromContext(ctx).Info("qemu: vmlinuz detected, reusing it")
		return "/boot/vmlinuz-virt", nil
	}

	clog.FromContext(ctx).Info("qemu: kernel not found, downloading...")
	// download mainline kernel from ubuntu
	response, err := http.Get("https://dl-cdn.alpinelinux.org/alpine/edge/main/x86_64/linux-virt-6.6.41-r0.apk")
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: can't download kernel - %v", err)
		return "", err
	}
	defer response.Body.Close()

	// Check if the request was successful
	if response.StatusCode != http.StatusOK {
		clog.FromContext(ctx).Errorf("qemu: can't download kernel - %v", err)
		return "", err
	}

	cachedir, err := os.MkdirTemp("", "")
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: can't setup cache dir - %v", err)
		return "", err
	}
	defer os.RemoveAll(cachedir)

	apk, err := expandapk.ExpandApk(ctx, response.Body, cachedir)
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: can't unpack kernel - %v", err)
		return "", err
	}

	clog.FromContext(ctx).Info("qemu: unpacking package")
	content, err := apk.PackageData()
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: can't unpack kernel - %v", err)
		return "", err
	}
	defer content.Close()

	var tarReader *tar.Reader = tar.NewReader(content)

	clog.FromContext(ctx).Info("qemu: unpacking kernel")
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			clog.FromContext(ctx).Errorf("qemu: can't unpack kernel - %v", err)
			return "", err
		}

		target := filepath.Join(rootfs, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				clog.FromContext(ctx).Errorf("qemu: can't unpack kernel - %v", err)
				return "", err
			}
		case tar.TypeReg:
			// Create file
			outFile, err := os.Create(target)
			if err != nil {
				clog.FromContext(ctx).Errorf("qemu: can't unpack kernel - %v", err)
				return "", err
			}
			defer outFile.Close()

			if _, err := io.Copy(outFile, tarReader); err != nil {
				clog.FromContext(ctx).Errorf("qemu: can't unpack kernel - %v", err)
				return "", err
			}
		default:
			clog.FromContext(ctx).Warnf("Unsupported type: %v in %s\n", header.Typeflag, header.Name)
		}
	}

	clog.FromContext(ctx).Info("qemu: kernel successfully unpacked")
	return filepath.Join(rootfs, "boot", "vmlinuz-virt"), nil
}

func generateInitrd(ctx context.Context, rootfs string) (string, error) {
	clog.FromContext(ctx).Info("qemu: building initramfs...")

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

	clog.FromContext(ctx).Debug("qemu: finding rootfs files...")
	err = findFiles.Run()
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: rootfs file fidning failed: %v", err)
		return "", err
	}

	initramfs, err := os.Create(filepath.Join(rootfs, "initramfs.cpio"))
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: initramfs file creation failed: %v", err)
		return "", err
	}
	defer initramfs.Close()

	content, _ := os.ReadFile(findFileOutput.Name())
	buffer := bytes.Buffer{}
	buffer.Write(content)

	cpioCmd := exec.Command("cpio", "--format=newc", "-o", "-R", "0:0")

	cpioCmd.Stdout = initramfs
	cpioCmd.Stdin = &buffer
	cpioCmd.Dir = rootfs

	clog.FromContext(ctx).Info("qemu: compressing rootfs...")
	clog.FromContext(ctx).Debugf("qemu: launching command - %s",
		strings.Join(cpioCmd.Args, " ")+" | "+strings.Join(cpioCmd.Args, " "))
	if err := cpioCmd.Run(); err != nil {
		clog.FromContext(ctx).Errorf("qemu: initramfs cpio command failed: %v", err)
		return "", err
	}

	clog.FromContext(ctx).Info("qemu: initramfs ready")
	return initramfs.Name(), nil
}

func sendSSHCommand(ctx context.Context, user, host, port string, cfg *Config, extraVars map[string]string, stderr, stdout io.Writer, command []string) error {
	server := host + ":" + port

	signer, err := ssh.ParsePrivateKey(cfg.SSHKey)
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

func generateSSHKeys(ctx context.Context, cfg *Config, rootfs string) ([]byte, error) {
	clog.FromContext(ctx).Info("qemu: generating ssh key pairs for ephemeral VM...")
	// Private Key generation
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Get ASN.1 DER format
	privDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	// pem.Block
	privBlock := pem.Block{
		Type:    "EC PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	cfg.SSHKey = pem.EncodeToMemory(&privBlock)

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: ssh keygen failed: %v", err)
		return nil, err
	}

	return ssh.MarshalAuthorizedKey(publicKey), nil
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
	mem := "16000000k"

	f, e := os.Open("/proc/meminfo")
	if e != nil {
		return mem
	}
	defer f.Close()

	s := bufio.NewScanner(f)

	for s.Scan() {
		var n int
		if nItems, _ := fmt.Sscanf(s.Text(), "MemTotal: %d kB", &n); nItems == 1 {
			return strconv.Itoa(n) + "k"
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
