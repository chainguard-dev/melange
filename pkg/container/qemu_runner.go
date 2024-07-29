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
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	apko_cpio "chainguard.dev/apko/pkg/cpio"
	"chainguard.dev/melange/internal/logwriter"
	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/ssh"
)

var _ Debugger = (*qemu)(nil)

const QemuName = "qemu"

const (
	defaultDiskSize   = "50Gi"
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
	clog.InfoContextf(ctx, "running command %s", strings.Join(args, " "))

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
		nil,
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
	clog.InfoContextf(ctx, "debugging command %s", strings.Join(args, " "))

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
		os.Stdin,
		os.Stderr,
		os.Stdout,
		args,
	)
	if err != nil {
		return err
	}

	return nil
}

// TestUsability determines if the Qemu runner can be used
// as a microvm runner.
func (bw *qemu) TestUsability(ctx context.Context) bool {
	log := clog.FromContext(ctx)

	arch := apko_types.Architecture(runtime.GOARCH)
	if _, err := exec.LookPath(fmt.Sprintf("qemu-system-%s", arch.ToAPK())); err != nil {
		log.Warnf("cannot use qemu for microvms: qemu-system-%s not found on $PATH", arch.ToAPK())
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
	ctx, span := otel.Tracer("melange").Start(ctx, "qemu.TerminatePod")
	defer span.End()
	defer os.Remove(cfg.ImgRef)
	defer os.Remove(cfg.Disk)

	clog.FromContext(ctx).Info("qemu: sending shutdown signal")
	err := sendSSHCommand(ctx,
		"root",
		"localhost",
		cfg.SSHPort,
		cfg,
		nil,
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

	clog.FromContext(ctx).Infof("fetching remote workspace")
	// work around missing scp (needs openssh-sftp package), we just tar the file
	// and pipe the output to our local file. It is potentially slower, but being
	// a localhost interface, the performance penalty should be negligible.
	err := sendSSHCommand(ctx,
		user,
		"localhost",
		cfg.SSHPort,
		cfg,
		nil,
		nil,
		nil,
		nil,
		[]string{"cp -r /home/build/melange-out /mnt"},
	)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

type qemuOCILoader struct{}

func (b qemuOCILoader) LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (ref string, err error) {
	_, span := otel.Tracer("melange").Start(ctx, "qemu.LoadImage")
	defer span.End()

	// qemu does not have the idea of container images or layers or such, just
	// create an initramfs from the layer
	guestInitramfs, err := os.CreateTemp("", "melange-guest-*.initramfs.cpio")
	if err != nil {
		return ref, fmt.Errorf("failed to create guest dir: %w", err)
	}

	// in case of some kernel images, we also need the /lib/modules directory to load
	// necessary drivers, like 9p, virtio_net which are foundamental for the VM working.
	if qemuModule, ok := os.LookupEnv("QEMU_KERNEL_MODULES"); ok {
		clog.FromContext(ctx).Info("qemu: QEMU_KERNEL_MODULES env set, injecting modules in initramfs")
		if _, err := os.Stat(qemuModule); err == nil {
			clog.FromContext(ctx).Infof("qemu: local QEMU_KERNEL_MODULES dir detected, injecting")
			layer, err = injectKernelModules(ctx, layer, qemuModule)
			if err != nil {
				clog.FromContext(ctx).Errorf("qemu: could not inject needed kernel modules into initramfs: %v", err)
				return "", err
			}
		}
	}

	err = apko_cpio.FromLayer(layer, guestInitramfs)
	if err != nil {
		return ref, fmt.Errorf("failed to create cpio initramfs: %w", err)
	}

	return guestInitramfs.Name(), nil
}

func (b qemuOCILoader) RemoveImage(ctx context.Context, ref string) error {
	clog.FromContext(ctx).Infof("removing image path %s", ref)
	return os.RemoveAll(ref)
}

func createMicroVM(ctx context.Context, cfg *Config) error {
	rootfs := cfg.ImgRef
	baseargs := []string{}
	injectFstab := ""

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
		memKb, err := convertMemoryToKB(cfg.Memory)
		if err != nil {
			return err
		}

		baseargs = append(baseargs, "-m", fmt.Sprintf("%dk", memKb))
	} else {
		baseargs = append(baseargs, "-m", getAvailableMemoryKB())
	}

	if cfg.CPU != "" {
		baseargs = append(baseargs, "-smp", cfg.CPU)
	} else {
		baseargs = append(baseargs, "-smp", fmt.Sprintf("%d", runtime.NumCPU()))
	}

	// use kvm on linux, and Hypervisor.framework on macOS
	if runtime.GOOS == "linux" {
		baseargs = append(baseargs, "-enable-kvm")
	} else if runtime.GOOS == "darwin" {
		baseargs = append(baseargs, "-accel", "hvf")
	}

	baseargs = append(baseargs, "-cpu", "host")
	baseargs = append(baseargs, "-daemonize")
	// ensure we disable unneeded devices, this is less needed if we use microvm machines
	// but still useful otherwise
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
	// panic=-1 ensures that if the init fails, we immediately exit the machine
	baseargs = append(baseargs, "-append", "quiet nomodeset panic=-1")
	// Add default SSH keys to the VM
	// we add a "defaultshare" 9pfs with the workspace dir sharing the authorized keys
	// inside it, without this the VM WILL NOT BOOT.
	baseargs = append(baseargs, "-fsdev", "local,security_model=mapped,id=fsdev100,path="+cfg.WorkspaceDir)
	baseargs = append(baseargs, "-device", "virtio-9p-pci,id=fs100,fsdev=fsdev100,mount_tag=defaultshare")

	// if no size is specified, let's go for a default
	if cfg.Disk == "" {
		clog.FromContext(ctx).Infof("qemu: no disk space specified, using default: %s", defaultDiskSize)
		cfg.Disk = defaultDiskSize
	}

	// if we want a disk, just add it, the init will mount it to the build home automatically
	diskFile, err := generateDiskFile(ctx, cfg.Disk)
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: could not generate additional disks: %v", err)
		return err
	}

	// append raw disk, init will take care of formatting it if present.
	baseargs = append(baseargs, "-drive", "if=virtio,file="+diskFile+",format=raw,werror=report,rerror=report")
	// save the disk name, we will wipe it off when done
	cfg.Disk = diskFile

	// we will *not* mount workspace using qemu, this will use 9pfs which is network-based, and will
	// kill all performances (lots of small files)
	// instead we will copy back the finished workspace artifacts when done.
	// this dramatically improves compile time, making them comparable to bwrap or docker runners.
	clog.FromContext(ctx).Info("qemu: generating qemu command")
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

		// mount tags have to be an alfanumeric string of 31 char max
		mountTag := strings.ReplaceAll(bind.Source, "/", "")
		if len(mountTag) > 30 {
			mountTag = mountTag[:30]
		}

		baseargs = append(baseargs, "-fsdev", "local,security_model=mapped,id=fsdev"+strconv.Itoa(count)+",path="+bind.Source)
		baseargs = append(baseargs, "-device", "virtio-9p-pci,id=fs"+strconv.Itoa(count)+",fsdev=fsdev"+strconv.Itoa(count)+",mount_tag="+mountTag)

		// create the mount string for the fstab
		injectFstab = injectFstab + "\n" + mountTag + " " + bind.Destination + " 9p  trans=virtio,version=9p2000.L   0   0"
	}

	// qemu-system-x86_64 or qemu-system-aarch64...
	execCmd := exec.CommandContext(ctx, fmt.Sprintf("qemu-system-%s", cfg.Arch.ToAPK()), baseargs...)
	clog.FromContext(ctx).Infof("qemu: executing - %s", strings.Join(execCmd.Args, " "))

	output, err := execCmd.CombinedOutput()
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: failed to run qemu command: %v - %s", err, string(output))
		return err
	}

	// in case of additional mount points, we inject them in the fstab, so that
	// they will be mounted automatically
	if injectFstab != "" {
		sshCmd := `echo "` + injectFstab + `" >> /etc/fstab
cat /etc/fstab | cut -d' ' -f2 | xargs mkdir -p
mount -a`

		clog.FromContext(ctx).Info("qemu: injecting fstab")
		clog.FromContext(ctx).Debugf("qemu: injecting fstab - %s", sshCmd)
		err = sendSSHCommand(ctx,
			"root",
			"localhost",
			cfg.SSHPort,
			cfg,
			nil,
			nil,
			nil,
			nil,
			[]string{sshCmd},
		)
		return err
	}

	// default to root user but if a different user is specified
	// we will use the embedded build:1000:1000 user
	user := "root"
	if cfg.RunAs != "" {
		user = "build"
	}
	clog.FromContext(ctx).Info("qemu: setting up local workspace")
	return sendSSHCommand(ctx,
		user,
		"localhost",
		cfg.SSHPort,
		cfg,
		nil,
		nil,
		nil,
		nil,
		[]string{"cp -r /mnt/* /home/build"},
	)
}

func createRootfs(ctx context.Context, cfg *Config, rootfs string) (string, string, error) {
	clog.FromContext(ctx).Debug("qemu: ssh - create ssh key pair")
	pubKeyBytes, err := generateSSHKeys(ctx, cfg, rootfs)
	if err != nil {
		return "", "", err
	}

	err = os.MkdirAll(filepath.Join(cfg.WorkspaceDir, "ssh"), os.ModePerm)
	if err != nil {
		return "", "", err
	}

	clog.FromContext(ctx).Debug("qemu: ssh - inject authorized_keys - root")
	err = os.WriteFile(filepath.Join(cfg.WorkspaceDir, "ssh/authorized_keys"), pubKeyBytes, 0400)
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: ssh pubkey write failed: %v", err)
		return "", "", err
	}

	clog.FromContext(ctx).Debug("qemu: setting up kernel for vm")
	kernel := "/boot/vmlinuz"
	if kernelVar, ok := os.LookupEnv("QEMU_KERNEL_IMAGE"); ok {
		clog.FromContext(ctx).Info("qemu: QEMU_KERNEL_IMAGE env set")
		if _, err := os.Stat(kernelVar); err == nil {
			clog.FromContext(ctx).Infof("qemu: local QEMU_KERNEL_IMAGE file detected, using: %s", kernelVar)
			kernel = kernelVar
		}
	}

	return kernel, cfg.ImgRef, nil
}

// in case of external modules (usually for 9p and virtio) we need a matching /lib/modules/kernel-$(uname)
// we need to inject this directly into the initramfs cpio, as we cannot share them via 9p later.
func injectKernelModules(ctx context.Context, rootfs v1.Layer, modulesPath string) (v1.Layer, error) {
	clog.FromContext(ctx).Info("qemu: appending modules to initramfs")

	// get tar layer, we will need to inject new files into it
	uncompressed, err := rootfs.Uncompressed()
	if err != nil {
		return nil, err
	}
	defer uncompressed.Close()

	// copy old tar layer into new tar
	buf := new(bytes.Buffer)
	tarWriter := tar.NewWriter(buf)
	tartReader := tar.NewReader(uncompressed)

	for {
		header, err := tartReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if err := tarWriter.WriteHeader(header); err != nil {
			return nil, err
		}
		if _, err := io.Copy(tarWriter, tartReader); err != nil {
			return nil, err
		}
	}

	// Walk through the input directory and add files to the tar archive
	err = filepath.Walk(modulesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", path, err)
		}

		header, err := tar.FileInfoHeader(info, path)
		if err != nil {
			return fmt.Errorf("failed to create tar header for %s: %w", path, err)
		}

		header.Name = "/lib/modules/" + filepath.ToSlash(path[len(modulesPath):])
		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header for %s: %w", path, err)
		}

		if _, err := tarWriter.Write(data); err != nil {
			return fmt.Errorf("failed to write file %s to tar: %w", path, err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	opener := func() (io.ReadCloser, error) {
		// Return a ReadCloser from the buffer
		return io.NopCloser(bytes.NewReader(buf.Bytes())), nil
	}

	// Create a layer from the Opener
	return tarball.LayerFromOpener(opener)
}

func generateDiskFile(ctx context.Context, diskSize string) (string, error) {
	diskPath, _ := os.LookupEnv("QEMU_DISKS_PATH")
	if diskPath == "" {
		diskPath = "."
	}

	if _, err := os.Stat(diskPath); err != nil {
		err = os.MkdirAll(diskPath, os.ModePerm)
		if err != nil {
			return "", err
		}
	}

	diskName, err := os.CreateTemp(diskPath, "*.img")
	if err != nil {
		return "", err
	}
	defer diskName.Close()

	size, err := convertMemoryToKB(diskSize)
	if err != nil {
		return "", err
	}

	// we need bytes
	size = size * 1024

	clog.FromContext(ctx).Infof("qemu: generating disk image, name %s, size %s:", diskName.Name(), diskSize)
	return diskName.Name(), os.Truncate(diskName.Name(), size)
}

func sendSSHCommand(ctx context.Context, user, host, port string,
	cfg *Config, extraVars map[string]string,
	stdin io.Reader, stderr, stdout io.Writer,
	command []string,
) error {
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
		Config: ssh.Config{
			Ciphers: []string{"aes128-ctr"},
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

	session.Stdin = stdin
	session.Stderr = stderr
	session.Stdout = stdout
	err = session.Run("set -e;" + strings.Join(command, " "))
	if err != nil {
		clog.FromContext(ctx).Errorf("Failed to run command: %s", err)
		return err
	}

	return nil
}

func generateSSHKeys(ctx context.Context, cfg *Config, rootfs string) ([]byte, error) {
	clog.FromContext(ctx).Info("qemu: generating ssh key pairs for ephemeral VM")
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

func convertMemoryToKB(memory string) (int64, error) {
	// Map of unit multipliers
	unitMultipliers := map[string]int64{
		"Ki": 1,                  // Kibibytes
		"Mi": 1024,               // Mebibytes
		"Gi": 1024 * 1024,        // Gibibytes
		"Ti": 1024 * 1024 * 1024, // Tebibytes
		"K":  1,                  // Kilobytes (KB)
		"M":  1 * 1024,           // Megabytes (MB)
		"G":  1024 * 1024,        // Gigabytes (GB)
		"T":  1024 * 1024 * 1024, // Terabytes (TB)
		"k":  1,                  // Kilobytes (KB)
		"m":  1 * 1024,           // Megabytes (MB)
		"g":  1024 * 1024,        // Gigabytes (GB)
		"t":  1024 * 1024 * 1024, // Terabytes (TB)
	}

	// Separate the numerical part from the unit part
	var numStr, unit string
	for i, r := range memory {
		if r < '0' || r > '9' {
			numStr = memory[:i]
			unit = memory[i:]
			break
		}
	}

	if numStr == "" || unit == "" {
		return 0, fmt.Errorf("invalid memory format: %s", memory)
	}

	// Convert the numerical part to a int
	num, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number: %s", numStr)
	}

	// Get the multiplier for the unit
	multiplier, exists := unitMultipliers[unit]
	if !exists {
		return 0, fmt.Errorf("unknown unit: %s", unit)
	}

	// Return the value in kilobytes
	return num * multiplier, nil
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
