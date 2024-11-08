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
	"encoding/base64"
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
	"time"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	apko_cpio "chainguard.dev/apko/pkg/cpio"
	"chainguard.dev/melange/internal/logwriter"
	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/kballard/go-shellquote"
	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var _ Debugger = (*qemu)(nil)

const QemuName = "qemu"

const (
	defaultDiskSize = "50Gi"
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
		cfg.SSHAddress,
		cfg,
		envOverride,
		nil,
		stderr,
		stdout,
		false,
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
		cfg.SSHAddress,
		cfg,
		envOverride,
		os.Stdin,
		os.Stderr,
		os.Stdout,
		true,
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

	port, err := randomPortN()
	if err != nil {
		return err
	}

	cfg.SSHAddress = "127.0.0.1:" + strconv.Itoa(port)

	return createMicroVM(ctx, cfg)
}

// TerminatePod terminates a pod if necessary.  Not implemented
// for Qemu runners.
func (bw *qemu) TerminatePod(ctx context.Context, cfg *Config) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "qemu.TerminatePod")
	defer span.End()
	defer os.Remove(cfg.ImgRef)
	defer os.Remove(cfg.Disk)
	defer os.Remove(cfg.SSHHostKey)

	clog.FromContext(ctx).Info("qemu: sending shutdown signal")
	err := sendSSHCommand(ctx,
		"root",
		cfg.SSHAddress,
		cfg,
		nil,
		nil,
		nil,
		nil,
		false,
		[]string{"sh", "-c", "echo s > /proc/sysrq-trigger && echo o > /proc/sysrq-trigger&"},
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

	outFile, err := os.Create(filepath.Join(cfg.WorkspaceDir, "melange-out.tar.gz"))
	if err != nil {
		return nil, err
	}
	defer outFile.Close()

	clog.FromContext(ctx).Infof("fetching remote workspace")
	// work around missing scp (needs openssh-sftp package), we just tar the file
	// and pipe the output to our local file. It is potentially slower, but being
	// a localhost interface, the performance penalty should be negligible.
	//
	// We could just cp -a to /mnt as it is our shared workspace directory, but
	// this will lose some file metadata like hardlinks, owners and so on.
	// Example of package that won't work when using "cp -a" is glibc.
	err = sendSSHCommand(ctx,
		user,
		cfg.SSHAddress,
		cfg,
		nil,
		nil,
		nil,
		outFile,
		false,
		[]string{"sh", "-c", "cd /home/build && tar cvzf - melange-out"},
	)
	if err != nil {
		return nil, err
	}

	return os.Open(outFile.Name())
}

type qemuOCILoader struct{}

func (b qemuOCILoader) LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (ref string, err error) {
	_, span := otel.Tracer("melange").Start(ctx, "qemu.LoadImage")
	defer span.End()

	// qemu does not have the idea of container images or layers or such, just
	// create an initramfs from the layer
	guestInitramfs, err := os.CreateTemp("", "melange-guest-*.initramfs.cpio")
	if err != nil {
		clog.FromContext(ctx).Errorf("failed to create guest dir: %v", err)
		return ref, err
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
		clog.FromContext(ctx).Errorf("failed to create cpio initramfs: %v", err)
		return ref, err
	}

	return guestInitramfs.Name(), nil
}

func (b qemuOCILoader) RemoveImage(ctx context.Context, ref string) error {
	clog.FromContext(ctx).Infof("removing image path %s", ref)
	return os.RemoveAll(ref)
}

func createMicroVM(ctx context.Context, cfg *Config) error {
	log := clog.FromContext(ctx)
	log.Debug("qemu: ssh - create ssh key pair")
	pubKey, err := generateSSHKeys(ctx, cfg)
	if err != nil {
		return err
	}

	// always be sure to create the VM rootfs first!
	kernelPath, rootfsInitrdPath, err := getKernelPath(ctx, cfg)
	if err != nil {
		clog.FromContext(ctx).Errorf("could not prepare rootfs: %v", err)
		return err
	}

	baseargs := []string{}
	microvm := false
	// load microvm profile and bios, shave some milliseconds from boot
	// using this will make a complete boot->initrd (with working network) In ~700ms
	// instead of ~900ms.
	for _, p := range []string{
		"/usr/share/qemu/bios-microvm.bin",
		"/usr/share/seabios/bios-microvm.bin",
	} {
		if _, err := os.Stat(p); err == nil && cfg.Arch.ToAPK() != "aarch64" {
			// only enable pcie for network, enable RTC for kernel, disable i8254PIT, i8259PIC and serial port
			baseargs = append(baseargs, "-machine", "microvm,rtc=on,pcie=on,pit=off,pic=off,isa-serial=off")
			baseargs = append(baseargs, "-bios", p)
			microvm = true
			break
		}
	}

	// we need to fallback to -machine virt, if not machine has been specified
	if !microvm {
		baseargs = append(baseargs, "-machine", "virt")
		if cfg.Arch.ToAPK() != apko_types.ParseArchitecture(runtime.GOARCH).ToAPK() {
			baseargs = append(baseargs, "-machine", "virt,virtualization=true")
		} else if _, err := os.Stat("/dev/kvm"); err == nil {
			baseargs = append(baseargs, "-machine", "virt")
		}
	}

	baseargs = append(baseargs, "-kernel", kernelPath)
	baseargs = append(baseargs, "-initrd", rootfsInitrdPath)

	if cfg.Memory != "" {
		memKb, err := convertHumanToKB(cfg.Memory)
		if err != nil {
			return err
		}

		if memKb > int64(getAvailableMemoryKB()) {
			log.Warnf("qemu: requested too much memory, requested: %d, have: %d", memKb, getAvailableMemoryKB())
			memKb = int64(getAvailableMemoryKB())
		}

		cfg.Memory = fmt.Sprintf("%dk", memKb)
	} else {
		cfg.Memory = fmt.Sprintf("%dk", getAvailableMemoryKB()/4)
	}
	baseargs = append(baseargs, "-m", cfg.Memory)

	if cfg.CPU != "" {
		baseargs = append(baseargs, "-smp", cfg.CPU)
	} else {
		baseargs = append(baseargs, "-smp", fmt.Sprintf("%d", runtime.NumCPU()))
	}

	// use kvm on linux, and Hypervisor.framework on macOS
	if runtime.GOOS == "linux" {
		if cfg.Arch.ToAPK() != apko_types.ParseArchitecture(runtime.GOARCH).ToAPK() {
			baseargs = append(baseargs, "-accel", "tcg,thread=multi")
		} else if _, err := os.Stat("/dev/kvm"); err == nil {
			baseargs = append(baseargs, "-accel", "kvm")
		}
	} else if runtime.GOOS == "darwin" {
		baseargs = append(baseargs, "-accel", "hvf")
	}

	if cfg.CPUModel != "" {
		baseargs = append(baseargs, "-cpu", cfg.CPUModel)
	} else {
		baseargs = append(baseargs, "-cpu", "host")
	}

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
	baseargs = append(baseargs, "-netdev", "user,id=id1,hostfwd=tcp:"+cfg.SSHAddress+"-:22")
	baseargs = append(baseargs, "-device", "virtio-net-pci,netdev=id1")
	// add random generator via pci, improve ssh startup time
	baseargs = append(baseargs, "-device", "virtio-rng-pci,rng=rng0", "-object", "rng-random,filename=/dev/urandom,id=rng0")
	// panic=-1 ensures that if the init fails, we immediately exit the machine
	// Add default SSH keys to the VM
	sshkey := base64.StdEncoding.EncodeToString(pubKey)
	baseargs = append(baseargs, "-append", "quiet nomodeset panic=-1 sshkey="+sshkey)
	// we will *not* mount workspace using qemu, this will use 9pfs which is network-based, and will
	// kill all performances (lots of small files)
	// instead we will copy back the finished workspace artifacts when done.
	// this dramatically improves compile time, making them comparable to bwrap or docker runners.
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
	baseargs = append(baseargs, "-object", "iothread,id=io1")
	baseargs = append(baseargs, "-device", "virtio-blk-pci,drive=disk0,iothread=io1")
	baseargs = append(baseargs, "-drive", "if=none,id=disk0,cache=none,format=raw,aio=threads,werror=report,rerror=report,file="+diskFile)
	// save the disk name, we will wipe it off when done
	cfg.Disk = diskFile

	// qemu-system-x86_64 or qemu-system-aarch64...
	qemuCmd := exec.CommandContext(ctx, fmt.Sprintf("qemu-system-%s", cfg.Arch.ToAPK()), baseargs...)
	clog.FromContext(ctx).Infof("qemu: executing - %s", strings.Join(qemuCmd.Args, " "))

	output, err := qemuCmd.CombinedOutput()
	if err != nil {
		// ensure cleanup of resources
		defer os.Remove(cfg.ImgRef)
		defer os.Remove(cfg.Disk)

		clog.FromContext(ctx).Errorf("qemu: failed to run qemu command: %v - %s", err, string(output))
		return err
	}

	// 5 minutes timeout
	retries := 6000
	try := 0
	for try <= retries {
		clog.FromContext(ctx).Infof("qemu: waiting for ssh to come up, try %d of %d", try, retries)
		// Attempt to connect to the address
		err = checkSSHServer(cfg.SSHAddress)
		if err == nil {
			break
		}
		try++
		time.Sleep(time.Millisecond * 200)
	}
	if try >= retries {
		// ensure cleanup of resources
		defer os.Remove(cfg.ImgRef)
		defer os.Remove(cfg.Disk)
		return fmt.Errorf("qemu: could not start VM, timeout reached")
	}

	err = getHostKey(ctx, cfg)
	if err != nil {
		return fmt.Errorf("qemu: could not get VM host key")
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
		cfg.SSHAddress,
		cfg,
		nil,
		nil,
		nil,
		nil,
		false,
		[]string{"sh", "-c", "cp -r /mnt/. /home/build"},
	)
}

func getKernelPath(ctx context.Context, cfg *Config) (string, string, error) {
	clog.FromContext(ctx).Debug("qemu: setting up kernel for vm")
	kernel := "/boot/vmlinuz"
	if kernelVar, ok := os.LookupEnv("QEMU_KERNEL_IMAGE"); ok {
		clog.FromContext(ctx).Info("qemu: QEMU_KERNEL_IMAGE env set")
		if _, err := os.Stat(kernelVar); err == nil {
			clog.FromContext(ctx).Infof("qemu: local QEMU_KERNEL_IMAGE file detected, using: %s", kernelVar)
			kernel = kernelVar
		}
	} else if _, err := os.Stat(kernel); err != nil {
		return "", "", fmt.Errorf("qemu: /boot/vmlinuz not found, specify a kernel path with env variable QEMU_KERNEL_IMAGE and QEMU_KERNEL_MODULES if needed")
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

	size, err := convertHumanToKB(diskSize)
	if err != nil {
		return "", err
	}

	// we need bytes
	size = size * 1024

	clog.FromContext(ctx).Infof("qemu: generating disk image, name %s, size %s:", diskName.Name(), diskSize)
	return diskName.Name(), os.Truncate(diskName.Name(), size)
}

// qemu will open the port way before the ssh daemon is ready to listen
// so we need to check if we get the SSH banner in order to value if the server
// is up or not.
// this avoids the ssh client trying to connect on a booting server.
func checkSSHServer(address string) error {
	// Establish a connection to the address
	conn, err := net.DialTimeout("tcp", address, time.Millisecond*500)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Set a deadline for the connection
	err = conn.SetDeadline(time.Now().Add(time.Millisecond * 500))
	if err != nil {
		return err
	}

	// Read the SSH banner
	buffer := make([]byte, 255)
	n, err := conn.Read(buffer)
	if err != nil {
		return err
	}

	// Check if the banner starts with "SSH-"
	banner := string(buffer[:n])
	if len(banner) >= 4 && banner[:4] == "SSH-" {
		return err
	}

	return nil
}

func getHostKey(ctx context.Context, cfg *Config) error {
	var hostKey ssh.PublicKey

	signer, err := ssh.ParsePrivateKey(cfg.SSHKey)
	if err != nil {
		clog.FromContext(ctx).Errorf("Unable to parse private key: %v", err)
		return err
	}

	// Create SSH client configuration
	config := &ssh.ClientConfig{
		User: "build",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		Config: ssh.Config{
			Ciphers: []string{"aes128-ctr"},
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			hostKey = key
			return nil // Accept the host key for the purpose of retrieving it
		},
	}

	// Connect to the SSH server
	client, err := ssh.Dial("tcp", cfg.SSHAddress, config)
	if err != nil {
		clog.FromContext(ctx).Errorf("Failed to dial: %s", err)
		return err
	}
	defer client.Close()

	// Write the host key to the known_hosts file
	hostKeyLine := fmt.Sprintf("%s %s %s\n", cfg.SSHAddress, hostKey.Type(), base64.StdEncoding.EncodeToString(hostKey.Marshal()))
	clog.FromContext(ctx).Infof("host-key: %s", hostKeyLine)

	knownHost, err := os.CreateTemp("", "known_hosts_*")
	if err != nil {
		clog.FromContext(ctx).Errorf("host-key fetch - failed to create random known_hosts file: %v", err)
		return err
	}
	defer knownHost.Close()

	cfg.SSHHostKey = knownHost.Name()

	_, err = knownHost.Write([]byte(hostKeyLine))
	if err != nil {
		clog.FromContext(ctx).Errorf("host-key fetch - failed to write to known_hosts file: %v", err)
		return err
	}
	return nil
}

func sendSSHCommand(ctx context.Context, user, address string,
	cfg *Config, extraVars map[string]string,
	stdin io.Reader, stderr, stdout io.Writer,
	tty bool, command []string,
) error {
	signer, err := ssh.ParsePrivateKey(cfg.SSHKey)
	if err != nil {
		clog.FromContext(ctx).Errorf("Unable to parse private key: %v", err)
		return err
	}

	hostKeyCallback, err := knownhosts.New(cfg.SSHHostKey)
	if err != nil {
		clog.FromContext(ctx).Errorf("could not create hostkeycallback function: %v", err)
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
		HostKeyCallback: hostKeyCallback,
	}

	// Connect to the SSH server
	client, err := ssh.Dial("tcp", address, config)
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

	if tty {
		clog.FromContext(ctx).Debug("requesting tty instance")
		modes := ssh.TerminalModes{
			ssh.ECHO:          0,     // disable echoing
			ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
			ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		}
		// Request pseudo terminal
		if err := session.RequestPty("xterm", 40, 80, modes); err != nil {
			clog.FromContext(ctx).Errorf("request for pseudo terminal failed: %s", err)
			return err
		}
	}

	cmd := shellquote.Join(command...)

	clog.FromContext(ctx).Infof("running (%d) %v", len(command), cmd)
	err = session.Run(cmd)
	if err != nil {
		clog.FromContext(ctx).Errorf("Failed to run command %v: %s", command, err)
		return err
	}

	return nil
}

func generateSSHKeys(ctx context.Context, cfg *Config) ([]byte, error) {
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

func convertHumanToKB(memory string) (int64, error) {
	// Map of unit multipliers
	unitMultipliers := map[string]int64{
		"Ki": 1024,                      // Kibibytes
		"Mi": 1024 * 1024,               // Mebibytes
		"Gi": 1024 * 1024 * 1024,        // Gibibytes
		"Ti": 1024 * 1024 * 1024 * 1024, // Tebibytes
		"K":  1024,                      // Kilobytes (KB)
		"M":  1024 * 1024,               // Megabytes (MB)
		"G":  1024 * 1024 * 1024,        // Gigabytes (GB)
		"T":  1024 * 1024 * 1024 * 1024, // Terabytes (TB)
		"k":  1024,                      // Kilobytes (KB)
		"m":  1024 * 1024,               // Megabytes (MB)
		"g":  1024 * 1024 * 1024,        // Gigabytes (GB)
		"t":  1024 * 1024 * 1024 * 1024, // Terabytes (TB)
		"B":  1,
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
	return num * multiplier / 1024, nil
}

func getAvailableMemoryKB() int {
	mem := 16000000

	f, e := os.Open("/proc/meminfo")
	if e != nil {
		return mem
	}
	defer f.Close()

	s := bufio.NewScanner(f)

	for s.Scan() {
		var n int
		if nItems, _ := fmt.Sscanf(s.Text(), "MemTotal: %d kB", &n); nItems == 1 {
			return n
		}
	}

	return mem
}

func randomPortN() (int, error) {
	l, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return 0, fmt.Errorf("no open port found")
	}
	defer l.Close()

	return l.Addr().(*net.TCPAddr).Port, nil
}
