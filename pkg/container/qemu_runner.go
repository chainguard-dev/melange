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
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	apko_cpio "chainguard.dev/apko/pkg/cpio"
	"chainguard.dev/melange/internal/logwriter"
	"chainguard.dev/melange/pkg/license"
	"github.com/chainguard-dev/clog"
	"github.com/charmbracelet/log"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/kballard/go-shellquote"
	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
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
	// in case of buildless pipelines we just nop
	if cfg.SSHKey == nil {
		return nil
	}

	log := clog.FromContext(ctx)
	stdout, stderr := logwriter.New(log.Info), logwriter.New(log.Warn)
	defer stdout.Close()
	defer stderr.Close()

	err := sendSSHCommand(ctx,
		cfg.SSHClient,
		cfg,
		envOverride,
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
	clog.FromContext(ctx).Debugf("running debug command: %v", args)

	// default to root user, unless a different user is specified
	user := "root"
	if cfg.RunAs != "" {
		user = cfg.RunAs
	}

	log.Debug("qemu: ssh - get user ssh key pair")
	pubKey, err := getUserSSHKey()
	if err != nil {
		log.Warn("qemu: could not get user ssh key pair, using ephemeral ones")
	}
	if pubKey != nil {
		command := fmt.Sprintf("echo %q | tee -a /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys", strings.TrimSpace(string(pubKey)))
		err := sendSSHCommand(ctx,
			cfg.WorkspaceClient,
			cfg,
			nil,
			nil,
			nil,
			false,
			[]string{"sh", "-c", command},
		)
		if err == nil {
			clog.InfoContextf(ctx, "To enter this environment: ssh %s@localhost -p %s",
				user,
				strings.Split(cfg.SSHAddress, ":")[1])
		}
	}

	// handle terminal size, resizing and sigwinch to keep
	// it updated
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("failed to set terminal to raw mode: %v", err)
	}
	//nolint:errcheck
	defer term.Restore(fd, oldState)

	width, height, err := term.GetSize(fd)
	if err != nil {
		return fmt.Errorf("failed to get terminal size: %v", err)
	}

	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)

	hostKeyCallback, err := knownhosts.New(cfg.SSHHostKey)
	if err != nil {
		clog.FromContext(ctx).Errorf("could not create hostkeycallback function: %v", err)
		return err
	}

	// Create SSH client configuration
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(cfg.SSHKey),
		},
		Config: ssh.Config{
			Ciphers: []string{"aes128-gcm@openssh.com"},
		},
		HostKeyCallback: hostKeyCallback,
	}

	// Connect to the SSH server
	client, err := ssh.Dial("tcp", cfg.SSHAddress, config)
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

	// Set environment variables
	for k, v := range cfg.Environment {
		err = session.Setenv(k, v)
		if err != nil {
			return err
		}
	}

	for k, v := range envOverride {
		err = session.Setenv(k, v)
		if err != nil {
			return err
		}
	}

	err = session.Setenv("CAP_ADD", strings.Join(cfg.Capabilities.Add, ","))
	if err != nil {
		return err
	}

	err = session.Setenv("CAP_DROP", strings.Join(cfg.Capabilities.Drop, ","))
	if err != nil {
		return err
	}

	// Get terminal type from environment
	termType := os.Getenv("TERM")
	if termType == "" {
		termType = "xterm-256color"
	}

	// Set up comprehensive terminal modes for full functionality
	modes := ssh.TerminalModes{
		// Input modes
		ssh.IGNPAR: 0, // Don't ignore parity errors
		ssh.PARMRK: 0, // Don't mark parity errors
		ssh.INPCK:  0, // Disable input parity checking
		ssh.ISTRIP: 0, // Don't strip high bit off input chars
		ssh.INLCR:  0, // Don't translate NL to CR on input
		ssh.IGNCR:  0, // Don't ignore carriage return on input
		ssh.ICRNL:  1, // Translate carriage return to newline on input
		ssh.IUCLC:  0, // Don't map uppercase to lowercase on input
		ssh.IXON:   1, // Enable XON/XOFF flow control on input
		ssh.IXANY:  0, // Allow any character to restart output
		ssh.IXOFF:  0, // Disable sending start/stop characters

		// Output modes
		ssh.OPOST:  1, // Enable output processing
		ssh.OLCUC:  0, // Don't map lowercase to uppercase on output
		ssh.ONLCR:  1, // Map NL to CR-NL on output
		ssh.OCRNL:  0, // Don't map CR to NL on output
		ssh.ONOCR:  0, // Output CR at column 0
		ssh.ONLRET: 0, // Don't output CR

		// Control modes
		ssh.CS7:    0, // Use 8 bit characters
		ssh.CS8:    1, // Use 8 bit characters
		ssh.PARENB: 0, // No parity
		ssh.PARODD: 0, // Not odd parity

		// Local modes
		ssh.ECHO:    1, // Enable echoing of input characters
		ssh.ECHOE:   1, // Echo erase character as BS-SP-BS
		ssh.ECHOK:   1, // Echo NL after kill character
		ssh.ECHONL:  0, // Don't echo NL
		ssh.NOFLSH:  0, // Flush after interrupt and quit characters
		ssh.IEXTEN:  1, // Enable extended input processing
		ssh.ECHOCTL: 1, // Echo control characters as ^X
		ssh.ECHOKE:  1, // BS-SP-BS erase entire line on line kill
		ssh.PENDIN:  0, // Don't redisplay pending input at next read

		// Special control characters
		ssh.VEOF:     4,   // EOF character (Ctrl-D)
		ssh.VEOL:     0,   // EOL character
		ssh.VEOL2:    0,   // Second EOL character
		ssh.VERASE:   127, // Erase character (DEL)
		ssh.VWERASE:  23,  // Word erase character (Ctrl-W)
		ssh.VKILL:    21,  // Line kill character (Ctrl-U)
		ssh.VREPRINT: 18,  // Reprint character (Ctrl-R)
		ssh.VINTR:    3,   // Interrupt character (Ctrl-C)
		ssh.VQUIT:    28,  // Quit character (Ctrl-\)
		ssh.VSUSP:    26,  // Suspend character (Ctrl-Z)
		ssh.VDSUSP:   25,  // Delayed suspend (Ctrl-Y)
		ssh.VSTART:   17,  // Start character (Ctrl-Q)
		ssh.VSTOP:    19,  // Stop character (Ctrl-S)
		ssh.VLNEXT:   22,  // Literal next character (Ctrl-V)
		ssh.VDISCARD: 15,  // Discard character (Ctrl-O)

		// Terminal speed
		ssh.TTY_OP_ISPEED: 38400, // Input speed
		ssh.TTY_OP_OSPEED: 38400, // Output speed
	}

	session.Stdin = os.Stdin
	session.Stderr = os.Stderr
	session.Stdout = os.Stdout

	if err := session.RequestPty(termType, height, width, modes); err != nil {
		clog.FromContext(ctx).Errorf("request for pseudo terminal failed: %s", err)
		return err
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-winch:
				newWidth, newHeight, err := term.GetSize(fd)
				if err != nil {
					continue
				}
				err = session.WindowChange(newHeight, newWidth)
				if err != nil {
					clog.FromContext(ctx).Debugf("failed to resize window: %v", err)
				}
			}
		}
	}()

	// Trigger an initial resize to make sure sizes match
	winch <- syscall.SIGWINCH

	cmd := shellquote.Join(args...)
	return session.Run(cmd)
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

	sshPort, err := randomPortN()
	if err != nil {
		return err
	}

	cfg.SSHAddress = "127.0.0.1:" + strconv.Itoa(sshPort)

	// ensure sshWorkspacePort is random but not same as port1
	var sshWorkspacePort int
	for {
		sshWorkspacePort, err = randomPortN()
		if err != nil {
			return err
		}

		if sshWorkspacePort != sshPort {
			break
		}
	}

	cfg.SSHWorkspaceAddress = "127.0.0.1:" + strconv.Itoa(sshWorkspacePort)

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
		cfg.SSHClient,
		cfg,
		nil,
		nil,
		nil,
		false,
		[]string{"sh", "-c", "echo s > /proc/sysrq-trigger && echo o > /proc/sysrq-trigger&"},
	)
	if err != nil {
		clog.FromContext(ctx).Warnf("failed to gracefully shutdown vm, killing it: %v", err)
		// in case of graceful shutdown failure, axe it with pkill
		return syscall.Kill(cfg.QemuPID, syscall.SIGKILL)
	}

	return nil
}

// WorkspaceTar implements Runner
func (bw *qemu) WorkspaceTar(ctx context.Context, cfg *Config, extraFiles []string) (io.ReadCloser, error) {
	// in case of buildless pipelines we just nop
	if cfg.SSHKey == nil {
		return nil, nil
	}

	// For qemu, we also want to get all the detected license files for the
	// license checking that will be done later.
	// First, get the list of all files from the remote workspace.
	licenseFiles, err := getWorkspaceLicenseFiles(ctx, cfg, extraFiles)
	if err != nil {
		clog.FromContext(ctx).Errorf("failed to extract list of files for licensing: %v", err)
		return nil, err
	}
	// Now, append those files to the extraFiles list (there should be no
	// duplicates)
	extraFiles = append(extraFiles, licenseFiles...)
	// We inject the list of extra files to a remote file in order to use it
	// with `-T` option of tar. This avoids passing too many arguments to
	// the command, that would lead to an "-ash: sh: Argument list too long"
	// error otherwise.
	if len(extraFiles) > 0 {
		err = streamExtraFilesList(ctx, cfg, extraFiles)
		if err != nil {
			clog.FromContext(ctx).Errorf("failed to send list of extra files: %v", err)
			return nil, err
		}
	}

	outFile, err := os.Create(filepath.Join(cfg.WorkspaceDir, "melange-out.tar"))
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
	retrieveCommand := "cd /mount/home/build && find melange-out -type p -delete > /dev/null 2>&1 || true && tar cvpf - --xattrs --acls melange-out"
	// we append also all the necessary files that we might need, for example Licenses
	// for license checks
	if len(extraFiles) > 0 {
		retrieveCommand = retrieveCommand + " -T extrafiles.txt"
	}

	log := clog.FromContext(ctx)
	stderr := logwriter.New(log.Debug)
	err = sendSSHCommand(ctx,
		cfg.WorkspaceClient,
		cfg,
		nil,
		stderr,
		outFile,
		false,
		[]string{"sh", "-c", retrieveCommand},
	)
	if err != nil {
		var buf bytes.Buffer
		_, cerr := io.Copy(&buf, outFile)
		if cerr != nil {
			clog.FromContext(ctx).Errorf("failed to tar workspace: %v", cerr)
			return nil, cerr
		}
		clog.FromContext(ctx).Errorf("failed to tar workspace: %v", buf.String())
		return nil, err
	}

	return os.Open(outFile.Name())
}

// GetReleaseData returns the OS information (os-release contents) for the Qemu runner.
func (bw *qemu) GetReleaseData(ctx context.Context, cfg *Config) (*apko_build.ReleaseData, error) {
	// in case of buildless pipelines we just nop
	if cfg.SSHKey == nil {
		return nil, nil
	}

	var buf bytes.Buffer
	bufWriter := bufio.NewWriter(&buf)
	defer bufWriter.Flush()
	err := sendSSHCommand(ctx,
		cfg.WorkspaceClient,
		cfg,
		nil,
		nil,
		bufWriter,
		false,
		[]string{"sh", "-c", "cat /etc/os-release"},
	)

	if err != nil {
		clog.FromContext(ctx).Errorf("failed to get os-release: %v", err)
		return nil, err
	}

	// Parse the os-release contents
	return apko_build.ParseReleaseData(&buf)
}

type qemuOCILoader struct{}

func (b qemuOCILoader) LoadImage(ctx context.Context, layer v1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (ref string, err error) {
	_, span := otel.Tracer("melange").Start(ctx, "qemu.LoadImage")
	defer span.End()

	// qemu does not have the idea of container images or layers or such, just
	// create a rootfs from the layer
	guestRootfs, err := os.CreateTemp("", "melange-guest-*.tar")
	if err != nil {
		clog.FromContext(ctx).Errorf("failed to create guest dir: %v", err)
		return ref, err
	}

	// the uncompressed layer will be unpacked in a rootfs by the
	// initramfs later
	layerUncompress, err := layer.Uncompressed()
	if err != nil {
		return "", err
	}
	_, err = io.Copy(guestRootfs, layerUncompress)
	guestRootfs.Close()

	return guestRootfs.Name(), nil
}

func (b qemuOCILoader) RemoveImage(ctx context.Context, ref string) error {
	clog.FromContext(ctx).Debugf("removing image path %s", ref)
	return os.RemoveAll(ref)
}

func createMicroVM(ctx context.Context, cfg *Config) error {
	log := clog.FromContext(ctx)
	log.Debug("qemu: ssh - create ssh key pair")
	pubKey, err := generateSSHKeys(ctx, cfg)
	if err != nil {
		return err
	}

	baseargs := []string{}
	bios := false
	useVM := false
	if qemuVM, ok := os.LookupEnv("QEMU_USE_MICROVM"); ok {
		if val, err := strconv.ParseBool(qemuVM); err == nil {
			useVM = val
		}
	}

	kernelConsole := "console=hvc0"

	// If the log level is debug, then crank up the logging.
	// Otherwise, use quiet mode.
	if log.Enabled(ctx, slog.LevelDebug) {
		kernelConsole += " debug loglevel=7"
	} else {
		kernelConsole += " quiet"
	}

	serialArgs := []string{
		"-device", "virtio-serial-pci,id=virtio-serial0",
		"-chardev", "stdio,id=charconsole0",
		"-device", "virtconsole,chardev=charconsole0,id=console0",
	}
	if useVM {
		// load microvm profile and bios, shave some milliseconds from boot
		// using this will make a complete boot->initrd (with working network) In ~700ms
		// instead of ~900ms.
		for _, p := range []string{
			"/usr/share/qemu/bios-microvm.bin",
			"/usr/share/seabios/bios-microvm.bin",
		} {
			if _, err := os.Stat(p); err == nil && cfg.Arch.ToAPK() != "aarch64" {
				// only enable pcie for network, enable RTC for kernel, disable i8254PIT, i8259PIC and serial port
				baseargs = append(baseargs, "-machine", "microvm,rtc=on,pcie=on,pit=off,pic=off,isa-serial=on")
				baseargs = append(baseargs, "-bios", p)
				// microvm in qemu any version tested will not send hvc0/virtconsole to stdout
				kernelConsole = "console=ttyS0"
				serialArgs = []string{"-serial", "stdio"}
				bios = true
				break
			}
		}
	}

	// we need to fall back to -machine virt if no microVM BIOS was found (or QEMU_USE_MICROVM is false)
	if !bios {
		// aarch64 supports virt machine type, let's use that if we're on it, else
		// if we're on x86 arch, but without microvm machine type, let's go to q35
		switch cfg.Arch.ToAPK() {
		case "aarch64":
			baseargs = append(baseargs, "-machine", "virt")
		case "x86_64":
			baseargs = append(baseargs, "-machine", "q35")
		default:
			return fmt.Errorf("unknown architecture: %s", cfg.Arch.ToAPK())
		}
	}

	// default to use 85% of available memory, if a mem limit is set, respect it.
	mem := int64(float64(getAvailableMemoryKB()) * 0.85)
	if cfg.Memory != "" {
		memKb, err := convertHumanToKB(cfg.Memory)
		if err != nil {
			return err
		}

		if mem > memKb {
			mem = memKb
		}
	}
	baseargs = append(baseargs, "-m", fmt.Sprintf("%dk", mem))

	// default to use all CPUs, if a cpu limit is set, respect it.
	nproc := runtime.NumCPU()
	if cfg.CPU != "" {
		cpu, err := strconv.Atoi(cfg.CPU)
		if err == nil && nproc > cpu {
			nproc = cpu
		}
	}
	baseargs = append(baseargs, "-smp", fmt.Sprintf("%d,dies=1,sockets=1,cores=%d,threads=1", nproc, nproc))

	// use kvm on linux, Hypervisor.framework on macOS, and software for cross-arch
	switch {
	case cfg.Arch.ToAPK() != apko_types.ParseArchitecture(runtime.GOARCH).ToAPK():
		baseargs = append(baseargs, "-accel", "tcg,thread=multi")
	case runtime.GOOS == "linux":
		baseargs = append(baseargs, "-accel", "kvm")
	case runtime.GOOS == "darwin":
		baseargs = append(baseargs, "-accel", "hvf")
	default:
		baseargs = append(baseargs, "-accel", "tcg,thread=multi")
	}

	switch {
	case cfg.CPUModel != "":
		baseargs = append(baseargs, "-cpu", cfg.CPUModel)
	case cfg.Arch.ToAPK() != apko_types.ParseArchitecture(runtime.GOARCH).ToAPK():
		if cfg.Arch.ToAPK() == "aarch64" {
			baseargs = append(baseargs, "-cpu", "cortex-a76")
		} else if cfg.Arch.ToAPK() == "x86_64" {
			baseargs = append(baseargs, "-cpu", "Haswell-v4")
		} else {
			return fmt.Errorf("unknown architecture: %s", cfg.Arch.ToAPK())
		}
	default:
		baseargs = append(baseargs, "-cpu", "host")
	}

	// ensure we disable unneeded devices, this is less needed if we use microvm machines
	// but still useful otherwise
	baseargs = append(baseargs, "-display", "none")
	baseargs = append(baseargs, "-no-reboot")
	baseargs = append(baseargs, "-no-user-config")
	baseargs = append(baseargs, "-nographic")
	baseargs = append(baseargs, "-nodefaults")
	baseargs = append(baseargs, "-parallel", "none")
	baseargs = append(baseargs, serialArgs...)
	baseargs = append(baseargs, "-vga", "none")
	// use -netdev + -device instead of -nic, as this is better supported by microvm machine type
	baseargs = append(baseargs, "-netdev", "user,id=id1,hostfwd=tcp:"+cfg.SSHAddress+"-:22,hostfwd=tcp:"+cfg.SSHWorkspaceAddress+"-:2223")
	baseargs = append(baseargs, "-device", "virtio-net-pci,netdev=id1")
	// add random generator via pci, improve ssh startup time
	baseargs = append(baseargs, "-device", "virtio-rng-pci,rng=rng0", "-object", "rng-random,filename=/dev/urandom,id=rng0")
	// panic=-1 ensures that if the init fails, we immediately exit the machine
	// Add default SSH keys to the VM
	sshkey := base64.StdEncoding.EncodeToString(pubKey)
	baseargs = append(baseargs, "-append", kernelConsole+" nomodeset random.trust_cpu=on panic=-1 sshkey="+sshkey+" melange_qemu_runner=1")
	// we will *not* mount workspace using qemu, this will use 9pfs which is network-based, and will
	// kill all performances (lots of small files)
	// instead we will copy back the finished workspace artifacts when done.
	// this dramatically improves compile time, making them comparable to bwrap or docker runners.
	baseargs = append(baseargs, "-fsdev", "local,security_model=mapped,id=fsdev100,path="+cfg.WorkspaceDir)
	baseargs = append(baseargs, "-device", "virtio-9p-pci,id=fs100,fsdev=fsdev100,mount_tag=defaultshare")

	if cfg.CacheDir != "" {
		baseargs = append(baseargs, "-fsdev", "local,security_model=mapped,id=fsdev101,path="+cfg.CacheDir)
		baseargs = append(baseargs, "-device", "virtio-9p-pci,id=fs101,fsdev=fsdev101,mount_tag=melange_cache")

		// ensure the cachedir exists
		if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
			return fmt.Errorf("failed to create shared cachedir: %w", err)
		}

	}

	// if no size is specified, let's go for a default
	if cfg.Disk == "" {
		clog.FromContext(ctx).Debugf("qemu: no disk space specified, using default: %s", defaultDiskSize)
		cfg.Disk = defaultDiskSize
	}

	kernelPath, err := getKernelPath(ctx)
	if err != nil {
		clog.FromContext(ctx).Errorf("could not prepare rootfs: %v", err)
		return err
	}

	initramFile, err := generateCpio(ctx, cfg)
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: could not generate initramfs: %v", err)
		return err
	}

	baseargs = append(baseargs, "-kernel", kernelPath)
	baseargs = append(baseargs, "-initrd", initramFile)

	// if we want a disk, just add it, the init will mount it to the build home automatically
	diskFile, err := generateDiskFile(ctx, cfg.Disk)
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: could not generate additional disks: %v", err)
		return err
	}

	// save the disk name, we will wipe it off when done
	cfg.Disk = diskFile

	// append raw disk, init will take care of formatting it if present.
	baseargs = append(baseargs, "-object", "iothread,id=io1")
	baseargs = append(baseargs, "-device", "virtio-blk-pci,drive=disk0,iothread=io1,packed=on,num-queues="+fmt.Sprintf("%d", nproc/2))
	if runtime.GOOS == "linux" {
		baseargs = append(baseargs, "-drive", "if=none,id=disk0,cache=unsafe,cache.direct=on,format=raw,aio=native,file="+diskFile)
	}
	if runtime.GOOS == "darwin" {
		baseargs = append(baseargs, "-drive", "if=none,id=disk0,cache=unsafe,format=raw,aio=threads,file="+diskFile)
	}

	// append the rootfs tar.gz, init will take care of populating the disk with it
	baseargs = append(baseargs, "-object", "iothread,id=io2")
	baseargs = append(baseargs, "-device", "virtio-blk-pci,drive=image.tar,iothread=io2,packed=on,num-queues="+fmt.Sprintf("%d", nproc/2))
	baseargs = append(baseargs, "-blockdev", "driver=raw,node-name=image.tar,file.driver=file,file.filename="+cfg.ImgRef)

	// qemu-system-x86_64 or qemu-system-aarch64...
	qemuCmd := exec.CommandContext(ctx, fmt.Sprintf("qemu-system-%s", cfg.Arch.ToAPK()), baseargs...)
	clog.FromContext(ctx).Info("qemu: starting VM")
	clog.FromContext(ctx).Debugf("qemu: executing - %s", strings.Join(qemuCmd.Args, " "))

	outRead, outWrite := io.Pipe()
	errRead, errWrite := io.Pipe()

	qemuCmd.Stdout = outWrite
	qemuCmd.Stderr = errWrite

	if err := qemuCmd.Start(); err != nil {
		defer os.Remove(cfg.ImgRef)
		defer os.Remove(cfg.Disk)
		return fmt.Errorf("qemu: failed to start qemu command: %w", err)
	}

	logCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		defer outRead.Close()
		scanner := bufio.NewScanner(outRead)
		for scanner.Scan() && logCtx.Err() == nil {
			line := scanner.Text()
			log.Infof("qemu: %s", line)
		}
		if err := scanner.Err(); err != nil {
			log.Warnf("qemu stdout scanner error: %v", err)
		}
	}()

	go func() {
		defer errRead.Close()
		scanner := bufio.NewScanner(errRead)
		for scanner.Scan() && logCtx.Err() == nil {
			line := scanner.Text()
			log.Warnf("qemu: %s", line)
		}
		if err := scanner.Err(); err != nil {
			log.Warnf("qemu stderr scanner error: %v", err)
		}
	}()

	qemuExit := make(chan error, 1)
	go func() {
		err := qemuCmd.Wait()
		outWrite.Close()
		errWrite.Close()
		qemuExit <- err
	}()

	started := make(chan struct{})

	clog.FromContext(ctx).Info("qemu: waiting for SSH")
	go func() {
		// one-min timeout with a 500ms sleep
		retries := 60
		try := 0
		for try < retries {
			if logCtx.Err() != nil {
				return
			}

			try++
			time.Sleep(time.Millisecond * 500)

			log.Debugf("qemu: waiting for ssh to come up, try %d of %d", try, retries)
			err = checkSSHServer(cfg.SSHAddress)
			if err == nil {
				close(started)
				return
			} else {
				log.Debug(err.Error())
			}
		}
	}()

	select {
	case <-started:
		log.Info("qemu: VM started successfully, SSH server is up")
	case err := <-qemuExit:
		defer os.Remove(cfg.ImgRef)
		defer os.Remove(cfg.Disk)
		return fmt.Errorf("qemu: VM exited unexpectedly: %v", err)
	case <-ctx.Done():
		defer os.Remove(cfg.ImgRef)
		defer os.Remove(cfg.Disk)
		return fmt.Errorf("qemu: context canceled while waiting for VM to start")
	}

	err = getHostKey(ctx, cfg)
	if err != nil {
		return fmt.Errorf("qemu: could not get VM host key")
	}

	err = setupSSHClients(ctx, cfg)
	if err != nil {
		return fmt.Errorf("qemu: could not setup SSH client")
	}

	stdout, stderr := logwriter.New(log.Info), logwriter.New(log.Warn)
	defer stdout.Close()
	defer stderr.Close()

	if cfg.CacheDir != "" {
		clog.FromContext(ctx).Infof("qemu: setting up melange cachedir: %s", cfg.CacheDir)
		setupMountCommand := fmt.Sprintf(
			"mkdir -p %s %s /mount/upper /mount/work && mount -t 9p melange_cache %s && "+
				"mount -t overlay overlay -o lowerdir=%s,upperdir=/mount/upper,workdir=/mount/work %s",
			DefaultCacheDir,
			filepath.Join("/mount", DefaultCacheDir),
			DefaultCacheDir,
			DefaultCacheDir,
			filepath.Join("/mount", DefaultCacheDir),
		)
		if setupMountCommand != ": " {
			err = sendSSHCommand(ctx,
				cfg.WorkspaceClient,
				cfg,
				nil,
				stderr,
				stdout,
				false,
				[]string{"sh", "-c", setupMountCommand},
			)
			if err != nil {
				err = qemuCmd.Process.Kill()
				if err != nil {
					return err
				}
			}
		}
	}

	clog.FromContext(ctx).Info("qemu: setting up local workspace")
	err = sendSSHCommand(ctx,
		cfg.SSHClient,
		cfg,
		nil,
		stderr,
		stdout,
		false,
		[]string{"sh", "-c", "find /mnt/ -mindepth 1 -maxdepth 1 -exec cp -a {} /home/build/ \\;"},
	)
	if err != nil {
		err = qemuCmd.Process.Kill()
		if err != nil {
			return err
		}
	}

	cfg.QemuPID = qemuCmd.Process.Pid
	return nil
}

func setupSSHClients(ctx context.Context, cfg *Config) error {
	hostKeyCallback, err := knownhosts.New(cfg.SSHHostKey)
	if err != nil {
		clog.FromContext(ctx).Errorf("could not create hostkeycallback function: %v", err)
		return err
	}

	// default to root user, unless a different user is specified
	user := "root"
	if cfg.RunAs != "" {
		user = cfg.RunAs
	}

	// Create SSH client configuration
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(cfg.SSHKey),
		},
		Config: ssh.Config{
			Ciphers: []string{"aes128-gcm@openssh.com"},
		},
		HostKeyCallback: hostKeyCallback,
	}

	// Connect to the SSH server
	cfg.SSHClient, err = ssh.Dial("tcp", cfg.SSHAddress, config)
	if err != nil {
		clog.FromContext(ctx).Errorf("Failed to dial: %s", err)
		return err
	}

	// Connect to the SSH server
	cfg.WorkspaceClient, err = ssh.Dial("tcp", cfg.SSHWorkspaceAddress, config)
	if err != nil {
		clog.FromContext(ctx).Errorf("Failed to dial: %s", err)
		return err
	}

	return nil
}

// getWorkspaceLicenseFiles returns a list of possible license files from the
// workspace
func getWorkspaceLicenseFiles(ctx context.Context, cfg *Config, extraFiles []string) ([]string, error) {
	// let's create a string writer so that the SSH command can write
	// the list of files to it
	var buf bytes.Buffer
	bufWriter := bufio.NewWriter(&buf)
	defer bufWriter.Flush()
	err := sendSSHCommand(ctx,
		cfg.WorkspaceClient,
		cfg,
		nil,
		nil,
		bufWriter,
		false,
		[]string{"sh", "-c", "cd /mount/home/build && find . -type f -links 1 -print"},
	)
	if err != nil {
		clog.FromContext(ctx).Errorf("failed to extract list of files for licensing: %v", buf.String())
		return nil, err
	}

	// Turn extraFiles into a map for faster lookup
	extraFilesMap := make(map[string]struct{})
	for _, file := range extraFiles {
		extraFilesMap[filepath.Clean(file)] = struct{}{}
	}

	// Now, we can read the list of files from the string writer and add those
	// license files that are not in the extraFiles list
	licenseFiles := []string{}
	foundFiles := strings.SplitSeq(buf.String(), "\n")
	for f := range foundFiles {
		if _, ok := extraFilesMap[filepath.Clean(f)]; ok {
			continue
		}
		if strings.Contains(f, "melange-out") {
			continue
		}
		if is, _ := license.IsLicenseFile(f); is {
			licenseFiles = append(licenseFiles, f)
		}
	}

	return licenseFiles, nil
}

// send to the builder the list of extra files, to avoid sending a single long
// command (avoiding "-ash: sh: Argument list too long") we will use stdin to
// stream it. this also has the upside of not relying on a single-shot connection
// to pass potentially lot of data.
// split in chunks (100 stirngs at time) in order to avoid flackiness in the
// connection.
func streamExtraFilesList(ctx context.Context, cfg *Config, extraFiles []string) error {
	writtenStrings := 0
	chunkSize := 100
	log := clog.FromContext(ctx)
	stdout, stderr := logwriter.New(log.Warn), logwriter.New(log.Error)
	for {
		session, err := cfg.SSHClient.NewSession()
		if err != nil {
			clog.FromContext(ctx).Errorf("Failed to create session: %s", err)
			return err
		}
		defer session.Close()

		session.Stderr = stderr
		session.Stdout = stdout
		stdin, err := session.StdinPipe()
		if err != nil {
			return fmt.Errorf("failed to create stdin pipe: %v", err)
		}
		cmd := "cat >> /home/build/extrafiles.txt"
		if err := session.Start(cmd); err != nil {
			return fmt.Errorf("failed to start command: %v", err)
		}

		// Write 100 strings there (or remainder)
		endIndex := writtenStrings + chunkSize
		endIndex = min(endIndex, len(extraFiles))
		chunk := extraFiles[writtenStrings:endIndex]

		clog.FromContext(ctx).Debugf("sent %d of %d",
			writtenStrings, len(extraFiles))
		if _, err := io.Copy(stdin, strings.NewReader(
			strings.Join(chunk, "\n")+"\n"),
		); err != nil {
			return fmt.Errorf("failed to write content: %v", err)
		}

		if err := stdin.Close(); err != nil {
			return fmt.Errorf("failed to close stdin: %v", err)
		}

		if err := session.Wait(); err != nil {
			return fmt.Errorf("command failed: %v", err)
		}

		writtenStrings = endIndex

		if writtenStrings >= len(extraFiles) {
			break
		}
	}

	clog.FromContext(ctx).Debugf("sent %d of %d",
		writtenStrings, len(extraFiles))

	return nil
}

func getKernelPath(ctx context.Context) (string, error) {
	clog.FromContext(ctx).Debug("qemu: setting up kernel for vm")
	kernel := "/boot/vmlinuz"
	if kernelVar, ok := os.LookupEnv("QEMU_KERNEL_IMAGE"); ok {
		clog.FromContext(ctx).Debug("qemu: QEMU_KERNEL_IMAGE env set")
		if _, err := os.Stat(kernelVar); err == nil {
			clog.FromContext(ctx).Debugf("qemu: local QEMU_KERNEL_IMAGE file detected, using: %s", kernelVar)
			kernel = kernelVar
		}
	} else if _, err := os.Stat(kernel); err != nil {
		return "", fmt.Errorf("qemu: /boot/vmlinuz not found, specify a kernel path with env variable QEMU_KERNEL_IMAGE")
	}

	return kernel, nil
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

	clog.FromContext(ctx).Debugf("qemu: generating disk image, name %s, size %s:", diskName.Name(), diskSize)
	return diskName.Name(), os.Truncate(diskName.Name(), size)
}

// qemu will open the port way before the ssh daemon is ready to listen
// so we need to check if we get the SSH banner in order to value if the server
// is up or not.
// this avoids the ssh client trying to connect on a booting server.
func checkSSHServer(address string) error {
	// Establish a connection to the address
	conn, err := net.DialTimeout("tcp", address, 50*time.Millisecond)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	// Set a deadline for the connection
	err = conn.SetDeadline(time.Now().Add(time.Second))
	if err != nil {
		return err
	}
	// Read the SSH banner
	buffer := make([]byte, 255)
	n, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("conn read: %w", err)
	}

	// Check if the banner starts with "SSH-"
	banner := string(buffer[:n])
	if strings.Contains(banner, "SSH-2.0-OpenSSH") {
		return nil
	}

	return fmt.Errorf("ssh: unknown connection error")
}

func getHostKey(ctx context.Context, cfg *Config) error {
	var hostKey ssh.PublicKey

	// default to root user, unless a different user is specified
	user := "root"
	if cfg.RunAs != "" {
		user = cfg.RunAs
	}

	// Create SSH client configuration
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(cfg.SSHKey),
		},
		Config: ssh.Config{
			Ciphers: []string{"aes128-gcm@openssh.com"},
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
	hostKeyLine := fmt.Sprintf("%s %s %s\n%s %s %s\n",
		cfg.SSHAddress, hostKey.Type(), base64.StdEncoding.EncodeToString(hostKey.Marshal()),
		cfg.SSHWorkspaceAddress, hostKey.Type(), base64.StdEncoding.EncodeToString(hostKey.Marshal()),
	)
	clog.FromContext(ctx).Debugf("host-key: %s", hostKeyLine)

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

func sendSSHCommand(ctx context.Context, client *ssh.Client,
	cfg *Config, extraVars map[string]string,
	stderr, stdout io.Writer,
	tty bool, command []string,
) error {
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

	err = session.Setenv("CAP_ADD", strings.Join(cfg.Capabilities.Add, ","))
	if err != nil {
		return err
	}

	err = session.Setenv("CAP_DROP", strings.Join(cfg.Capabilities.Drop, ","))
	if err != nil {
		return err
	}

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

	clog.FromContext(ctx).Debugf("running (%d) %v", len(command), cmd)
	err = session.Run(cmd)
	if err != nil {
		clog.FromContext(ctx).Errorf("Failed to run command %q: %v", cmd, err)
		return err
	}

	return nil
}

func getUserSSHKey() ([]byte, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		log.Warnf("Failed to open SSH_AUTH_SOCK: %v, falling back to key search", err)
		currentUser, err := user.Current()
		if err != nil {
			return nil, fmt.Errorf("failed to get current user: %w", err)
		}
		sshDir := filepath.Join(currentUser.HomeDir, ".ssh")
		knownPublicKeyFiles := []string{
			"id_ecdsa.pub",
			"id_ed25519.pub",
		}

		for _, keyFile := range knownPublicKeyFiles {
			path := filepath.Join(sshDir, keyFile)
			content, err := os.ReadFile(path)
			if err == nil {
				return content, nil
			}
		}

		return nil, nil
	}

	agentClient := agent.NewClient(conn)

	signer, err := agentClient.Signers()
	if err != nil {
		return nil, err
	}

	for _, v := range signer {
		res := v.PublicKey()
		if res != nil {
			return ssh.MarshalAuthorizedKey(res), nil
		}
	}

	return nil, nil
}

func generateSSHKeys(ctx context.Context, cfg *Config) ([]byte, error) {
	clog.FromContext(ctx).Info("qemu: generating ssh key pairs for ephemeral VM")
	// Private Key generation
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Private key in PEM format
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, err
	}
	cfg.SSHKey = signer

	publicKey, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		clog.FromContext(ctx).Errorf("qemu: ssh keygen failed: %v", err)
		return nil, err
	}

	return ssh.MarshalAuthorizedKey(publicKey), nil
}

// Use binary values for all units
const (
	_  = iota
	KB = 1 << (10 * iota)
	MB
	GB
	TB
)

func convertHumanToKB(memory string) (int64, error) {
	// Map of unit multipliers
	unitMultipliers := map[string]int64{
		"Ki": KB, // Kibibytes
		"Mi": MB, // Mebibytes
		"Gi": GB, // Gibibytes
		"Ti": TB, // Tebibytes
		"K":  KB, // Kilobytes
		"M":  MB, // Megabytes
		"G":  GB, // Gigabytes
		"T":  TB, // Terabytes
		"k":  KB, // Kilobytes
		"m":  MB, // Megabytes
		"g":  GB, // Gigabytes
		"t":  TB, // Terabytes
		"B":  1,  // Bytes
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

	switch runtime.GOOS {
	case "linux":
		f, e := os.Open("/proc/meminfo")
		if e != nil {
			return mem
		}
		defer f.Close()

		s := bufio.NewScanner(f)

		for s.Scan() {
			var n int
			// Try to get MemAvailable first (available on newer kernels)
			if nItems, _ := fmt.Sscanf(s.Text(), "MemAvailable: %d kB", &n); nItems == 1 {
				return n
			}
		}

		// If MemAvailable is not found, fall back to MemFree + Buffers + Cached
		// Reset the file position
		if _, err := f.Seek(0, 0); err != nil {
			return 0
		}
		s = bufio.NewScanner(f)

		var memFree, buffers, cached int
		for s.Scan() {
			if nItems, _ := fmt.Sscanf(s.Text(), "MemFree: %d kB", &memFree); nItems == 1 {
				continue
			}
			if nItems, _ := fmt.Sscanf(s.Text(), "Buffers: %d kB", &buffers); nItems == 1 {
				continue
			}
			if nItems, _ := fmt.Sscanf(s.Text(), "Cached: %d kB", &cached); nItems == 1 {
				continue
			}
		}

		if memFree > 0 {
			return memFree + buffers + cached
		}
	case "darwin":
		var memSize int64

		cmd := exec.Command("sysctl", "-n", "hw.memsize_available")
		sysctlOut, err := cmd.Output()
		if err != nil {
			return mem
		}

		sysctlOutStr := strings.TrimSpace(string(sysctlOut))
		memSize, err = strconv.ParseInt(sysctlOutStr, 10, 64)
		if err != nil {
			return mem
		}

		// use at most 50% of total ram, in kb
		return int(memSize) / 2 / 1024
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

func generateCpio(ctx context.Context, cfg *Config) (string, error) {
	/*
	 * we only build once, useful for local development, we
	 * cache it.
	 * if present, we nop and return, else we build it.
	 */
	cacheDir := filepath.Join(
		"kernel",
		cfg.Arch.ToAPK())

	cacheDir = filepath.Join(cacheDir, "melange-cpio")

	initramfs := filepath.Join(
		cacheDir,
		"melange-guest.initramfs.cpio")
	initramfsInfo, err := os.Stat(initramfs)

	// if file is presend and less than 24h old, then we just reuse it
	if err == nil && time.Since(initramfsInfo.ModTime()) < 24*time.Hour {
		return initramfs, nil
	}

	clog.FromContext(ctx).Info("qemu: generating initramfs")

	err = os.MkdirAll(cacheDir, os.ModePerm)
	if err != nil {
		return "", fmt.Errorf("unable to dest directory: %w", err)
	}

	spec := apko_types.ImageConfiguration{
		Contents: apko_types.ImageContents{
			BuildRepositories: []string{
				"https://apk.cgr.dev/chainguard",
			},
			Packages: []string{
				"microvm-init",
			},
		},
	}
	opts := []apko_build.Option{
		apko_build.WithImageConfiguration(spec),
		apko_build.WithArch(cfg.Arch),
	}

	tmpDir, err := os.MkdirTemp("", "melange-guest-*.initramfs")
	if err != nil {
		return "", fmt.Errorf("unable to create build context: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	bc, err := apko_build.New(ctx, apkofs.DirFS(ctx, tmpDir, apkofs.WithCreateDir()), opts...)
	if err != nil {
		return "", fmt.Errorf("unable to create build context: %w", err)
	}

	bc.Summarize(ctx)
	if err := bc.BuildImage(ctx); err != nil {
		return "", fmt.Errorf("unable to generate image: %w", err)
	}
	layerTarGZ, layer, err := bc.ImageLayoutToLayer(ctx)
	if err != nil {
		return "", err
	}
	defer os.Remove(layerTarGZ)

	log.Debugf("using %s for image layer", layerTarGZ)

	// in case of some kernel images, we also need the /lib/modules directory to load
	// necessary drivers, like 9p, virtio_net which are foundamental for the VM working.
	if qemuModule, ok := os.LookupEnv("QEMU_KERNEL_MODULES"); ok {
		clog.FromContext(ctx).Debugf("qemu: QEMU_KERNEL_MODULES env set, injecting modules in initramfs")
		if _, err := os.Stat(qemuModule); err == nil {
			clog.FromContext(ctx).Debugf("qemu: local QEMU_KERNEL_MODULES dir detected, injecting")
			layer, err = injectKernelModules(ctx, layer, qemuModule)
			if err != nil {
				clog.FromContext(ctx).Errorf("qemu: could not inject needed kernel modules into initramfs: %v", err)
				return "", err
			}
		}
	}

	guestInitramfs, err := os.Create(initramfs)
	if err != nil {
		clog.FromContext(ctx).Errorf("failed to create cpio initramfs: %v", err)
		return "", err
	}

	if err := apko_cpio.FromLayer(layer, guestInitramfs); err != nil {
		clog.FromContext(ctx).Errorf("failed to convert cpio initramfs: %v", err)
		return "", err
	}

	return guestInitramfs.Name(), nil
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
