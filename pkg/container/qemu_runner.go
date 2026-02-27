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
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	apkofs "chainguard.dev/apko/pkg/apk/fs"
	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	apko_cpio "chainguard.dev/apko/pkg/cpio"
	"github.com/chainguard-dev/clog"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/kballard/go-shellquote"
	"github.com/u-root/u-root/pkg/cpio"
	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"

	"chainguard.dev/melange/internal/logwriter"
	"chainguard.dev/melange/pkg/license"
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
		cfg.SSHBuildClient,
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
	log := clog.FromContext(ctx)
	log.Debugf("running debug command: %v", args)

	// default to root user, unless a different user is specified
	user := "root"
	if cfg.RunAs != "" {
		user = cfg.RunAs
	}

	log.Debug("qemu: ssh - get user ssh key pair")
	pubKey, err := getUserSSHKey(ctx)
	if err != nil {
		log.Warn("qemu: could not get user ssh key pair, using ephemeral ones")
	}
	if pubKey != nil {
		command := fmt.Sprintf("echo %q | tee -a /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys", strings.TrimSpace(string(pubKey)))
		err := sendSSHCommand(ctx,
			cfg.SSHControlClient,
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
		return fmt.Errorf("failed to set terminal to raw mode: %w", err)
	}
	//nolint:errcheck
	defer term.Restore(fd, oldState)

	width, height, err := term.GetSize(fd)
	if err != nil {
		return fmt.Errorf("failed to get terminal size: %w", err)
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

	// ensure sshControlPort is random but not same as port1
	var sshControlPort int
	for {
		sshControlPort, err = randomPortN()
		if err != nil {
			return err
		}

		if sshControlPort != sshPort {
			break
		}
	}

	cfg.SSHControlAddress = "127.0.0.1:" + strconv.Itoa(sshControlPort)

	return createMicroVM(ctx, cfg)
}

// TerminatePod terminates a pod if necessary. For Qemu runners, shuts
// down the guest VM.
func (bw *qemu) TerminatePod(ctx context.Context, cfg *Config) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "qemu.TerminatePod")
	defer span.End()
	defer os.Remove(cfg.ImgRef)
	defer os.Remove(cfg.Disk)
	defer os.Remove(cfg.SSHHostKey)
	defer secureDelete(ctx, cfg.InitramfsPath)
	defer stopVirtiofsd(ctx, cfg)

	clog.FromContext(ctx).Info("qemu: sending shutdown signal")
	err := sendSSHCommand(ctx,
		cfg.SSHControlClient,
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

	errFile_path := filepath.Join(cfg.WorkspaceDir, ".error-file")
	errFile, err := os.Create(errFile_path)
	if err != nil {
		return nil, err
	}
	defer errFile.Close()

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
		retrieveCommand += " -T extrafiles.txt"
	}

	err = sendSSHCommand(ctx,
		cfg.SSHControlClient,
		cfg,
		nil,
		errFile,
		outFile,
		false,
		[]string{"sh", "-c", retrieveCommand},
	)
	if err != nil {
		savederr := err
		outErr, err := os.ReadFile(errFile_path)
		if err == nil {
			clog.FromContext(ctx).Errorf("failed to tar workspace:\n%s", string(outErr))
		} else {
			clog.FromContext(ctx).Errorf("failed to tar workspace; failed to obtain error output")
		}

		return nil, savederr
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
		cfg.SSHControlClient,
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

// getGuestKernelVersion returns the kernel version for the Qemu runner.
func getGuestKernelVersion(ctx context.Context, cfg *Config) (version string, err error) {
	if cfg.SSHKey == nil {
		return "", nil
	}

	var buf bytes.Buffer
	bufWriter := bufio.NewWriter(&buf)
	defer bufWriter.Flush()
	err = sendSSHCommand(ctx,
		cfg.SSHControlClient,
		cfg,
		nil,
		nil,
		bufWriter,
		false,
		[]string{"uname", "-rv"},
	)
	if err != nil {
		clog.FromContext(ctx).Errorf("failed to get kernel release version: %v", err)
		return "", err
	}

	return strings.TrimSpace(buf.String()), nil
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
	if closeErr := guestRootfs.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}

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

	// Generate VM host key for pre-provisioned, secure host key verification
	err = generateVMHostKey(ctx, cfg)
	if err != nil {
		return err
	}

	// Set up virtiofs for cache directory if enabled and available
	if cfg.CacheDir != "" {
		// Ensure the cachedir exists
		if err := os.MkdirAll(cfg.CacheDir, 0o755); err != nil {
			return fmt.Errorf("failed to create shared cachedir: %w", err)
		}

		var err error
		cfg.VirtiofsEnabled, err = useVirtiofs()
		if err != nil {
			return err
		}

		if cfg.VirtiofsEnabled {
			// Generate a random socket path
			var randBytes [8]byte
			if _, err := rand.Read(randBytes[:]); err != nil {
				return fmt.Errorf("failed to generate random bytes for socket path: %w", err)
			}
			cfg.VirtiofsdSocketPath = filepath.Join(os.TempDir(), fmt.Sprintf("melange-virtiofsd-%x.sock", randBytes))

			virtiofsdCmd, err := startVirtiofsd(ctx, cfg)
			if err != nil {
				return fmt.Errorf("failed to start virtiofsd: %w", err)
			}
			cfg.VirtiofsdPID = virtiofsdCmd.Process.Pid
		}
	}

	baseargs := []string{}

	kernelConsole := ""
	// If the log level is debug, then crank up the logging.
	// Otherwise, use quiet mode.
	if log.Enabled(ctx, slog.LevelDebug) {
		kernelConsole += " debug loglevel=7"
	} else {
		kernelConsole += " quiet"
	}

	// Only enable console on debug runs.
	// Spare some boot time and memory
	serialArgs := []string{}
	if log.Enabled(ctx, slog.LevelDebug) {
		kernelConsole = "console=hvc0"
		serialArgs = []string{
			"-device", "virtio-serial-pci,id=virtio-serial0,max_ports=2",
			"-chardev", "stdio,id=charconsole0",
			"-device", "virtconsole,chardev=charconsole0,id=console0",
		}
	}

	// Helper to add memory-backend suffix for virtiofs shared memory
	machineMemorySuffix := ""
	if cfg.VirtiofsEnabled {
		machineMemorySuffix = ",memory-backend=mem"
	}

	// aarch64 supports virt machine type, let's use that if we're on it, else
	// if we're on x86 arch, but without microvm machine type, let's go to q35
	switch cfg.Arch.ToAPK() {
	case "aarch64":
		baseargs = append(baseargs, "-machine", "virt"+machineMemorySuffix)
	case "x86_64":
		baseargs = append(baseargs, "-machine", "q35,hpet=off,smm=off,pit=off,i8042=off,sata=off,smbus=off,usb=off,vmport=off,graphics=off"+machineMemorySuffix)
	default:
		return fmt.Errorf("unknown architecture: %s", cfg.Arch.ToAPK())
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
	// Memory configuration - virtiofs requires shared memory backend
	if cfg.VirtiofsEnabled {
		// Round up memory to MiB boundary for memory-backend-memfd alignment
		memMiB := (mem + 1023) / 1024 * 1024
		baseargs = append(baseargs, "-m", fmt.Sprintf("%dk", memMiB))
		baseargs = append(baseargs, "-object", fmt.Sprintf("memory-backend-memfd,id=mem,size=%dM,share=on", memMiB/1024))
	} else {
		baseargs = append(baseargs, "-m", fmt.Sprintf("%dk", mem))
	}

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
		switch cfg.Arch.ToAPK() {
		case "aarch64":
			baseargs = append(baseargs, "-cpu", "cortex-a76")
		case "x86_64":
			baseargs = append(baseargs, "-cpu", "Haswell-v4")
		default:
			return fmt.Errorf("unknown architecture: %s", cfg.Arch.ToAPK())
		}
	default:
		baseargs = append(baseargs, "-cpu", "host")
	}

	cmdlineVar, ok := os.LookupEnv("QEMU_KERNEL_CMDLINE")
	if ok {
		clog.FromContext(ctx).Infof("qemu: QEMU_KERNEL_CMDLINE set to: %s", cmdlineVar)
	} else {
		cmdlineVar = ""
	}

	// ensure we disable unneeded devices, this is less needed if we use microvm machines
	// but still useful otherwise
	baseargs = append(baseargs, "-display", "none")
	baseargs = append(baseargs, "-no-reboot")
	baseargs = append(baseargs, "-no-user-config")
	baseargs = append(baseargs, "-nodefaults")
	baseargs = append(baseargs, serialArgs...)
	// use -netdev + -device instead of -nic, as this is better supported by microvm machine type
	baseargs = append(baseargs, "-netdev", "user,id=id1,hostfwd=tcp:"+cfg.SSHAddress+"-:22,hostfwd=tcp:"+cfg.SSHControlAddress+"-:2223")
	baseargs = append(baseargs, "-device", "virtio-net-pci,netdev=id1,romfile=")
	// add random generator via pci, improve ssh startup time
	baseargs = append(baseargs, "-device", "virtio-rng-pci,rng=rng0", "-object", "rng-random,filename=/dev/urandom,id=rng0")
	// panic=-1 ensures that if the init fails, we immediately exit the machine
	// Add default SSH keys to the VM
	sshkey := base64.StdEncoding.EncodeToString(pubKey)

	// Build kernel command line arguments
	kernelArgs := kernelConsole +
		" nomodeset random.trust_cpu=on" +
		" noapic nomodules 8250.nr_uarts=0 tsc=reliable" +
		" no_timer_check cryptomgr.notests" +
		" rcupdate.rcu_expedited=1 panic=-1" +
		" pci=lastbus=0 ftrace=off swiotlb=noforce edd=off " +
		cmdlineVar + " sshkey=" + sshkey +
		" melange_qemu_runner=1"

	// Check for TESTING environment variable and pass it to microvm-init
	// TESTING must be a number (0 for disabled, non-zero for enabled)
	if testingValue, ok := os.LookupEnv("TESTING"); ok {
		if _, err := strconv.Atoi(testingValue); err == nil {
			log.Infof("qemu: TESTING env set to %s, passing to microvm-init via kernel cmdline", testingValue)
			kernelArgs += " melange.testing=" + testingValue
		} else {
			log.Warnf("qemu: TESTING env must be a number, ignoring invalid value: %s", testingValue)
		}
	}

	baseargs = append(baseargs, "-append", kernelArgs)
	// we will *not* mount workspace using qemu, this will use 9pfs which is network-based, and will
	// kill all performances (lots of small files)
	// instead we will copy back the finished workspace artifacts when done.
	// this dramatically improves compile time, making them comparable to bwrap or docker runners.
	// FIXME: set readonly=on once the microvm-init script does not twiddle with /mount/mnt
	baseargs = append(baseargs, "-fsdev", "local,security_model=mapped,id=fsdev100,path="+cfg.WorkspaceDir)
	baseargs = append(baseargs, "-device", "virtio-9p-pci,id=fs100,fsdev=fsdev100,mount_tag=defaultshare")

	if cfg.CacheDir != "" {
		if cfg.VirtiofsEnabled {
			log.Info("qemu: using virtiofs for cache directory (read-write)")
			// Chardev for socket communication
			baseargs = append(baseargs,
				"-chardev",
				fmt.Sprintf("socket,id=char_cache,path=%s", cfg.VirtiofsdSocketPath))
			// vhost-user-fs-pci device
			baseargs = append(baseargs, "-device",
				"vhost-user-fs-pci,queue-size=1024,chardev=char_cache,tag=melange_cache")
		} else {
			log.Info("qemu: using 9p for cache directory (read-only with overlay)")
			baseargs = append(baseargs, "-fsdev", "local,security_model=mapped,id=fsdev101,readonly=on,path="+cfg.CacheDir)
			baseargs = append(baseargs, "-device", "virtio-9p-pci,id=fs101,fsdev=fsdev101,mount_tag=melange_cache")
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

	// Store initramfs path for cleanup
	cfg.InitramfsPath = initramFile

	defer func() {
		if cfg.InitramfsPath != "" {
			secureDelete(ctx, cfg.InitramfsPath)
		}
	}()

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
	baseargs = append(baseargs, "-device", "virtio-blk-pci,drive=disk0,iothread=io1,packed=on,num-queues="+fmt.Sprintf("%d", max(1, nproc/2)))
	baseargs = append(baseargs, "-drive", "if=none,id=disk0,cache=unsafe,format=raw,aio=threads,file="+diskFile)

	// append the rootfs tar.gz, init will take care of populating the disk with it
	baseargs = append(baseargs, "-object", "iothread,id=io2")
	baseargs = append(baseargs, "-device", "virtio-blk-pci,drive=image.tar,iothread=io2,packed=on,num-queues="+fmt.Sprintf("%d", max(1, nproc/2)))
	baseargs = append(baseargs, "-blockdev", "driver=raw,node-name=image.tar,file.driver=file,file.filename="+cfg.ImgRef)

	// qemu-system-x86_64 or qemu-system-aarch64...
	// #nosec G204 - Architecture is from validated configuration, not user input
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
		defer stopVirtiofsd(ctx, cfg)
		return fmt.Errorf("qemu: failed to start qemu command: %w", err)
	}

	logCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(fmt.Errorf("normal cleanup"))

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
		_ = outWrite.Close() // Ignore error in goroutine cleanup
		_ = errWrite.Close() // Ignore error in goroutine cleanup
		qemuExit <- err
	}()

	started := make(chan struct{})

	clog.FromContext(ctx).Info("qemu: waiting for SSH")
	go func() {
		// 100ms timeout with a 100ms sleep
		retries := 60
		try := 0
		for try < retries {
			if logCtx.Err() != nil {
				return
			}

			try++
			time.Sleep(time.Millisecond * 100)

			log.Debugf("qemu: waiting for ssh to come up, try %d of %d", try, retries)
			err = checkSSHServer(cfg.SSHAddress)
			if err == nil {
				close(started)
				return
			} else {
				log.Info(err.Error())
			}
		}

		cancel(fmt.Errorf("ssh server never came up"))
	}()

	select {
	case <-started:
		log.Info("qemu: VM started successfully, SSH server is up")
		secureDelete(ctx, cfg.InitramfsPath)
		cfg.InitramfsPath = ""
	case err := <-qemuExit:
		defer os.Remove(cfg.ImgRef)
		defer os.Remove(cfg.Disk)
		defer stopVirtiofsd(ctx, cfg)
		return fmt.Errorf("qemu: VM exited unexpectedly: %w", err)
	case <-ctx.Done():
		defer os.Remove(cfg.ImgRef)
		defer os.Remove(cfg.Disk)
		defer stopVirtiofsd(ctx, cfg)
		return fmt.Errorf("qemu: context canceled while waiting for VM to start: %w", context.Cause(ctx))
	}

	err = getHostKey(ctx, cfg)
	if err != nil {
		return fmt.Errorf("qemu: could not get VM host key")
	}

	err = setupSSHClients(ctx, cfg)
	if err != nil {
		return fmt.Errorf("qemu: could not setup SSH client")
	}

	// Zero out sensitive private key material now that all SSH connections are established
	// The public key is retained for verification in setupSSHClients
	zeroSensitiveFields(ctx, cfg)

	stdout, stderr := logwriter.New(log.Info), logwriter.New(log.Warn)
	defer stdout.Close()
	defer stderr.Close()

	kv, err := getGuestKernelVersion(ctx, cfg)
	if err != nil {
		return fmt.Errorf("qemu: unable to query guest kernel version")
	}
	clog.FromContext(ctx).Infof("qemu: running kernel version: %s", kv)

	if cfg.CacheDir != "" {
		var setupMountCommand string

		if cfg.VirtiofsEnabled {
			// Virtiofs: read-write mount at the chroot path
			// The build runs chrooted at /mount/, so we mount at /mount/var/cache/melange
			// which appears as /var/cache/melange inside the chroot
			chrootCacheDir := filepath.Join("/mount", DefaultCacheDir)
			clog.FromContext(ctx).Infof("qemu: setting up virtiofs cache mount (read-write): %s -> %s", cfg.CacheDir, chrootCacheDir)
			setupMountCommand = fmt.Sprintf(
				"mkdir -p %s && mount -t virtiofs melange_cache %s",
				chrootCacheDir,
				chrootCacheDir,
			)
		} else {
			// 9p: readonly with overlay for write support
			clog.FromContext(ctx).Infof("qemu: setting up 9p cache mount (read-only with overlay): %s", cfg.CacheDir)
			setupMountCommand = fmt.Sprintf(
				"mkdir -p %s %s /mount/upper /mount/work && "+
					"chmod 1777 /mount/upper && "+
					"mount -t 9p -o ro melange_cache %s && "+
					"mount -t overlay overlay -o lowerdir=%s,upperdir=/mount/upper,workdir=/mount/work %s",
				DefaultCacheDir,
				filepath.Join("/mount", DefaultCacheDir),
				DefaultCacheDir,
				DefaultCacheDir,
				filepath.Join("/mount", DefaultCacheDir),
			)
		}

		err = sendSSHCommand(ctx,
			cfg.SSHControlClient,
			cfg,
			nil,
			stderr,
			stdout,
			false,
			[]string{"sh", "-c", setupMountCommand},
		)
		if err != nil {
			// Clean up virtiofsd on failure
			if cfg.VirtiofsEnabled {
				stopVirtiofsd(ctx, cfg)
			}
			err = qemuCmd.Process.Kill()
			if err != nil {
				return err
			}
		}
	}

	clog.FromContext(ctx).Info("qemu: setting up local workspace")
	// because microvm-init both mounts and modifies /mnt/ in the
	// workspace, but want to get rid of that, we need to handle both
	// remounting and first mount of the defaultshare virtfs share.
	setupMountCommand := "if grep -q '^defaultshare ' /proc/mounts ; then " +
		"  mount -t 9p -o remount,ro,trans=virtio defaultshare /mount/mnt ; " +
		"else " +
		"  mount -t 9p -o ro,trans=virtio defaultshare /mount/mnt; " +
		"fi"
	err = sendSSHCommand(ctx,
		cfg.SSHControlClient,
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

	// This has to happen as the user we are building as, so
	// files copied are owned by the build user, and thus cleanup
	// step that happens at the end of the build to remove the
	// files succeeds
	copyFilesCommand := fmt.Sprintf(
		"find /mnt/ -mindepth 1 -maxdepth 1 -exec cp -a {} /home/build/ \\; && "+
			"chown -R %s /home/build",
		cfg.SSHBuildClient.User(),
	)
	err = sendSSHCommand(ctx,
		cfg.SSHControlBuildClient,
		cfg,
		nil,
		stderr,
		stdout,
		false,
		[]string{"sh", "-c", copyFilesCommand},
	)
	if err != nil {
		err = qemuCmd.Process.Kill()
		if err != nil {
			return err
		}
	}

	clog.FromContext(ctx).Info("qemu: unmounting host workspace from guest")
	// now that we've copied files from the host filesystem into the
	// guest's workspace, we can umount the filesystem, as nothing in
	// the build should reference the original location and it reduces
	// the ability of later build steps to possibly interact with the
	// host.
	err = sendSSHCommand(ctx,
		cfg.SSHControlClient,
		cfg,
		nil,
		stderr,
		stdout,
		false,
		[]string{"sh", "-c", "if [ -x /usr/bin/umount ] ; then umount /mount/mnt ; fi"},
	)
	if err != nil {
		clog.FromContext(ctx).Warnf("qemu: failed to unmount /mount/mnt in guest")
		err = qemuCmd.Process.Kill()
		if err != nil {
			return err
		}
		// don't fail the build because of this.
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

	// Create privileged SSH control client configuration
	controlConfig := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(cfg.SSHKey),
		},
		Config: ssh.Config{
			Ciphers: []string{"aes128-gcm@openssh.com"},
		},
		HostKeyCallback: hostKeyCallback,
	}

	// Create SSH build client configuration
	buildConfig := &ssh.ClientConfig{
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
	cfg.SSHBuildClient, err = ssh.Dial("tcp", cfg.SSHAddress, buildConfig)
	if err != nil {
		clog.FromContext(ctx).Errorf("Failed to dial: %s", err)
		return err
	}

	// Connect to the SSH server on the control (unchrooted) port
	cfg.SSHControlClient, err = ssh.Dial("tcp", cfg.SSHControlAddress, controlConfig)
	if err != nil {
		clog.FromContext(ctx).Errorf("Failed to dial: %s", err)
		return err
	}

	// Connect to the SSH server on the chrooted port with privilege
	cfg.SSHControlBuildClient, err = ssh.Dial("tcp", cfg.SSHAddress, controlConfig)
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
		cfg.SSHControlClient,
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
		if is, _ := license.IsLicenseFile(f, false); is {
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
		session, err := cfg.SSHBuildClient.NewSession()
		if err != nil {
			clog.FromContext(ctx).Errorf("Failed to create session: %s", err)
			return err
		}
		defer session.Close()

		session.Stderr = stderr
		session.Stdout = stdout
		stdin, err := session.StdinPipe()
		if err != nil {
			return fmt.Errorf("failed to create stdin pipe: %w", err)
		}
		cmd := "cat >> /home/build/extrafiles.txt"
		if err := session.Start(cmd); err != nil {
			return fmt.Errorf("failed to start command: %w", err)
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
			return fmt.Errorf("failed to write content: %w", err)
		}

		if err := stdin.Close(); err != nil {
			return fmt.Errorf("failed to close stdin: %w", err)
		}

		if err := session.Wait(); err != nil {
			return fmt.Errorf("command failed: %w", err)
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
		err = os.MkdirAll(diskPath, 0o755)
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
	size *= 1024

	clog.FromContext(ctx).Debugf("qemu: generating disk image, name %s, size %s:", diskName.Name(), diskSize)
	return diskName.Name(), os.Truncate(diskName.Name(), size)
}

// qemu will open the port way before the ssh daemon is ready to listen
// so we need to check if we get the SSH banner in order to value if the server
// is up or not.
// this avoids the ssh client trying to connect on a booting server.
func checkSSHServer(address string) error {
	// Establish a connection to the address
	conn, err := net.DialTimeout("tcp", address, 150*time.Millisecond)
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

// getHostKey verifies the VM's SSH host key against the pre-provisioned key
func getHostKey(ctx context.Context, cfg *Config) error {
	if cfg.VMHostKeyPublic == nil {
		return fmt.Errorf("VM host key not pre-provisioned")
	}

	clog.FromContext(ctx).Info("qemu: verifying VM host key against pre-provisioned key")

	// Validate this is a localhost connection
	host, _, err := net.SplitHostPort(cfg.SSHAddress)
	if err != nil {
		return fmt.Errorf("invalid SSH address format: %w", err)
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return fmt.Errorf("refusing SSH connection to non-localhost address: %s", host)
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
		HostKeyCallback: ssh.FixedHostKey(cfg.VMHostKeyPublic),
	}

	client, err := ssh.Dial("tcp", cfg.SSHAddress, config)
	if err != nil {
		clog.FromContext(ctx).Errorf("Failed to verify and connect to VM: %s", err)
		return fmt.Errorf("vm host key verification failed (possible security issue): %w", err)
	}
	defer client.Close()

	clog.FromContext(ctx).Info("qemu: VM host key successfully verified against pre-provisioned key")

	// Write the verified host key to a known_hosts file for use by setupSSHClients
	// which uses knownhosts.New() for subsequent connections
	hostKeyLine := fmt.Sprintf("%s %s %s\n%s %s %s\n",
		cfg.SSHAddress, cfg.VMHostKeyPublic.Type(), base64.StdEncoding.EncodeToString(cfg.VMHostKeyPublic.Marshal()),
		cfg.SSHControlAddress, cfg.VMHostKeyPublic.Type(), base64.StdEncoding.EncodeToString(cfg.VMHostKeyPublic.Marshal()),
	)

	knownHost, err := os.CreateTemp("", "known_hosts_*")
	if err != nil {
		clog.FromContext(ctx).Errorf("host-key - failed to create known_hosts file: %v", err)
		return err
	}
	defer knownHost.Close()

	cfg.SSHHostKey = knownHost.Name()

	_, err = knownHost.Write([]byte(hostKeyLine))
	if err != nil {
		clog.FromContext(ctx).Errorf("host-key - failed to write to known_hosts file: %v", err)
		return err
	}

	clog.FromContext(ctx).Debugf("qemu: host key written to %s for subsequent connections", cfg.SSHHostKey)
	return nil
}

func sendSSHCommand(ctx context.Context, client *ssh.Client,
	cfg *Config, extraVars map[string]string,
	stderr, stdout io.Writer,
	tty bool, command []string, //nolint:unparam
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

func getUserSSHKey(ctx context.Context) ([]byte, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	conn, err := net.Dial("unix", socket)
	if err != nil {
		clog.FromContext(ctx).Warnf("Failed to open SSH_AUTH_SOCK: %v, falling back to key search", err)
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
			content, err := os.ReadFile(path) // #nosec G304 - Reading SSH key from known location
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

// generateVMHostKey generates an SSH host key pair for the VM.
func generateVMHostKey(ctx context.Context, cfg *Config) error {
	clog.FromContext(ctx).Info("qemu: generating SSH host key for VM")

	// Generate Ed25519 key (modern, secure, and fast)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate VM host key: %w", err)
	}

	// Create SSH signer from the private key
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to create signer from VM host key: %w", err)
	}

	// Marshal the private key in OpenSSH format for injection into initramfs
	privateKeyPEM, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return fmt.Errorf("failed to marshal VM host private key: %w", err)
	}

	// Store the signer, public key, raw private key, and marshaled private key
	cfg.VMHostKeySigner = signer
	cfg.VMHostKeyPublic = signer.PublicKey()
	cfg.VMHostKeyPrivate = privateKey // Keep reference to raw key for explicit zeroing
	cfg.VMHostKeyPrivateKeyBytes = pem.EncodeToMemory(privateKeyPEM)

	clog.FromContext(ctx).Debugf("qemu: generated VM host key: %s %s",
		cfg.VMHostKeyPublic.Type(),
		base64.StdEncoding.EncodeToString(publicKey))

	return nil
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

// getCgroupMemoryLimitKB reads the cgroup memory limit for the current process.
// It checks cgroup v2 first, then falls back to cgroup v1. Returns 0 if no
// cgroup limit is found or the limit is effectively unlimited.
func getCgroupMemoryLimitKB() int {
	// cgroup v2: /sys/fs/cgroup/memory.max
	if data, err := os.ReadFile("/sys/fs/cgroup/memory.max"); err == nil {
		s := strings.TrimSpace(string(data))
		if s != "max" {
			if bytes, err := strconv.ParseInt(s, 10, 64); err == nil && bytes > 0 {
				return int(bytes / 1024)
			}
		}
	}

	// cgroup v1: /sys/fs/cgroup/memory/memory.limit_in_bytes
	if data, err := os.ReadFile("/sys/fs/cgroup/memory/memory.limit_in_bytes"); err == nil {
		s := strings.TrimSpace(string(data))
		if bytes, err := strconv.ParseInt(s, 10, 64); err == nil && bytes > 0 {
			// cgroup v1 reports a very large number (close to max int64) when unlimited
			const unlimitedThreshold = 1 << 50 // ~1 PiB, well above any real limit
			if bytes < unlimitedThreshold {
				return int(bytes / 1024)
			}
		}
	}

	return 0
}

func getAvailableMemoryKB() int {
	mem := 16000000

	switch runtime.GOOS {
	case "linux":
		// Check cgroup limits first — in a container (e.g. Kubernetes pod),
		// /proc/meminfo reports the entire node's memory, not the pod's allocation.
		// The cgroup limit reflects the actual memory available to this process.
		if cgroupMem := getCgroupMemoryLimitKB(); cgroupMem > 0 {
			return cgroupMem
		}

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
		memSize, err = strconv.ParseInt(sysctlOutStr, 10, strconv.IntSize)
		if err != nil {
			return mem
		}

		// use at most 50% of total ram, in kb
		if memSize > 0 {
			return int(memSize) / 2 / 1024
		}
		return mem
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

// virtiofsdSearchPaths defines where to look for the virtiofsd binary.
var virtiofsdSearchPaths = []string{
	"/usr/libexec/virtiofsd",  // Fedora, RHEL
	"/usr/lib/qemu/virtiofsd", // Debian, Ubuntu
	"virtiofsd",               // In PATH
}

// isVirtiofsdAvailable checks if virtiofsd is installed and returns its path.
// If QEMU_VIRTIOFS_PATH is set, it will look for virtiofsd in that directory.
func isVirtiofsdAvailable() (string, bool) {
	// Check for user-specified directory first (useful for macOS/brew or custom installs)
	if customDir, ok := os.LookupEnv("QEMU_VIRTIOFS_PATH"); ok && customDir != "" {
		customPath := filepath.Join(customDir, "virtiofsd")
		if _, err := os.Stat(customPath); err == nil {
			return customPath, true
		}
	}
	for _, path := range virtiofsdSearchPaths {
		if p, err := exec.LookPath(path); err == nil {
			return p, true
		}
	}
	return "", false
}

// useVirtiofs checks if virtiofs should be used based on environment variable.
// Returns (true, nil) if virtiofs is enabled and available.
// Returns (false, nil) if virtiofs is not requested.
// Returns (false, error) if virtiofs is explicitly requested but not available.
func useVirtiofs() (bool, error) {
	if envVal, ok := os.LookupEnv("QEMU_USE_VIRTIOFS"); ok {
		if val, err := strconv.ParseBool(envVal); err == nil && val {
			if _, available := isVirtiofsdAvailable(); available {
				return true, nil
			}
			return false, fmt.Errorf("QEMU_USE_VIRTIOFS=1 but virtiofsd not found (checked %v, or set QEMU_VIRTIOFS_PATH)", virtiofsdSearchPaths)
		}
	}
	return false, nil
}

// startVirtiofsd starts the virtiofsd daemon and returns its process.
func startVirtiofsd(ctx context.Context, cfg *Config) (*exec.Cmd, error) {
	log := clog.FromContext(ctx)

	virtiofsdPath, ok := isVirtiofsdAvailable()
	if !ok {
		return nil, fmt.Errorf("virtiofsd not found")
	}

	// Remove stale socket if exists
	os.Remove(cfg.VirtiofsdSocketPath)

	args := []string{
		"--socket-path=" + cfg.VirtiofsdSocketPath,
		fmt.Sprintf("--thread-pool-size=%d", runtime.NumCPU()*2), // Parallel I/O
		"-o", "source=" + cfg.CacheDir,
		"-o", "cache=always", // Balance coherency and performance
		"-o", "sandbox=namespace", // Use namespace sandbox (works without root)
		"-o", "xattr", // Enable xattr support
		"-o", "writeback", // Enable writeback caching for better write performance
		"-o", "no_posix_lock",
	}

	log.Debugf("starting virtiofsd: %s %v", virtiofsdPath, args)

	// #nosec G204 - virtiofsdPath is from known paths checked by isVirtiofsdAvailable
	cmd := exec.CommandContext(ctx, virtiofsdPath, args...)

	// Capture stderr for debugging
	errPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start virtiofsd: %w", err)
	}

	// Log virtiofsd output in background
	go func() {
		scanner := bufio.NewScanner(errPipe)
		for scanner.Scan() {
			log.Debugf("virtiofsd: %s", scanner.Text())
		}
	}()

	// Wait for socket to be created (max 5 seconds)
	for range 50 {
		if _, err := os.Stat(cfg.VirtiofsdSocketPath); err == nil {
			log.Infof("virtiofsd started successfully, socket: %s", cfg.VirtiofsdSocketPath)
			return cmd, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Socket not created, kill process and return error
	_ = cmd.Process.Kill()
	return nil, fmt.Errorf("virtiofsd socket not created within timeout")
}

// stopVirtiofsd gracefully stops the virtiofsd daemon.
func stopVirtiofsd(ctx context.Context, cfg *Config) {
	log := clog.FromContext(ctx)

	if cfg.VirtiofsdPID > 0 {
		log.Debugf("stopping virtiofsd (PID %d)", cfg.VirtiofsdPID)

		// Send SIGTERM for graceful shutdown
		if err := syscall.Kill(cfg.VirtiofsdPID, syscall.SIGTERM); err != nil {
			log.Warnf("failed to send SIGTERM to virtiofsd: %v", err)
			// Force kill if SIGTERM fails
			_ = syscall.Kill(cfg.VirtiofsdPID, syscall.SIGKILL)
		}

		cfg.VirtiofsdPID = 0
	}

	// Clean up socket file
	if cfg.VirtiofsdSocketPath != "" {
		if err := os.Remove(cfg.VirtiofsdSocketPath); err != nil && !os.IsNotExist(err) {
			log.Warnf("failed to remove virtiofsd socket: %v", err)
		}
		cfg.VirtiofsdSocketPath = ""
	}
}

// zeroSensitiveFields zeros out sensitive cryptographic material from memory after it's no longer needed.
func zeroSensitiveFields(ctx context.Context, cfg *Config) {
	clog.FromContext(ctx).Debug("qemu: zeroing sensitive cryptographic material from memory")

	if cfg.VMHostKeyPrivate != nil {
		for i := range cfg.VMHostKeyPrivate {
			cfg.VMHostKeyPrivate[i] = 0
		}
		cfg.VMHostKeyPrivate = nil
	}

	if cfg.VMHostKeyPrivateKeyBytes != nil {
		for i := range cfg.VMHostKeyPrivateKeyBytes {
			cfg.VMHostKeyPrivateKeyBytes[i] = 0
		}
		cfg.VMHostKeyPrivateKeyBytes = nil
	}

	cfg.VMHostKeySigner = nil

	runtime.GC()

	clog.FromContext(ctx).Debug("qemu: sensitive key material zeroed and GC triggered")
}

// secureDelete overwrites a file with random data before deleting it.
func secureDelete(ctx context.Context, path string) {
	if path == "" {
		return
	}

	info, err := os.Stat(path)
	if err != nil {
		if !os.IsNotExist(err) {
			clog.FromContext(ctx).Debugf("secure delete: cannot stat %s: %v", path, err)
		}
		return
	}

	if err := os.Chmod(path, 0o600); err != nil {
		clog.FromContext(ctx).Debugf("secure delete: cannot make %s writable: %v", path, err)
	}

	file, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 - Secure file deletion operation
	if err != nil {
		clog.FromContext(ctx).Warnf("secure delete: cannot open %s for overwriting: %v", path, err)
		_ = os.Remove(path) // Best effort cleanup in error path
		return
	}
	defer file.Close()

	size := info.Size()
	buf := make([]byte, 4096)
	for written := int64(0); written < size; {
		toWrite := min(int64(len(buf)), size-written)

		if _, err := rand.Read(buf[:toWrite]); err != nil {
			clog.FromContext(ctx).Warnf("secure delete: failed to generate random data: %v", err)
			break
		}

		if _, err := file.Write(buf[:toWrite]); err != nil {
			clog.FromContext(ctx).Warnf("secure delete: failed to overwrite %s: %v", path, err)
			break
		}

		written += toWrite
	}

	if err := file.Sync(); err != nil {
		clog.FromContext(ctx).Warnf("secure delete: failed to sync %s: %v", path, err)
	}
	// Close explicitly before remove (defer also closes but this ensures it's closed first)
	if err := file.Close(); err != nil {
		clog.FromContext(ctx).Warnf("secure delete: failed to close %s: %v", path, err)
	}

	if err := os.Remove(path); err != nil {
		clog.FromContext(ctx).Warnf("secure delete: failed to remove %s: %v", path, err)
	} else {
		clog.FromContext(ctx).Debugf("secure delete: successfully deleted %s", path)
	}
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

	// Include additional packages in cache filename to invalidate cache when they change
	additionalPkgs := getAdditionalPackages(ctx)
	cacheSuffix := getPackageCacheSuffix(additionalPkgs)

	baseInitramfs := filepath.Join(
		cacheDir,
		fmt.Sprintf("melange-guest%s.initramfs.cpio", cacheSuffix))
	initramfsInfo, err := os.Stat(baseInitramfs)

	// Check if we can use the cached base initramfs (less than 24h old)
	useCache := err == nil && time.Since(initramfsInfo.ModTime()) < 24*time.Hour

	if !useCache {
		err = generateBaseInitramfs(ctx, cfg, baseInitramfs, cacheDir, additionalPkgs)
		if err != nil {
			return "", err
		}
	}

	return injectHostKeyIntoCpio(ctx, cfg, baseInitramfs)
}

// generateBaseInitramfs creates the base initramfs with microvm-init.
// This is cached for performance as it doesn't change often.
func generateBaseInitramfs(ctx context.Context, cfg *Config, initramfsPath, cacheDir string, additionalPkgs []string) error {
	clog.FromContext(ctx).Info("qemu: generating base initramfs")

	err := os.MkdirAll(cacheDir, 0o755)
	if err != nil {
		return fmt.Errorf("unable to create dest directory: %w", err)
	}

	// Start with base packages and add any additional packages from environment
	packages := make([]string, 0, len(additionalPkgs)+1)
	packages = append(packages, "microvm-init")
	packages = append(packages, additionalPkgs...)

	spec := apko_types.ImageConfiguration{
		Contents: apko_types.ImageContents{
			BuildRepositories: []string{
				"https://apk.cgr.dev/chainguard",
			},
			Packages: packages,
		},
	}
	opts := []apko_build.Option{
		apko_build.WithImageConfiguration(spec),
		apko_build.WithArch(cfg.Arch),
	}

	tmpDir, err := os.MkdirTemp("", "melange-guest-*.initramfs")
	if err != nil {
		return fmt.Errorf("unable to create build context: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	bc, err := apko_build.New(ctx, apkofs.DirFS(ctx, tmpDir, apkofs.WithCreateDir()), opts...)
	if err != nil {
		return fmt.Errorf("unable to create build context: %w", err)
	}

	bc.Summarize(ctx)
	if err := bc.BuildImage(ctx); err != nil {
		return fmt.Errorf("unable to generate image: %w", err)
	}
	layerTarGZ, layer, err := bc.ImageLayoutToLayer(ctx)
	if err != nil {
		return err
	}
	defer os.Remove(layerTarGZ)

	clog.FromContext(ctx).Debugf("using %s for image layer", layerTarGZ)

	// in case of some kernel images, we also need the /lib/modules directory to load
	// necessary drivers, like 9p, virtio_net which are foundamental for the VM working.
	if qemuModule, ok := os.LookupEnv("QEMU_KERNEL_MODULES"); ok {
		clog.FromContext(ctx).Debugf("qemu: QEMU_KERNEL_MODULES env set, injecting modules in initramfs")
		if _, err := os.Stat(qemuModule); err == nil {
			clog.FromContext(ctx).Debugf("qemu: local QEMU_KERNEL_MODULES dir detected, injecting")
			layer, err = injectKernelModules(ctx, layer, qemuModule)
			if err != nil {
				clog.FromContext(ctx).Errorf("qemu: could not inject needed kernel modules into initramfs: %v", err)
				return err
			}
		}
	}

	guestInitramfs, err := os.Create(initramfsPath) // #nosec G304 - Creating initramfs in build output
	if err != nil {
		clog.FromContext(ctx).Errorf("failed to create cpio initramfs: %v", err)
		return err
	}
	defer guestInitramfs.Close()

	if err := apko_cpio.FromLayer(layer, guestInitramfs); err != nil {
		clog.FromContext(ctx).Errorf("failed to convert cpio initramfs: %v", err)
		return err
	}

	return nil
}

// getAdditionalPackages parses and validates the QEMU_ADDITIONAL_PACKAGES environment variable.
// Returns a list of package names to add to the initramfs, or empty slice if none/invalid.
func getAdditionalPackages(ctx context.Context) []string {
	pkgEnv := os.Getenv("QEMU_ADDITIONAL_PACKAGES")
	if pkgEnv == "" {
		return nil
	}

	// Basic validation: check for suspicious characters that could cause injection
	// Allow: alphanumeric, hyphens, underscores, commas, dots
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_,.-]+$`, pkgEnv); !matched {
		clog.FromContext(ctx).Warnf("qemu: QEMU_ADDITIONAL_PACKAGES contains invalid characters, ignoring: %s", pkgEnv)
		return nil
	}

	clog.FromContext(ctx).Infof("qemu: QEMU_ADDITIONAL_PACKAGES env set to %s, adding to initramfs", pkgEnv)

	// Split comma-separated list and filter empty entries
	var packages []string
	for pkg := range strings.SplitSeq(pkgEnv, ",") {
		pkg = strings.TrimSpace(pkg)
		if pkg != "" {
			packages = append(packages, pkg)
		}
	}

	return packages
}

// getPackageCacheSuffix generates a deterministic cache suffix based on the package list.
// Uses SHA256 hash (first 12 chars) to avoid collisions and keep filenames reasonable.
// Returns empty string if packages list is empty.
func getPackageCacheSuffix(packages []string) string {
	if len(packages) == 0 {
		return ""
	}

	// Join packages with commas to create a stable input string
	pkgString := strings.Join(packages, ",")

	// Generate SHA256 hash
	hash := sha256.Sum256([]byte(pkgString))

	// Use first 12 characters of hex encoding (like git short SHA)
	return fmt.Sprintf("-%x", hash[:6])
}

// injectHostKeyIntoCpio creates a new initramfs by concatenating the base
// initramfs with a secondary cpio containing the VM's SSH host key.
// This allows us to use cached base initramfs while injecting fresh keys each time.
//
// The file exists only briefly until QEMU reads it into memory, at which point it should be deleted.
func injectHostKeyIntoCpio(ctx context.Context, cfg *Config, baseInitramfs string) (string, error) {
	if cfg.VMHostKeySigner == nil || cfg.VMHostKeyPrivateKeyBytes == nil {
		return "", fmt.Errorf("VM host key not generated")
	}

	clog.FromContext(ctx).Debug("qemu: injecting SSH host key into initramfs")

	combinedInitramfs, err := os.CreateTemp("", "melange-initramfs-*.cpio")
	if err != nil {
		return "", fmt.Errorf("failed to create temp initramfs file: %w", err)
	}
	defer combinedInitramfs.Close()
	initramfsPath := combinedInitramfs.Name()

	success := false
	defer func() {
		if !success {
			secureDelete(ctx, initramfsPath)
		}
	}()

	baseFile, err := os.Open(baseInitramfs) // #nosec G304 - Reading base initramfs from cache
	if err != nil {
		return "", fmt.Errorf("failed to open base initramfs: %w", err)
	}
	defer baseFile.Close()

	if _, err := io.Copy(combinedInitramfs, baseFile); err != nil {
		return "", fmt.Errorf("failed to copy base initramfs: %w", err)
	}

	// Create u-root CPIO writer for appending additional files
	cpioWriter := cpio.Newc.Writer(combinedInitramfs)

	publicKeyBytes := ssh.MarshalAuthorizedKey(cfg.VMHostKeyPublic)

	// Write the private key file with 0400 permissions (read-only, owner only)
	privateKeyRecord := cpio.StaticFile("etc/ssh/ssh_host_ed25519_key", string(cfg.VMHostKeyPrivateKeyBytes), 0o400)
	if err := cpio.WriteRecordsAndDirs(cpioWriter, []cpio.Record{privateKeyRecord}); err != nil {
		return "", fmt.Errorf("failed to write host private key: %w", err)
	}

	// Write the public key file with 0644 permissions (world-readable)
	publicKeyRecord := cpio.StaticFile("etc/ssh/ssh_host_ed25519_key.pub", string(publicKeyBytes), 0o644)
	if err := cpio.WriteRecordsAndDirs(cpioWriter, []cpio.Record{publicKeyRecord}); err != nil {
		return "", fmt.Errorf("failed to write host public key: %w", err)
	}

	// Write CPIO trailer to finalize the archive
	if err := cpioWriter.WriteRecord(cpio.TrailerRecord); err != nil {
		return "", fmt.Errorf("failed to finalize cpio: %w", err)
	}

	if err := combinedInitramfs.Close(); err != nil {
		return "", fmt.Errorf("failed to close initramfs: %w", err)
	}

	if err := os.Chmod(initramfsPath, 0o400); err != nil {
		return "", fmt.Errorf("failed to set read-only permissions on initramfs: %w", err)
	}

	clog.FromContext(ctx).Debugf("qemu: created initramfs with injected host key at %s", initramfsPath)
	success = true
	return initramfsPath, nil
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
		// #nosec G110 - Copying trusted tar content in controlled build environment
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

		data, err := os.ReadFile(path) // #nosec G304 - Reading guest file for verification
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
