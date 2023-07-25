// Copyright 2023 Chainguard, Inc.
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
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	apko_build "chainguard.dev/apko/pkg/build"
	apko_types "chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/log"
	"github.com/chainguard-dev/kontext"
	"github.com/dustin/go-humanize"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/imdario/mergo"
	"github.com/kelseyhightower/envconfig"
	"go.opentelemetry.io/otel"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"k8s.io/client-go/util/exec"
	"knative.dev/pkg/ptr"
	"sigs.k8s.io/yaml"

	ggcrv1 "github.com/google/go-containerregistry/pkg/v1"

	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	KubernetesName                             = "kubernetes"
	KubernetesConfigFileName                   = ".melange.k8s.yaml"
	kubernetesBuilderPodWorkspaceContainerName = "workspace"
)

// k8s is a Runner implementation that uses kubernetes pods.
type k8s struct {
	Config *KubernetesRunnerConfig

	clientset  kubernetes.Interface
	restConfig *rest.Config
	logger     log.Logger
	pod        *corev1.Pod
}

func KubernetesRunner(_ context.Context, logger log.Logger) (Runner, error) {
	cfg, err := NewKubernetesConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to configure kubernetes runner: %v", err)
	}

	runner := &k8s{
		Config: cfg,
		logger: logger,
	}

	restConfig, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(clientcmd.NewDefaultClientConfigLoadingRules(), &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %v", err)
	}
	runner.restConfig = restConfig

	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}
	runner.clientset = client

	return runner, nil
}

// Name implements Runner
func (*k8s) Name() string {
	return KubernetesName
}

// StartPod implements Runner
func (k *k8s) StartPod(ctx context.Context, cfg *Config) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "k8s.StartPod")
	defer span.End()

	if cfg.PodID != "" {
		return fmt.Errorf("pod already running: %s", cfg.PodID)
	}

	builderPod, err := k.NewBuildPod(ctx, cfg)
	if err != nil {
		return err
	}

	podclient := k.clientset.CoreV1().Pods(builderPod.Namespace)

	pod, err := podclient.Create(ctx, builderPod, metav1.CreateOptions{})
	if err != nil {
		data, _ := yaml.Marshal(builderPod)
		k.logger.Warnf("failed creating builder pod\n%v", string(data))
		return fmt.Errorf("creating builder pod: %v", err)
	}
	k.logger.Infof("created builder pod '%s' with UID '%s'", pod.Name, pod.UID)

	if err := wait.PollUntilContextTimeout(ctx, 10*time.Second, k.Config.StartTimeout.Duration, true, func(ctx context.Context) (done bool, err error) {
		p, err := podclient.Get(ctx, pod.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		ready := false
		k.logger.Infof("pod [%s/%s] status:", pod.Namespace, pod.Name)
		for _, condition := range p.Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				ready = true
			}
			k.logger.Infof("  - %s=%s (%s): %s", condition.Type, condition.Status, condition.Reason, condition.Message)
		}
		return ready, nil
	}); err != nil {
		p, perr := podclient.Get(ctx, pod.Name, metav1.GetOptions{})
		if perr != nil {
			p = pod
		}
		data, _ := yaml.Marshal(p)
		// NOTE: We don't dump pod logs here since they're generally useless because
		// all commands are already captured by melange, however this could change in
		// the future
		k.logger.Errorf("builder pod [%s/%s] timed out waiting for ready status, dumping pod data\n\n%s", pod.Namespace, pod.Name, string(data))
		return err
	}
	k.logger.Infof("pod [%s/%s] is ready", pod.Namespace, pod.Name)

	k.pod = pod
	cfg.PodID = pod.Name
	return nil
}

// Run implements Runner
func (k *k8s) Run(ctx context.Context, cfg *Config, cmd ...string) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "k8s.Run")
	defer span.End()

	if cfg.PodID == "" {
		return fmt.Errorf("pod isn't running")
	}

	stdoutPipeR, stdoutPipeW, err := os.Pipe()
	if err != nil {
		return err
	}
	stderrPipeR, stderrPipeW, err := os.Pipe()
	if err != nil {
		return err
	}
	finishStdout := make(chan struct{})
	finishStderr := make(chan struct{})

	go monitorPipe(cfg.Logger, log.InfoLevel, stdoutPipeR, finishStdout)
	go monitorPipe(cfg.Logger, log.WarnLevel, stderrPipeR, finishStderr)

	if err := k.Exec(ctx, cfg.PodID, cmd, remotecommand.StreamOptions{
		Stdout: stdoutPipeW,
		Stderr: stderrPipeW,
	}); err != nil {
		return fmt.Errorf("running remote command: %v", err)
	}

	stdoutPipeW.Close()
	stderrPipeW.Close()

	<-finishStdout
	<-finishStderr
	return nil
}

// TempDir implements Runner
func (*k8s) TempDir() string {
	return ""
}

// TerminatePod implements Runner
func (k *k8s) TerminatePod(ctx context.Context, cfg *Config) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "k8s.TerminatePod")
	defer span.End()

	if cfg.PodID == "" {
		return fmt.Errorf("pod not running")
	}

	deletePolicy := metav1.DeletePropagationForeground
	if err := k.clientset.CoreV1().Pods(k.Config.Namespace).Delete(ctx, cfg.PodID, metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	}); err != nil {
		return fmt.Errorf("deleting pod: %v", err)
	}

	cfg.PodID = ""
	k.pod = nil
	return nil
}

// TestUsability implements Runner
func (k *k8s) TestUsability(ctx context.Context) bool {
	ssar := &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace: k.Config.Namespace,
				Verb:      "create",
				Resource:  "pods",
			},
		},
	}

	response, err := k.clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, ssar, metav1.CreateOptions{})
	if err != nil {
		return false
	}

	return response.Status.Allowed
}

// WorkspaceTar implements Runner
func (k *k8s) WorkspaceTar(ctx context.Context, cfg *Config) (io.ReadCloser, error) {
	ctx, span := otel.Tracer("melange").Start(ctx, "k8s.WorkspaceTar")
	defer span.End()

	fetcher, err := newK8sTarFetcher(k.restConfig, k.pod)
	if err != nil {
		return nil, fmt.Errorf("creating k8s tar fetcher: %v", err)
	}
	return fetcher.Fetch(ctx)
}

// OCIImageLoader implements Runner
func (k *k8s) OCIImageLoader() Loader {
	return &k8sLoader{repo: k.Config.Repo, logger: k.logger}
}

// Exec runs a command on the pod
func (k *k8s) Exec(ctx context.Context, podName string, cmd []string, streamOpts remotecommand.StreamOptions) error {
	ctx, span := otel.Tracer("melange").Start(ctx, "k8s.Exec")
	defer span.End()

	// The k8s runner has no concept of a "WorkingDir", so we prepend the standard
	// command to root us in WorkingDir
	if len(cmd) != 3 {
		k.logger.Warnf("unknown command format, expected 3 elements but got %d, this might not work...", len(cmd))
	} else if cmd[0] != "/bin/sh" || cmd[1] != "-c" {
		k.logger.Warnf("unknown command format, expected '/bin/sh -c' but got [%s %s], this might not work...", cmd[0], cmd[1])
	} else {
		cmd[2] = fmt.Sprintf(`[ -d '%s' ] || mkdir -p '%s'
cd '%s'
%s`, runnerWorkdir, runnerWorkdir, runnerWorkdir, cmd[2])
	}

	req := k.clientset.
		CoreV1().
		RESTClient().
		Post().
		Resource("pods").
		Name(podName).
		Namespace(k.Config.Namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: kubernetesBuilderPodWorkspaceContainerName,
			Command:   cmd,
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(k.restConfig, "POST", req.URL())
	if err != nil {
		return fmt.Errorf("failed to create remote command executor: %v", err)
	}

	// Backoff up to 4 times with a 1 second initial delay, tripling each time
	backoff := wait.Backoff{
		Steps:    6,
		Duration: 1 * time.Second,
		Factor:   3,
		Jitter:   0.1,
	}

	k.logger.Infof("remote executing command %v", cmd)
	if err := wait.ExponentialBackoffWithContext(ctx, backoff, func(ctx context.Context) (bool, error) {
		err := executor.StreamWithContext(ctx, streamOpts)
		switch e := err.(type) {
		case *exec.CodeExitError, exec.ExitError:
			// Non recoverable error
			k.logger.Warnf("non-recoverable error (%T) executing remote command: %v", e, err)
			return false, err
		case nil:
			// Succeeded without error
			return true, nil
		}

		// Everything else is retryable without altering the existing build step
		k.logger.Warnf("attempting to recover (%T) after failing to execute remote command: %v", err, err)
		return false, nil
	}); err != nil {
		return fmt.Errorf("failed executing remote command: %v", err)
	}

	return nil
}

func (k *k8s) NewBuildPod(ctx context.Context, cfg *Config) (*corev1.Pod, error) {
	ctx, span := otel.Tracer("melange").Start(ctx, "k8s.NewBuildPod")
	defer span.End()

	repo, err := name.NewRepository(k.Config.Repo)
	if err != nil {
		return nil, err
	}

	pod := k.Config.defaultBuilderPod(cfg)

	for i, mount := range cfg.Mounts {
		if k.filterMounts(mount) {
			continue
		}

		mountName := fmt.Sprintf("mount-%d", i)
		k.logger.Infof("creating mount '%s' from %s at %s", mountName, mount.Source, mount.Destination)
		bundle, err := k.bundle(ctx, mount.Source, repo.Tag(fmt.Sprintf("%s-%s", cfg.PackageName, mountName)))
		if err != nil {
			k.logger.Warnf("error creating bundle: %v", err)
			return nil, err
		}
		k.logger.Infof("mount '%s' uploaded to %s", mountName, bundle.String())

		pod.Spec.InitContainers = append(pod.Spec.InitContainers, corev1.Container{
			Name:       mountName,
			Image:      bundle.String(),
			WorkingDir: mount.Destination, // kontext unpacks to os.Getwd()
			VolumeMounts: []corev1.VolumeMount{{
				Name:      mountName,
				MountPath: mount.Destination,
			}},
		})
		pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{
			Name:      mountName,
			MountPath: mount.Destination,
		})

		// Only append the volume if it doesn't already volumeExists. This prevents us
		// from overriding any user defined volume, such as generic ephemeral
		// volumes
		volumeExists := false
		for _, v := range pod.Spec.Volumes {
			if v.Name == mountName {
				volumeExists = true
			}
		}
		if !volumeExists {
			// Use a generic empty dir volume as the default
			pod.Spec.Volumes = append(pod.Spec.Volumes, corev1.Volume{
				Name: mountName,
				VolumeSource: corev1.VolumeSource{
					EmptyDir: &corev1.EmptyDirVolumeSource{},
				},
			})
		}
	}

	return pod, nil
}

// bundle is a thin wrapper around kontext.Bundle that ensures the bundle is rooted in the given path
// TODO: This should be upstreamed in kontext.Bundle() when we change that to use go-apk.FullFS
func (k *k8s) bundle(ctx context.Context, path string, tag name.Tag) (name.Digest, error) {
	ctx, span := otel.Tracer("melange").Start(ctx, "k8s.bundle")
	defer span.End()

	var ref name.Digest
	cwd, err := os.Getwd()
	if err != nil {
		return ref, err
	}
	defer func() {
		if err := os.Chdir(cwd); err != nil {
			k.logger.Warnf("error changing directory back to %s: %v", cwd, err)
		}
	}()

	if err := os.Chdir(path); err != nil {
		return ref, err
	}
	return kontext.Bundle(ctx, ".", tag)
}

// filterMounts filters mounts that are not supported by the k8s runner
func (k *k8s) filterMounts(mount BindMount) bool {
	// the kubelet handles this
	if mount.Source == DefaultResolvConfPath {
		return true
	}

	if mount.Destination == DefaultCacheDir {
		k.logger.Warnf("skipping k8s runner irrelevant cache mount %s -> %s", mount.Source, mount.Destination)
		return true
	}

	// Skip anything that can't be mounted to a destination
	if mount.Destination == "" {
		return true
	}

	return false
}

// KubernetesRunnerConfig handles the configuration for the Kubernetes runner
// It sources from various locations, in the following order of precedence:
//  1. The "global" config file
//  2. Defaults
//
// TODO: Add loaders from package config and environment
type KubernetesRunnerConfig struct {
	Provider    string            `json:"provider" yaml:"provider"`
	Repo        string            `json:"repo" yaml:"repo"`
	Namespace   string            `json:"namespace" yaml:"namespace"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`

	StartTimeout metav1.Duration `json:"startTimeout" yaml:"startTimeout" split_words:"true"`

	// This field and everything below it is ignored by the environment variable parser
	PodTemplate *KubernetesRunnerConfigPodTemplate `json:"podTemplate,omitempty" yaml:"podTemplate,omitempty" ignored:"true"`

	// A "burstable" QOS is really the only thing that makes sense for ephemeral builder pods
	// Only set the requests, and not the limits
	Resources corev1.ResourceList

	baseConfigFile string
}

type KubernetesRunnerConfigPodTemplate struct {
	ServiceAccountName string               `json:"serviceAccountName,omitempty" yaml:"serviceAccountName,omitempty"`
	NodeSelector       map[string]string    `json:"nodeSelector,omitempty" yaml:"nodeSelector,omitempty"`
	Env                []corev1.EnvVar      `json:"env,omitempty" yaml:"env,omitempty"`
	Affinity           *corev1.Affinity     `json:"affinity,omitempty" yaml:"affinity,omitempty"`
	RuntimeClassName   *string              `json:"runtimeClassName,omitempty" yaml:"runtimeClassName,omitempty"`
	Volumes            []corev1.Volume      `json:"volumes,omitempty" yaml:"volumes,omitempty"`
	VolumeMounts       []corev1.VolumeMount `json:"volumeMounts,omitempty" yaml:"volumeMounts,omitempty"`
}

// NewKubernetesConfig returns a default Kubernetes runner config setup
func NewKubernetesConfig(opt ...KubernetesRunnerConfigOptions) (*KubernetesRunnerConfig, error) {
	cfg := &KubernetesRunnerConfig{
		Provider:     "generic",
		Namespace:    "default",
		Repo:         "ttl.sh/melange",
		StartTimeout: metav1.Duration{Duration: 10 * time.Minute},
		Resources: corev1.ResourceList{
			corev1.ResourceCPU:    resource.MustParse("2"),
			corev1.ResourceMemory: resource.MustParse("4Gi"),
		},

		baseConfigFile: KubernetesConfigFileName,
	}

	for _, o := range opt {
		o(cfg)
	}

	// Override the defaults with values obtained from the global config file
	global := &KubernetesRunnerConfig{}
	data, err := os.ReadFile(cfg.baseConfigFile)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("error reading config file %s: %w", cfg.baseConfigFile, err)
	} else {
		if err := yaml.Unmarshal(data, global); err != nil {
			return nil, fmt.Errorf("error parsing config file %s: %w", cfg.baseConfigFile, err)
		}
	}

	if err := mergo.Merge(cfg, global, mergo.WithOverride); err != nil {
		return nil, fmt.Errorf("error merging config file values %s with defaults: %w", cfg.baseConfigFile, err)
	}

	// Finally, override with the values from the environment
	var envcfg KubernetesRunnerConfig
	if err := envconfig.Process("melange", &envcfg); err != nil {
		return nil, fmt.Errorf("error parsing environment variables: %w", err)
	}

	if err := mergo.Merge(cfg, envcfg, mergo.WithOverride); err != nil {
		return nil, fmt.Errorf("error merging environment variables with defaults: %w", err)
	}

	return cfg, nil
}

// escapeRFC1123 escapes a string to be RFC1123 compliant.  We don't worry about
// being collision free because these are generally fed to generateName which
// appends a randomized suffix.
func escapeRFC1123(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, ".", "-"), "_", "-")
}

func (c KubernetesRunnerConfig) defaultBuilderPod(cfg *Config) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: fmt.Sprintf("melange-builder-%s-%s-", escapeRFC1123(cfg.PackageName), cfg.Arch.String()),
			Namespace:    c.Namespace,
			Labels: map[string]string{
				"kubernetes.io/arch":             cfg.Arch.String(),
				"app.kubernetes.io/component":    cfg.PackageName,
				"melange.chainguard.dev/arch":    cfg.Arch.ToOCIPlatform().Architecture,
				"melange.chainguard.dev/package": cfg.PackageName,
			},
			Annotations: map[string]string{},
		},
		Spec: corev1.PodSpec{
			// Don't putz around for 30s when we kill things.
			TerminationGracePeriodSeconds: ptr.Int64(0),
			Containers: []corev1.Container{{
				Name:  kubernetesBuilderPodWorkspaceContainerName,
				Image: cfg.ImgRef,
				// ldconfig is run to prime ld.so.cache for glibc packages which require it.
				Command: []string{"/bin/sh", "-c", "[ -x /sbin/ldconfig ] && /sbin/ldconfig /lib || true\nsleep infinity"},
				Resources: corev1.ResourceRequirements{
					Requests: c.Resources,
				},
				VolumeMounts: []corev1.VolumeMount{},
			}},
			RestartPolicy:                corev1.RestartPolicyNever,
			AutomountServiceAccountToken: ptr.Bool(false),
			NodeSelector: map[string]string{
				"kubernetes.io/arch": cfg.Arch.String(),
			},
			ServiceAccountName: "default",
			SecurityContext: &corev1.PodSecurityContext{
				SeccompProfile: &corev1.SeccompProfile{
					Type: corev1.SeccompProfileTypeRuntimeDefault,
				},
			},
			Volumes: []corev1.Volume{},
		},
	}

	for k, v := range cfg.Environment {
		pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, corev1.EnvVar{
			Name:  k,
			Value: v,
		})
	}

	for k, v := range c.Annotations {
		pod.Annotations[k] = v
	}

	for k, v := range c.Labels {
		pod.Labels[k] = v
	}

	if pt := c.PodTemplate; pt != nil {
		if pt.Volumes != nil {
			pod.Spec.Volumes = append(pod.Spec.Volumes, pt.Volumes...)
		}

		if pt.VolumeMounts != nil {
			// Only mount to the workspace container
			pod.Spec.Containers[0].VolumeMounts = append(pod.Spec.Containers[0].VolumeMounts, pt.VolumeMounts...)
		}

		for k, v := range pt.NodeSelector {
			pod.Spec.NodeSelector[k] = v
		}

		if pt.Affinity != nil {
			pod.Spec.Affinity = pt.Affinity
		}

		if pt.RuntimeClassName != nil {
			pod.Spec.RuntimeClassName = pt.RuntimeClassName
		}

		if pt.Env != nil {
			pod.Spec.Containers[0].Env = append(pod.Spec.Containers[0].Env, pt.Env...)
		}

		if pt.ServiceAccountName != "" {
			pod.Spec.ServiceAccountName = pt.ServiceAccountName
		}
	}

	switch c.Provider {
	case "gke":
		// Be specific here, since not all regions support all compute classes
		// Ref: https://cloud.google.com/kubernetes-engine/docs/concepts/autopilot-compute-classes
		if cfg.Arch == apko_types.Architecture("arm64") {
			pod.Spec.NodeSelector["cloud.google.com/compute-class"] = "Scale-Out"
		}
	}

	return pod
}

type KubernetesRunnerConfigOptions func(*KubernetesRunnerConfig)

func WithKubernetesRunnerConfigBaseConfigFile(path string) KubernetesRunnerConfigOptions {
	return func(c *KubernetesRunnerConfig) {
		c.baseConfigFile = path
	}
}

type k8sLoader struct {
	repo   string
	logger log.Logger
}

// LoadImage implements Loader
func (k *k8sLoader) LoadImage(ctx context.Context, layer ggcrv1.Layer, arch apko_types.Architecture, bc *apko_build.Context) (string, error) {
	ctx, span := otel.Tracer("melange").Start(ctx, "k8s.LoadImage")
	defer span.End()

	img, err := mutate.ConfigFile(empty.Image, &ggcrv1.ConfigFile{
		OS:           arch.ToOCIPlatform().OS,
		Architecture: arch.ToOCIPlatform().Architecture,
		Variant:      arch.ToOCIPlatform().Variant,
	})
	if err != nil {
		return "", err
	}

	img, err = mutate.AppendLayers(img, layer)
	if err != nil {
		return "", err
	}

	d, err := img.Digest()
	if err != nil {
		return "", err
	}
	sz, err := layer.Size()
	if err != nil {
		return "", err
	}

	repo, err := name.NewRepository(k.repo)
	if err != nil {
		return "", err
	}
	ref := repo.Digest(d.String())
	k.logger.Infof("pushing build image (%s) to %s", humanize.Bytes(uint64(sz)), ref.String())
	if err := remote.Write(ref, img, remote.WithAuthFromKeychain(authn.DefaultKeychain), remote.WithContext(ctx)); err != nil {
		k.logger.Infof("error publishing build image: %v", err)
		return "", err
	}

	return ref.String(), nil
}

type k8sTarFetcher struct {
	client     kubernetes.Interface
	restconfig *rest.Config
	pod        metav1.Object
}

func newK8sTarFetcher(restconfig *rest.Config, pod metav1.Object) (*k8sTarFetcher, error) {
	client, err := kubernetes.NewForConfig(restconfig)
	if err != nil {
		return nil, err
	}

	return &k8sTarFetcher{
		client:     client,
		restconfig: restconfig,
		pod:        pod,
	}, nil
}

func (f *k8sTarFetcher) Fetch(ctx context.Context) (io.ReadCloser, error) {
	ctx, span := otel.Tracer("melange").Start(ctx, "k8s.Fetch")
	defer span.End()

	readAt := func(w io.Writer, offset uint64) error {
		req := f.client.CoreV1().RESTClient().Post().Resource("pods").Name(f.pod.GetName()).Namespace(f.pod.GetNamespace()).SubResource("exec").VersionedParams(&corev1.PodExecOptions{
			Container: kubernetesBuilderPodWorkspaceContainerName,
			Command: []string{
				"/bin/sh", "-c",
				// Write a gzip compressed tar stream to stdout, starting at the given offset (n)
				fmt.Sprintf("([ -f /tmp/melange-out.tar.gz ] || tar -czf /tmp/melange-out.tar.gz -C %s melange-out) && cat /tmp/melange-out.tar.gz | tail -c+%d", runnerWorkdir, offset),
			},
			Stdout: true,
			Stderr: true,
		}, scheme.ParameterCodec)

		exec, err := remotecommand.NewSPDYExecutor(f.restconfig, "POST", req.URL())
		if err != nil {
			return err
		}
		return exec.StreamWithContext(ctx, remotecommand.StreamOptions{
			Stdout: w,
			Stderr: os.Stderr,
		})
	}
	tp := &retryableTarPipe{
		MaxRetries: 5,
		ReadAt:     readAt,
	}
	tp.initReadFrom(0)
	return tp, nil
}

type retryableTarPipe struct {
	ReadAt     func(w io.Writer, n uint64) error
	MaxRetries int

	reader   *io.PipeReader
	out      *io.PipeWriter
	progress uint64
	retries  int
}

func (p *retryableTarPipe) Close() error {
	return p.out.Close()
}

func (p *retryableTarPipe) initReadFrom(n uint64) {
	p.reader, p.out = io.Pipe()

	go func() {
		defer p.out.Close()
		err := p.ReadAt(p.out, n)
		if err != nil {
			fmt.Println("failed to read: ", err)
		}
	}()
}

func (p *retryableTarPipe) Read(data []byte) (n int, err error) {
	n, err = p.reader.Read(data)
	if err != nil {
		if p.retries < p.MaxRetries {
			p.retries++
			p.initReadFrom(p.progress + 1)
			err = nil
		}
	} else {
		p.progress += uint64(n)
	}
	return
}
