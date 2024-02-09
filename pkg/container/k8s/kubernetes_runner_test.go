package k8s

import (
	"fmt"
	"os"
	"testing"
	"time"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/melange/pkg/container"
	"dario.cat/mergo"
	"github.com/chainguard-dev/clog/slogtest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"knative.dev/pkg/ptr"
	"sigs.k8s.io/yaml"
)

func TestKubernetesRunnerConfig(t *testing.T) {
	dwant, _ := NewKubernetesConfig()

	// Intentionally use raw yaml to surface any type marshaling issues
	writeRaw := func(data []byte) string {
		f, err := os.CreateTemp("", "config.yaml")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()

		if _, err := f.Write(data); err != nil {
			t.Fatal(err)
		}

		return f.Name()
	}

	tests := []struct {
		name     string
		rawInput string
		envs     map[string]string
		want     *KubernetesRunnerConfig
	}{
		{
			name: "should have default values",
			want: dwant,
		},
		{
			name: "should override default values with global yaml values",
			rawInput: `
namespace: foo
startTimeout: 10s
`,
			want: &KubernetesRunnerConfig{
				Namespace:    "foo",
				StartTimeout: metav1.Duration{Duration: 10 * time.Second},
			},
		},
		{
			name: "should override values with global yaml values and env vars",
			rawInput: `
namespace: foo
startTimeout: 5m
repo: somewhere
`,
			envs: map[string]string{
				"MELANGE_REPO": "nowhere",
			},
			want: &KubernetesRunnerConfig{
				Namespace:    "foo",
				StartTimeout: metav1.Duration{Duration: 5 * time.Minute},
				Repo:         "nowhere",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Pickup the default want values
			want, _ := NewKubernetesConfig()
			if err := mergo.Merge(want, tt.want, mergo.WithOverride); err != nil {
				t.Fatal(err)
			}

			for k, v := range tt.envs {
				if err := os.Setenv(k, v); err != nil {
					t.Fatalf("setting env var %s=%s: %v", k, v, err)
				}
			}
			got, err := NewKubernetesConfig(WithKubernetesRunnerConfigBaseConfigFile(writeRaw([]byte(tt.rawInput))))
			if err != nil {
				t.Fatal(err)
			}

			if diff := cmp.Diff(got, want, cmpopts.IgnoreUnexported(KubernetesRunnerConfig{})); diff != "" {
				t.Errorf("KubernetesConfig mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_k8s_StartPod(t *testing.T) {
	t.Parallel()

	ctx := slogtest.TestContextWithLogger(t)

	tests := []struct {
		name   string
		pkgCfg *container.Config
		envs   map[string]string
		k8sCfg *KubernetesRunnerConfig
		wanter func(got corev1.Pod) bool
	}{
		{
			name:   "should have a default namespace",
			pkgCfg: &container.Config{PackageName: "donkey", Arch: types.Architecture("amd64")},
			k8sCfg: &KubernetesRunnerConfig{},
			wanter: func(got corev1.Pod) bool {
				return got.Namespace == "default"
			},
		},
		{
			name:   "should load global configs from yaml",
			pkgCfg: &container.Config{PackageName: "donkey", Arch: types.Architecture("amd64")},
			k8sCfg: &KubernetesRunnerConfig{Namespace: "not-default"},
			wanter: func(got corev1.Pod) bool {
				return got.Namespace == "not-default"
			},
		},
		{
			name:   "should prioritize environment configs",
			pkgCfg: &container.Config{PackageName: "donkey", Arch: types.Architecture("amd64")},
			k8sCfg: &KubernetesRunnerConfig{Namespace: "not-default"},
			envs: map[string]string{
				"MELANGE_NAMESPACE": "from-env",
				"MELANGE_REPO":      "nowhere",
			},
			wanter: func(got corev1.Pod) bool {
				return got.Namespace == "from-env"
			},
		},
		{
			name:   "should skip environment configs for certain fields",
			pkgCfg: &container.Config{PackageName: "donkey", Arch: types.Architecture("amd64")},
			k8sCfg: &KubernetesRunnerConfig{PodTemplate: &KubernetesRunnerConfigPodTemplate{ServiceAccountName: "foo"}},
			envs: map[string]string{
				"MELANGE_SERVICE_ACCOUNT_NAME": "bar",
				"MELANGE_SERVICEACCOUNTNAME":   "bar",
				"SERVICE_ACCOUNT_NAME":         "bar",
				"SERVICEACCOUNTNAME":           "bar",
			},
			wanter: func(got corev1.Pod) bool {
				return got.Spec.ServiceAccountName == "foo"
			},
		},
		{
			name:   "should support additional labels",
			pkgCfg: &container.Config{PackageName: "donkey", Arch: types.Architecture("amd64")},
			k8sCfg: &KubernetesRunnerConfig{Labels: map[string]string{"foo": "bar"}},
			wanter: func(got corev1.Pod) bool {
				return got.Labels["foo"] == "bar"
			},
		},
		{
			name:   "should support additional annotations",
			pkgCfg: &container.Config{PackageName: "donkey", Arch: types.Architecture("amd64")},
			k8sCfg: &KubernetesRunnerConfig{Annotations: map[string]string{"foo": "bar"}},
			wanter: func(got corev1.Pod) bool {
				return got.Annotations["foo"] == "bar"
			},
		},
		{
			name:   "should default nodeselector to package arch",
			pkgCfg: &container.Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
			k8sCfg: &KubernetesRunnerConfig{Namespace: "not-default"},
			wanter: func(got corev1.Pod) bool {
				return got.Labels["kubernetes.io/arch"] == "arm64"
			},
		},
		{
			name:   "should append nodeselectors",
			pkgCfg: &container.Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
			k8sCfg: &KubernetesRunnerConfig{
				PodTemplate: &KubernetesRunnerConfigPodTemplate{
					NodeSelector: map[string]string{"foo": "bar"},
				},
			},
			wanter: func(got corev1.Pod) bool {
				return got.Spec.NodeSelector["foo"] == "bar"
			},
		},
		{
			name: "should override resources",
			pkgCfg: &container.Config{
				PackageName: "donkey",
				Arch:        types.Architecture("arm64"),
				CPU:         "1",
				Memory:      "9001",
			},
			k8sCfg: &KubernetesRunnerConfig{},
			wanter: func(got corev1.Pod) bool {
				return got.Spec.Containers[0].Resources.Requests.Cpu().Equal(resource.MustParse("1")) && got.Spec.Containers[0].Resources.Requests.Memory().Equal(resource.MustParse("9001"))
			},
		},
		{
			name:   "should support custom volumes",
			pkgCfg: &container.Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
			k8sCfg: &KubernetesRunnerConfig{
				PodTemplate: &KubernetesRunnerConfigPodTemplate{
					Volumes: []corev1.Volume{{
						Name:         "foo",
						VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
					}},
					VolumeMounts: []corev1.VolumeMount{{
						Name:      "foo",
						MountPath: "/foo",
					}},
				},
			},
			wanter: func(got corev1.Pod) bool {
				return got.Spec.Volumes[0].Name == "foo" && got.Spec.Containers[0].VolumeMounts[0].Name == "foo"
			},
		},
		{
			name:   "should pass additional environment variables to workspace pod",
			pkgCfg: &container.Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
			k8sCfg: &KubernetesRunnerConfig{
				PodTemplate: &KubernetesRunnerConfigPodTemplate{
					Env: []corev1.EnvVar{{
						Name:  "foo",
						Value: "bar",
					}},
				},
			},
			wanter: func(got corev1.Pod) bool {
				return got.Spec.Containers[0].Env[0].Name == "foo" && got.Spec.Containers[0].Env[0].Value == "bar"
			},
		},
		{
			name:   "should appropriately handle gke provider",
			pkgCfg: &container.Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
			k8sCfg: &KubernetesRunnerConfig{
				Provider: "gke",
			},
			wanter: func(got corev1.Pod) bool {
				return got.Spec.NodeSelector["cloud.google.com/compute-class"] != ""
			},
		},
		{
			name:   "should support custom service account names",
			pkgCfg: &container.Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
			k8sCfg: &KubernetesRunnerConfig{
				PodTemplate: &KubernetesRunnerConfigPodTemplate{
					ServiceAccountName: "foo",
				},
			},
			wanter: func(got corev1.Pod) bool {
				return got.Spec.ServiceAccountName == "foo"
			},
		},
		{
			name:   "should support custom runtime classes",
			pkgCfg: &container.Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
			k8sCfg: &KubernetesRunnerConfig{
				PodTemplate: &KubernetesRunnerConfigPodTemplate{
					RuntimeClassName: ptr.String("foo"),
				},
			},
			wanter: func(got corev1.Pod) bool {
				return *got.Spec.RuntimeClassName == "foo"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envs {
				if err := os.Setenv(k, v); err != nil {
					t.Fatalf("setting env var %s=%s: %v", k, v, err)
				}
			}
			gotCfg, err := NewKubernetesConfig(WithKubernetesRunnerConfigBaseConfigFile(writeYamlToTemp(t, tt.k8sCfg)))
			if err != nil {
				t.Fatal(err)
			}

			fc := fake.NewSimpleClientset()
			fc.PrependReactor("create", "pods", podDefaulterAction(t, tt.pkgCfg, gotCfg))

			r := &k8s{
				Config:    gotCfg,
				clientset: fc,
			}

			if err := r.StartPod(ctx, tt.pkgCfg); err != nil {
				t.Fatal(err)
			}

			gots, err := fc.CoreV1().Pods(gotCfg.Namespace).List(ctx, metav1.ListOptions{})
			if err != nil {
				t.Fatal(err)
			}

			if len(gots.Items) != 1 {
				t.Fatalf("expected 1 pod, got %d", len(gots.Items))
			}

			if !tt.wanter(gots.Items[0]) {
				t.Fatal("want condition returned false")
			}
		})
	}
}

func podDefaulterAction(t *testing.T, cfg *container.Config, k8sCfg *KubernetesRunnerConfig) ktesting.ReactionFunc {
	return func(action ktesting.Action) (handled bool, ret runtime.Object, err error) {
		create, ok := action.(ktesting.CreateAction)
		if !ok {
			return false, nil, fmt.Errorf("unexpected action type: %v", action)
		}

		pod, ok := create.GetObject().(*corev1.Pod)
		if !ok {
			return false, nil, fmt.Errorf("unexpected object type: %v", create.GetObject())
		}

		if pod.Name == "" && pod.GenerateName != "" {
			pod.Name = fmt.Sprintf("%s%s", pod.GenerateName, "1234567890")
		}

		pod.Status.Conditions = []corev1.PodCondition{{Status: corev1.ConditionTrue, Type: corev1.PodReady}}

		return false, pod, nil
	}
}

func writeYamlToTemp(t *testing.T, obj interface{}) string {
	f, err := os.CreateTemp("", "melange-k8s-test")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := yaml.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}

	return f.Name()
}
