package container

import (
	"context"
	"fmt"
	"os"
	"testing"

	"chainguard.dev/apko/pkg/build/types"
	"chainguard.dev/apko/pkg/log"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
	"knative.dev/pkg/ptr"
	"sigs.k8s.io/yaml"
)

func Test_k8s_StartPod(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	tests := []struct {
		name   string
		pkgCfg *Config
		k8sCfg *KubernetesRunnerConfig
		wanter func(got corev1.Pod) bool
	}{
		{
			name:   "should have a default namespace",
			pkgCfg: &Config{PackageName: "donkey", Arch: types.Architecture("amd64")},
			k8sCfg: &KubernetesRunnerConfig{},
			wanter: func(got corev1.Pod) bool {
				return got.Namespace == "default"
			},
		},
		{
			name:   "should use global namespace instead of default",
			pkgCfg: &Config{PackageName: "donkey", Arch: types.Architecture("amd64")},
			k8sCfg: &KubernetesRunnerConfig{Namespace: "not-default"},
			wanter: func(got corev1.Pod) bool {
				return got.Namespace == "not-default"
			},
		},
		{
			name:   "should support additional labels",
			pkgCfg: &Config{PackageName: "donkey", Arch: types.Architecture("amd64")},
			k8sCfg: &KubernetesRunnerConfig{Labels: map[string]string{"foo": "bar"}},
			wanter: func(got corev1.Pod) bool {
				return got.Labels["foo"] == "bar"
			},
		},
		{
			name:   "should support additional annotations",
			pkgCfg: &Config{PackageName: "donkey", Arch: types.Architecture("amd64")},
			k8sCfg: &KubernetesRunnerConfig{Annotations: map[string]string{"foo": "bar"}},
			wanter: func(got corev1.Pod) bool {
				return got.Annotations["foo"] == "bar"
			},
		},
		{
			name:   "should default nodeselector to package arch",
			pkgCfg: &Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
			k8sCfg: &KubernetesRunnerConfig{Namespace: "not-default"},
			wanter: func(got corev1.Pod) bool {
				return got.Labels["kubernetes.io/arch"] == "arm64"
			},
		},
		{
			name:   "should append nodeselectors",
			pkgCfg: &Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
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
			name:   "should override resources",
			pkgCfg: &Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
			k8sCfg: &KubernetesRunnerConfig{
				Resources: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("1"),
					corev1.ResourceMemory: resource.MustParse("9001"),
				},
			},
			wanter: func(got corev1.Pod) bool {
				return got.Spec.Containers[0].Resources.Requests.Cpu().Equal(resource.MustParse("1")) && got.Spec.Containers[0].Resources.Requests.Memory().Equal(resource.MustParse("9001"))
			},
		},
		{
			name:   "should support custom volumes",
			pkgCfg: &Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
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
			pkgCfg: &Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
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
			pkgCfg: &Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
			k8sCfg: &KubernetesRunnerConfig{
				Provider: "gke",
			},
			wanter: func(got corev1.Pod) bool {
				return got.Spec.NodeSelector["cloud.google.com/compute-class"] != ""
			},
		},
		{
			name:   "should support custom service account names",
			pkgCfg: &Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
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
			pkgCfg: &Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
			k8sCfg: &KubernetesRunnerConfig{
				PodTemplate: &KubernetesRunnerConfigPodTemplate{
					RuntimeClassName: ptr.String("foo"),
				},
			},
			wanter: func(got corev1.Pod) bool {
				return *got.Spec.RuntimeClassName == "foo"
			},
		},
		{
			name:   "profiles should merge with resources with glob matcher",
			pkgCfg: &Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
			k8sCfg: &KubernetesRunnerConfig{
				Resources: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("1"),
					corev1.ResourceMemory: resource.MustParse("9001Gi"),
				},
				Profiles: map[string]KubernetesRunnerConfigProfile{
					"foo": {
						Matchers: KubernetesRunnerConfigProfileMatcher{Glob: []string{"do*key"}},
						Resources: corev1.ResourceList{
							corev1.ResourceCPU: resource.MustParse("2"),
						},
					},
					"bar": {
						Matchers: KubernetesRunnerConfigProfileMatcher{Glob: []string{"donkey"}},
						Resources: corev1.ResourceList{
							corev1.ResourceEphemeralStorage: resource.MustParse("10Gi"),
						},
					},
				},
			},
			wanter: func(got corev1.Pod) bool {
				return got.Spec.Containers[0].Resources.Requests.Cpu().Equal(resource.MustParse("2")) &&
					got.Spec.Containers[0].Resources.Requests.Memory().Equal(resource.MustParse("9001Gi")) &&
					got.Spec.Containers[0].Resources.Requests.StorageEphemeral().Equal(resource.MustParse("10Gi"))
			},
		},
		{
			name:   "profile should merge with pod template with regex matcher",
			pkgCfg: &Config{PackageName: "donkey", Arch: types.Architecture("arm64")},
			k8sCfg: &KubernetesRunnerConfig{
				PodTemplate: &KubernetesRunnerConfigPodTemplate{
					Volumes: []corev1.Volume{{
						Name:         "foo",
						VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
					}},
				},
				Profiles: map[string]KubernetesRunnerConfigProfile{
					"foo": {
						Matchers: KubernetesRunnerConfigProfileMatcher{Regex: []string{"^donkey$"}},
						PodTemplate: &KubernetesRunnerConfigPodTemplate{
							Volumes: []corev1.Volume{{
								Name:         "bar",
								VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}},
							}},
						},
					},
					"bar": {
						Matchers: KubernetesRunnerConfigProfileMatcher{Regex: []string{"donkey"}},
						PodTemplate: &KubernetesRunnerConfigPodTemplate{
							NodeSelector: map[string]string{"foo": "bar"},
							Volumes: []corev1.Volume{
								{Name: "bar", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
								{Name: "baz", VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
							},
						},
					},
				},
			},
			wanter: func(got corev1.Pod) bool {
				if len(got.Spec.Volumes) != 3 {
					return false
				}
				if got.Spec.NodeSelector["foo"] != "bar" {
					return false
				}
				if got.Spec.NodeSelector["kubernetes.io/arch"] != "arm64" {
					return false
				}
				return got.Spec.Volumes[0].Name == "foo" && got.Spec.Volumes[1].Name == "bar" && got.Spec.Volumes[2].Name == "baz"
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantCfg := NewKubernetesConfig(WithKubernetesRunnerConfigBaseConfigFile(writeYamlToTemp(t, tt.k8sCfg)))

			fc := fake.NewSimpleClientset()
			fc.PrependReactor("create", "pods", podDefaulterAction(t, tt.pkgCfg, wantCfg))

			r := &k8s{
				Config:    wantCfg,
				logger:    log.NewLogger(os.Stdout),
				clientset: fc,
			}

			if err := r.StartPod(ctx, tt.pkgCfg); err != nil {
				t.Fatal(err)
			}

			gots, err := fc.CoreV1().Pods(wantCfg.Namespace).List(ctx, metav1.ListOptions{})
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

func podDefaulterAction(t *testing.T, cfg *Config, k8sCfg *KubernetesRunnerConfig) ktesting.ReactionFunc {
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
