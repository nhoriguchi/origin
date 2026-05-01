package hapolicymanagement

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/openshift/origin/pkg/monitor/monitorapi"
	"github.com/openshift/origin/pkg/monitortestframework"
	"github.com/openshift/origin/pkg/test/ginkgo/junitapi"
	exutil "github.com/openshift/origin/test/extended/util"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var defaultSCCs = sets.NewString(
	"anyuid",
	"hostaccess",
	"hostmount-anyuid",
	"hostnetwork",
	"hostnetwork-v2",
	"nonroot",
	"nonroot-v2",
	"privileged",
	"restricted",
	"restricted-v2",
)

var nonStandardSCCNamespaces = map[string]sets.Set[string]{
	"node-exporter":                   sets.New("openshift-monitoring"),
	"machine-api-termination-handler": sets.New("openshift-machine-api"),
}

// namespacesWithPendingSCCPinning includes namespaces with workloads that have pending SCC pinning.
var namespacesWithPendingSCCPinning = sets.NewString(
	"openshift-cluster-csi-drivers",
	"openshift-cluster-version",
	"openshift-image-registry",
	"openshift-ingress",
	"openshift-ingress-canary",
	"openshift-ingress-operator",
	"openshift-insights",
	"openshift-machine-api",
	"openshift-monitoring",
	// run-level namespaces
	"openshift-cloud-controller-manager",
	"openshift-cloud-controller-manager-operator",
	"openshift-cluster-api",
	"openshift-cluster-machine-approver",
	"openshift-dns",
	"openshift-dns-operator",
	"openshift-etcd",
	"openshift-etcd-operator",
	"openshift-kube-apiserver",
	"openshift-kube-apiserver-operator",
	"openshift-kube-controller-manager",
	"openshift-kube-controller-manager-operator",
	"openshift-kube-proxy",
	"openshift-kube-scheduler",
	"openshift-kube-scheduler-operator",
	"openshift-multus",
	"openshift-network-operator",
	"openshift-ovn-kubernetes",
	"openshift-sdn",
	"openshift-storage",
)

// systemNamespaces includes namespaces that should be treated as flaking.
// these namespaces are included because we don't control their creation or labeling on their creation.
var systemNamespaces = sets.NewString(
	"default",
	"kube-system",
	"kube-public",
	"openshift-node",
	"openshift-infra",
	"openshift",
)

type haPolicyManagementChecker struct {
	kubeClient kubernetes.Interface
}

func NewAnalyzer() monitortestframework.MonitorTest {
	return &haPolicyManagementChecker{}
}

func (w *haPolicyManagementChecker) PrepareCollection(ctx context.Context, adminRESTConfig *rest.Config, recorder monitorapi.RecorderWriter) error {
	return nil
}

func (w *haPolicyManagementChecker) StartCollection(ctx context.Context, adminRESTConfig *rest.Config, recorder monitorapi.RecorderWriter) error {
	var err error
	w.kubeClient, err = kubernetes.NewForConfig(adminRESTConfig)
	if err != nil {
		return err
	}

	return nil
}

func (w *haPolicyManagementChecker) CheckNonMetricsPorts(container corev1.Container) bool {
	for _, port := range container.Ports {
		if port.Name != "metrics" {
			return true
		}
	}
	return false
}

func (w *haPolicyManagementChecker) CheckPodReadinessLivenessProbes(namespace string, initOrSidecar bool, container corev1.Container) *junitapi.JUnitTestCase {
	testName := fmt.Sprintf("[???-%v] %v %v proper probe set", namespace, container.Name)
	fmt.Printf("Container Name: %s, readinessProbe: %v, livenessProbe: %v, startupProbe: %v\n", container.Name, container.ReadinessProbe != nil, container.LivenessProbe != nil, container.StartupProbe != nil)

	if initOrSidecar == true {
		return &junitapi.JUnitTestCase{Name: testName}
	}

	if container.LivenessProbe == nil {
		return &junitapi.JUnitTestCase{
			Name:          testName,
			SystemOut:     "lack of livenessProbe",
			FailureOutput: &junitapi.FailureOutput{Output: "lack of livenessProbe"},
		}
	}

	if w.CheckNonMetricsPorts(container) == false {
		return &junitapi.JUnitTestCase{Name: testName}
	}

	if container.ReadinessProbe == nil {
		return &junitapi.JUnitTestCase{
			Name:          testName,
			SystemOut:     "lack of readinessProbe",
			FailureOutput: &junitapi.FailureOutput{Output: "lack of readinessProbe"},
		}
	}

	return &junitapi.JUnitTestCase{Name: testName}
}

func (w *haPolicyManagementChecker) CheckPodStartupProbes(namespace string, initOrSidecar bool, container corev1.Container) *junitapi.JUnitTestCase {
	testName := fmt.Sprintf("[???-%v] %v %v proper startup probe set", namespace, container.Name)
	fmt.Printf("Container Name: %s, readinessProbe: %v, livenessProbe: %v, startupProbe: %v\n", container.Name, container.ReadinessProbe != nil, container.LivenessProbe != nil, container.StartupProbe != nil)

	if initOrSidecar == true {
		return &junitapi.JUnitTestCase{Name: testName}
	}

	if container.StartupProbe == nil && w.CheckNonMetricsPorts(container) == true {
		return &junitapi.JUnitTestCase{
			Name:          testName,
			SystemOut:     "lack of startupProbe",
			FailureOutput: &junitapi.FailureOutput{Output: "lack of startupProbe"},
		}
	}

	return &junitapi.JUnitTestCase{Name: testName}
}

func (w *haPolicyManagementChecker) CheckPodDisruptionBudget(namespace string, name string, podTemplate corev1.PodTemplateSpec, selector *metav1.LabelSelector, pdbList *policyv1.PodDisruptionBudgetList) *junitapi.JUnitTestCase {
	testName := fmt.Sprintf("[???-%v] %v %v proper redundancy check set", namespace, name)

	depSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		fmt.Printf("Failed to parse deployment selector: %v\n", err)
	}

	// Deployment が作成する Pod のラベルセットを取得
	podLabels := labels.Set(podTemplate.Labels)

	var matchedPDB *policyv1.PodDisruptionBudget
	// 3. 各 PDB の Selector が Deployment の対象 Pod とマッチするか検証
	for _, pdb := range pdbList.Items {
		if pdb.Spec.Selector == nil {
			continue
		}

		pdbSelector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			continue
		}

		// 簡易的な判定：お互いのセレクター文字列が一致するか、
		// または Deployment のラベル（Spec.Template.Labels）を PDB が選択できているかを判定します。
		// ここでは、Deployment の Pod テンプレートのラベルが PDB のセレクターにマッチするかをチェックします。
		if pdbSelector.Matches(podLabels) && depSelector.Matches(podLabels) {
			matchedPDB = &pdb
			break
		}
	}

	// 4. 検証結果の判定
	if matchedPDB == nil {
		fmt.Errorf("Deployment %s does not have a matching PodDisruptionBudget\n", name)
		return &junitapi.JUnitTestCase{
			Name:          testName,
			SystemOut:     "lack of podAntiAffinity setting",
			FailureOutput: &junitapi.FailureOutput{Output: "lack of podAntiAffinity setting"},
		}
	} else {
		fmt.Printf("Found PDB %s, MinAvailable: %v, MaxUnavailable: %v\n", matchedPDB.Name, matchedPDB.Spec.MinAvailable, matchedPDB.Spec.MaxUnavailable)
		return &junitapi.JUnitTestCase{Name: testName}

		// 必要に応じて HA ポリシーのチェックを実施（例: MaxUnavailable が 1 を超えていないか等）
	}
}

func (w *haPolicyManagementChecker) CheckPodAntiAffinity(namespace string, name string, podTemplate corev1.PodTemplateSpec) *junitapi.JUnitTestCase {
	testName := fmt.Sprintf("[???-%v] %v %v proper redundancy check set", namespace, name)

	// 3. Affinity 設定の存在チェック
	podSpec := podTemplate.Spec
	if podSpec.Affinity == nil || podSpec.Affinity.PodAntiAffinity == nil {
		fmt.Printf("Deployment %s does not have PodAntiAffinity configured\n", name)
		return &junitapi.JUnitTestCase{Name: testName}
	}

	antiAffinity := podSpec.Affinity.PodAntiAffinity

	// 4. 設定詳細の検証 (必要に応じてさらに深くチェック)
	// 例: 強制的な排除（Required）または 努力目標（Preferred）のどちらかが入っているか
	hasRequired := len(antiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) > 0
	hasPreferred := len(antiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) > 0

	if !hasRequired && !hasPreferred {
		fmt.Printf("PodAntiAffinity not set\n", name)
		return &junitapi.JUnitTestCase{
			Name:          testName,
			SystemOut:     "lack of podAntiAffinity setting",
			FailureOutput: &junitapi.FailureOutput{Output: "lack of podAntiAffinity setting"},
		}
	} else {
		fmt.Printf("Valid Anti-Affinity found (Required: %v, Preferred: %v)\n", hasRequired, hasPreferred)
		return &junitapi.JUnitTestCase{Name: testName}
	}
}

func hasControllerOwner(pod *corev1.Pod) bool {
	// OwnerReferences が存在しない場合は、完全に独立した Bare Pod
	if len(pod.OwnerReferences) == 0 {
		return false
	}

	// OwnerReferences の中に Controller: true のフラグを持つ親がいるかチェック
	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
			// ReplicaSet, StatefulSet, DaemonSet などの管理者（Controller）が存在する
			return true
		}
	}

	return false
}

func (w *haPolicyManagementChecker) CollectData(ctx context.Context, storageDir string, beginning, end time.Time) (monitorapi.Intervals, []*junitapi.JUnitTestCase, error) {
	if w.kubeClient == nil {
		return nil, nil, nil
	}

	namespaces, err := w.kubeClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}

	junits := []*junitapi.JUnitTestCase{}
	for _, ns := range namespaces.Items {
		// skip managed service namespaces
		if exutil.ManagedServiceNamespaces.Has(ns.Name) {
			continue
		}

		// require that all workloads in openshift, kube-*, or default namespaces must have the required-scc annotation
		// ignore openshift-must-gather-* namespaces which are generated dynamically
		isPermanentOpenShiftNamespace := (ns.Name == "openshift" || strings.HasPrefix(ns.Name, "openshift-")) && !strings.HasPrefix(ns.Name, "openshift-must-gather-")
		if !(strings.HasPrefix(ns.Name, "kube-") || ns.Name == "default" || isPermanentOpenShiftNamespace) {
			continue
		}

		// このフィルタでいいの? セットしていないリソースは無視されない?
		pdbList, err := w.kubeClient.PolicyV1().PodDisruptionBudgets(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		deployments, err := w.kubeClient.AppsV1().Deployments(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		for _, dep := range deployments.Items {
			fmt.Printf("Deployment: %s in namespace %s\n", dep.Name, ns.Name)

			for _, container := range dep.Spec.Template.Spec.Containers {
				junits = append(junits, w.CheckPodReadinessLivenessProbes(ns.Name, true, container))
				junits = append(junits, w.CheckPodStartupProbes(ns.Name, true, container))
			}
			for _, container := range dep.Spec.Template.Spec.InitContainers {
				junits = append(junits, w.CheckPodReadinessLivenessProbes(ns.Name, false, container))
				junits = append(junits, w.CheckPodStartupProbes(ns.Name, false, container))
			}

			if dep.Spec.Replicas != nil && *dep.Spec.Replicas <= 1 {
				fmt.Printf("  Skipping %s: Replicas is 1 or less\n", dep.Name)
				continue
			}

			junits = append(junits, w.CheckPodDisruptionBudget(ns.Name, dep.Name, dep.Spec.Template, dep.Spec.Selector, pdbList))
			junits = append(junits, w.CheckPodAntiAffinity(ns.Name, dep.Name, dep.Spec.Template))
		}

		statefulsets, err := w.kubeClient.AppsV1().StatefulSets(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		for _, sts := range statefulsets.Items {
			fmt.Printf("StatefulSet: %s in namespace %s\n", sts.Name, ns.Name)

			for _, container := range sts.Spec.Template.Spec.Containers {
				junits = append(junits, w.CheckPodReadinessLivenessProbes(ns.Name, true, container))
				junits = append(junits, w.CheckPodStartupProbes(ns.Name, true, container))
			}
			for _, container := range sts.Spec.Template.Spec.InitContainers {
				junits = append(junits, w.CheckPodReadinessLivenessProbes(ns.Name, false, container))
				junits = append(junits, w.CheckPodStartupProbes(ns.Name, false, container))
			}

			if sts.Spec.Replicas != nil && *sts.Spec.Replicas <= 1 {
				fmt.Printf("  Skipping %s: Replicas is 1 or less\n", sts.Name)
				continue
			}

			junits = append(junits, w.CheckPodDisruptionBudget(ns.Name, sts.Name, sts.Spec.Template, sts.Spec.Selector, pdbList))
			junits = append(junits, w.CheckPodAntiAffinity(ns.Name, sts.Name, sts.Spec.Template))
		}

		daemonsets, err := w.kubeClient.AppsV1().DaemonSets(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		for _, dms := range daemonsets.Items {
			fmt.Printf("DaemonSets: %s in namespace %s\n", dms.Name, ns.Name)

			for _, container := range dms.Spec.Template.Spec.Containers {
				junits = append(junits, w.CheckPodReadinessLivenessProbes(ns.Name, true, container))
				junits = append(junits, w.CheckPodStartupProbes(ns.Name, true, container))
			}
			for _, container := range dms.Spec.Template.Spec.InitContainers {
				junits = append(junits, w.CheckPodReadinessLivenessProbes(ns.Name, false, container))
				junits = append(junits, w.CheckPodStartupProbes(ns.Name, false, container))
			}
		}

		pods, err := w.kubeClient.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		for _, pod := range pods.Items {
			if hasControllerOwner(&pod) {
				continue
			}
			fmt.Fprintf(os.Stderr, "Bare pod: %s in namespace %s\n", pod.Name, ns.Name)

			for _, container := range pod.Spec.Containers {
				junits = append(junits, w.CheckPodReadinessLivenessProbes(ns.Name, true, container))
				junits = append(junits, w.CheckPodStartupProbes(ns.Name, true, container))
			}
			for _, container := range pod.Spec.InitContainers {
				junits = append(junits, w.CheckPodReadinessLivenessProbes(ns.Name, false, container))
				junits = append(junits, w.CheckPodStartupProbes(ns.Name, false, container))
			}
		}
	}

	fmt.Printf("-- junits len: %v\n", len(junits))
	return nil, junits, nil
}

func (w *haPolicyManagementChecker) ConstructComputedIntervals(ctx context.Context, startingIntervals monitorapi.Intervals, recordedResources monitorapi.ResourcesMap, beginning, end time.Time) (monitorapi.Intervals, error) {
	return nil, nil
}

func (w *haPolicyManagementChecker) EvaluateTestsFromConstructedIntervals(ctx context.Context, finalIntervals monitorapi.Intervals) ([]*junitapi.JUnitTestCase, error) {
	return nil, nil
}

func (w *haPolicyManagementChecker) WriteContentToStorage(ctx context.Context, storageDir, timeSuffix string, finalIntervals monitorapi.Intervals, finalResourceState monitorapi.ResourcesMap) error {
	return nil
}

func (w *haPolicyManagementChecker) Cleanup(ctx context.Context) error {
	return nil
}
