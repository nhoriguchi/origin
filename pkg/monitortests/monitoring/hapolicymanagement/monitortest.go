package hapolicymanagement

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openshift/origin/pkg/monitor/monitorapi"
	"github.com/openshift/origin/pkg/monitortestframework"
	"github.com/openshift/origin/pkg/test/ginkgo/junitapi"
	exutil "github.com/openshift/origin/test/extended/util"

	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
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

func checkNonMetricsPorts(container corev1.Container) bool {
	for _, port := range container.Ports {
		if port.Name != "metrics" {
			return true
		}
	}
	return false
}

func checkPodReadinessLivenessProbes(namespace string, initOrSidecar bool, container corev1.Container) *junitapi.JUnitTestCase {
	testName := fmt.Sprintf("[Monitor:ha-compliance][sig-arch] %s/%s workload should have a valid readiness/liveness probe", namespace, container.Name)

	if initOrSidecar == true {
		return &junitapi.JUnitTestCase{Name: testName}
	}

	if container.LivenessProbe == nil {
		// Mark as flake until it's ready.
		return &junitapi.JUnitTestCase{
			Name:      testName,
			SystemOut: "livenessProve is missing",
		}
	}

	if checkNonMetricsPorts(container) == false {
		return &junitapi.JUnitTestCase{Name: testName}
	}

	if container.ReadinessProbe == nil {
		// Mark as flake until it's ready.
		return &junitapi.JUnitTestCase{
			Name:      testName,
			SystemOut: "readinessProve is missing",
		}
	}

	return &junitapi.JUnitTestCase{Name: testName}
}

func checkPodStartupProbes(namespace string, initOrSidecar bool, container corev1.Container) *junitapi.JUnitTestCase {
	testName := fmt.Sprintf("[Monitor:ha-compliance][sig-arch] %s/%s workload should have a valid startup probe", namespace, container.Name)

	if initOrSidecar == true {
		return &junitapi.JUnitTestCase{Name: testName}
	}

	if container.StartupProbe == nil && checkNonMetricsPorts(container) == true {
		// Mark as flake until it's ready.
		return &junitapi.JUnitTestCase{
			Name:      testName,
			SystemOut: "startupProbe is missing",
		}
	}

	return &junitapi.JUnitTestCase{Name: testName}
}

func checkPodDisruptionBudget(namespace string, name string, podTemplate corev1.PodTemplateSpec, selector *metav1.LabelSelector, pdbList *policyv1.PodDisruptionBudgetList) *junitapi.JUnitTestCase {
	testName := fmt.Sprintf("[Monitor:ha-compliance][sig-arch] %s/%s workload should have a valid PodDisruptionBudget", namespace, name)

	depSelector, err := metav1.LabelSelectorAsSelector(selector)
	if err != nil {
		fmt.Printf("Failed to parse deployment selector for %s: %v\n", name, err)
		// return ? nil reference risk?
	}

	podLabels := labels.Set(podTemplate.Labels)

	var matchedPDB *policyv1.PodDisruptionBudget
	for _, pdb := range pdbList.Items {
		if pdb.Spec.Selector == nil {
			continue
		}

		pdbSelector, err := metav1.LabelSelectorAsSelector(pdb.Spec.Selector)
		if err != nil {
			continue
		}

		// Perform bidirectional selector matching: verify that both the PDB selector
		// and the Deployment selector successfully target the same underlying Pod labels.
		if pdbSelector.Matches(podLabels) && depSelector.Matches(podLabels) {
			matchedPDB = &pdb
			break
		}
	}

	if matchedPDB == nil {
		// Mark as flake until it's ready.
		return &junitapi.JUnitTestCase{
			Name:      testName,
			SystemOut: "PodDisruptionBudget is missing",
		}
	}

	return &junitapi.JUnitTestCase{Name: testName}
}

func checkPodAntiAffinity(namespace string, name string, podTemplate corev1.PodTemplateSpec) *junitapi.JUnitTestCase {
	testName := fmt.Sprintf("[Monitor:ha-compliance][sig-arch] %s/%s workload should have a valid redundancy check set", namespace, name)

	podSpec := podTemplate.Spec
	if podSpec.Affinity == nil || podSpec.Affinity.PodAntiAffinity == nil {
		return &junitapi.JUnitTestCase{Name: testName}
	}

	antiAffinity := podSpec.Affinity.PodAntiAffinity

	hasRequired := len(antiAffinity.RequiredDuringSchedulingIgnoredDuringExecution) > 0
	hasPreferred := len(antiAffinity.PreferredDuringSchedulingIgnoredDuringExecution) > 0

	if !hasRequired && !hasPreferred {
		// Mark as flake until it's ready.
		return &junitapi.JUnitTestCase{
			Name:      testName,
			SystemOut: "podAntiAffinity is missing",
		}
	}

	return &junitapi.JUnitTestCase{Name: testName}
}

func hasControllerOwner(pod *corev1.Pod) bool {
	if len(pod.OwnerReferences) == 0 {
		return false
	}

	for _, ref := range pod.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
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

		// Filter OpenShift namespaces
		isOpenShiftNamespace := ns.Name == "openshift" || strings.HasPrefix(ns.Name, "openshift-")
		if !(strings.HasPrefix(ns.Name, "kube-") || ns.Name == "default" || isOpenShiftNamespace) {
			continue
		}

		pdbList, err := w.kubeClient.PolicyV1().PodDisruptionBudgets(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		deployments, err := w.kubeClient.AppsV1().Deployments(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		for _, dep := range deployments.Items {
			for _, container := range dep.Spec.Template.Spec.Containers {
				junits = append(junits, checkPodReadinessLivenessProbes(ns.Name, true, container))
				junits = append(junits, checkPodStartupProbes(ns.Name, true, container))
			}
			for _, container := range dep.Spec.Template.Spec.InitContainers {
				junits = append(junits, checkPodReadinessLivenessProbes(ns.Name, false, container))
				junits = append(junits, checkPodStartupProbes(ns.Name, false, container))
			}

			if dep.Spec.Replicas != nil && *dep.Spec.Replicas <= 1 {
				continue
			}

			junits = append(junits, checkPodDisruptionBudget(ns.Name, dep.Name, dep.Spec.Template, dep.Spec.Selector, pdbList))
			junits = append(junits, checkPodAntiAffinity(ns.Name, dep.Name, dep.Spec.Template))
		}

		statefulsets, err := w.kubeClient.AppsV1().StatefulSets(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		for _, sts := range statefulsets.Items {
			for _, container := range sts.Spec.Template.Spec.Containers {
				junits = append(junits, checkPodReadinessLivenessProbes(ns.Name, true, container))
				junits = append(junits, checkPodStartupProbes(ns.Name, true, container))
			}
			for _, container := range sts.Spec.Template.Spec.InitContainers {
				junits = append(junits, checkPodReadinessLivenessProbes(ns.Name, false, container))
				junits = append(junits, checkPodStartupProbes(ns.Name, false, container))
			}

			if sts.Spec.Replicas != nil && *sts.Spec.Replicas <= 1 {
				continue
			}

			junits = append(junits, checkPodDisruptionBudget(ns.Name, sts.Name, sts.Spec.Template, sts.Spec.Selector, pdbList))
			junits = append(junits, checkPodAntiAffinity(ns.Name, sts.Name, sts.Spec.Template))
		}

		daemonsets, err := w.kubeClient.AppsV1().DaemonSets(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		for _, dms := range daemonsets.Items {
			for _, container := range dms.Spec.Template.Spec.Containers {
				junits = append(junits, checkPodReadinessLivenessProbes(ns.Name, true, container))
				junits = append(junits, checkPodStartupProbes(ns.Name, true, container))
			}
			for _, container := range dms.Spec.Template.Spec.InitContainers {
				junits = append(junits, checkPodReadinessLivenessProbes(ns.Name, false, container))
				junits = append(junits, checkPodStartupProbes(ns.Name, false, container))
			}
		}

		pods, err := w.kubeClient.CoreV1().Pods(ns.Name).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, nil, err
		}
		for _, pod := range pods.Items {
			// Filter bare pods
			if hasControllerOwner(&pod) {
				continue
			}

			for _, container := range pod.Spec.Containers {
				junits = append(junits, checkPodReadinessLivenessProbes(ns.Name, true, container))
				junits = append(junits, checkPodStartupProbes(ns.Name, true, container))
			}
			for _, container := range pod.Spec.InitContainers {
				junits = append(junits, checkPodReadinessLivenessProbes(ns.Name, false, container))
				junits = append(junits, checkPodStartupProbes(ns.Name, false, container))
			}
		}
	}

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
