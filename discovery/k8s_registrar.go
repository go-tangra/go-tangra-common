package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/go-kratos/kratos/v2/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// K8sRegistrar patches the current Pod with tangra module labels and annotations
// so the admin gateway can discover it via the Kubernetes API.
type K8sRegistrar struct {
	client    kubernetes.Interface
	namespace string
	podName   string
	log       *log.Helper
}

// NewK8sRegistrar creates a registrar using in-cluster config.
func NewK8sRegistrar(logger log.Logger) (*K8sRegistrar, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("k8s in-cluster config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("k8s clientset: %w", err)
	}

	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		ns, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err == nil {
			namespace = string(ns)
		} else {
			namespace = "default"
		}
	}

	podName := os.Getenv("POD_NAME")
	if podName == "" {
		hostname, _ := os.Hostname()
		podName = hostname
	}

	return &K8sRegistrar{
		client:    clientset,
		namespace: namespace,
		podName:   podName,
		log:       log.NewHelper(log.With(logger, "module", "k8s-registrar")),
	}, nil
}

// Register patches the current Pod with module discovery labels and annotations.
func (r *K8sRegistrar) Register(ctx context.Context, meta ModuleMetadata) error {
	patch := map[string]interface{}{
		"metadata": map[string]interface{}{
			"labels":      meta.Labels(),
			"annotations": meta.Annotations(),
		},
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal patch: %w", err)
	}

	_, err = r.client.CoreV1().Pods(r.namespace).Patch(
		ctx,
		r.podName,
		types.MergePatchType,
		patchBytes,
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("patch pod %s/%s: %w", r.namespace, r.podName, err)
	}

	r.log.Infof("Registered module %s via K8s Pod labels/annotations on %s/%s",
		meta.ModuleID, r.namespace, r.podName)
	return nil
}

// Unregister removes module labels from the current Pod.
func (r *K8sRegistrar) Unregister(ctx context.Context) error {
	patch := []map[string]interface{}{
		{"op": "remove", "path": "/metadata/labels/tangra.io~1module"},
		{"op": "remove", "path": "/metadata/labels/tangra.io~1module-id"},
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return err
	}

	_, err = r.client.CoreV1().Pods(r.namespace).Patch(
		context.Background(),
		r.podName,
		types.JSONPatchType,
		patchBytes,
		metav1.PatchOptions{},
	)
	if err != nil {
		r.log.Warnf("Failed to unregister from K8s: %v", err)
	}
	return err
}
