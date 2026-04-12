package discovery

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// DiscoveredModule represents a module discovered via K8s Pod watching.
type DiscoveredModule struct {
	ModuleMetadata

	// PodIP is the Pod's cluster IP.
	PodIP string

	// ServiceEndpoint is the K8s service DNS name (e.g., "ipam-service.tangra-system.svc.cluster.local").
	ServiceEndpoint string

	// GRPCEndpoint is the full gRPC address (service:port).
	GRPCEndpoint string

	// HTTPEndpoint is the full HTTP address (service:port).
	HTTPEndpoint string

	// OpenapiSpec is fetched from the module's HTTP server.
	OpenapiSpec []byte

	// ProtoDescriptor is fetched from the module's HTTP server.
	ProtoDescriptor []byte

	// MenusYaml is fetched from the module's HTTP server.
	MenusYaml []byte
}

// ModuleEvent is emitted when a module is added, updated, or removed.
type ModuleEvent struct {
	Type   ModuleEventType
	Module DiscoveredModule
}

// ModuleEventType describes what happened to a module.
type ModuleEventType int

const (
	ModuleAdded   ModuleEventType = iota
	ModuleUpdated
	ModuleRemoved
)

// K8sWatcher watches Kubernetes Pods with tangra module labels
// and emits events when modules appear or disappear.
type K8sWatcher struct {
	client    kubernetes.Interface
	namespace string
	log       *log.Helper
	events    chan ModuleEvent
	stopCh    chan struct{}
}

// NewK8sWatcher creates a watcher for module pods.
func NewK8sWatcher(logger log.Logger) (*K8sWatcher, error) {
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

	return &K8sWatcher{
		client:    clientset,
		namespace: namespace,
		log:       log.NewHelper(log.With(logger, "module", "k8s-module-watcher")),
		events:    make(chan ModuleEvent, 32),
		stopCh:    make(chan struct{}),
	}, nil
}

// Events returns the channel that emits module discovery events.
func (w *K8sWatcher) Events() <-chan ModuleEvent {
	return w.events
}

// Start begins watching for module pods. Blocks until Stop is called.
func (w *K8sWatcher) Start(ctx context.Context) error {
	w.log.Info("Starting K8s module watcher")

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-w.stopCh:
			return nil
		default:
			if err := w.watchPods(ctx); err != nil {
				w.log.Warnf("Watch error, retrying in 5s: %v", err)
				select {
				case <-time.After(5 * time.Second):
				case <-ctx.Done():
					return ctx.Err()
				case <-w.stopCh:
					return nil
				}
			}
		}
	}
}

// Stop terminates the watcher.
func (w *K8sWatcher) Stop() {
	close(w.stopCh)
}

func (w *K8sWatcher) watchPods(ctx context.Context) error {
	watcher, err := w.client.CoreV1().Pods(w.namespace).Watch(ctx, metav1.ListOptions{
		LabelSelector: LabelModuleEnabled + "=true",
	})
	if err != nil {
		return fmt.Errorf("watch pods: %w", err)
	}
	defer watcher.Stop()

	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("watch channel closed")
			}
			pod, ok := event.Object.(*corev1.Pod)
			if !ok {
				continue
			}
			w.handlePodEvent(event.Type, pod)

		case <-ctx.Done():
			return ctx.Err()
		case <-w.stopCh:
			return nil
		}
	}
}

func (w *K8sWatcher) handlePodEvent(eventType watch.EventType, pod *corev1.Pod) {
	// Only process Running pods
	if pod.Status.Phase != corev1.PodRunning {
		return
	}

	moduleID := pod.Labels[LabelModuleID]
	if moduleID == "" {
		return
	}

	meta := ModuleMetadata{
		ModuleID:         moduleID,
		ModuleName:       pod.Annotations[AnnotationModuleName],
		Version:          pod.Labels[LabelModuleVersion],
		Description:      pod.Annotations[AnnotationModuleDescription],
		GRPCPort:         pod.Annotations[AnnotationGRPCPort],
		HTTPPort:         pod.Annotations[AnnotationHTTPPort],
		FrontendEntryURL: pod.Annotations[AnnotationFrontendEntryURL],
		ServerName:       pod.Annotations[AnnotationServerName],
	}

	serviceName := moduleID + "-service"
	discovered := DiscoveredModule{
		ModuleMetadata:  meta,
		PodIP:           pod.Status.PodIP,
		ServiceEndpoint: fmt.Sprintf("%s.%s.svc.cluster.local", serviceName, w.namespace),
		GRPCEndpoint:    fmt.Sprintf("%s:%s", serviceName, meta.GRPCPort),
		HTTPEndpoint:    fmt.Sprintf("%s:%s", serviceName, meta.HTTPPort),
	}

	switch eventType {
	case watch.Added, watch.Modified:
		// Fetch assets from the module's HTTP server
		if meta.HTTPPort != "" {
			w.fetchModuleAssets(&discovered)
		}

		evType := ModuleAdded
		if eventType == watch.Modified {
			evType = ModuleUpdated
		}
		w.events <- ModuleEvent{Type: evType, Module: discovered}
		w.log.Infof("Module %s discovered at %s (grpc=%s, http=%s)",
			moduleID, pod.Status.PodIP, meta.GRPCPort, meta.HTTPPort)

	case watch.Deleted:
		w.events <- ModuleEvent{Type: ModuleRemoved, Module: discovered}
		w.log.Infof("Module %s removed", moduleID)
	}
}

func (w *K8sWatcher) fetchModuleAssets(mod *DiscoveredModule) {
	httpBase := fmt.Sprintf("http://%s", mod.HTTPEndpoint)
	client := &http.Client{Timeout: 10 * time.Second}

	mod.OpenapiSpec = fetchURL(client, httpBase+"/openapi.yaml", w.log)
	mod.ProtoDescriptor = fetchURL(client, httpBase+"/proto-descriptor", w.log)
	mod.MenusYaml = fetchURL(client, httpBase+"/menus.yaml", w.log)
}

func fetchURL(client *http.Client, url string, l *log.Helper) []byte {
	resp, err := client.Get(url)
	if err != nil {
		l.Warnf("Failed to fetch %s: %v", url, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		l.Warnf("Non-200 from %s: %d", url, resp.StatusCode)
		return nil
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		l.Warnf("Failed to read %s: %v", url, err)
		return nil
	}

	return data
}
