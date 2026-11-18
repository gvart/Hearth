// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"context"
	"fmt"
	"strconv"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// Resources a watcher lists and watches.
const (
	resNodes        = "nodes"
	resNamespaces   = "namespaces"
	resPods         = "pods"
	resEvents       = "events"
	resDeployments  = "deployments"
	resStatefulSets = "statefulsets"
	resDaemonSets   = "daemonsets"
)

// clients is how a watcher reads a cluster: a lister-watcher per resource
// and a pod log reader.
type clients struct {
	lw   map[string]cache.ListerWatcher
	logs func(ctx context.Context, namespace, pod string, opts podLogOptions) ([]byte, error)
}

type podLogOptions struct {
	container  string
	tailLines  int64
	limitBytes int64
}

// newClients connects to the API server of k's current context.
//
// It uses plain REST clients over a scheme of only core/v1 and apps/v1
// rather than client-go's typed clientset, whose scheme registers every
// built-in API group: linked into the one hearth binary, that would add
// tens of MB to it and to every agent's start-up memory.
func newClients(k *kubeconfig) (clients, error) {
	rc, err := k.restConfig()
	if err != nil {
		return clients{}, err
	}
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return clients{}, fmt.Errorf("kubernetes scheme: %w", err)
	}
	if err := appsv1.AddToScheme(scheme); err != nil {
		return clients{}, fmt.Errorf("kubernetes scheme: %w", err)
	}
	codecs := serializer.NewCodecFactory(scheme)
	httpClient, err := rest.HTTPClientFor(rc)
	if err != nil {
		return clients{}, fmt.Errorf("kubernetes http client: %w", err)
	}
	restFor := func(gv schema.GroupVersion, apiPath string) (*rest.RESTClient, error) {
		cfg := rest.CopyConfig(rc)
		cfg.GroupVersion = &gv
		cfg.APIPath = apiPath
		cfg.NegotiatedSerializer = codecs.WithoutConversion()
		c, err := rest.RESTClientForConfigAndClient(cfg, httpClient)
		if err != nil {
			return nil, fmt.Errorf("kubernetes %s client: %w", gv, err)
		}
		return c, nil
	}
	core, err := restFor(corev1.SchemeGroupVersion, "/api")
	if err != nil {
		return clients{}, err
	}
	apps, err := restFor(appsv1.SchemeGroupVersion, "/apis")
	if err != nil {
		return clients{}, err
	}
	return clients{
		lw: map[string]cache.ListerWatcher{
			resNodes:        restListWatch(core, resNodes, func() runtime.Object { return &corev1.NodeList{} }),
			resNamespaces:   restListWatch(core, resNamespaces, func() runtime.Object { return &corev1.NamespaceList{} }),
			resPods:         restListWatch(core, resPods, func() runtime.Object { return &corev1.PodList{} }),
			resEvents:       restListWatch(core, resEvents, func() runtime.Object { return &corev1.EventList{} }),
			resDeployments:  restListWatch(apps, resDeployments, func() runtime.Object { return &appsv1.DeploymentList{} }),
			resStatefulSets: restListWatch(apps, resStatefulSets, func() runtime.Object { return &appsv1.StatefulSetList{} }),
			resDaemonSets:   restListWatch(apps, resDaemonSets, func() runtime.Object { return &appsv1.DaemonSetList{} }),
		},
		logs: func(ctx context.Context, namespace, pod string, o podLogOptions) ([]byte, error) {
			req := core.Get().Namespace(namespace).Resource(resPods).Name(pod).SubResource("log").
				Param("tailLines", strconv.FormatInt(o.tailLines, 10)).
				Param("limitBytes", strconv.FormatInt(o.limitBytes, 10))
			if o.container != "" {
				req = req.Param("container", o.container)
			}
			return req.DoRaw(ctx)
		},
	}, nil
}

// restListWatch lists and watches resource in every namespace.
func restListWatch(c rest.Interface, resource string, newList func() runtime.Object) *cache.ListWatch {
	return &cache.ListWatch{
		ListWithContextFunc: func(ctx context.Context, opts metav1.ListOptions) (runtime.Object, error) {
			out := newList()
			err := c.Get().Resource(resource).VersionedParams(&opts, metav1.ParameterCodec).Do(ctx).Into(out)
			return out, err
		},
		WatchFuncWithContext: func(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error) {
			opts.Watch = true
			return c.Get().Resource(resource).VersionedParams(&opts, metav1.ParameterCodec).Watch(ctx)
		},
	}
}
