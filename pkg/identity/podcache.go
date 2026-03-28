/*
Copyright 2026 Cloudaura sp. z o.o.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package identity

import (
	"context"
	"sync"

	"k8s.io/client-go/kubernetes"
)

// PodInfo contains resolved pod metadata stored in the IP cache.
type PodInfo struct {
	// Name is the Kubernetes pod name.
	Name string

	// Namespace is the Kubernetes namespace.
	Namespace string

	// Labels contains the pod's Kubernetes labels.
	Labels map[string]string

	// ServiceAccount is the pod's service account name.
	ServiceAccount string
}

// PodCache is a thread-safe in-memory cache mapping pod IPs to pod metadata.
type PodCache struct {
	mu    sync.RWMutex
	items map[string]PodInfo
}

// NewPodCache creates a new empty PodCache.
func NewPodCache() *PodCache {
	return &PodCache{
		items: make(map[string]PodInfo),
	}
}

// Get retrieves pod info for the given IP. Returns false if not found.
// TODO: implement.
func (c *PodCache) Get(ip string) (PodInfo, bool) {
	return PodInfo{}, false
}

// Set adds or updates a pod info entry for the given IP.
// TODO: implement.
func (c *PodCache) Set(ip string, info PodInfo) {
}

// Delete removes a pod info entry for the given IP.
// TODO: implement.
func (c *PodCache) Delete(ip string) {
}

// PodCacheInformer watches Kubernetes pods and keeps the PodCache in sync.
type PodCacheInformer struct {
	client kubernetes.Interface
	cache  *PodCache
}

// NewPodCacheInformer creates a new PodCacheInformer.
func NewPodCacheInformer(client kubernetes.Interface, cache *PodCache) *PodCacheInformer {
	return &PodCacheInformer{
		client: client,
		cache:  cache,
	}
}

// Run starts the informer and blocks until the context is cancelled.
// TODO: implement.
func (i *PodCacheInformer) Run(ctx context.Context) {
}

// WaitForSync blocks until the informer's cache has synced or the context is cancelled.
// TODO: implement.
func (i *PodCacheInformer) WaitForSync(ctx context.Context) bool {
	return false
}
