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
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// identityResolutionTotal tracks agent identity resolution attempts
	// by method (jwt, pod, ip) and result (success, fallback, unknown).
	identityResolutionTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "panoptium_agent_identity_resolution_total",
			Help: "Total number of agent identity resolution attempts by method and result",
		},
		[]string{"method", "result"},
	)
)

func init() {
	metrics.Registry.MustRegister(identityResolutionTotal)
}

// recordResolution records an identity resolution metric.
func recordResolution(method, result string) {
	identityResolutionTotal.WithLabelValues(method, result).Inc()
}
