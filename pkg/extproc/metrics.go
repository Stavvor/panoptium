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

package extproc

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// activeStreams tracks the number of currently active ExtProc streams.
	activeStreams = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "panoptium_extproc_active_streams",
			Help: "Number of currently active ExtProc bidirectional streams",
		},
	)

	// requestsTotal tracks the total number of ExtProc requests observed.
	requestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "panoptium_extproc_requests_total",
			Help: "Total number of ExtProc requests observed, by provider",
		},
		[]string{"provider"},
	)

	// tokensObservedTotal tracks the total number of tokens observed.
	tokensObservedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "panoptium_extproc_tokens_observed_total",
			Help: "Total number of tokens observed in LLM streaming responses, by provider",
		},
		[]string{"provider"},
	)

	// parseErrorsTotal tracks the total number of parsing errors.
	parseErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "panoptium_extproc_parse_errors_total",
			Help: "Total number of parse errors encountered during ExtProc processing, by provider and phase",
		},
		[]string{"provider", "phase"},
	)
)

func init() {
	metrics.Registry.MustRegister(
		activeStreams,
		requestsTotal,
		tokensObservedTotal,
		parseErrorsTotal,
	)
}

// RecordStreamStart increments the active streams gauge.
func RecordStreamStart() {
	activeStreams.Inc()
}

// RecordStreamEnd decrements the active streams gauge.
func RecordStreamEnd() {
	activeStreams.Dec()
}

// RecordRequest increments the total requests counter for the given provider.
func RecordRequest(provider string) {
	requestsTotal.WithLabelValues(provider).Inc()
}

// RecordTokensObserved increments the total tokens counter for the given provider.
func RecordTokensObserved(provider string, count int) {
	tokensObservedTotal.WithLabelValues(provider).Add(float64(count))
}

// RecordParseError increments the parse errors counter for the given provider and phase.
func RecordParseError(provider, phase string) {
	parseErrorsTotal.WithLabelValues(provider, phase).Inc()
}
