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

package ebpf

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf/ringbuf"
)

const (
	// defaultBatchSize is the max events to read per poll cycle.
	defaultBatchSize = 64

	// defaultDrainTimeout is how long to wait when draining remaining events.
	defaultDrainTimeout = 5 * time.Second
)

// ReaderMetrics tracks ring buffer reader performance counters.
type ReaderMetrics struct {
	EventsRead  atomic.Int64
	ReadErrors  atomic.Int64
	BatchesRead atomic.Int64
}

// RingBufferReader reads events from an eBPF ring buffer in batches.
type RingBufferReader struct {
	mu     sync.Mutex
	reader *ringbuf.Reader
	closed bool

	batchSize    int
	drainTimeout time.Duration

	metrics ReaderMetrics
}

// ReaderOption configures the RingBufferReader.
type ReaderOption func(*RingBufferReader)

// WithBatchSize sets the maximum events per batch read.
func WithBatchSize(size int) ReaderOption {
	return func(r *RingBufferReader) {
		if size > 0 {
			r.batchSize = size
		}
	}
}

// WithDrainTimeout sets the timeout for draining events on shutdown.
func WithDrainTimeout(d time.Duration) ReaderOption {
	return func(r *RingBufferReader) {
		r.drainTimeout = d
	}
}

// NewRingBufferReader creates a reader for the given ring buffer.
// The ringbuf.Reader is provided by cilium/ebpf after loading the eBPF programs.
func NewRingBufferReader(reader *ringbuf.Reader, opts ...ReaderOption) *RingBufferReader {
	r := &RingBufferReader{
		reader:       reader,
		batchSize:    defaultBatchSize,
		drainTimeout: defaultDrainTimeout,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// ReadBatch reads up to batchSize events from the ring buffer.
// Returns the raw event bytes for each event. Blocks until at least
// one event is available or the context is cancelled.
func (r *RingBufferReader) ReadBatch(ctx context.Context) ([][]byte, error) {
	r.mu.Lock()
	if r.closed || r.reader == nil {
		r.mu.Unlock()
		return nil, errors.New("reader is closed")
	}
	r.mu.Unlock()

	var batch [][]byte

	for i := 0; i < r.batchSize; i++ {
		select {
		case <-ctx.Done():
			return batch, ctx.Err()
		default:
		}

		record, err := r.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return batch, nil
			}
			r.metrics.ReadErrors.Add(1)
			if len(batch) > 0 {
				break // Return what we have
			}
			return nil, err
		}

		batch = append(batch, record.RawSample)
		r.metrics.EventsRead.Add(1)
	}

	if len(batch) > 0 {
		r.metrics.BatchesRead.Add(1)
	}

	return batch, nil
}

// Drain reads remaining events from the ring buffer with a timeout.
// Used during graceful shutdown.
func (r *RingBufferReader) Drain() [][]byte {
	ctx, cancel := context.WithTimeout(context.Background(), r.drainTimeout)
	defer cancel()

	var all [][]byte
	for {
		batch, err := r.ReadBatch(ctx)
		if len(batch) > 0 {
			all = append(all, batch...)
		}
		if err != nil || len(batch) == 0 {
			break
		}
	}

	slog.Info("ring buffer drained",
		"events", len(all),
	)
	return all
}

// Close closes the ring buffer reader. It is safe to call multiple times.
func (r *RingBufferReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true

	if r.reader != nil {
		return r.reader.Close()
	}
	return nil
}

// Metrics returns the reader's performance counters.
func (r *RingBufferReader) Metrics() ReaderMetrics {
	return r.metrics
}
