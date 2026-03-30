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

package tetragon

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockEventStream implements EventStream for testing.
type mockEventStream struct {
	mu       sync.Mutex
	events   []*RawEvent
	idx      int
	recvErr  error
	closed   bool
	recvChan chan struct{} // signal when Recv is called
}

func newMockEventStream(events []*RawEvent) *mockEventStream {
	return &mockEventStream{
		events:   events,
		recvChan: make(chan struct{}, 100),
	}
}

func (m *mockEventStream) Recv() (*RawEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		return nil, errors.New("stream closed")
	}
	if m.recvErr != nil {
		return nil, m.recvErr
	}
	if m.idx >= len(m.events) {
		// Block until closed.
		m.mu.Unlock()
		select {
		case m.recvChan <- struct{}{}:
		default:
		}
		<-make(chan struct{}) // block forever
		m.mu.Lock()
		return nil, errors.New("stream ended")
	}

	evt := m.events[m.idx]
	m.idx++
	select {
	case m.recvChan <- struct{}{}:
	default:
	}
	return evt, nil
}

func (m *mockEventStream) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

// mockStreamFactory implements StreamFactory for testing.
type mockStreamFactory struct {
	mu      sync.Mutex
	streams []*mockEventStream
	idx     int
	err     error
}

func newMockStreamFactory(streams ...*mockEventStream) *mockStreamFactory {
	return &mockStreamFactory{streams: streams}
}

func (f *mockStreamFactory) Connect(_ context.Context, _ string) (EventStream, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.err != nil {
		return nil, f.err
	}
	if f.idx >= len(f.streams) {
		return nil, errors.New("no more streams")
	}
	stream := f.streams[f.idx]
	f.idx++
	return stream, nil
}

func TestNewClient(t *testing.T) {
	cfg := ClientConfig{
		Address: "localhost:54321",
	}
	c := NewClient(cfg)
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.config.Address != "localhost:54321" {
		t.Errorf("expected address localhost:54321, got %q", c.config.Address)
	}
}

func TestNewClientDefaults(t *testing.T) {
	cfg := ClientConfig{
		Address: "localhost:54321",
	}
	c := NewClient(cfg)

	if c.config.InitialBackoff != defaultInitialBackoff {
		t.Errorf("expected default initial backoff %v, got %v", defaultInitialBackoff, c.config.InitialBackoff)
	}
	if c.config.MaxBackoff != defaultMaxBackoff {
		t.Errorf("expected default max backoff %v, got %v", defaultMaxBackoff, c.config.MaxBackoff)
	}
	if c.config.BackoffMultiplier != defaultBackoffMultiplier {
		t.Errorf("expected default backoff multiplier %v, got %v", defaultBackoffMultiplier, c.config.BackoffMultiplier)
	}
}

func TestClientConnectAndReceiveEvents(t *testing.T) {
	events := []*RawEvent{
		{Type: EventTypeProcessExec, ProcessPID: 100, ProcessComm: "test-proc"},
		{Type: EventTypeProcessKprobe, ProcessPID: 200, ProcessComm: "openat-proc"},
	}
	stream := newMockEventStream(events)
	factory := newMockStreamFactory(stream)

	cfg := ClientConfig{
		Address: "localhost:54321",
	}
	c := NewClient(cfg, WithStreamFactory(factory))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	eventCh := c.Events()
	go c.Start(ctx)

	var received []*RawEvent
	for i := 0; i < len(events); i++ {
		select {
		case evt := <-eventCh:
			received = append(received, evt)
		case <-ctx.Done():
			t.Fatalf("timed out waiting for event %d", i)
		}
	}

	if len(received) != 2 {
		t.Fatalf("expected 2 events, got %d", len(received))
	}
	if received[0].ProcessPID != 100 {
		t.Errorf("event 0: expected PID 100, got %d", received[0].ProcessPID)
	}
	if received[1].ProcessPID != 200 {
		t.Errorf("event 1: expected PID 200, got %d", received[1].ProcessPID)
	}
}

func TestClientReconnectsOnStreamError(t *testing.T) {
	// First stream fails immediately.
	failStream := newMockEventStream(nil)
	failStream.recvErr = errors.New("connection lost")

	// Second stream succeeds with one event.
	successEvents := []*RawEvent{
		{Type: EventTypeProcessExec, ProcessPID: 42, ProcessComm: "reconnected"},
	}
	successStream := newMockEventStream(successEvents)

	factory := newMockStreamFactory(failStream, successStream)

	cfg := ClientConfig{
		Address:        "localhost:54321",
		InitialBackoff: 10 * time.Millisecond, // fast backoff for test
		MaxBackoff:     50 * time.Millisecond,
	}
	c := NewClient(cfg, WithStreamFactory(factory))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	eventCh := c.Events()
	go c.Start(ctx)

	select {
	case evt := <-eventCh:
		if evt.ProcessPID != 42 {
			t.Errorf("expected PID 42, got %d", evt.ProcessPID)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for event after reconnect")
	}

	metrics := c.Metrics()
	if metrics.ReconnectCount.Load() < 1 {
		t.Error("expected at least 1 reconnect")
	}
}

func TestClientGracefulShutdown(t *testing.T) {
	// Stream that blocks forever.
	stream := newMockEventStream(nil)
	factory := newMockStreamFactory(stream)

	cfg := ClientConfig{
		Address:        "localhost:54321",
		InitialBackoff: 10 * time.Millisecond,
	}
	c := NewClient(cfg, WithStreamFactory(factory))

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		c.Start(ctx)
		close(done)
	}()

	// Give client time to start.
	time.Sleep(50 * time.Millisecond)

	cancel()

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("client did not shut down within timeout")
	}
}

func TestClientBackoffStrategy(t *testing.T) {
	// All streams fail immediately.
	var streams []*mockEventStream
	for i := 0; i < 5; i++ {
		s := newMockEventStream(nil)
		s.recvErr = errors.New("always fail")
		streams = append(streams, s)
	}
	factory := newMockStreamFactory(streams...)

	cfg := ClientConfig{
		Address:           "localhost:54321",
		InitialBackoff:    10 * time.Millisecond,
		MaxBackoff:        100 * time.Millisecond,
		BackoffMultiplier: 2.0,
	}
	c := NewClient(cfg, WithStreamFactory(factory))

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go c.Start(ctx)

	// Wait for context to expire.
	<-ctx.Done()

	metrics := c.Metrics()
	if metrics.ReconnectCount.Load() < 2 {
		t.Errorf("expected at least 2 reconnects, got %d", metrics.ReconnectCount.Load())
	}
}

func TestClientConnectFailureTriggersReconnect(t *testing.T) {
	factory := &mockStreamFactory{
		err: errors.New("connect refused"),
	}

	cfg := ClientConfig{
		Address:        "localhost:54321",
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
	}
	c := NewClient(cfg, WithStreamFactory(factory))

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go c.Start(ctx)
	<-ctx.Done()

	metrics := c.Metrics()
	if metrics.ReconnectCount.Load() < 1 {
		t.Error("expected at least 1 reconnect attempt on connect failure")
	}
}

func TestClientMetrics(t *testing.T) {
	events := []*RawEvent{
		{Type: EventTypeProcessExec, ProcessPID: 1},
		{Type: EventTypeProcessExec, ProcessPID: 2},
		{Type: EventTypeProcessExec, ProcessPID: 3},
	}
	stream := newMockEventStream(events)
	factory := newMockStreamFactory(stream)

	cfg := ClientConfig{
		Address: "localhost:54321",
	}
	c := NewClient(cfg, WithStreamFactory(factory))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	eventCh := c.Events()
	go c.Start(ctx)

	// Drain all events.
	for i := 0; i < 3; i++ {
		select {
		case <-eventCh:
		case <-ctx.Done():
			t.Fatalf("timed out at event %d", i)
		}
	}

	metrics := c.Metrics()
	if metrics.EventsReceived.Load() != 3 {
		t.Errorf("expected 3 events received, got %d", metrics.EventsReceived.Load())
	}
}

func TestClientState(t *testing.T) {
	events := []*RawEvent{
		{Type: EventTypeProcessExec, ProcessPID: 1},
	}
	stream := newMockEventStream(events)
	factory := newMockStreamFactory(stream)

	cfg := ClientConfig{
		Address: "localhost:54321",
	}
	c := NewClient(cfg, WithStreamFactory(factory))

	// Before start, state should be disconnected.
	if c.State() != StateDisconnected {
		t.Errorf("expected initial state disconnected, got %q", c.State())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var stateChecked atomic.Bool
	go func() {
		c.Start(ctx)
		stateChecked.Store(true)
	}()

	// Wait for event to confirm connected state.
	select {
	case <-c.Events():
	case <-ctx.Done():
		t.Fatal("timed out waiting for event")
	}

	state := c.State()
	if state != StateConnected {
		t.Errorf("expected state connected, got %q", state)
	}

	cancel()
	// Give goroutine time to finish.
	time.Sleep(50 * time.Millisecond)
}
