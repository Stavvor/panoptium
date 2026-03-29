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

package nats

import (
	"fmt"

	natsgo "github.com/nats-io/nats.go"
)

// DeliverPolicy configures how a durable consumer starts consuming messages.
type DeliverPolicy struct {
	policy        natsgo.DeliverPolicy
	startSequence uint64
}

// DeliverAll creates a policy that delivers all available messages from the beginning.
func DeliverAll() DeliverPolicy {
	return DeliverPolicy{policy: natsgo.DeliverAllPolicy}
}

// DeliverLast creates a policy that delivers only the last message.
func DeliverLast() DeliverPolicy {
	return DeliverPolicy{policy: natsgo.DeliverLastPolicy}
}

// DeliverByStartSequence creates a policy that starts delivery from a specific sequence number.
func DeliverByStartSequence(seq uint64) DeliverPolicy {
	return DeliverPolicy{
		policy:        natsgo.DeliverByStartSequencePolicy,
		startSequence: seq,
	}
}

// ConsumerFactory creates durable JetStream consumers for event replay
// and crash recovery scenarios.
type ConsumerFactory struct {
	js natsgo.JetStreamContext
}

// NewConsumerFactory creates a new ConsumerFactory.
func NewConsumerFactory(js natsgo.JetStreamContext) *ConsumerFactory {
	return &ConsumerFactory{js: js}
}

// Subscribe creates or reconnects a durable pull consumer on the specified stream.
// The durableName uniquely identifies this consumer across restarts.
// The DeliverPolicy controls where the consumer starts reading from on first creation.
func (f *ConsumerFactory) Subscribe(streamName, durableName string, dp DeliverPolicy) (*natsgo.Subscription, error) {
	cfg := &natsgo.ConsumerConfig{
		Durable:       durableName,
		AckPolicy:     natsgo.AckExplicitPolicy,
		DeliverPolicy: dp.policy,
	}
	if dp.policy == natsgo.DeliverByStartSequencePolicy {
		cfg.OptStartSeq = dp.startSequence
	}

	// Use pull-based subscription for durable consumers
	sub, err := f.js.PullSubscribe("", durableName, natsgo.Bind(streamName, durableName))
	if err != nil {
		// Consumer might not exist; create it first
		_, addErr := f.js.AddConsumer(streamName, cfg)
		if addErr != nil {
			return nil, fmt.Errorf("adding consumer %q on stream %q: %w", durableName, streamName, addErr)
		}
		sub, err = f.js.PullSubscribe("", durableName, natsgo.Bind(streamName, durableName))
		if err != nil {
			return nil, fmt.Errorf("subscribing to consumer %q on stream %q: %w", durableName, streamName, err)
		}
	}

	return sub, nil
}
