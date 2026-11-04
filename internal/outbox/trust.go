// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package outbox

import (
	"context"
	"errors"
	"fmt"

	"github.com/kalahroudi/parley/internal/trust"
)

// TrustPresence is the Config.Presence for a daemon talking to the gateway: it
// asks about the card's device, passes the gateway's rate limit through (the
// outbox waits it out), and turns "no such card for this caller" into ErrGone.
func TrustPresence(c *trust.Client) func(ctx context.Context, card string) (bool, error) {
	return func(ctx context.Context, card string) (bool, error) {
		on, err := c.Presence(ctx, card)
		if errors.Is(err, trust.ErrNotFound) {
			err = fmt.Errorf("%w: %v", ErrGone, err)
		}
		return on, err
	}
}
