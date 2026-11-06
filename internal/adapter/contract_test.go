// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"testing"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/bot"
	"github.com/kalahroudi/parley/internal/bot/bottest"
)

// The API adapter meets the same contract as the Fake, against the Fake served
// as a bot service. One server for the whole run: the contract counts goroutines.
func TestAPIMeetsContract(t *testing.T) {
	_, srv := newRefServer(t)
	bottest.Contract(t, func(*testing.T) bot.Bot {
		a, err := adapter.NewAPI(adapter.APIConfig{URL: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		return a
	})
}
