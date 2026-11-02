// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// T109: the T108 soak shape against a real Worker on Cloudflare, with the real
// client. Driven by tests/reality/cf/run.mjs, which deploys a throwaway
// `parley-test-*` Worker (tests/reality/cf/worker/entry.ts) and sets:
//
//	PARLEY_REALITY_URL         wss://<worker>/v1/connect
//	PARLEY_REALITY_TENANT      random tenant id (also the bearer token's tenant)
//	PARLEY_REALITY_PROBE_TOKEN guards the /__push, /__drop and /__counters routes
//	PARLEY_REALITY_DEPLOY_CMD  JSON array: the command that runs one real `wrangler deploy`;
//	                           it gets a build id as its last argument and the environment
//	PARLEY_REALITY_OUT         file the JSON result is written to
//	PARLEY_REALITY_FRAME_INTERVAL_MS  pause between queued frames (default 10, about 100/s)
//
// Control points are spread over the run: PARLEY_REALITY_DEPLOYS real deploys and
// the rest server-side closes (code 1012), PARLEY_REALITY_FORCED in all. Nothing
// here prints the token or any frame body.
func TestRealSoak(t *testing.T) {
	wsURL := os.Getenv("PARLEY_REALITY_URL")
	if wsURL == "" {
		t.Skip("PARLEY_REALITY_URL not set")
	}
	tenant, probe, out := os.Getenv("PARLEY_REALITY_TENANT"), os.Getenv("PARLEY_REALITY_PROBE_TOKEN"), os.Getenv("PARLEY_REALITY_OUT")
	var deployCmd []string
	_ = json.Unmarshal([]byte(os.Getenv("PARLEY_REALITY_DEPLOY_CMD")), &deployCmd)
	total, forced, deploys := envInt("PARLEY_REALITY_TOTAL", 10_000), envInt("PARLEY_REALITY_FORCED", 20), envInt("PARLEY_REALITY_DEPLOYS", 3)
	if tenant == "" || probe == "" || len(deployCmd) == 0 || deploys > forced {
		t.Fatal("PARLEY_REALITY_TENANT, _PROBE_TOKEN and _DEPLOY_CMD are required, and deploys cannot exceed forced")
	}
	pace := time.Duration(envInt("PARLEY_REALITY_FRAME_INTERVAL_MS", 10)) * time.Millisecond
	httpBase := strings.NewReplacer("wss://", "https://", "ws://", "http://").Replace(strings.TrimSuffix(wsURL, "/v1/connect"))
	const device = "soak"
	t0 := time.Now()
	rel := func() int64 { return time.Since(t0).Milliseconds() }

	// Control calls to the measurement routes.
	var httpErrs, httpConsec atomic.Int64
	post := func(path string, body any) (map[string]any, error) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("POST", httpBase+path, bytes.NewReader(b))
		req.Header.Set("x-probe-token", probe)
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
		if err == nil {
			defer resp.Body.Close()
			data, _ := io.ReadAll(resp.Body)
			if resp.StatusCode == 200 {
				var m map[string]any
				err = json.Unmarshal(data, &m)
				if err == nil {
					httpConsec.Store(0)
					return m, nil
				}
			} else {
				err = fmt.Errorf("status %d", resp.StatusCode)
			}
		}
		httpErrs.Add(1)
		if httpConsec.Add(1) >= 15 || httpErrs.Load() > 60 {
			t.Errorf("stopping: control calls failing (%d total, %d in a row): %v", httpErrs.Load(), httpConsec.Load(), err)
		}
		return nil, err
	}

	type conn struct {
		AtMs      int64 `json:"at_ms"`
		Connected bool  `json:"connected"`
	}
	var (
		cmu      sync.Mutex
		conns    []conn
		epoch    int64
		lastUpAt time.Time
		// Frames still unacknowledged when a connection came up: what had to be retransmitted.
		unackedAtResume []int
	)
	var c *Client
	c = New(Config{
		URL: wsURL, Token: "dev:" + tenant + ":" + device, MinBackoff: 100 * time.Millisecond, MaxBackoff: 5 * time.Second,
		OnState: func(up bool) {
			cmu.Lock()
			defer cmu.Unlock()
			conns = append(conns, conn{rel(), up})
			if up {
				epoch++
				lastUpAt = time.Now()
				c.mu.Lock()
				unackedAtResume = append(unackedAtResume, len(c.outbox))
				c.mu.Unlock()
			}
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Minute)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	getEpoch := func() (int64, time.Time) { cmu.Lock(); defer cmu.Unlock(); return epoch, lastUpAt }

	// Daemon to gateway. Send only queues, so progress is measured in frames the
	// gateway has acknowledged, and queuing stays within a window of that, so
	// drops and deploys land while traffic is in flight rather than after a backlog.
	var sent atomic.Int64
	acked := func() int64 {
		c.mu.Lock()
		defer c.mu.Unlock()
		return sent.Load() - int64(len(c.outbox))
	}
	go func() {
		for i := 0; i < total; i++ {
			for int64(i)-acked() > 200 && ctx.Err() == nil {
				time.Sleep(2 * time.Millisecond)
			}
			if c.Send("m"+strconv.Itoa(i)) != nil {
				return
			}
			sent.Add(1)
			// About 100 frames/s: slow enough that the transfer spans every control point.
			time.Sleep(pace)
		}
	}()

	// Gateway to daemon: consume.
	var (
		emu       sync.Mutex
		delivered = map[string]int{}
		seqs      []uint64
	)
	go func() {
		for e := range c.Events() {
			emu.Lock()
			delivered[e.Body]++
			seqs = append(seqs, e.Seq)
			emu.Unlock()
		}
	}()
	has := func(i int) bool { emu.Lock(); defer emu.Unlock(); return delivered["e"+strconv.Itoa(i)] > 0 }

	// The sender (a peer, through the Device DO) pushes events and retries any that
	// were sent on an earlier connection and never arrived.
	var (
		retried, pushes int
		sentOn          = map[int]int64{}
		retriedBodies   = map[string]bool{}
		pushDone        = make(chan struct{})
	)
	go func() {
		defer close(pushDone)
		next := 0
		for t.Failed() == false && ctx.Err() == nil {
			ep, up := getEpoch()
			var batch []int
			if ep > 0 && time.Since(up) > time.Second { // let in-flight events from the new connection land first
				for i := 0; i < next && len(batch) < 100; i++ {
					if !has(i) && sentOn[i] < ep {
						batch = append(batch, i)
						retriedBodies["e"+strconv.Itoa(i)] = true
					}
				}
			}
			retried += len(batch)
			// Events follow the frames, so they are also in flight when a connection drops.
			// They go in batches of 100: one request per batch keeps the run's cost small.
			if a := acked(); a-int64(next) >= 100 || a >= int64(total) {
				for len(batch) < 100 && next < total && int64(next) < a {
					batch = append(batch, next)
					next++
				}
			}
			if len(batch) == 0 {
				if next < total {
					time.Sleep(20 * time.Millisecond)
					continue
				}
				emu.Lock()
				all := len(delivered) == total
				emu.Unlock()
				if all {
					return
				}
				time.Sleep(300 * time.Millisecond)
				continue
			}
			bodies := make([]string, len(batch))
			for k, i := range batch {
				bodies[k] = "e" + strconv.Itoa(i)
			}
			pushes++
			m, err := post("/__push", map[string]any{"tenant": tenant, "device": device, "bodies": bodies})
			delivered := 0
			if err == nil {
				for _, s := range m["statuses"].([]any) {
					if s == "delivered" {
						delivered++
					}
				}
			}
			for k, i := range batch {
				if k < delivered {
					sentOn[i] = ep
				}
			}
			// Events not delivered (offline) were never sent; those not yet pushed go back.
			for k := len(batch) - 1; k >= delivered; k-- {
				if batch[k] == next-1 {
					next--
				}
			}
			if delivered < len(batch) {
				time.Sleep(300 * time.Millisecond)
			}
		}
	}()

	// Forced reconnects: real deploys at three points, server closes at the rest.
	type action struct {
		Kind    string `json:"kind"`
		AtMs    int64  `json:"at_ms"`
		EndMs   int64  `json:"end_ms,omitempty"`
		AtSent  int64  `json:"at_acked"`
		Err     string `json:"err,omitempty"`
		Closed  any    `json:"closed,omitempty"`
		Dropped bool   `json:"dropped_a_connection"`
	}
	var actions []action
	deployAt := map[int]bool{}
	for k := 1; k <= deploys; k++ {
		deployAt[k*forced/(deploys+1)] = true
	}
	for i := 1; i <= forced && !t.Failed(); i++ {
		for acked() < int64(i)*int64(total)/int64(forced+1) && ctx.Err() == nil {
			time.Sleep(20 * time.Millisecond)
		}
		before, _ := getEpoch()
		a := action{AtMs: rel(), AtSent: acked()}
		if deployAt[i] {
			a.Kind = "deploy"
			cmd := exec.CommandContext(ctx, deployCmd[0], append(deployCmd[1:], "build-"+strconv.Itoa(i))...)
			if err := cmd.Run(); err != nil {
				a.Err = err.Error()
				t.Errorf("deploy %d failed: %v", i, err)
			}
			a.EndMs = rel()
		} else {
			a.Kind = "close-1012"
			m, _ := post("/__drop", map[string]any{"tenant": tenant, "device": device, "code": 1012})
			a.Closed = m["closed"]
		}
		// A close must produce its own reconnect before the next control point. A deploy
		// may not (that is a finding, not a failure), so it is given 20 s instead of 60 s.
		wait := 600
		if a.Kind == "deploy" {
			wait = 200
		}
		for k := 0; k < wait; k++ {
			if ep, _ := getEpoch(); ep > before {
				a.Dropped = true
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		actions = append(actions, a)
	}

	// Drain.
	for end := time.Now().Add(10 * time.Minute); time.Now().Before(end) && !t.Failed(); time.Sleep(200 * time.Millisecond) {
		c.mu.Lock()
		acked := len(c.outbox) == 0
		c.mu.Unlock()
		select {
		case <-pushDone:
			if acked && sent.Load() == int64(total) {
				goto settled
			}
		default:
		}
	}
settled:
	cancel()
	<-done

	// Server-side truth (a fresh read after the run; the Worker is still deployed).
	var rx float64 = -1
	var boots float64
	if m, err := post("/__counters", map[string]any{"tenant": tenant, "device": device}); err == nil {
		boots, _ = m["boots"].(float64)
		if s, ok := m["session"].(map[string]any); ok {
			rx, _ = s["rx_seq"].(float64)
		}
	}

	emu.Lock()
	dupSeq, dupBodyRetried, dupBodyUnretried, missing := 0, 0, 0, 0
	for i := 1; i < len(seqs); i++ {
		if seqs[i] <= seqs[i-1] {
			dupSeq++
		}
	}
	for i := 0; i < total; i++ {
		n := delivered["e"+strconv.Itoa(i)]
		switch {
		case n == 0:
			missing++
		case n > 1 && retriedBodies["e"+strconv.Itoa(i)]:
			dupBodyRetried++
		case n > 1:
			dupBodyUnretried++
		}
	}
	emu.Unlock()
	cmu.Lock()
	connects := 0
	for _, e := range conns {
		if e.Connected {
			connects++
		}
	}
	cmu.Unlock()

	res := map[string]any{
		"total": total, "sent": sent.Load(), "gateway_rx_seq": rx, "boots_after": boots, "elapsed_ms": rel(),
		"connections": connects, "forced": forced, "deploys": deploys, "actions": actions,
		"events_missing": missing, "events_out_of_order_or_dup_seq": dupSeq,
		"events_duplicate_bodies_after_sender_retry": dupBodyRetried, "events_duplicate_bodies_not_retried": dupBodyUnretried,
		"events_retried": retried, "push_calls": pushes, "control_http_errors": httpErrs.Load(),
		"unacked_frames_at_end": len(c.outbox), "unacked_at_resume": unackedAtResume, "conn_log": conns,
	}
	defer func() { // written last, so every field below is included even when an assertion fails
		if out != "" {
			b, _ := json.MarshalIndent(res, "", "  ")
			_ = os.WriteFile(out, b, 0o600)
		}
	}()
	if rx != float64(total) || missing != 0 || dupSeq != 0 || dupBodyUnretried != 0 || len(c.outbox) != 0 || sent.Load() != int64(total) {
		t.Fatalf("soak failed: rx_seq=%v/%d missing=%d dupSeq=%d dupBodyUnretried=%d unacked=%d sent=%d", rx, total, missing, dupSeq, dupBodyUnretried, len(c.outbox), sent.Load())
	}
	// Real deploys are not forced disconnects unless the connection actually dropped
	// (the measured result is that they do not, see reality-check-1.md), so only
	// the server-side closes are required to have produced reconnects.
	closes, closeReconnects, deployReconnects := 0, 0, 0
	for _, a := range actions {
		switch {
		case a.Kind == "deploy" && a.Dropped:
			deployReconnects++
		case a.Kind != "deploy":
			closes++
			if a.Dropped {
				closeReconnects++
			}
		}
	}
	res["close_actions"], res["close_actions_that_reconnected"], res["deploys_that_dropped_the_connection"] = closes, closeReconnects, deployReconnects
	if closeReconnects != closes || connects < closes+1 {
		t.Fatalf("%d server closes, %d reconnected, %d connections", closes, closeReconnects, connects)
	}
	// As in T108: a soak that never had anything to recover proves nothing.
	resumed := 0
	for _, n := range unackedAtResume {
		resumed += n
	}
	if resumed == 0 {
		t.Fatal("no frame was unacknowledged at any reconnect: the soak did not exercise recovery")
	}
}

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}
