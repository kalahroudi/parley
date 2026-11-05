// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package trust

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/kalahroudi/parley/internal/binding"
	"github.com/kalahroudi/parley/internal/revocation"
)

var (
	// ErrRejected means the admin rejected the enrollment request.
	ErrRejected = errors.New("trust: enrollment rejected by the admin")
	// ErrWrongBinding means the gateway returned a binding that is not for this device and key.
	ErrWrongBinding = errors.New("trust: binding is not for this device")
)

// Daemon is the part of a daemon that decides whether it may send to a peer.
// Both halves are pinned to the root public key, and both persist what they
// have seen so a restart cannot be rolled back.
type Daemon struct {
	Tracker *binding.Tracker
	Guard   *revocation.Guard
	Client  *Client
	Tenant  string
}

// AuthorizeSend is called before a task is sent: the target's binding must be
// signed by the root, unexpired and not older than one already seen, and the
// revocation list held must be fresh and not revoke the target.
func (d *Daemon) AuthorizeSend(target *binding.Signed, now time.Time) error {
	if err := d.Tracker.Accept(target, now); err != nil {
		return err
	}
	return d.Guard.CheckSend(target.DeviceID, now)
}

// Refresh fetches the newest list from the gateway and accepts it. On any
// failure the held list is kept and keeps ageing toward the warning and refusal.
func (d *Daemon) Refresh(ctx context.Context, now time.Time) error {
	return d.Guard.Refresh(ctx, func(ctx context.Context) (*revocation.Signed, error) {
		return d.Client.FetchRevocations(ctx, d.Tenant)
	}, now)
}

// Warning is the text to show the user when the list is old or missing, or "".
func (d *Daemon) Warning(now time.Time) string {
	s := d.Guard.Status(now)
	switch {
	case s.Version == 0:
		return "no revocation list yet: sends are refused until one is fetched"
	case s.Stale:
		return fmt.Sprintf("revocation list is %d days old: sends are refused until it refreshes", int(s.Age/(24*time.Hour)))
	case s.Warn:
		return fmt.Sprintf("revocation list is %d days old: it will be refused after 14 days", int(s.Age/(24*time.Hour)))
	}
	return ""
}

// defaultPoll is used when a non-positive interval is given, so a zero value
// cannot turn a loop into a busy loop against the gateway (or panic a Ticker).
const defaultPoll = 5 * time.Second

// maxEnrollWait bounds how long Await waits for a decision and its binding.
const maxEnrollWait = 24 * time.Hour

// maxPoll caps the backoff between status polls: an admin may take hours, and every poll costs the gateway a request.
const maxPoll = 30 * time.Second

// jitter spreads the polls of devices that started together (a fleet restarted at once) so they do not
// arrive at the gateway in step: up to a quarter of the interval is added. A variable so tests can pin it.
var jitter = func(poll time.Duration) time.Duration { return rand.N(poll/4 + 1) }

// RunRefresh refreshes every interval until ctx ends, reporting failures to onErr.
func (d *Daemon) RunRefresh(ctx context.Context, every time.Duration, clock func() time.Time, onErr func(error)) {
	if every <= 0 {
		every = defaultPoll
	}
	if onErr == nil {
		onErr = func(error) {}
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := d.Refresh(ctx, clock()); err != nil && ctx.Err() == nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Enroll requests approval for key, waits for the admin's decision and
// returns the root-signed binding. The binding is verified against the pinned
// root and recorded in the tracker, so a gateway cannot substitute another.
func (d *Daemon) Enroll(ctx context.Context, name string, key ed25519.PublicKey, poll time.Duration, clock func() time.Time) (*binding.Signed, error) {
	id, secret, err := d.Client.RequestEnrollment(ctx, name, key)
	if err != nil {
		return nil, err
	}
	return d.Await(ctx, id, secret, key, poll, clock)
}

// Await waits for the decision on a request already made (id and secret from
// RequestEnrollment), so a device that restarted can pick the wait up again.
// It returns ErrNotFound when the gateway no longer knows the request (it
// expired), ErrRejected, or the verified and recorded binding.
func (d *Daemon) Await(ctx context.Context, id, secret string, key ed25519.PublicKey, poll time.Duration, clock func() time.Time) (*binding.Signed, error) {
	if poll <= 0 {
		poll = defaultPoll
	}
	ctx, cancel := context.WithTimeout(ctx, maxEnrollWait)
	defer cancel()
	for {
		st, err := d.Client.EnrollmentStatus(ctx, d.Tenant, id, secret)
		if err != nil {
			return nil, err
		}
		if st.Status == "rejected" {
			return nil, ErrRejected
		}
		if st.Status == "approved" && st.Binding != nil {
			b := st.Binding
			if b.DeviceID != id || b.Tenant != d.Tenant || !b.SigningKey.Equal(key) {
				return nil, ErrWrongBinding
			}
			if err := d.Tracker.Accept(b, clock()); err != nil {
				return nil, err
			}
			return b, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll + jitter(poll)):
		}
		// Back off by half each time, up to maxPoll.
		poll = min(poll+poll/2+1, maxPoll)
	}
}

// Admin is the root holder's daemon: it approves devices, signs bindings and
// keeps the revocation list fresh.
type Admin struct {
	Root    ed25519.PrivateKey
	Tenant  string
	Client  *Client
	Renewer *revocation.Renewer
}

// NewAdmin builds the root holder's side, publishing renewed lists to the gateway.
func NewAdmin(rootKey ed25519.PrivateKey, tenant string, c *Client, own *revocation.Guard) *Admin {
	return &Admin{
		Root: rootKey, Tenant: tenant, Client: c,
		Renewer: &revocation.Renewer{Root: rootKey, Tenant: tenant, Guard: own, Push: c.PostRevocations},
	}
}

// Approve records the decision and posts a binding signed with the root key.
// The device id is the request id. Rotating a key is Approve again with a higher version.
func (a *Admin) Approve(ctx context.Context, p Pending, version uint64, now time.Time) error {
	b, err := binding.Sign(a.Root, binding.Binding{
		Tenant: a.Tenant, Owner: p.Owner, DeviceID: p.ID, SigningKey: p.SigningKey,
		Version: version, NotAfter: now.Add(binding.Lifetime),
	})
	if err != nil {
		return err
	}
	if err := a.Client.Decide(ctx, p.ID, "approved"); err != nil {
		return err
	}
	return a.Client.PostBinding(ctx, p.ID, b)
}

// Reject records a rejection; no binding is ever signed for the request.
func (a *Admin) Reject(ctx context.Context, p Pending) error {
	return a.Client.Decide(ctx, p.ID, "rejected")
}

// Revoke adds devices to the signed list and publishes it. With no ids it is
// the periodic refresh. The root holder's own copy is updated even if the
// publish fails; call it again to retry.
func (a *Admin) Revoke(ctx context.Context, ids []string, now time.Time) (*revocation.Signed, error) {
	return a.Renewer.Renew(ctx, ids, now)
}

// RenewIfDue refreshes the list when it is a day old (or missing). It reports
// whether it renewed.
func (a *Admin) RenewIfDue(ctx context.Context, now time.Time) (bool, error) {
	if !a.Renewer.Guard.Due(now) {
		return false, nil
	}
	_, err := a.Renewer.Renew(ctx, nil, now)
	return err == nil, err
}
