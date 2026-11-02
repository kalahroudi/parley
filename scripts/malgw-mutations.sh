#!/bin/sh
# Copyright 2026 The Parley Authors
# SPDX-License-Identifier: Apache-2.0

# Proof that the malicious-gateway tests (internal/acceptance, T206) fail when
# the defence they exercise is removed. Each line of the table below replaces
# one expression in the real code with a permissive one, runs the acceptance
# suite and requires it to FAIL. A mutant that survives means an attack test
# does not depend on its defence: fix the test, never the table. The sources are
# restored on exit, also on interrupt; run on a clean tree.
#
#   scripts/malgw-mutations.sh            # all mutants
#   scripts/malgw-mutations.sh receive    # only labels containing "receive"
#   MALGW_RUN='Crash|Junk' scripts/malgw-mutations.sh   # which tests must kill them (go test -run)
#
# Fields are separated by "@@": file, original text, replacement, label.
set -eu
cd "$(dirname "$0")/.."
filter=${1:-}
if [ -n "$(git status --porcelain -- internal)" ]; then
	echo "refusing to run with local changes under internal/" >&2
	exit 2
fi
trap 'git checkout -q -- internal' EXIT INT TERM

table='internal/receive/receive.go@@owner, err := r.authenticate(m)@@owner, err := "", error(nil)@@receive: sender not authenticated
internal/receive/receive.go@@m.Verify(ed25519.PublicKey(b.SigningKey))@@func() error { _ = ed25519.PublicKey(b.SigningKey); return nil }()@@receive: transcript signature not checked
internal/receive/receive.go@@r.cfg.Revoked(h.SenderDevice)@@false@@receive: revocation ignored
internal/receive/receive.go@@!r.cfg.Allow(b.Owner)@@false@@receive: allowlist ignored
internal/receive/receive.go@@b.Version != h.BindingVersion@@false@@receive: binding version not matched
internal/receive/receive.go@@h.IssuedAt.After(now.Add(r.cfg.Skew))@@false@@receive: future issued-at accepted
internal/receive/receive.go@@!now.Before(h.Expiry)@@false@@receive: expiry not checked
internal/receive/receive.go@@if err := r.cfg.Replay.Accept(rk, h.Expiry); err != nil {@@if err := error(nil); err != nil {@@receive: replay table skipped
internal/receive/receive.go@@r.cfg.Replay.Forget(rk)@@_ = rk@@receive: replay entry kept after a failed open
internal/receive/receive.go@@if err := r.cfg.Pool.Consume(id); err != nil {@@if err := error(nil); err != nil {@@receive: prekey never erased
internal/receive/receive.go@@!eq(h.TargetDevice, r.cfg.Device)@@false@@receive: target device not checked
internal/receive/receive.go@@!eq(h.Tenant, r.cfg.Tenant)@@false@@receive: tenant not checked
internal/envelope/envelope.go@@len(ct) > MaxCiphertextSize ||@@false ||@@envelope: oversize ciphertext accepted
internal/envelope/envelope.go@@!ed25519.Verify(sender, m.Transcript(), m.Signature)@@false@@envelope: signature never fails
internal/binding/binding.go@@return ErrRollback@@return nil@@binding: rollback accepted
internal/prekey/prekey.go@@!bytes.Equal(s.Nonce, e.Nonce)@@false@@prekey: nonce not matched
internal/prekey/prekey.go@@!ed25519.Verify(signingKey, s.Encode(), s.Signature)@@false@@prekey: signature not verified
internal/prekey/prekey.go@@!e.Now.Before(s.ExpiresAt)@@false@@prekey: expiry not checked
internal/prekey/prekey.go@@held >= p.cfg.PerCaller@@false@@prekey: per-caller request limit ignored
internal/prekey/prekey.go@@err = fn(p.scalar(s.index))@@err = fn(p.scalar(s.index)); if err != nil { return err }@@prekey: a failed open burns the key
internal/prekey/prekey.go@@return slot{}, ErrExpired@@return s, nil@@prekey: expired key still found
internal/receive/receive.go@@started = true@@_ = started@@receive: replay entry forgotten after execute started
internal/receive/receive.go@@case errors.Is(err, prekey.ErrExpired):@@case false:@@receive: expired prekey not reported as expired
internal/receive/receive.go@@errors.Is(err, prekey.ErrUnknown), @@@@receive: a gone prekey not dropped
internal/replay/replay.go@@if _, dup := t.seen[k]; dup {@@if _, dup := t.seen[k]; false \&\& dup {@@replay: duplicate accepted
internal/acceptance/malgw_test.go@@h.Seq > out.nextSeq@@false@@harness reply path: gap not detected
internal/acceptance/malgw_test.go@@!bytes.Equal(h.PrevHash, out.last)@@false@@harness reply path: chain not checked
internal/acceptance/malgw_test.go@@h.SenderDevice != out.target@@false@@harness reply path: sender not the target
internal/acceptance/malgw_test.go@@out.canceling \&\& h.Type != envelope.TypeCancel@@false@@harness reply path: reply after cancel
internal/acceptance/malgw_test.go@@h.SenderDevice != in.caller@@false@@harness cancel path: caller not checked'

# A mutant that does not compile is not a kill: start from a suite that builds.
go test -count=1 -run '^$' ./internal/acceptance >/dev/null
survived=0 ran=0
IFS='
'
for row in $table; do
	file=${row%%@@*}; rest=${row#*@@}
	from=${rest%%@@*}; rest=${rest#*@@}
	to=${rest%%@@*}; label=${rest#*@@}
	case $label in *"$filter"*) ;; *) continue ;; esac
	ran=$((ran + 1))
	FROM=$(printf '%s' "$from" | sed 's/\\&/\&/g') TO=$(printf '%s' "$to" | sed 's/\\&/\&/g') \
		perl -0pi -e 'BEGIN { $f = $ENV{FROM}; $t = $ENV{TO} } $n = s/\Q$f\E/$t/; END { exit($n ? 0 : 3) }' "$file" ||
		{ echo "MISSING  $label: pattern not found in $file"; survived=$((survived + 1)); git checkout -q -- "$file"; continue; }
	if ! go test -count=1 -run '^$' ./internal/acceptance >/dev/null 2>&1; then
		echo "BROKEN   $label: the mutant does not compile"
		survived=$((survived + 1))
	elif go test -count=1 -run "${MALGW_RUN:-.}" ./internal/acceptance >/dev/null 2>&1; then
		echo "SURVIVED $label"
		survived=$((survived + 1))
	else
		echo "killed   $label"
	fi
	git checkout -q -- "$file"
done
echo "$ran mutants, $survived survived or missing"
[ "$survived" -eq 0 ]
