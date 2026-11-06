// Copyright 2026 The Parley Authors
// SPDX-License-Identifier: Apache-2.0

package adapter_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kalahroudi/parley/internal/adapter"
	"github.com/kalahroudi/parley/internal/bot"
)

// stub is a Session that records what the adapter forwards.
type stub struct {
	statuses []string
	asked    []string
	answer   string
	askErr   error
	statErr  error
}

func (s *stub) Status(_ context.Context, b []byte) error {
	s.statuses = append(s.statuses, string(b))
	return s.statErr
}

func (s *stub) Ask(_ context.Context, b []byte) ([]byte, error) {
	s.asked = append(s.asked, string(b))
	return []byte(s.answer), s.askErr
}

var task = bot.Task{ID: [16]byte{0xab}, Context: "ctx-1", Caller: "dev-a", Owner: "a@example.com",
	Content: []byte("echo hi"), Expiry: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)}

func api(t *testing.T, url, token string) *adapter.API {
	t.Helper()
	a, err := adapter.NewAPI(adapter.APIConfig{URL: url, Token: token})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func serve(t *testing.T, h http.HandlerFunc) *httptest.Server {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestAPIConfigRejectsUnsafeURLs(t *testing.T) {
	for _, u := range []string{"", "ftp://example.com/x", "http://example.com/bot", "http://10.0.0.5/bot", "https://", "https://user:pw@example.com/",
		"https://example.com/bot?token=1", "https://example.com/bot?", "https://example.com/bot#f", "example.com/bot", "http://[::1", "https://example.com/\x7f"} {
		if _, err := adapter.NewAPI(adapter.APIConfig{URL: u}); !errors.Is(err, adapter.ErrAPIConfig) {
			t.Errorf("%q accepted: %v", u, err)
		}
	}
	if _, err := adapter.NewAPI(adapter.APIConfig{URL: "https://example.com/bot", Token: "a\nb"}); !errors.Is(err, adapter.ErrAPIConfig) {
		t.Error("a token with a newline was accepted")
	}
	for _, u := range []string{"https://example.com/bot", "http://localhost:8080/bot", "http://127.0.0.1:1/", "http://[::1]:9/bot"} {
		if _, err := adapter.NewAPI(adapter.APIConfig{URL: u}); err != nil {
			t.Errorf("%q refused: %v", u, err)
		}
	}
}

func TestAPISendsTheTaskAndTheTokenToTheConfiguredURLOnly(t *testing.T) {
	ref, srv := newRefServer(t)
	res, err := api(t, srv.URL, "s3cret").Handle(context.Background(), task, &stub{})
	if err != nil || string(res) != "echo hi" {
		t.Fatalf("%q %v", res, err)
	}
	ref.mu.Lock()
	defer ref.mu.Unlock()
	if len(ref.auth) != 1 || ref.auth[0] != "Bearer s3cret" {
		t.Fatalf("authorization %v", ref.auth)
	}
	got := ref.requests[0]
	if got.Type != "task" || got.ID != "ab000000000000000000000000000000" || got.Context != "ctx-1" || got.Caller != "dev-a" ||
		got.Owner != "a@example.com" || got.Expires != "2030-01-02T03:04:05Z" || string(got.Content) != "echo hi" {
		t.Fatalf("task line %+v", got)
	}
	if ref.cancels != 0 {
		t.Fatal("a cancel was sent for a task that finished")
	}
}

func TestAPIDoesNotFollowRedirects(t *testing.T) {
	for _, code := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		var hits atomic.Int32
		target := serve(t, func(http.ResponseWriter, *http.Request) { hits.Add(1) })
		redir := serve(t, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, code)
		})
		_, err := api(t, redir.URL, "tok").Handle(context.Background(), task, &stub{})
		if err == nil || !strings.Contains(err.Error(), fmt.Sprint(code)) {
			t.Fatalf("%d: %v", code, err)
		}
		if hits.Load() != 0 {
			t.Fatalf("%d: the redirect was followed", code)
		}
	}
}

func TestAPIErrorsNameNeitherTheURLNorTheBody(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "SECRET-CANARY", http.StatusInternalServerError)
	})
	_, err := api(t, srv.URL, "").Handle(context.Background(), task, &stub{})
	if err == nil || !strings.Contains(err.Error(), "500") || strings.Contains(err.Error(), "SECRET-CANARY") {
		t.Fatalf("%v", err)
	}
	url := srv.URL
	srv.Close()
	_, err = api(t, url, "").Handle(context.Background(), task, &stub{})
	if err == nil || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("%v", err)
	}
}

func TestAPIHostileStreams(t *testing.T) {
	long := `{"type":"result","content":"` + strings.Repeat("A", adapter.MaxLine) + `"}` + "\n"
	for name, body := range map[string]string{
		"not json":         "nonsense\n",
		"unknown type":     `{"type":"shout"}` + "\n",
		"empty line":       "\n",
		"ends early":       `{"type":"status","content":"aGk="}` + "\n",
		"line too long":    long,
		"bad base64":       `{"type":"result","content":"@@@"}` + "\n",
		"status flood":     strings.Repeat(`{"type":"status","content":"aGk="}`+"\n", adapter.MaxStatuses+1),
		"question not met": `{"type":"question","content":"cQ=="}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			var served atomic.Int32
			srv := serve(t, func(w http.ResponseWriter, r *http.Request) {
				if served.Add(1) == 1 {
					fmt.Fprint(w, body)
				} // the cancel notice that follows gets an empty 200
			})
			_, err := api(t, srv.URL, "").Handle(context.Background(), task, &stub{answer: "a"})
			var f *bot.Failure
			if err == nil || errors.As(err, &f) {
				t.Fatalf("%v", err)
			}
		})
	}
}

func TestAPISessionFailuresEndTheTask(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"type":"status","content":"aGk="}`+"\n"+`{"type":"question","content":"cQ=="}`+"\n")
	})
	boom := errors.New("send failed")
	if _, err := api(t, srv.URL, "").Handle(context.Background(), task, &stub{statErr: boom}); err != boom {
		t.Fatalf("status: %v", err)
	}
	if _, err := api(t, srv.URL, "").Handle(context.Background(), task, &stub{askErr: boom}); err != boom {
		t.Fatalf("ask: %v", err)
	}
}

func TestAPIAnswerPostFailureEndsTheTask(t *testing.T) {
	var n atomic.Int32
	srv := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			fmt.Fprint(w, `{"type":"question","content":"cQ=="}`+"\n")
			return
		}
		http.Error(w, "gone", http.StatusGone)
	})
	_, err := api(t, srv.URL, "").Handle(context.Background(), task, &stub{answer: "x"})
	if err == nil || !strings.Contains(err.Error(), "410") {
		t.Fatalf("%v", err)
	}
}

// A task that ends while the service waits for an answer is announced, so the
// service can drop what it holds; one that ends with the bot's own final
// message is not.
func TestAPIAnnouncesATaskThatEndedWithoutAFinalMessage(t *testing.T) {
	ref, srv := newRefServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	s := &blockAsk{cancel: cancel}
	t2 := task
	t2.Content = []byte("ask q")
	if _, err := api(t, srv.URL, "").Handle(ctx, t2, s); !errors.Is(err, context.Canceled) {
		t.Fatalf("%v", err)
	}
	ref.mu.Lock()
	defer ref.mu.Unlock()
	if ref.cancels != 1 || ref.requests[len(ref.requests)-1].Type != "cancel" {
		t.Fatalf("cancels %d, requests %+v", ref.cancels, ref.requests)
	}
}

type blockAsk struct{ cancel context.CancelFunc }

func (blockAsk) Status(context.Context, []byte) error { return nil }
func (b *blockAsk) Ask(ctx context.Context, _ []byte) ([]byte, error) {
	b.cancel()
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestAPIDeadlineEndsAStalledService(t *testing.T) {
	srv := serve(t, func(_ http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body) // the server notices a closed connection once the body is read
		<-r.Context().Done()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := api(t, srv.URL, "").Handle(ctx, task, &stub{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

// A service that answers before it has read the task (an 8 MB one) leaves the transport writing it. The adapter's
// scrub waits for the transport to let go of the line, so it never clears a buffer that is still being sent.
func TestAPIServiceThatAnswersWithoutReadingTheTask(t *testing.T) {
	srv := serve(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"type":"result","content":"b2s="}`+"\n")
	})
	big := task
	big.Content = make([]byte, 8<<20)
	// Either the response wins or the transport reports the broken write; what matters is that nothing races or hangs.
	_, _ = api(t, srv.URL, "").Handle(context.Background(), big, &stub{})
}
