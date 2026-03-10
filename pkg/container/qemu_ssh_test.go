// Copyright 2026 Chainguard, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package container

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/crypto/ssh"
)

// mockKeepaliveClient implements sshKeepaliveClient for testing.
type mockKeepaliveClient struct {
	sendFunc    func() error
	closed      atomic.Bool
	closeCalled atomic.Int32
}

func (m *mockKeepaliveClient) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	if m.closed.Load() {
		return false, nil, errors.New("client closed")
	}
	if m.sendFunc != nil {
		return false, nil, m.sendFunc()
	}
	return true, nil, nil
}

func (m *mockKeepaliveClient) Close() error {
	m.closed.Store(true)
	m.closeCalled.Add(1)
	return nil
}

// newTestSSHServer starts an in-process SSH server that accepts connections and
// completes the handshake. Returns the listener address and a cleanup function.
func newTestSSHServer(t *testing.T) (string, func()) {
	t.Helper()

	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatalf("failed to create signer: %v", err)
	}

	serverConfig := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	serverConfig.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, chans, reqs, err := ssh.NewServerConn(c, serverConfig)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for newChan := range chans {
					newChan.Reject(ssh.Prohibited, "no channels allowed")
				}
			}(conn)
		}
	}()

	cleanup := func() {
		listener.Close()
		<-done
	}

	return listener.Addr().String(), cleanup
}

func TestSSHDialWithTimeout_Success(t *testing.T) {
	addr, cleanup := newTestSSHServer(t)
	defer cleanup()

	config := &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := sshDialWithTimeout(addr, config, 5*time.Second)
	if err != nil {
		t.Fatalf("sshDialWithTimeout failed: %v", err)
	}
	defer client.Close()
}

func TestSSHDialWithTimeout_ConnectRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	config := &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	_, err = sshDialWithTimeout(addr, config, 2*time.Second)
	if err == nil {
		t.Fatal("expected error dialing closed port")
	}
}

func TestSSHDialWithTimeout_HandshakeHang(t *testing.T) {
	// TCP listener that accepts but never speaks SSH
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 1024)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	config := &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	timeout := 500 * time.Millisecond
	start := time.Now()
	_, err = sshDialWithTimeout(listener.Addr().String(), config, timeout)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected error on handshake hang")
	}
	if elapsed > 5*time.Second {
		t.Errorf("sshDialWithTimeout took %v, expected ~%v", elapsed, timeout)
	}
}

func TestSSHDialWithTimeout_ReturnsClient(t *testing.T) {
	addr, cleanup := newTestSSHServer(t)
	defer cleanup()

	config := &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := sshDialWithTimeout(addr, config, 5*time.Second)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer client.Close()

	// Session open will fail (server rejects channels) but proves client works
	_, err = client.NewSession()
	if err == nil {
		t.Fatal("expected session rejection from test server")
	}
}

func TestSSHSendKeepalive_Success(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mock := &mockKeepaliveClient{}
		ctx := t.Context()

		if err := sshSendKeepalive(ctx, mock); err != nil {
			t.Fatalf("sshSendKeepalive failed on healthy client: %v", err)
		}
	})
}

func TestSSHSendKeepalive_Error(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mock := &mockKeepaliveClient{
			sendFunc: func() error {
				return errors.New("connection reset")
			},
		}
		ctx := t.Context()

		if err := sshSendKeepalive(ctx, mock); err == nil {
			t.Fatal("expected error from failing client")
		}
	})
}

func TestSSHSendKeepalive_Timeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// SendRequest blocks until released, simulating a hung connection
		block := make(chan struct{})
		mock := &mockKeepaliveClient{
			sendFunc: func() error {
				<-block
				return errors.New("unblocked")
			},
		}
		ctx := t.Context()

		err := sshSendKeepalive(ctx, mock)
		if err == nil {
			t.Fatal("expected timeout error")
		}
		t.Logf("got expected error: %v", err)

		// Unblock the leaked goroutine so synctest can clean up
		close(block)
		synctest.Wait()
	})
}

func TestSSHSendKeepalive_ContextCanceled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// SendRequest blocks until released
		block := make(chan struct{})
		mock := &mockKeepaliveClient{
			sendFunc: func() error {
				<-block
				return errors.New("unblocked")
			},
		}
		ctx, cancel := context.WithCancel(t.Context())

		// Cancel after 1s (before the 10s request timeout)
		go func() {
			time.Sleep(1 * time.Second)
			cancel()
		}()

		err := sshSendKeepalive(ctx, mock)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got: %v", err)
		}

		// Unblock the leaked goroutine so synctest can clean up
		close(block)
		synctest.Wait()
	})
}

func TestRunSSHKeepalive_SendsAtInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var count atomic.Int32
		mock := &mockKeepaliveClient{
			sendFunc: func() error {
				count.Add(1)
				return nil
			},
		}

		ctx, cancel := context.WithCancel(t.Context())
		go runSSHKeepalive(ctx, mock, "test")

		// Advance past 3 intervals (30s each = 90s)
		time.Sleep(sshKeepaliveInterval*3 + time.Nanosecond)
		synctest.Wait()

		got := count.Load()
		if got != 3 {
			t.Errorf("expected 3 keepalives after 3 intervals, got %d", got)
		}

		cancel()
		synctest.Wait()
	})
}

func TestRunSSHKeepalive_ClosesAfterMaxMissed(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		mock := &mockKeepaliveClient{
			sendFunc: func() error {
				return errors.New("connection reset")
			},
		}

		go runSSHKeepalive(t.Context(), mock, "test")

		// After sshKeepaliveMaxMissed intervals, the client should be closed.
		// Each tick is 30s; need 3 ticks for 3 misses.
		time.Sleep(sshKeepaliveInterval*time.Duration(sshKeepaliveMaxMissed) + time.Nanosecond)
		synctest.Wait()

		if !mock.closed.Load() {
			t.Fatal("expected client to be closed after max missed keepalives")
		}
		if got := mock.closeCalled.Load(); got != 1 {
			t.Errorf("expected Close called once, got %d", got)
		}
	})
}

func TestRunSSHKeepalive_ResetsOnSuccess(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var callCount atomic.Int32
		mock := &mockKeepaliveClient{
			sendFunc: func() error {
				n := callCount.Add(1)
				// Fail on calls 1 and 2, succeed on 3, fail on 4 and 5, succeed on 6...
				if n%3 != 0 {
					return errors.New("temporary failure")
				}
				return nil
			},
		}

		ctx, cancel := context.WithCancel(t.Context())
		go runSSHKeepalive(ctx, mock, "test")

		// After 6 intervals: fail, fail, succeed, fail, fail, succeed
		// The missed counter resets each time a keepalive succeeds,
		// so we never hit maxMissed (3).
		time.Sleep(sshKeepaliveInterval*6 + time.Nanosecond)
		synctest.Wait()

		if mock.closed.Load() {
			t.Fatal("client should not be closed — missed counter resets on success")
		}

		cancel()
		synctest.Wait()
	})
}

func TestRunSSHKeepalive_StopsOnContextCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var count atomic.Int32
		mock := &mockKeepaliveClient{
			sendFunc: func() error {
				count.Add(1)
				return nil
			},
		}

		ctx, cancel := context.WithCancel(t.Context())
		go runSSHKeepalive(ctx, mock, "test")

		// Let one keepalive fire
		time.Sleep(sshKeepaliveInterval + time.Nanosecond)
		synctest.Wait()

		if got := count.Load(); got != 1 {
			t.Fatalf("expected 1 keepalive before cancel, got %d", got)
		}

		// Cancel and verify no more keepalives fire
		cancel()
		synctest.Wait()

		countAfterCancel := count.Load()
		time.Sleep(sshKeepaliveInterval * 3)
		synctest.Wait()

		if got := count.Load(); got != countAfterCancel {
			t.Errorf("keepalives continued after cancel: had %d, now %d", countAfterCancel, got)
		}

		if mock.closed.Load() {
			t.Error("client should not be closed on context cancel")
		}
	})
}

func TestRunSSHKeepalive_HungRequestCountsAsMiss(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// SendRequest blocks until released — each keepalive should time out
		// after sshKeepaliveRequestTimeout and count as a miss.
		block := make(chan struct{})
		mock := &mockKeepaliveClient{
			sendFunc: func() error {
				<-block
				return errors.New("unblocked")
			},
		}

		go runSSHKeepalive(t.Context(), mock, "test")

		// Each keepalive tick (30s) starts a request that times out after 10s,
		// so each tick takes ~30s from the ticker's perspective (the timeout
		// completes within the interval). After 3 ticks, client should close.
		time.Sleep(sshKeepaliveInterval*time.Duration(sshKeepaliveMaxMissed) + sshKeepaliveRequestTimeout + time.Nanosecond)
		synctest.Wait()

		if !mock.closed.Load() {
			t.Fatal("expected client to be closed after hung requests exceed max missed")
		}

		// Unblock leaked goroutines so synctest can clean up
		close(block)
		synctest.Wait()
	})
}
