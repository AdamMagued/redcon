package redcon

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func testTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Redcon"},
		},
		NotBefore:   time.Now().Add(-time.Hour),
		NotAfter:    time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{certDER},
				PrivateKey:  priv,
			},
		},
	}
}

func TestServerReusePortListener(t *testing.T) {
	s1 := NewServerNetwork("tcp", "127.0.0.1:0",
		func(conn Conn, cmd Command) {},
		nil,
		nil,
	)
	s1.ReusePort = true

	ln1, err := s1.Listen()
	if err != nil {
		if errors.Is(err, ErrReusePortNotSupported) {
			t.Skip("SO_REUSEPORT is not supported on this platform")
		}
		t.Fatalf("failed to listen on s1 with ReusePort: %v", err)
	}
	defer ln1.Close()

	addr := ln1.Addr().String()

	s2 := NewServerNetwork("tcp", addr,
		func(conn Conn, cmd Command) {},
		nil,
		nil,
	)
	s2.SetReusePort(true)

	ln2, err := s2.Listen()
	if err != nil {
		t.Fatalf("failed to listen on s2 with ReusePort on same addr: %v", err)
	}
	defer ln2.Close()

	if ln2.Addr().String() != addr {
		t.Fatalf("expected address %s, got %s", addr, ln2.Addr().String())
	}

	s3 := NewServerNetwork("tcp", addr,
		func(conn Conn, cmd Command) {},
		nil,
		nil,
	)
	s3.ReusePort = false

	ln3, err := s3.Listen()
	if err == nil {
		ln3.Close()
		t.Fatalf("expected error when binding to used port without ReusePort")
	}
}

func TestServerReusePortServe(t *testing.T) {
	s1 := NewServerNetwork("tcp", "127.0.0.1:0",
		func(conn Conn, cmd Command) {
			if strings.ToLower(string(cmd.Args[0])) == "ping" {
				conn.WriteString("PONG-1")
			}
		},
		nil,
		nil,
	)
	s1.ReusePort = true

	ln1, err := s1.Listen()
	if err != nil {
		if errors.Is(err, ErrReusePortNotSupported) {
			t.Skip("SO_REUSEPORT is not supported on this platform")
		}
		t.Fatalf("failed to listen s1: %v", err)
	}
	addr := ln1.Addr().String()
	ln1.Close()

	s1 = NewServerNetwork("tcp", addr,
		func(conn Conn, cmd Command) {
			if strings.ToLower(string(cmd.Args[0])) == "ping" {
				conn.WriteString("PONG-1")
			}
		},
		nil,
		nil,
	)
	s1.ReusePort = true

	s2 := NewServerNetwork("tcp", addr,
		func(conn Conn, cmd Command) {
			if strings.ToLower(string(cmd.Args[0])) == "ping" {
				conn.WriteString("PONG-2")
			}
		},
		nil,
		nil,
	)
	s2.ReusePort = true

	sig1 := make(chan error, 1)
	sig2 := make(chan error, 1)

	go func() {
		_ = s1.ListenServeAndSignal(sig1)
	}()
	if err := <-sig1; err != nil {
		t.Fatalf("s1 failed to start: %v", err)
	}
	defer s1.Close()

	go func() {
		_ = s2.ListenServeAndSignal(sig2)
	}()
	if err := <-sig2; err != nil {
		t.Fatalf("s2 failed to start: %v", err)
	}
	defer s2.Close()

	for i := 0; i < 5; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("failed to dial server on attempt %d: %v", i, err)
		}
		_, err = io.WriteString(conn, "PING\r\n")
		if err != nil {
			conn.Close()
			t.Fatalf("failed to write ping: %v", err)
		}
		buf := make([]byte, 128)
		n, err := conn.Read(buf)
		conn.Close()
		if err != nil {
			t.Fatalf("failed to read pong: %v", err)
		}
		resp := string(buf[:n])
		if resp != "+PONG-1\r\n" && resp != "+PONG-2\r\n" {
			t.Fatalf("unexpected response: %q", resp)
		}
	}
}

func TestServerListenConfigCustomControl(t *testing.T) {
	var userControlInvoked uint32

	lc := &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			atomic.AddUint32(&userControlInvoked, 1)
			return nil
		},
	}

	s := NewServerNetwork("tcp", "127.0.0.1:0",
		func(conn Conn, cmd Command) {},
		nil,
		nil,
	)
	s.SetListenConfig(lc)
	s.SetReusePort(true)

	ln, err := s.Listen()
	if err != nil {
		if errors.Is(err, ErrReusePortNotSupported) {
			t.Skip("SO_REUSEPORT is not supported on this platform")
		}
		t.Fatalf("failed to listen with custom ListenConfig and ReusePort: %v", err)
	}
	defer ln.Close()

	if atomic.LoadUint32(&userControlInvoked) == 0 {
		t.Fatalf("expected user ListenConfig.Control to be invoked")
	}
}

func TestTLSServerReusePort(t *testing.T) {
	tlsCfg := testTLSConfig(t)

	s1 := NewServerNetworkTLS("tcp", "127.0.0.1:0",
		func(conn Conn, cmd Command) {},
		nil,
		nil,
		tlsCfg,
	)
	s1.ReusePort = true

	ln1, err := s1.Listen()
	if err != nil {
		if errors.Is(err, ErrReusePortNotSupported) {
			t.Skip("SO_REUSEPORT is not supported on this platform")
		}
		t.Fatalf("failed to listen on s1 TLS with ReusePort: %v", err)
	}
	defer ln1.Close()

	addr := ln1.Addr().String()

	s2 := NewServerNetworkTLS("tcp", addr,
		func(conn Conn, cmd Command) {},
		nil,
		nil,
		tlsCfg,
	)
	s2.SetReusePort(true)

	ln2, err := s2.Listen()
	if err != nil {
		t.Fatalf("failed to listen on s2 TLS with ReusePort on same addr: %v", err)
	}
	defer ln2.Close()

	if ln2.Addr().String() != addr {
		t.Fatalf("expected address %s, got %s", addr, ln2.Addr().String())
	}
}

func TestReusePortUnsupportedError(t *testing.T) {
	if ErrReusePortNotSupported == nil {
		t.Fatalf("expected ErrReusePortNotSupported to be non-nil")
	}
	expectedMsg := "redcon: reuseport is not supported on this platform"
	if ErrReusePortNotSupported.Error() != expectedMsg {
		t.Fatalf("expected %q, got %q", expectedMsg, ErrReusePortNotSupported.Error())
	}
}
