// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"testing"
)

func TestFirefox160CapturedClientHello(t *testing.T) {
	if HelloFirefox_Auto != HelloFirefox_160 {
		t.Fatalf("HelloFirefox_Auto = %s, want %s", HelloFirefox_Auto.Str(), HelloFirefox_160.Str())
	}
	testFirefoxCapturedClientHello(t, HelloFirefox_160, "testdata/firefox160_clienthellos.hex")
	// Firefox 160's fresh hello is 156's, so either matches both captures.
	testFirefoxCapturedClientHello(t, HelloFirefox_156, "testdata/firefox160_clienthellos.hex")
	testFirefoxCapturedClientHello(t, HelloFirefox_160, "testdata/firefox156_clienthellos.hex")
}

func TestFirefox160Handshake(t *testing.T) {
	testFirefoxHandshake(t, HelloFirefox_160)
}

// A resumed Firefox 160 hello drops session_ticket, ends with pre_shared_key
// and has a larger GREASE ECH payload. HelloFirefox_160 offers no PSK, so
// with a session cache it keeps sending the fresh hello and never resumes.
func TestFirefox160FreshHelloWithSessionCache(t *testing.T) {
	cache := NewLRUClientSessionCache(1)
	serverConfig := testConfigServer.Clone()
	serverConfig.MinVersion = VersionTLS13
	for i := 0; i < 2; i++ {
		clientConfig := testConfigClient.Clone()
		clientConfig.ServerName = "example.com"
		clientConfig.InsecureSkipVerify = true
		clientConfig.ClientSessionCache = cache

		clientConn, serverConn := localPipe(t)
		server := Server(serverConn, serverConfig)
		client := UClient(clientConn, clientConfig, HelloFirefox_160)
		serverErr := make(chan error, 1)
		go func() {
			if err := server.Handshake(); err != nil {
				serverErr <- err
				return
			}
			_, err := server.Write([]byte{0})
			serverErr <- err
		}()
		if err := client.Handshake(); err != nil {
			t.Fatalf("client handshake: %v", err)
		}
		// The NewSessionTicket comes before the byte.
		if _, err := client.Read(make([]byte, 1)); err != nil {
			t.Fatalf("client read: %v", err)
		}
		if err := <-serverErr; err != nil {
			t.Fatalf("server: %v", err)
		}
		_, _, generated := chrome155ParseWire(t, client.HandshakeState.Hello.Raw)
		if _, ok := generated[41]; ok {
			t.Fatalf("connection %d offered pre_shared_key", i)
		}
		if ticket, ok := generated[35]; !ok || len(ticket) != 0 {
			t.Fatalf("connection %d: session_ticket %x, want the fresh hello's empty one", i, ticket)
		}
		if client.ConnectionState().DidResume {
			t.Fatalf("connection %d resumed", i)
		}
		client.Close()
		server.Close()
		if n := len(cache.(*lruSessionCache).m); n != 1 {
			t.Fatalf("%d sessions in the cache after connection %d, want 1", n, i)
		}
	}
}
