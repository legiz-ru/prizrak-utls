// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// capturedClientHellos returns the ClientHello handshake messages in a
// testdata file holding one hex-encoded message per line and # comments.
func capturedClientHellos(t *testing.T, path string) [][]byte {
	t.Helper()
	text, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var hellos [][]byte
	for _, line := range strings.Split(string(text), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hello, err := hex.DecodeString(line)
		if err != nil {
			t.Fatal(err)
		}
		hellos = append(hellos, hello)
	}
	if len(hellos) == 0 {
		t.Fatalf("no captured ClientHello in %s", path)
	}
	return hellos
}

// capturedHandshake completes a TLS 1.3 handshake of a fingerprint with a
// crypto/tls server that only accepts curve and reports whether it took a
// HelloRetryRequest.
func capturedHandshake(t *testing.T, id ClientHelloID, curve CurveID) (didHRR bool) {
	t.Helper()
	serverConfig := testConfigServer.Clone()
	serverConfig.CurvePreferences = []CurveID{curve}
	clientConfig := testConfigClient.Clone()
	clientConfig.ServerName = "example.com"
	clientConfig.InsecureSkipVerify = true

	clientConn, serverConn := localPipe(t)
	server := Server(serverConn, serverConfig)
	client := UClient(clientConn, clientConfig, id)
	defer server.Close()
	defer client.Close()

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if state := client.ConnectionState(); state.Version != VersionTLS13 || state.DidResume {
		t.Fatalf("expected a full TLS 1.3 handshake: %+v", state)
	}
	if client.curveID != curve {
		t.Fatalf("negotiated %v, want %v", client.curveID, curve)
	}
	return client.didHRR
}
