// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// firefox156Fixtures returns the ClientHello handshake messages in
// testdata/firefox156_clienthellos.hex, captured from Firefox 156.0 itself.
func firefox156Fixtures(t *testing.T) [][]byte {
	t.Helper()
	text, err := os.ReadFile("testdata/firefox156_clienthellos.hex")
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
		t.Fatal("no captured ClientHello")
	}
	return hellos
}

func firefox156KeyShares(t *testing.T, body []byte) map[CurveID][]byte {
	t.Helper()
	r := chrome155Reader{t, body, "key_share"}
	entries := chrome155Reader{t, r.vector(2), "key_share entries"}
	r.end()
	shares := make(map[CurveID][]byte)
	for len(entries.b) > 0 {
		group := CurveID(entries.number(2))
		shares[group] = entries.vector(2)
	}
	return shares
}

// firefox156ECH returns the AEAD and the payload length of a GREASE
// encrypted_client_hello extension.
func firefox156ECH(t *testing.T, body []byte) (aead uint16, payloadLen int) {
	t.Helper()
	r := chrome155Reader{t, body, "encrypted_client_hello"}
	r.take(1 + 2) // outer, KDF
	aead = uint16(r.number(2))
	r.take(1)   // config_id
	r.vector(2) // enc
	payloadLen = len(r.vector(2))
	r.end()
	return aead, payloadLen
}

// firefox156ECHAEADs are the AEADs Firefox draws its GREASE ECH from.
var firefox156ECHAEADs = []uint16{0x0001, 0x0003} // AES-128-GCM, ChaCha20-Poly1305

func TestFirefox156CapturedClientHello(t *testing.T) {
	if HelloFirefox_Auto != HelloFirefox_156 {
		t.Fatalf("HelloFirefox_Auto = %s, want %s", HelloFirefox_Auto.Str(), HelloFirefox_156.Str())
	}
	for _, fixture := range firefox156Fixtures(t) {
		want, wantOrder, captured := chrome155ParseWire(t, fixture)
		serverName := chrome155FixtureServerName(t, captured)
		if aead, n := firefox156ECH(t, captured[0xfe0d]); !slices.Contains(firefox156ECHAEADs, aead) || n != 240 {
			t.Fatalf("capture's GREASE ECH: AEAD %#04x, payload %d bytes", aead, n)
		}
		t.Run(serverName, func(t *testing.T) {
			// SessionTicketsDisabled as REALITY sets it must not change the hello.
			for _, ticketsDisabled := range []bool{false, true} {
				// Keys, the GREASE ECH cipher suite and payload are drawn per connection.
				for i := 0; i < 8; i++ {
					client := UClient(&net.TCPConn{}, &Config{
						ServerName:             serverName,
						SessionTicketsDisabled: ticketsDisabled,
					}, HelloFirefox_156)
					if err := client.BuildHandshakeState(); err != nil {
						t.Fatal(err)
					}
					raw := client.HandshakeState.Hello.Raw
					got, gotOrder, generated := chrome155ParseWire(t, raw)
					aead, payloadLen := firefox156ECH(t, generated[0xfe0d])
					if !slices.Contains(firefox156ECHAEADs, aead) {
						t.Fatalf("GREASE ECH AEAD %#04x, Firefox 156 uses AES-128-GCM or ChaCha20-Poly1305", aead)
					}
					if payloadLen != 240 {
						t.Fatalf("GREASE ECH payload of %d bytes, Firefox 156 sends 240", payloadLen)
					}
					// The AEAD is drawn per connection; everything else must match.
					got.Extensions[0xfe0d] = want.Extensions[0xfe0d]
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("generated ClientHello differs from the Firefox 156 capture:\n got: %+v\nwant: %+v", got, want)
					}
					if !slices.Equal(gotOrder, wantOrder) {
						t.Fatalf("extension order %x, Firefox 156 sends %x", gotOrder, wantOrder)
					}
					if len(raw) != len(fixture) {
						t.Fatalf("ClientHello of %d bytes, Firefox 156 sends %d", len(raw), len(fixture))
					}
					shares := firefox156KeyShares(t, generated[51])
					hybrid, classical := shares[X25519MLKEM768], shares[X25519]
					if len(hybrid) < 32 || !bytes.Equal(classical, hybrid[len(hybrid)-32:]) {
						t.Fatal("the X25519 key share must be the one inside X25519MLKEM768, as Firefox sends it")
					}
					if ticket, ok := generated[35]; !ok || len(ticket) != 0 {
						t.Fatal("a fresh connection must advertise an empty session_ticket extension")
					}
					if _, ok := generated[41]; ok {
						t.Fatal("a fresh connection unexpectedly offers pre_shared_key")
					}
				}
			}
		})
	}
}

func TestFirefox156Handshake(t *testing.T) {
	for _, tc := range []struct {
		name  string
		curve CurveID
	}{
		{"X25519MLKEM768", X25519MLKEM768},
		{"X25519", X25519},
		{"P-256", CurveP256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverConfig := testConfigServer.Clone()
			serverConfig.CurvePreferences = []CurveID{tc.curve}
			clientConfig := testConfigClient.Clone()
			clientConfig.ServerName = "example.com"
			clientConfig.InsecureSkipVerify = true

			clientConn, serverConn := localPipe(t)
			server := Server(serverConn, serverConfig)
			client := UClient(clientConn, clientConfig, HelloFirefox_156)
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
			if client.curveID != tc.curve {
				t.Fatalf("negotiated %v, want %v", client.curveID, tc.curve)
			}
			if client.didHRR {
				t.Fatal("unexpected HelloRetryRequest: Firefox 156 offers a key share for this group")
			}
		})
	}
}
