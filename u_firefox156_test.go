// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"net"
	"reflect"
	"slices"
	"testing"
)

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
	aead, _, payloadLen = firefoxECH(t, body)
	return aead, payloadLen
}

// firefoxECH returns the AEAD, the enc and the payload length of a GREASE
// encrypted_client_hello extension.
func firefoxECH(t *testing.T, body []byte) (aead uint16, enc []byte, payloadLen int) {
	t.Helper()
	r := chrome155Reader{t, body, "encrypted_client_hello"}
	r.take(1 + 2) // outer, KDF
	aead = uint16(r.number(2))
	r.take(1) // config_id
	enc = r.vector(2)
	payloadLen = len(r.vector(2))
	r.end()
	return aead, enc, payloadLen
}

// firefox156ECHAEADs are the AEADs Firefox draws its GREASE ECH from.
var firefox156ECHAEADs = []uint16{0x0001, 0x0003} // AES-128-GCM, ChaCha20-Poly1305

func TestFirefox156CapturedClientHello(t *testing.T) {
	if HelloFirefox_Auto != HelloFirefox_156 {
		t.Fatalf("HelloFirefox_Auto = %s, want %s", HelloFirefox_Auto.Str(), HelloFirefox_156.Str())
	}
	testFirefoxCapturedClientHello(t, HelloFirefox_156, "testdata/firefox156_clienthellos.hex")
}

// testFirefoxCapturedClientHello compares the ClientHellos of a Firefox
// fingerprint with fresh ones captured from the browser.
func testFirefoxCapturedClientHello(t *testing.T, id ClientHelloID, path string) {
	t.Helper()
	encTopBits := make(map[byte]bool)
	for _, fixture := range capturedClientHellos(t, path) {
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
					}, id)
					if err := client.BuildHandshakeState(); err != nil {
						t.Fatal(err)
					}
					raw := client.HandshakeState.Hello.Raw
					got, gotOrder, generated := chrome155ParseWire(t, raw)
					aead, enc, payloadLen := firefoxECH(t, generated[0xfe0d])
					if !slices.Contains(firefox156ECHAEADs, aead) {
						t.Fatalf("GREASE ECH AEAD %#04x, Firefox uses AES-128-GCM or ChaCha20-Poly1305", aead)
					}
					if payloadLen != 240 {
						t.Fatalf("GREASE ECH payload of %d bytes, Firefox sends 240", payloadLen)
					}
					if len(enc) != 32 {
						t.Fatalf("GREASE ECH enc of %d bytes, Firefox sends 32", len(enc))
					}
					encTopBits[enc[31]>>7] = true
					// The AEAD is drawn per connection; everything else must match.
					got.Extensions[0xfe0d] = want.Extensions[0xfe0d]
					if !reflect.DeepEqual(got, want) {
						t.Fatalf("generated ClientHello differs from the Firefox capture:\n got: %+v\nwant: %+v", got, want)
					}
					if !slices.Equal(gotOrder, wantOrder) {
						t.Fatalf("extension order %x, Firefox sends %x", gotOrder, wantOrder)
					}
					if len(raw) != len(fixture) {
						t.Fatalf("ClientHello of %d bytes, Firefox sends %d", len(raw), len(fixture))
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
	// NSS draws the GREASE ECH enc as random bytes; an X25519 public key
	// never has the top bit of its last byte set.
	if !encTopBits[0] || !encTopBits[1] {
		t.Fatalf("top bits of the GREASE ECH enc's last byte: %v, Firefox sends uniformly random bytes", encTopBits)
	}
}

func TestFirefox156Handshake(t *testing.T) {
	testFirefoxHandshake(t, HelloFirefox_156)
}

func testFirefoxHandshake(t *testing.T, id ClientHelloID) {
	t.Helper()
	// Firefox offers a key share for each of them.
	for _, curve := range []CurveID{X25519MLKEM768, X25519, CurveP256} {
		t.Run(curve.String(), func(t *testing.T) {
			if capturedHandshake(t, id, curve) {
				t.Fatal("unexpected HelloRetryRequest: Firefox offers a key share for this group")
			}
		})
	}
}
