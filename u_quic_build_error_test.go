// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A UQUICConn whose ClientHello cannot be built must return that error from
// Start and Close, as a failed QUIC handshake does, instead of blocking: the
// error has to go through the QUIC cleanup in handshakeContext, which closes
// blockedc and signalc.
func TestUQUICBuildHandshakeStateError(t *testing.T) {
	clientConfig := testConfigClient.Clone()
	clientConfig.NextProtos = []string{"h3"}
	client := UQUICClient(&QUICConfig{TLSConfig: clientConfig}, ClientHelloID{Client: "NoSuchClient", Version: "1"})
	client.SetTransportParameters(nil)

	errc := make(chan error, 1)
	go func() { errc <- client.Start(context.Background()) }()
	var startErr error
	select {
	case startErr = <-errc:
	case <-time.After(10 * time.Second):
		t.Fatal("Start blocked after BuildHandshakeState failed")
	}
	if startErr == nil {
		t.Fatal("Start succeeded with an unknown ClientHelloID")
	}
	var alert AlertError
	if !errors.As(startErr, &alert) {
		t.Errorf("Start error %v does not carry a TLS alert as QUIC handshake errors do", startErr)
	}
	if ev := client.NextEvent(); ev.Kind != QUICErrorEvent {
		t.Errorf("NextEvent kind = %v, want QUICErrorEvent", ev.Kind)
	}

	closec := make(chan error, 1)
	go func() { closec <- client.Close() }()
	select {
	case err := <-closec:
		if err == nil {
			t.Error("Close returned no error after a failed handshake")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close blocked after BuildHandshakeState failed")
	}
}
