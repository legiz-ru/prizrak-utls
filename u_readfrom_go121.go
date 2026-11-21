// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.21

package tls

import (
	"bytes"
	"io"
)

// readAtLeast reads from r into buf until needs more bytes have arrived.
// It is the loop of upstream (*Conn).readFromUntil.
func readAtLeast(buf *bytes.Buffer, r io.Reader, needs int) error {
	// There might be extra input waiting on the wire. Make a best effort
	// attempt to fetch it so that it can be used in (*Conn).Read to
	// "predict" closeNotify alerts.
	// TODO(dmo): we use bytes.MinRead here because we used the buffer
	// ReadFrom mechanism to avoid allocations, but we've hoisted this
	// loop for performance. We really should use our own heuristic here
	// for how much to read ahead.
	buf.Grow(needs + bytes.MinRead)
	for {
		b := buf.AvailableBuffer()[:buf.Available()]
		n, err := r.Read(b)
		// This write is just to update the internal state of the
		// rawInput bytes.Buffer. It cannot fail.
		buf.Write(b[:n])
		needs -= n
		if needs <= 0 {
			if err == io.EOF {
				err = nil
			}
			return err
		}
		if err == io.EOF {
			return io.ErrUnexpectedEOF
		}
		if err != nil {
			return err
		}
	}
}
