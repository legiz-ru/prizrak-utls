// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !go1.21

package tls

import (
	"bytes"
	"io"
)

// atLeastReader reads from R, stopping with EOF once at least N bytes have been
// read. It is different from an io.LimitedReader in that it doesn't cut short
// the last Read call, and in that it considers an early EOF an error.
type atLeastReader struct {
	R io.Reader
	N int64
}

func (r *atLeastReader) Read(p []byte) (int, error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	n, err := r.R.Read(p)
	r.N -= int64(n) // won't underflow unless len(p) >= n > 9223372036854775809
	if r.N > 0 && err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	if r.N <= 0 && err == nil {
		return n, io.EOF
	}
	return n, err
}

// readAtLeast reads from r into buf until needs more bytes have arrived.
// bytes.Buffer.AvailableBuffer needs Go 1.21, so this keeps the pre-Go 1.27
// atLeastReader form of (*Conn).readFromUntil.
func readAtLeast(buf *bytes.Buffer, r io.Reader, needs int) error {
	// There might be extra input waiting on the wire. Make a best effort
	// attempt to fetch it so that it can be used in (*Conn).Read to
	// "predict" closeNotify alerts.
	buf.Grow(needs + bytes.MinRead)
	_, err := buf.ReadFrom(&atLeastReader{r, int64(needs)})
	return err
}
