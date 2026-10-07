// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.26

// Package fips140 stands in for crypto/fips140 so the module builds with
// Go 1.20. From Go 1.26 it forwards to the standard library.
package fips140

import "crypto/fips140"

// Version forwards to crypto/fips140.Version.
func Version() string { return fips140.Version() }

// WithoutEnforcement forwards to crypto/fips140.WithoutEnforcement.
func WithoutEnforcement(f func()) { fips140.WithoutEnforcement(f) }
