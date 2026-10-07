// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !go1.26

// Package fips140 stands in for crypto/fips140 so the module builds with
// Go 1.20. Before Go 1.26 there is no FIPS 140-3 enforcement to lift.
package fips140

// Version reports no FIPS 140-3 module version.
func Version() string { return "" }

// WithoutEnforcement runs f.
func WithoutEnforcement(f func()) { f() }
