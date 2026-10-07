// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !go1.27

// Package mldsa stands in for crypto/mldsa so the module builds with Go 1.20.
// Before Go 1.27 the standard library has no ML-DSA: crypto/x509 never returns
// these key types, so the TLS code paths that switch on them are unreachable
// and every operation here reports that ML-DSA is unavailable.
package mldsa

import (
	"crypto"
	"errors"
	"io"
)

// Supported reports whether ML-DSA certificates can be used.
const Supported = false

var errUnsupported = errors.New("mldsa: ML-DSA certificates require Go 1.27 or later")

// Parameters names an ML-DSA parameter set.
type Parameters struct{ name string }

func (p Parameters) String() string { return p.name }

func MLDSA44() Parameters { return Parameters{"ML-DSA-44"} }
func MLDSA65() Parameters { return Parameters{"ML-DSA-65"} }
func MLDSA87() Parameters { return Parameters{"ML-DSA-87"} }

// Options mirrors crypto/mldsa.Options.
type Options struct {
	Context string
}

// PublicKey is never produced before Go 1.27.
type PublicKey struct{ params Parameters }

func (pk *PublicKey) Parameters() Parameters { return pk.params }

func (pk *PublicKey) Equal(x crypto.PublicKey) bool { return false }

// PrivateKey is never produced before Go 1.27.
type PrivateKey struct{ pub PublicKey }

func (sk *PrivateKey) PublicKey() *PublicKey { return &sk.pub }

func (sk *PrivateKey) Public() crypto.PublicKey { return &sk.pub }

func (sk *PrivateKey) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errUnsupported
}

func GenerateKey(Parameters) (*PrivateKey, error) { return nil, errUnsupported }

func Verify(*PublicKey, []byte, []byte, *Options) error { return errUnsupported }
