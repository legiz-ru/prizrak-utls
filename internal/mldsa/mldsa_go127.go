// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.27

// Package mldsa stands in for crypto/mldsa so the module builds with Go 1.20.
// From Go 1.27 its types are aliases of the standard library ones, so the keys
// crypto/x509 returns match the type switches in the TLS code.
package mldsa

import "crypto/mldsa"

// Supported reports whether ML-DSA certificates can be used.
const Supported = true

type (
	PublicKey  = mldsa.PublicKey
	PrivateKey = mldsa.PrivateKey
	Parameters = mldsa.Parameters
	Options    = mldsa.Options
)

func MLDSA44() Parameters { return mldsa.MLDSA44() }
func MLDSA65() Parameters { return mldsa.MLDSA65() }
func MLDSA87() Parameters { return mldsa.MLDSA87() }

func GenerateKey(params Parameters) (*PrivateKey, error) { return mldsa.GenerateKey(params) }

func Verify(pk *PublicKey, message, signature []byte, opts *Options) error {
	return mldsa.Verify(pk, message, signature, opts)
}
