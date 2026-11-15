package tls

// realityClassicKeyShare returns the X25519 key share a REALITY server may
// authenticate with when the Client Hello does not offer X25519MLKEM768 at
// all: a browser fingerprint from before hybrid key exchange, or a client
// that leaves the hybrid group out. A Client Hello that offers the hybrid
// group must authenticate through it, with X25519MLKEM768 before an optional
// X25519, as XTLS/REALITY requires since 8cdf7bf9. It returns nil when
// config.RequireMLKEM is set or unless the hello carries exactly one
// well-formed X25519 key share.
//
// Same rule as fork_keyshare.go of github.com/Jolymmiles/Xray-core.
func realityClassicKeyShare(config *RealityConfig, hello *clientHelloMsg) []byte {
	if config.RequireMLKEM {
		return nil
	}
	for _, group := range hello.supportedCurves {
		if group == X25519MLKEM768 {
			return nil
		}
	}
	var share []byte
	for _, keyShare := range hello.keyShares {
		switch keyShare.group {
		case X25519MLKEM768:
			return nil
		case X25519:
			if share != nil || len(keyShare.data) != 32 {
				return nil
			}
			share = keyShare.data
		}
	}
	return share
}
