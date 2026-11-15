package tls

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/metacubex/utls/mlkem"
	"golang.org/x/crypto/hkdf"
)

func TestRealityClassicKeyShare(t *testing.T) {
	x25519 := bytes.Repeat([]byte{1}, 32)
	hybrid := make([]byte, mlkem.EncapsulationKeySize768+32)
	p256 := make([]byte, 65)
	tests := []struct {
		name         string
		requireMLKEM bool
		curves       []CurveID
		keyShares    []keyShare
		want         []byte
	}{
		{
			name:      "hybrid key share offered",
			curves:    []CurveID{X25519MLKEM768, X25519, CurveP256},
			keyShares: []keyShare{{group: X25519MLKEM768, data: hybrid}, {group: X25519, data: x25519}},
		},
		{
			name:      "hybrid group without its key share",
			curves:    []CurveID{X25519MLKEM768, X25519},
			keyShares: []keyShare{{group: X25519, data: x25519}},
		},
		{
			name:      "hybrid key share outside supported groups",
			curves:    []CurveID{X25519},
			keyShares: []keyShare{{group: X25519, data: x25519}, {group: X25519MLKEM768, data: hybrid}},
		},
		{
			name:         "RequireMLKEM",
			requireMLKEM: true,
			curves:       []CurveID{X25519, CurveP256},
			keyShares:    []keyShare{{group: X25519, data: x25519}},
		},
		{
			name:      "one X25519 key share",
			curves:    []CurveID{X25519, CurveP256, CurveP384},
			keyShares: []keyShare{{group: X25519, data: x25519}},
			want:      x25519,
		},
		{
			name:      "one X25519 key share after GREASE and before P-256",
			curves:    []CurveID{0x0a0a, X25519, CurveP256},
			keyShares: []keyShare{{group: 0x0a0a, data: []byte{0}}, {group: X25519, data: x25519}, {group: CurveP256, data: p256}},
			want:      x25519,
		},
		{
			name:      "two X25519 key shares",
			curves:    []CurveID{X25519},
			keyShares: []keyShare{{group: X25519, data: x25519}, {group: X25519, data: x25519}},
		},
		{
			name:      "short X25519 key share",
			curves:    []CurveID{X25519},
			keyShares: []keyShare{{group: X25519, data: x25519[:31]}},
		},
		{
			name:      "long X25519 key share",
			curves:    []CurveID{X25519},
			keyShares: []keyShare{{group: X25519, data: append(append([]byte(nil), x25519...), 0)}},
		},
		{
			name:      "no X25519 key share",
			curves:    []CurveID{X25519, CurveP256},
			keyShares: []keyShare{{group: CurveP256, data: p256}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := &RealityConfig{RequireMLKEM: test.requireMLKEM}
			hello := &clientHelloMsg{supportedCurves: test.curves, keyShares: test.keyShares}
			if got := realityClassicKeyShare(config, hello); !bytes.Equal(got, test.want) {
				t.Fatalf("realityClassicKeyShare() = %x, want %x", got, test.want)
			}
		})
	}
}

// TestRealityServerKeyShares runs RealityServer against Client Hellos of
// browser fingerprints. The target selects X25519 without a HelloRetryRequest,
// so the client completes a handshake either way; RealityServer reports
// whether it authenticated the client, and the client sees whose certificate
// it was shown.
func TestRealityServerKeyShares(t *testing.T) {
	target, targetLeaf := startRealityTestTarget(t)
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	version := [3]byte{26, 11, 10}

	tests := []struct {
		name         string
		id           ClientHelloID
		shape        func(t *testing.T, spec *ClientHelloSpec)
		requireMLKEM bool
		minVer       []byte
		want         bool
	}{
		{name: "chrome", id: HelloChrome_Auto, want: true},
		{name: "firefox", id: HelloFirefox_Auto, want: true},
		{name: "safari", id: HelloSafari_Auto, want: true},
		{name: "ios without X25519MLKEM768", id: HelloIOS_Auto, want: true},
		{name: "edge without X25519MLKEM768", id: HelloEdge_Auto, want: true},
		{name: "chrome RequireMLKEM", id: HelloChrome_Auto, requireMLKEM: true, want: true},
		{name: "firefox RequireMLKEM", id: HelloFirefox_Auto, requireMLKEM: true, want: true},
		{name: "ios RequireMLKEM", id: HelloIOS_Auto, requireMLKEM: true},
		{name: "edge RequireMLKEM", id: HelloEdge_Auto, requireMLKEM: true},
		{name: "chrome without hybrid key share", id: HelloChrome_Auto, shape: realityTestDropHybridKeyShare},
		{name: "chrome with X25519 before hybrid key share", id: HelloChrome_Auto, shape: realityTestX25519First},
		{name: "chrome without hybrid group", id: HelloChrome_Auto, shape: realityTestDropHybridGroup, want: true},
		{name: "chrome without hybrid group RequireMLKEM", id: HelloChrome_Auto, shape: realityTestDropHybridGroup, requireMLKEM: true},
		{name: "ios below MinClientVer", id: HelloIOS_Auto, minVer: []byte{26, 11, 11}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := &RealityConfig{
				DialContext:  (&net.Dialer{}).DialContext,
				Type:         "tcp",
				Dest:         target,
				ServerNames:  map[string]bool{"localhost": true},
				PrivateKey:   serverKey.Bytes(),
				MinClientVer: test.minVer,
				ShortIds:     map[[8]byte]bool{{1, 2, 3, 4, 5, 6, 7, 8}: true},
				RequireMLKEM: test.requireMLKEM,
			}
			config.SessionTicketsDisabled = true
			authenticated, leaf := runRealityTestHandshake(t, config, serverKey.PublicKey(), test.id, test.shape, version, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
			if authenticated != test.want {
				t.Fatalf("RealityServer authenticated = %v, want %v", authenticated, test.want)
			}
			if shownTarget := bytes.Equal(leaf, targetLeaf); shownTarget == test.want {
				t.Fatalf("client was shown the target certificate: %v, want %v", shownTarget, !test.want)
			}
		})
	}
}

func runRealityTestHandshake(t *testing.T, config *RealityConfig, serverPub *ecdh.PublicKey, id ClientHelloID, shape func(*testing.T, *ClientHelloSpec), version [3]byte, shortID [8]byte) (authenticated bool, leaf []byte) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		tlsConn, err := RealityServer(context.Background(), conn, config)
		if err == nil {
			tlsConn.Close()
		}
		serverResult <- err
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	uConfig := &Config{ServerName: "localhost", InsecureSkipVerify: true, SessionTicketsDisabled: true}
	var uConn *UConn
	if shape == nil {
		uConn = UClient(conn, uConfig, id)
	} else {
		spec, err := UTLSIdToSpec(id)
		if err != nil {
			t.Fatal(err)
		}
		shape(t, &spec)
		uConn = UClient(conn, uConfig, HelloCustom)
		if err := uConn.ApplyPreset(&spec); err != nil {
			t.Fatal(err)
		}
	}
	if err := uConn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}
	sealRealityTestSessionID(t, uConn, serverPub, version, shortID)
	if err := uConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if certificates := uConn.ConnectionState().PeerCertificates; len(certificates) > 0 {
		leaf = certificates[0].Raw
	}
	conn.Close()

	select {
	case err := <-serverResult:
		return err == nil, leaf
	case <-time.After(10 * time.Second):
		t.Fatal("RealityServer did not return")
	}
	return false, nil
}

// sealRealityTestSessionID writes the REALITY session ID the way REALITY
// clients do: version, reserved byte, Unix time and short ID, sealed with a
// key derived from the hello's X25519 key and the server's public key.
func sealRealityTestSessionID(t *testing.T, uConn *UConn, serverPub *ecdh.PublicKey, version [3]byte, shortID [8]byte) {
	t.Helper()
	hello := uConn.HandshakeState.Hello
	for i := range hello.Raw[39 : 39+32] {
		hello.Raw[39+i] = 0
	}
	binary.BigEndian.PutUint64(hello.SessionId, uint64(time.Now().Unix()))
	copy(hello.SessionId[:3], version[:])
	copy(hello.SessionId[8:], shortID[:])

	keys := uConn.HandshakeState.State13.KeyShareKeys
	if keys == nil {
		t.Fatal("no key share keys")
	}
	key := keys.Ecdhe
	if key == nil || key.Curve() != ecdh.X25519() {
		key = keys.MlkemEcdhe
	}
	if key == nil {
		t.Fatal("no X25519 key share key")
	}
	authKey, err := key.ECDH(serverPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(authKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)
}

func realityTestKeyShares(t *testing.T, spec *ClientHelloSpec) *KeyShareExtension {
	t.Helper()
	for _, extension := range spec.Extensions {
		if shares, ok := extension.(*KeyShareExtension); ok {
			return shares
		}
	}
	t.Fatal("hello has no key_share extension")
	return nil
}

func realityTestDropHybridKeyShare(t *testing.T, spec *ClientHelloSpec) {
	shares := realityTestKeyShares(t, spec)
	kept := shares.KeyShares[:0]
	for _, share := range shares.KeyShares {
		if share.Group != X25519MLKEM768 {
			kept = append(kept, share)
		}
	}
	if len(kept) == len(shares.KeyShares) {
		t.Fatal("hello has no X25519MLKEM768 key share")
	}
	shares.KeyShares = kept
}

func realityTestDropHybridGroup(t *testing.T, spec *ClientHelloSpec) {
	realityTestDropHybridKeyShare(t, spec)
	for _, extension := range spec.Extensions {
		if curves, ok := extension.(*SupportedCurvesExtension); ok {
			kept := curves.Curves[:0]
			for _, curve := range curves.Curves {
				if curve != X25519MLKEM768 {
					kept = append(kept, curve)
				}
			}
			curves.Curves = kept
		}
	}
}

func realityTestX25519First(t *testing.T, spec *ClientHelloSpec) {
	shares := realityTestKeyShares(t, spec)
	reordered := make([]KeyShare, 0, len(shares.KeyShares))
	for _, share := range shares.KeyShares {
		if share.Group == X25519 {
			reordered = append(reordered, share)
		}
	}
	if len(reordered) == 0 {
		t.Fatal("hello has no X25519 key share")
	}
	for _, share := range shares.KeyShares {
		if share.Group != X25519 {
			reordered = append(reordered, share)
		}
	}
	shares.KeyShares = reordered
}

// startRealityTestTarget runs the TLS 1.3 site REALITY forwards to. It
// selects X25519 so that it never sends a HelloRetryRequest, which REALITY
// cannot mirror, and it closes each connection after its handshake. It
// returns its address and its leaf certificate.
func startRealityTestTarget(t *testing.T) (string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leaf, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{
		Certificates:     []stdtls.Certificate{{Certificate: [][]byte{leaf}, PrivateKey: key}},
		MinVersion:       stdtls.VersionTLS13,
		CurvePreferences: []stdtls.CurveID{stdtls.X25519},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				// Hang up once a client that REALITY turned away completed
				// its handshake, so that RealityServer returns.
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(10 * time.Second))
				conn.(*stdtls.Conn).Handshake()
			}()
		}
	}()
	return listener.Addr().String(), leaf
}
