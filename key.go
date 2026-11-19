package mailbox

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	boxKeyMagic = "glyph-box-key-v1\n"
	boxPubMagic = "glyph-box-pub-v1\n"
)

func loadOrCreateBoxKey(dir string) (ed25519.PrivateKey, error) {
	path := filepath.Join(dir, "box-key")
	priv, err := readBoxKey(path)
	if errors.Is(err, os.ErrNotExist) {
		_, priv, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		seed := priv.Seed()
		encoded := append([]byte(boxKeyMagic), []byte(hex.EncodeToString(seed)+"\n")...)
		clear(seed)
		if err := writeNew(path, encoded); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	if err := writeBoxPub(dir, pub); err != nil {
		return nil, err
	}
	return priv, nil
}

func readBoxKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < len(boxKeyMagic) || string(b[:len(boxKeyMagic)]) != boxKeyMagic {
		return nil, ErrInvalid
	}
	rest := b[len(boxKeyMagic):]
	if len(rest) > 0 && rest[len(rest)-1] == '\n' {
		rest = rest[:len(rest)-1]
	}
	if len(rest) != hex.EncodedLen(ed25519.SeedSize) {
		return nil, ErrInvalid
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return nil, ErrInvalid
		}
	}
	seed, err := hex.DecodeString(string(rest))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, ErrInvalid
	}
	priv := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	if _, err := ParsePin(priv.Public().(ed25519.PublicKey)); err != nil {
		return nil, err
	}
	return priv, nil
}

func writeBoxPub(dir string, pub ed25519.PublicKey) error {
	if _, err := ParsePin(pub); err != nil {
		return err
	}
	body := append([]byte(boxPubMagic), []byte(hex.EncodeToString(pub)+"\n")...)
	return writeAtomic(filepath.Join(dir, "box-pub"), body)
}

// LoadPub reads the mailbox's public pin. The private key stays in the mailbox directory.
func LoadPub(dir string) (ed25519.PublicKey, error) {
	b, err := os.ReadFile(filepath.Join(dir, "box-pub"))
	if err != nil {
		return nil, err
	}
	if len(b) < len(boxPubMagic) || string(b[:len(boxPubMagic)]) != boxPubMagic {
		return nil, ErrInvalid
	}
	rest := b[len(boxPubMagic):]
	if len(rest) > 0 && rest[len(rest)-1] == '\n' {
		rest = rest[:len(rest)-1]
	}
	raw, err := hex.DecodeString(string(rest))
	if err != nil {
		return nil, ErrInvalid
	}
	return ParsePin(raw)
}

// ParsePin accepts the raw Ed25519 public key of a mailbox.
func ParsePin(raw []byte) (ed25519.PublicKey, error) {
	if err := validatePoint(raw); err != nil {
		return nil, ErrInvalid
	}
	out := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(out, raw)
	return out, nil
}

func certificate(priv ed25519.PrivateKey) (tls.Certificate, error) {
	pub := priv.Public().(ed25519.PublicKey)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	serial.Add(serial, big.NewInt(1))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}, nil
}

func serverTLS(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}
}

func clientTLS(pin ed25519.PublicKey) *tls.Config {
	expect := append(ed25519.PublicKey(nil), pin...)
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return ErrProtocol
			}
			cert, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return ErrProtocol
			}
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok || subtle.ConstantTimeCompare(pub, expect) != 1 {
				return ErrProtocol
			}
			return nil
		},
	}
}
