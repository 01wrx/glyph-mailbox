// Package mailbox is a LAN mailbox for one owner. It stores sealed glyph
// letters and never opens them.
package mailbox

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"

	"filippo.io/edwards25519"
)

const idPrefix = "glyph:"

// ErrInvalidID means the value is not a full canonical glyph ID.
var ErrInvalidID = errors.New("mailbox: invalid glyph id")

// ParseID accepts only a full canonical glyph ID: the prefix "glyph:" plus
// the 64-character lowercase hex of one canonical Ed25519 public key.
// A short prefix is not an address.
func ParseID(s string) (ed25519.PublicKey, error) {
	if len(s) != len(idPrefix)+hex.EncodedLen(ed25519.PublicKeySize) {
		return nil, ErrInvalidID
	}
	if s[:len(idPrefix)] != idPrefix {
		return nil, ErrInvalidID
	}
	h := s[len(idPrefix):]
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return nil, ErrInvalidID
		}
	}
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrInvalidID
	}
	if err := validatePoint(raw); err != nil {
		return nil, ErrInvalidID
	}
	out := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(out, raw)
	return out, nil
}

// FormatID returns the canonical glyph ID of a public key.
func FormatID(pub ed25519.PublicKey) (string, error) {
	if err := validatePoint(pub); err != nil {
		return "", ErrInvalidID
	}
	return idPrefix + hex.EncodeToString(pub), nil
}

func validatePoint(raw []byte) error {
	if len(raw) != ed25519.PublicKeySize {
		return ErrInvalidID
	}
	p, err := new(edwards25519.Point).SetBytes(raw)
	if err != nil {
		return ErrInvalidID
	}
	if !bytes.Equal(p.Bytes(), raw) {
		return ErrInvalidID
	}
	// Reject the identity and every other small-order point. Those keys are
	// not usable glyph IDs, and a torsion point must not be a second spelling
	// of someone.
	if new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return ErrInvalidID
	}
	return nil
}
