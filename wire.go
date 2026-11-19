package mailbox

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

const (
	maxBlob  = 64 * 1024
	maxFrame = maxBlob + 4096
	protoV   = 2
	maxConns = 32
)

var (
	// ErrUnauthorized means the caller did not prove a glyph ID, or that ID
	// is not the owner or an introduced friend.
	ErrUnauthorized = errors.New("mailbox: unauthorized")
	// ErrForbidden means an allowlisted caller asked for something that is
	// not theirs: another box, or an introduction by someone who is not the owner.
	ErrForbidden = errors.New("mailbox: forbidden")
	// ErrInvalid means the request was rejected before any change.
	ErrInvalid = errors.New("mailbox: invalid")
	// ErrProtocol means the mailbox spoke a protocol this program does not use.
	ErrProtocol = errors.New("mailbox: protocol")
)

// Protocol is the mailbox protocol this program speaks.
func Protocol() uint { return protoV }

type helloMsg struct {
	V     uint   `json:"v"`
	Type  string `json:"type"`
	Nonce []byte `json:"nonce"`
}

type authMsg struct {
	V    uint   `json:"v"`
	Type string `json:"type"`
	ID   string `json:"id"`
	Sig  []byte `json:"sig"`
}

type request struct {
	V         uint     `json:"v"`
	N         uint64   `json:"n"`
	Op        string   `json:"op"`
	Friend    string   `json:"friend,omitempty"`
	Recipient string   `json:"recipient,omitempty"`
	Blob      []byte   `json:"blob,omitempty"`
	IDs       []string `json:"ids,omitempty"`
	After     string   `json:"after,omitempty"`
}

type wireLetter struct {
	ID   string `json:"id"`
	Blob []byte `json:"blob"`
}

type response struct {
	V       uint         `json:"v"`
	OK      bool         `json:"ok"`
	Error   string       `json:"error,omitempty"`
	Letters []wireLetter `json:"letters,omitempty"`
	More    bool         `json:"more,omitempty"`
}

func authSignBytes(nonce, pub []byte) []byte {
	m := make([]byte, 0, len("glyph-mailbox-auth-v1\n")+len(nonce)+len(pub))
	m = append(m, "glyph-mailbox-auth-v1\n"...)
	m = append(m, nonce...)
	m = append(m, pub...)
	return m
}

func reqSignBytes(nonce, raw []byte) []byte {
	m := make([]byte, 0, len("glyph-mailbox-req-v1\n")+len(nonce)+len(raw))
	m = append(m, "glyph-mailbox-req-v1\n"...)
	m = append(m, nonce...)
	m = append(m, raw...)
	return m
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > maxFrame {
		return ErrInvalid
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxFrame {
		return nil, ErrInvalid
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func decodeStrict(raw []byte, dest any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dest); err != nil {
		return err
	}
	if dec.InputOffset() != int64(len(raw)) {
		return ErrInvalid
	}
	return nil
}

func writeJSON(w io.Writer, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFrame(w, raw)
}

func writeOK(w io.Writer) error {
	return writeJSON(w, response{V: protoV, OK: true})
}

func writeWireErr(w io.Writer, msg string) error {
	return writeJSON(w, response{V: protoV, OK: false, Error: msg})
}
