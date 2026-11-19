package mailbox

import (
	"bufio"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"net"
	"time"
)

// Client is an authenticated connection to a mailbox. The glyph ID is the
// public half of priv. The caller cannot choose a different sender.
type Client struct {
	conn  net.Conn
	br    *bufio.Reader
	priv  ed25519.PrivateKey
	id    string
	nonce []byte
	n     uint64
}

// Dial connects to a mailbox on a private LAN address or loopback, checks the
// TLS certificate against pin, and proves possession of priv. A public address
// is refused before any dial. A certificate that is not pin is a protocol failure.
func Dial(addr string, priv ed25519.PrivateKey, pin ed25519.PublicKey) (*Client, error) {
	if err := ValidateAddr(addr); err != nil {
		return nil, err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, ErrUnauthorized
	}
	if _, err := ParsePin(pin); err != nil {
		return nil, ErrProtocol
	}
	pub := priv.Public().(ed25519.PublicKey)
	id, err := FormatID(pub)
	if err != nil {
		return nil, ErrUnauthorized
	}
	raw, err := (&net.Dialer{Timeout: 5 * time.Second}).Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, clientTLS(pin))
	_ = conn.SetDeadline(time.Now().Add(preAuth))
	if err := conn.Handshake(); err != nil {
		raw.Close()
		return nil, ErrProtocol
	}
	c := &Client{
		conn: conn,
		br:   bufio.NewReader(conn),
		priv: append(ed25519.PrivateKey(nil), priv...),
		id:   id,
	}
	if err := c.handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

func (c *Client) handshake() error {
	_ = c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	body, err := readFrame(c.br)
	if err != nil {
		return err
	}
	var hello helloMsg
	if err := decodeStrict(body, &hello); err != nil {
		return ErrUnauthorized
	}
	if hello.Type != "hello" || len(hello.Nonce) != 32 {
		return ErrUnauthorized
	}
	if hello.V != protoV {
		return ErrProtocol
	}
	pub := c.priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(c.priv, authSignBytes(hello.Nonce, pub))
	if err := writeJSON(c.conn, authMsg{V: protoV, Type: "auth", ID: c.id, Sig: sig}); err != nil {
		return err
	}
	raw, err := readFrame(c.br)
	if err != nil {
		return err
	}
	var resp response
	if err := decodeStrict(raw, &resp); err != nil || !resp.OK || resp.Error != "" {
		return ErrUnauthorized
	}
	c.nonce = append([]byte(nil), hello.Nonce...)
	return nil
}

// Close closes the connection.
func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

// ID is the authenticated glyph ID.
func (c *Client) ID() string { return c.id }

// Introduce adds a friend. Only the owner's connection succeeds.
func (c *Client) Introduce(friend string) error {
	_, err := c.roundTrip(request{Op: "introduce", Friend: friend})
	return err
}

// Put deposits an opaque blob for recipient. The sender is this connection.
func (c *Client) Put(recipient string, blob []byte) error {
	_, err := c.roundTrip(request{Op: "put", Recipient: recipient, Blob: blob})
	return err
}

// List walks every page and returns this caller's waiting blobs. It does not
// delete them and it does not return anyone else's box.
func (c *Client) List() ([]Letter, error) {
	var all []Letter
	after := ""
	for {
		page, more, err := c.ListAfter(after)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		if !more || len(page) == 0 {
			return all, nil
		}
		after = page[len(page)-1].ID
	}
}

// ListAfter returns the next page of this caller's blobs after the given id.
// after is empty for the first page. more is set when another page remains.
func (c *Client) ListAfter(after string) ([]Letter, bool, error) {
	resp, err := c.roundTrip(request{Op: "list", After: after})
	if err != nil {
		return nil, false, err
	}
	out := make([]Letter, len(resp.Letters))
	for i, lt := range resp.Letters {
		b := make([]byte, len(lt.Blob))
		copy(b, lt.Blob)
		out[i] = Letter{ID: lt.ID, Blob: b}
	}
	return out, resp.More, nil
}

// Ack deletes letters from this caller's box only, and only after the caller
// asks. A failed open is not an ack.
func (c *Client) Ack(ids []string) error {
	return c.delete("ack", ids)
}

// Drop deletes letters from this caller's box. The caller uses it for a blob
// that will never open or that the transcript has permanently rejected.
func (c *Client) Drop(ids []string) error {
	return c.delete("drop", ids)
}

func (c *Client) delete(op string, ids []string) error {
	if len(ids) == 0 {
		return ErrInvalid
	}
	cp := append([]string(nil), ids...)
	_, err := c.roundTrip(request{Op: op, IDs: cp})
	return err
}

// Remove drops a friend from the allowlist. Only the owner's connection succeeds.
// The owner's own id cannot be removed.
func (c *Client) Remove(friend string) error {
	_, err := c.roundTrip(request{Op: "remove", Friend: friend})
	return err
}

func (c *Client) roundTrip(req request) (response, error) {
	raw, err := c.roundTripRaw(req)
	if err != nil {
		return response{}, err
	}
	var resp response
	if err := decodeStrict(raw, &resp); err != nil {
		return response{}, ErrInvalid
	}
	if !resp.OK {
		return resp, mapWireErr(resp.Error)
	}
	return resp, nil
}

func (c *Client) roundTripRaw(req request) ([]byte, error) {
	c.n++
	req.V = protoV
	req.N = c.n
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(c.priv, reqSignBytes(c.nonce, body))
	frame := make([]byte, ed25519.SignatureSize+len(body))
	copy(frame, sig)
	copy(frame[ed25519.SignatureSize:], body)
	_ = c.conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := writeFrame(c.conn, frame); err != nil {
		return nil, err
	}
	raw, err := readFrame(c.br)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func mapWireErr(msg string) error {
	switch msg {
	case "unauthorized":
		return ErrUnauthorized
	case "forbidden":
		return ErrForbidden
	default:
		return ErrInvalid
	}
}
