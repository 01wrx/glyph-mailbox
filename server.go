package mailbox

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	maxBox   = 1024
	preAuth  = 5 * time.Second
	reqLimit = 30 * time.Second
)

// Server is the mailbox daemon for one owner. It keeps the owner's public
// glyph ID and the friends that owner has introduced. It has no private key
// and cannot open a letter.
type Server struct {
	mu     sync.Mutex
	dir    string
	owner  string
	allow  map[string]struct{}
	ln     net.Listener
	conns  map[net.Conn]struct{}
	closed bool
	pin    ed25519.PublicKey
	tls    *tls.Config
}

// New loads or creates a mailbox for ownerID. ownerID is a public glyph ID.
// The server is not given a private key.
func New(dir, ownerID string) (*Server, error) {
	pub, err := ParseID(ownerID)
	if err != nil {
		return nil, err
	}
	owner, err := FormatID(pub)
	if err != nil || owner != ownerID {
		return nil, ErrInvalidID
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	priv, err := loadOrCreateBoxKey(dir)
	if err != nil {
		return nil, err
	}
	cert, err := certificate(priv)
	if err != nil {
		return nil, err
	}
	s := &Server{
		dir:   dir,
		owner: owner,
		allow: map[string]struct{}{},
		conns: map[net.Conn]struct{}{},
		pin:   append(ed25519.PublicKey(nil), priv.Public().(ed25519.PublicKey)...),
		tls:   serverTLS(cert),
	}
	if err := s.loadAllow(owner); err != nil {
		return nil, err
	}
	return s, nil
}

// Pin is the public key clients must see on the TLS certificate.
func (s *Server) Pin() ed25519.PublicKey {
	if s == nil {
		return nil
	}
	out := make(ed25519.PublicKey, len(s.pin))
	copy(out, s.pin)
	return out
}

// Start listens on addr. The address must be a private LAN address or
// loopback. A public or unspecified address is refused and nothing is bound.
func (s *Server) Start(addr string) (string, error) {
	if err := ValidateAddr(addr); err != nil {
		return "", err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	if s.closed || s.ln != nil {
		s.mu.Unlock()
		ln.Close()
		return "", errors.New("mailbox: not started")
	}
	s.ln = ln
	s.mu.Unlock()
	go s.accept()
	return ln.Addr().String(), nil
}

// Close stops the listener and open connections. Stored letters stay on disk.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	var err error
	if ln != nil {
		err = ln.Close()
	}
	for _, c := range conns {
		c.Close()
	}
	return err
}

func (s *Server) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		if !sourceAllowed(c.RemoteAddr()) {
			c.Close()
			continue
		}
		s.mu.Lock()
		if s.closed || len(s.conns) >= maxConns {
			s.mu.Unlock()
			c.Close()
			if s.closed {
				return
			}
			continue
		}
		s.conns[c] = struct{}{}
		s.mu.Unlock()
		go s.handshake(c)
	}
}

func (s *Server) handshake(raw net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, raw)
		s.mu.Unlock()
		raw.Close()
	}()
	tc := tls.Server(raw, s.tls)
	_ = tc.SetDeadline(time.Now().Add(preAuth))
	if err := tc.Handshake(); err != nil {
		return
	}
	s.serveConn(tc)
}

func (s *Server) serveConn(conn net.Conn) {
	br := bufio.NewReader(conn)
	_ = conn.SetDeadline(time.Now().Add(preAuth))
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return
	}
	if err := writeJSON(conn, helloMsg{V: protoV, Type: "hello", Nonce: nonce}); err != nil {
		return
	}
	body, err := readFrame(br)
	if err != nil {
		return
	}
	var auth authMsg
	if err := decodeStrict(body, &auth); err != nil || auth.V != protoV || auth.Type != "auth" {
		_ = writeWireErr(conn, "unauthorized")
		return
	}
	pub, err := ParseID(auth.ID)
	canon, ferr := FormatID(pub)
	if err != nil || ferr != nil || canon != auth.ID || len(auth.Sig) != ed25519.SignatureSize ||
		!ed25519.Verify(pub, authSignBytes(nonce, pub), auth.Sig) || !s.isAllowed(canon) {
		_ = writeWireErr(conn, "unauthorized")
		return
	}
	if err := writeOK(conn); err != nil {
		return
	}
	expect := uint64(1)
	for {
		_ = conn.SetDeadline(time.Now().Add(reqLimit))
		body, err := readFrame(br)
		if err != nil {
			return
		}
		if len(body) < ed25519.SignatureSize {
			_ = writeWireErr(conn, "unauthorized")
			return
		}
		sig, raw := body[:ed25519.SignatureSize], body[ed25519.SignatureSize:]
		if !ed25519.Verify(pub, reqSignBytes(nonce, raw), sig) {
			_ = writeWireErr(conn, "unauthorized")
			return
		}
		var req request
		if err := decodeStrict(raw, &req); err != nil {
			_ = writeWireErr(conn, "invalid")
			return
		}
		if req.V != protoV || req.N != expect {
			_ = writeWireErr(conn, "unauthorized")
			return
		}
		expect++
		resp := s.dispatch(canon, req)
		out, err := json.Marshal(resp)
		if err != nil {
			return
		}
		if err := writeFrame(conn, out); err != nil {
			return
		}
	}
}

func (s *Server) dispatch(caller string, req request) response {
	switch req.Op {
	case "introduce":
		if req.Friend == "" || req.Recipient != "" || len(req.Blob) != 0 || len(req.IDs) != 0 || req.After != "" {
			return response{V: protoV, OK: false, Error: "invalid"}
		}
		if err := s.introduce(caller, req.Friend); err != nil {
			return fail(err)
		}
		return response{V: protoV, OK: true}
	case "remove":
		if req.Friend == "" || req.Recipient != "" || len(req.Blob) != 0 || len(req.IDs) != 0 || req.After != "" {
			return response{V: protoV, OK: false, Error: "invalid"}
		}
		if err := s.remove(caller, req.Friend); err != nil {
			return fail(err)
		}
		return response{V: protoV, OK: true}
	case "put":
		if req.Friend != "" || req.Recipient == "" || len(req.Blob) == 0 || len(req.IDs) != 0 || req.After != "" {
			return response{V: protoV, OK: false, Error: "invalid"}
		}
		if err := s.put(caller, req.Recipient, req.Blob); err != nil {
			return fail(err)
		}
		return response{V: protoV, OK: true}
	case "list":
		if req.Friend != "" || len(req.Blob) != 0 || len(req.IDs) != 0 {
			return response{V: protoV, OK: false, Error: "invalid"}
		}
		if req.After != "" && !validBlobID(req.After) {
			return response{V: protoV, OK: false, Error: "invalid"}
		}
		if req.Recipient != "" && req.Recipient != caller {
			return response{V: protoV, OK: false, Error: "forbidden"}
		}
		letters, more, err := s.list(caller, req.After)
		if err != nil {
			return fail(err)
		}
		var wire []wireLetter
		if len(letters) > 0 {
			wire = make([]wireLetter, len(letters))
			for i, lt := range letters {
				wire[i] = wireLetter{ID: lt.ID, Blob: lt.Blob}
			}
		}
		return response{V: protoV, OK: true, Letters: wire, More: more}
	case "ack", "drop":
		if req.Friend != "" || len(req.Blob) != 0 || len(req.IDs) == 0 || req.After != "" {
			return response{V: protoV, OK: false, Error: "invalid"}
		}
		if req.Recipient != "" && req.Recipient != caller {
			return response{V: protoV, OK: false, Error: "forbidden"}
		}
		if err := s.ack(caller, req.IDs); err != nil {
			return fail(err)
		}
		return response{V: protoV, OK: true}
	default:
		return response{V: protoV, OK: false, Error: "invalid"}
	}
}

func fail(err error) response {
	switch {
	case errors.Is(err, ErrForbidden):
		return response{V: protoV, OK: false, Error: "forbidden"}
	case errors.Is(err, ErrUnauthorized):
		return response{V: protoV, OK: false, Error: "unauthorized"}
	default:
		return response{V: protoV, OK: false, Error: "invalid"}
	}
}

func (s *Server) introduce(caller, friend string) error {
	if caller != s.owner {
		return ErrForbidden
	}
	pub, err := ParseID(friend)
	if err != nil {
		return ErrInvalid
	}
	canon, err := FormatID(pub)
	if err != nil || canon != friend {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.allow[canon]; ok {
		return nil
	}
	s.allow[canon] = struct{}{}
	if err := s.writeAllow(); err != nil {
		delete(s.allow, canon)
		return err
	}
	return nil
}

func (s *Server) remove(caller, friend string) error {
	if caller != s.owner {
		return ErrForbidden
	}
	pub, err := ParseID(friend)
	if err != nil {
		return ErrInvalid
	}
	canon, err := FormatID(pub)
	if err != nil || canon != friend {
		return ErrInvalid
	}
	if canon == s.owner {
		return ErrForbidden
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.allow[canon]; !ok {
		return nil
	}
	delete(s.allow, canon)
	if err := s.writeAllow(); err != nil {
		s.allow[canon] = struct{}{}
		return err
	}
	dir, err := laneDir(s.dir, wayIn, canon)
	if err != nil {
		return ErrInvalid
	}
	if err := os.RemoveAll(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Server) put(caller, recipient string, blob []byte) error {
	if len(blob) == 0 || len(blob) > maxBlob {
		return ErrInvalid
	}
	if _, err := ParseID(caller); err != nil {
		return ErrUnauthorized
	}
	pub, err := ParseID(recipient)
	if err != nil {
		return ErrInvalid
	}
	canon, err := FormatID(pub)
	if err != nil || canon != recipient {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.allow[caller]; !ok {
		return ErrForbidden
	}
	if _, ok := s.allow[canon]; !ok {
		return ErrForbidden
	}
	dir, err := laneDir(s.dir, wayIn, canon)
	if err != nil {
		return ErrInvalid
	}
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	n := 0
	for _, e := range entries {
		if validBlobID(e.Name()) {
			n++
		}
	}
	if n >= maxBox {
		return ErrInvalid
	}
	cp := make([]byte, len(blob))
	copy(cp, blob)
	return s.saveWait(caller, canon, cp)
}

func (s *Server) list(caller, after string) ([]Letter, bool, error) {
	if _, err := ParseID(caller); err != nil {
		return nil, false, ErrUnauthorized
	}
	if after != "" && !validBlobID(after) {
		return nil, false, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.allow[caller]; !ok {
		return nil, false, ErrForbidden
	}
	all, err := s.readBox(caller)
	if err != nil {
		return nil, false, err
	}
	if after != "" {
		i := 0
		for i < len(all) && all[i].ID <= after {
			i++
		}
		all = all[i:]
	}
	return packPage(all)
}

func packPage(letters []Letter) ([]Letter, bool, error) {
	var chosen []Letter
	for _, lt := range letters {
		next := append(append([]Letter{}, chosen...), lt)
		wire := make([]wireLetter, len(next))
		for i, item := range next {
			wire[i] = wireLetter{ID: item.ID, Blob: item.Blob}
		}
		raw, err := json.Marshal(response{V: protoV, OK: true, Letters: wire, More: true})
		if err != nil {
			return nil, false, err
		}
		if len(raw) > maxFrame {
			if len(chosen) == 0 {
				return nil, false, ErrInvalid
			}
			return chosen, true, nil
		}
		chosen = next
	}
	return chosen, false, nil
}

func (s *Server) ack(caller string, ids []string) error {
	if _, err := ParseID(caller); err != nil {
		return ErrUnauthorized
	}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if !validBlobID(id) {
			return ErrForbidden
		}
		if _, ok := seen[id]; ok {
			return ErrInvalid
		}
		seen[id] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.allow[caller]; !ok {
		return ErrForbidden
	}
	inDir, err := laneDir(s.dir, wayIn, caller)
	if err != nil {
		return ErrInvalid
	}
	type pair struct {
		inPath  string
		outPath string
		dropOut bool
	}
	pairs := make([]pair, len(ids))
	for i, id := range ids {
		// id is hex, so it cannot escape the caller's inbound directory.
		inPath := filepath.Join(inDir, id)
		way, from, to, _, err := readWait(inPath)
		if err != nil || way != wayIn || to != caller {
			return ErrForbidden
		}
		outDir, err := laneDir(s.dir, wayOut, from)
		if err != nil {
			return ErrInvalid
		}
		outPath := filepath.Join(outDir, id)
		dropOut := false
		if oWay, oFrom, oTo, _, oErr := readWait(outPath); oErr == nil && oWay == wayOut && oFrom == from && oTo == caller {
			dropOut = true
		}
		pairs[i] = pair{inPath: inPath, outPath: outPath, dropOut: dropOut}
	}
	for _, p := range pairs {
		if p.dropOut {
			if err := os.Remove(p.outPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if err := os.Remove(p.inPath); err != nil {
			return err
		}
	}
	return nil
}
