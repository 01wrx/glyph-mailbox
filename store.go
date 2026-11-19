package mailbox

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
)

const allowMagic = "glyph-allow-v1"

func (s *Server) allowPath() string { return filepath.Join(s.dir, "allowlist") }

func (s *Server) loadAllow(owner string) error {
	for _, path := range []string{s.allowPath(), s.allowPath() + ".tmp", s.allowPath() + ".bak"} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if err := s.parseAllow(owner, b); err != nil {
			continue
		}
		if path != s.allowPath() {
			if err := writeAtomic(s.allowPath(), b); err != nil {
				return err
			}
		}
		return nil
	}
	if mailboxHasLanes(s.dir) {
		return ErrInvalid
	}
	s.allow = map[string]struct{}{owner: {}}
	return s.writeAllow()
}

func mailboxHasLanes(dir string) bool {
	for _, way := range []string{wayIn, wayOut} {
		entries, err := os.ReadDir(filepath.Join(dir, way))
		if err == nil && len(entries) > 0 {
			return true
		}
	}
	return false
}

func (s *Server) parseAllow(owner string, b []byte) error {
	lines := bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n"))
	if len(lines) < 2 || string(lines[0]) != allowMagic {
		return ErrInvalid
	}
	s.allow = map[string]struct{}{}
	for i, line := range lines[1:] {
		if len(line) == 0 || bytes.Contains(line, []byte("\r")) {
			return ErrInvalid
		}
		id := string(line)
		pub, err := ParseID(id)
		if err != nil {
			return ErrInvalid
		}
		canon, err := FormatID(pub)
		if err != nil || canon != id {
			return ErrInvalid
		}
		if i == 0 && canon != owner {
			return ErrInvalid
		}
		s.allow[canon] = struct{}{}
	}
	if _, ok := s.allow[owner]; !ok {
		return ErrInvalid
	}
	return nil
}

func (s *Server) writeAllow() error {
	ids := make([]string, 0, len(s.allow))
	for id := range s.allow {
		if id != s.owner {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	var buf bytes.Buffer
	buf.WriteString(allowMagic)
	buf.WriteByte('\n')
	buf.WriteString(s.owner)
	buf.WriteByte('\n')
	for _, id := range ids {
		buf.WriteString(id)
		buf.WriteByte('\n')
	}
	return writeAtomic(s.allowPath(), buf.Bytes())
}

func (s *Server) isAllowed(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.allow[id]
	return ok
}

const (
	waitMagic = "glyph-wait-v1\n"
	wayIn     = "in"
	wayOut    = "out"
)

func laneDir(root, way, id string) (string, error) {
	if way != wayIn && way != wayOut {
		return "", ErrInvalid
	}
	pub, err := ParseID(id)
	if err != nil {
		return "", err
	}
	canon, err := FormatID(pub)
	if err != nil || canon != id {
		return "", ErrInvalid
	}
	return filepath.Join(root, way, hex.EncodeToString(pub)), nil
}

func validBlobID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func (s *Server) saveWait(from, to string, blob []byte) error {
	if len(blob) == 0 || len(blob) > maxBlob {
		return ErrInvalid
	}
	inDir, err := laneDir(s.dir, wayIn, to)
	if err != nil {
		return ErrInvalid
	}
	outDir, err := laneDir(s.dir, wayOut, from)
	if err != nil {
		return ErrInvalid
	}
	if err := os.MkdirAll(inDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0o700); err != nil {
		return err
	}
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	name := hex.EncodeToString(rnd[:])
	inFile := filepath.Join(inDir, name)
	outFile := filepath.Join(outDir, name)
	inBody, err := encodeWait(wayIn, from, to, blob)
	if err != nil {
		return err
	}
	outBody, err := encodeWait(wayOut, from, to, blob)
	if err != nil {
		return err
	}
	if err := writeNew(inFile, inBody); err != nil {
		return err
	}
	if err := writeNew(outFile, outBody); err != nil {
		_ = os.Remove(inFile)
		return err
	}
	return nil
}

func (s *Server) readBox(id string) ([]Letter, error) {
	dir, err := laneDir(s.dir, wayIn, id)
	if err != nil {
		return nil, ErrInvalid
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !validBlobID(e.Name()) {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	out := make([]Letter, 0, len(names))
	for _, name := range names {
		way, from, to, blob, err := readWait(filepath.Join(dir, name))
		if err != nil || way != wayIn || to != id {
			return nil, ErrInvalid
		}
		if _, err := ParseID(from); err != nil {
			return nil, ErrInvalid
		}
		out = append(out, Letter{ID: name, Blob: blob})
	}
	return out, nil
}

func encodeWait(way, from, to string, blob []byte) ([]byte, error) {
	if way != wayIn && way != wayOut {
		return nil, ErrInvalid
	}
	idLen := len(idPrefix) + hex.EncodedLen(ed25519.PublicKeySize)
	if stringsContainNL(from) || stringsContainNL(to) || len(from) != idLen || len(to) != idLen {
		return nil, ErrInvalid
	}
	if _, err := ParseID(from); err != nil {
		return nil, ErrInvalid
	}
	if _, err := ParseID(to); err != nil {
		return nil, ErrInvalid
	}
	if len(blob) == 0 || len(blob) > maxBlob {
		return nil, ErrInvalid
	}
	var buf bytes.Buffer
	buf.WriteString(waitMagic)
	buf.WriteString(way)
	buf.WriteByte('\n')
	buf.WriteString(from)
	buf.WriteByte('\n')
	buf.WriteString(to)
	buf.WriteByte('\n')
	buf.Write(blob)
	return buf.Bytes(), nil
}

func readWait(path string) (way, from, to string, blob []byte, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", nil, err
	}
	return decodeWait(b)
}

func decodeWait(b []byte) (way, from, to string, blob []byte, err error) {
	magic := []byte(waitMagic)
	if !bytes.HasPrefix(b, magic) {
		return "", "", "", nil, ErrInvalid
	}
	rest := b[len(magic):]
	var ok bool
	way, rest, ok = cutLineMax(rest, 3)
	if !ok || (way != wayIn && way != wayOut) {
		return "", "", "", nil, ErrInvalid
	}
	idLen := len(idPrefix) + hex.EncodedLen(ed25519.PublicKeySize)
	from, rest, ok = cutLine(rest, idLen)
	if !ok {
		return "", "", "", nil, ErrInvalid
	}
	to, rest, ok = cutLine(rest, idLen)
	if !ok {
		return "", "", "", nil, ErrInvalid
	}
	fromPub, err := ParseID(from)
	if err != nil {
		return "", "", "", nil, ErrInvalid
	}
	canonFrom, err := FormatID(fromPub)
	if err != nil || canonFrom != from {
		return "", "", "", nil, ErrInvalid
	}
	toPub, err := ParseID(to)
	if err != nil {
		return "", "", "", nil, ErrInvalid
	}
	canonTo, err := FormatID(toPub)
	if err != nil || canonTo != to {
		return "", "", "", nil, ErrInvalid
	}
	if len(rest) == 0 || len(rest) > maxBlob {
		return "", "", "", nil, ErrInvalid
	}
	blob = make([]byte, len(rest))
	copy(blob, rest)
	return way, from, to, blob, nil
}

func cutLineMax(b []byte, max int) (string, []byte, bool) {
	i := bytes.IndexByte(b, '\n')
	if i <= 0 || i > max {
		return "", nil, false
	}
	return string(b[:i]), b[i+1:], true
}

func cutLine(b []byte, n int) (string, []byte, bool) {
	if len(b) < n+1 || b[n] != '\n' {
		return "", nil, false
	}
	return string(b[:n]), b[n+1:], true
}

func stringsContainNL(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			return true
		}
	}
	return false
}

func writeNew(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	bak := path + ".bak"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(bak)
		if err := os.Rename(path, bak); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		if _, statErr := os.Stat(bak); statErr == nil {
			_ = os.Rename(bak, path)
		}
		return err
	}
	_ = os.Remove(bak)
	return nil
}

// Letter is one opaque blob waiting in a caller's box.
type Letter struct {
	ID   string
	Blob []byte
}
