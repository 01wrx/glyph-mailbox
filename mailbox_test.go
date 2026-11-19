package mailbox

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseIDRejectsPrefix(t *testing.T) {
	priv := newKey(t)
	id := idOf(t, priv)
	if _, err := ParseID(id); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{id[:len(id)-1], id[:20], strings.ToUpper(id), id + "aa", ""} {
		if _, err := ParseID(bad); !errors.Is(err, ErrInvalidID) {
			t.Fatalf("ParseID(%q) err=%v", bad, err)
		}
	}
}

func TestStrangerRejected(t *testing.T) {
	owner := newKey(t)
	bob := newKey(t)
	eve := newKey(t)
	dir, srv, addr := startBox(t, owner)
	defer srv.Close()
	alice := dial(t, addr, owner, srv.Pin())
	defer alice.Close()
	if _, err := Dial(addr, eve, srv.Pin()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stranger dial err=%v", err)
	}
	if err := alice.Introduce(idOf(t, bob)); err != nil {
		t.Fatal(err)
	}
	friend := dial(t, addr, bob, srv.Pin())
	defer friend.Close()
	if err := friend.Introduce(idOf(t, eve)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("friend introduce err=%v", err)
	}
	if err := alice.Introduce(idOf(t, eve)[:len(idOf(t, eve))-1]); !errors.Is(err, ErrInvalid) {
		t.Fatalf("prefix introduce err=%v", err)
	}
	if _, err := Dial(addr, eve, srv.Pin()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("eve dial after prefix err=%v", err)
	}
	if err := alice.Put(idOf(t, eve), []byte("nope")); !errors.Is(err, ErrForbidden) {
		t.Fatalf("deposit to stranger err=%v", err)
	}
	allow, err := os.ReadFile(filepath.Join(dir, "allowlist"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(allow, []byte(idOf(t, eve))) {
		t.Fatal("rejected introduce was stored")
	}
	if err := alice.Introduce(idOf(t, eve)); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial(addr, eve, srv.Pin()); err != nil {
		t.Fatal(err)
	}
}

func TestDepositSenderIsAuthenticatedCaller(t *testing.T) {
	owner := newKey(t)
	bob := newKey(t)
	_, srv, addr := startBox(t, owner)
	defer srv.Close()
	alice := dial(t, addr, owner, srv.Pin())
	defer alice.Close()
	if err := alice.Introduce(idOf(t, bob)); err != nil {
		t.Fatal(err)
	}
	raw := []byte(fmt.Sprintf(`{"v":%d,"n":1,"op":"put","recipient":"%s","blob":"eA==","sender":"%s"}`, protoV, idOf(t, bob), idOf(t, owner)))
	frame := signFrame(t, alice, raw)
	if err := writeFrame(alice.conn, frame); err != nil {
		t.Fatal(err)
	}
	respRaw, err := readFrame(alice.br)
	if err != nil {
		t.Fatal(err)
	}
	var resp response
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.OK {
		t.Fatal("request with a sender field was accepted")
	}
	alice.Close()
	friend := dial(t, addr, bob, srv.Pin())
	defer friend.Close()
	got, err := friend.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("smuggled deposit stored %d blobs", len(got))
	}
	alice = dial(t, addr, owner, srv.Pin())
	defer alice.Close()
	if err := alice.Put(idOf(t, bob), []byte("from-alice")); err != nil {
		t.Fatal(err)
	}
	got, err = friend.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !bytes.Equal(got[0].Blob, []byte("from-alice")) {
		t.Fatalf("caller deposit = %#v", got)
	}
	own, err := alice.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(own) != 0 {
		t.Fatal("sender fetched the recipient box")
	}
}

func TestCrossBoxFetchAndAck(t *testing.T) {
	owner := newKey(t)
	bobKey := newKey(t)
	_, srv, addr := startBox(t, owner)
	defer srv.Close()
	alice := dial(t, addr, owner, srv.Pin())
	defer alice.Close()
	if err := alice.Introduce(idOf(t, bobKey)); err != nil {
		t.Fatal(err)
	}
	bob := dial(t, addr, bobKey, srv.Pin())
	defer bob.Close()
	if err := alice.Put(idOf(t, bobKey), []byte("for-bob")); err != nil {
		t.Fatal(err)
	}
	if err := bob.Put(idOf(t, owner), []byte("for-alice")); err != nil {
		t.Fatal(err)
	}
	aliceMail, err := alice.List()
	if err != nil {
		t.Fatal(err)
	}
	bobMail, err := bob.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(aliceMail) != 1 || !bytes.Equal(aliceMail[0].Blob, []byte("for-alice")) {
		t.Fatalf("alice box %#v", aliceMail)
	}
	if len(bobMail) != 1 || !bytes.Equal(bobMail[0].Blob, []byte("for-bob")) {
		t.Fatalf("bob box %#v", bobMail)
	}
	if _, err := alice.roundTrip(request{Op: "list", Recipient: idOf(t, bobKey)}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-box list err=%v", err)
	}
	if _, err := alice.roundTrip(request{Op: "ack", Recipient: idOf(t, bobKey), IDs: []string{bobMail[0].ID}}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("cross-box ack err=%v", err)
	}
	if err := alice.Ack([]string{bobMail[0].ID}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("ack of other id err=%v", err)
	}
	still, err := bob.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(still) != 1 || still[0].ID != bobMail[0].ID {
		t.Fatalf("cross-box ack deleted bob's letter: %#v", still)
	}
	if err := bob.Ack([]string{bobMail[0].ID}); err != nil {
		t.Fatal(err)
	}
	gone, err := bob.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(gone) != 0 {
		t.Fatalf("bob ack left %#v", gone)
	}
	if len(mustList(t, alice)) != 1 {
		t.Fatal("alice letter was deleted with bob's ack")
	}
}

func TestAckDeletesLetter(t *testing.T) {
	owner := newKey(t)
	dir, srv, addr := startBox(t, owner)
	defer srv.Close()
	alice := dial(t, addr, owner, srv.Pin())
	defer alice.Close()
	blob := []byte("keep-until-ack")
	if err := alice.Put(idOf(t, owner), blob); err != nil {
		t.Fatal(err)
	}
	got := mustList(t, alice)
	if len(got) != 1 || !bytes.Equal(got[0].Blob, blob) {
		t.Fatalf("before ack %#v", got)
	}
	if err := alice.Ack([]string{got[0].ID}); err != nil {
		t.Fatal(err)
	}
	if len(mustList(t, alice)) != 0 {
		t.Fatal("ack did not delete")
	}
	if blobFiles(t, dir) != 0 {
		t.Fatal("ack left the blob on disk")
	}
}

func TestNoAckRetainsLetter(t *testing.T) {
	owner := newKey(t)
	bobKey := newKey(t)
	dir, srv, addr := startBox(t, owner)
	alice := dial(t, addr, owner, srv.Pin())
	if err := alice.Introduce(idOf(t, bobKey)); err != nil {
		t.Fatal(err)
	}
	blob := []byte("waiting-without-ack")
	if err := alice.Put(idOf(t, bobKey), blob); err != nil {
		t.Fatal(err)
	}
	bob := dial(t, addr, bobKey, srv.Pin())
	first := mustList(t, bob)
	second := mustList(t, bob)
	if len(first) != 1 || len(second) != 1 || first[0].ID != second[0].ID || !bytes.Equal(second[0].Blob, blob) {
		t.Fatalf("list removed a letter first=%#v second=%#v", first, second)
	}
	bob.Close()
	alice.Close()
	srv.Close()

	srv2, err := New(dir, idOf(t, owner))
	if err != nil {
		t.Fatal(err)
	}
	defer srv2.Close()
	addr2, err := srv2.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bob2 := dial(t, addr2, bobKey, srv2.Pin())
	defer bob2.Close()
	kept := mustList(t, bob2)
	if len(kept) != 1 || !bytes.Equal(kept[0].Blob, blob) {
		t.Fatalf("restart dropped the letter: %#v", kept)
	}
	if err := bob2.Ack([]string{kept[0].ID}); err != nil {
		t.Fatal(err)
	}
	if len(mustList(t, bob2)) != 0 {
		t.Fatal("ack after restart failed")
	}
}

func TestPublicBindRefused(t *testing.T) {
	refused := []string{
		"0.0.0.0:0",
		"8.8.8.8:80",
		"1.1.1.1:9",
		"1.2.3.4:1",
		":0",
		"localhost:80",
		"172.32.0.1:1",
		"11.0.0.0:1",
		"192.169.0.1:1",
		"255.255.255.255:1",
		"[::]:1",
		"[2001:db8::1]:1",
		"[::ffff:8.8.8.8]:80",
	}
	for _, addr := range refused {
		if err := ValidateAddr(addr); !errors.Is(err, ErrPublicBind) {
			t.Fatalf("ValidateAddr(%s) err=%v", addr, err)
		}
	}
	allowed := []string{
		"127.0.0.1:0",
		"127.0.0.2:1",
		"10.1.2.3:1",
		"192.168.1.5:9",
		"172.16.0.1:1",
		"172.31.255.255:1",
		"169.254.1.1:1",
		"[::1]:1",
		"[fc00::1]:1",
		"[fd12:3456::1]:1",
		"[fe80::1]:1",
		"[::ffff:10.0.0.1]:1",
		"[::ffff:127.0.0.1]:1",
	}
	for _, addr := range allowed {
		if err := ValidateAddr(addr); err != nil {
			t.Fatalf("ValidateAddr(%s) err=%v", addr, err)
		}
	}
	owner := newKey(t)
	s, err := New(t.TempDir(), idOf(t, owner))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, addr := range []string{"0.0.0.0:0", "8.8.8.8:80", ":0"} {
		got, err := s.Start(addr)
		if err == nil {
			s.Close()
			t.Fatalf("listened on %s as %s", addr, got)
		}
		if !errors.Is(err, ErrPublicBind) {
			t.Fatalf("Start(%s) err=%v", addr, err)
		}
	}
	if _, err := Dial("8.8.8.8:80", owner, nil); !errors.Is(err, ErrPublicBind) {
		t.Fatalf("dial public err=%v", err)
	}
	if _, err := Dial("0.0.0.0:80", owner, nil); !errors.Is(err, ErrPublicBind) {
		t.Fatalf("dial unspecified err=%v", err)
	}
	privSrv, err := New(t.TempDir(), idOf(t, owner))
	if err != nil {
		t.Fatal(err)
	}
	defer privSrv.Close()
	if _, err := privSrv.Start("192.168.0.1:0"); errors.Is(err, ErrPublicBind) {
		t.Fatal("private LAN address was refused")
	}
}

func TestBlobStaysOpaque(t *testing.T) {
	owner := newKey(t)
	dir, srv, addr := startBox(t, owner)
	defer srv.Close()
	alice := dial(t, addr, owner, srv.Pin())
	defer alice.Close()
	blobs := [][]byte{
		{0x00, 0x01, 0xff, 'h', 'i'},
		[]byte(`{"sender":"glyph:abcd","text":"read me","counter":1}`),
	}
	for _, blob := range blobs {
		if err := alice.Put(idOf(t, owner), blob); err != nil {
			t.Fatal(err)
		}
	}
	got := mustList(t, alice)
	if len(got) != 2 {
		t.Fatalf("list %#v", got)
	}
	seen := map[string]bool{}
	for _, lt := range got {
		seen[string(lt.Blob)] = true
		pub := hex.EncodeToString(owner.Public().(ed25519.PublicKey))
		disk, err := os.ReadFile(filepath.Join(dir, "in", pub, lt.ID))
		if err != nil {
			t.Fatal(err)
		}
		way, from, to, blob, err := decodeWait(disk)
		if err != nil {
			t.Fatal(err)
		}
		if way != wayIn || from != idOf(t, owner) || to != from || !bytes.Equal(blob, lt.Blob) {
			t.Fatal("inbound file changed the opaque blob")
		}
		out, err := os.ReadFile(filepath.Join(dir, "out", pub, lt.ID))
		if err != nil {
			t.Fatal(err)
		}
		oWay, _, _, oBlob, err := decodeWait(out)
		if err != nil || oWay != wayOut || !bytes.Equal(oBlob, lt.Blob) {
			t.Fatal("outbound file changed the opaque blob")
		}
	}
	for _, blob := range blobs {
		if !seen[string(blob)] {
			t.Fatalf("blob %q was rewritten", blob)
		}
	}
	seed := owner.Seed()
	hexSeed := hex.EncodeToString(seed)
	priv := owner
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, seed) || bytes.Contains(b, []byte(hexSeed)) || bytes.Contains(b, priv) {
			t.Fatalf("mailbox stored an opening key in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSourceDoesNotOpenLetters(t *testing.T) {
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{
		"chacha20poly1305",
		"nacl/box",
		"crypto/ecdh",
		"glyph/seal",
		"sha512.Sum512",
		"golang.org/x/crypto",
	}
	for _, e := range ents {
		if e.IsDir() || strings.HasSuffix(e.Name(), "_test.go") || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range banned {
			if bytes.Contains(b, []byte(bad)) {
				t.Fatalf("%s references %s", e.Name(), bad)
			}
		}
	}
}

func TestPresenceNotRevealed(t *testing.T) {
	owner := newKey(t)
	bobKey := newKey(t)
	_, srv, addr := startBox(t, owner)
	defer srv.Close()
	alice := dial(t, addr, owner, srv.Pin())
	defer alice.Close()
	empty, err := alice.roundTripRaw(request{Op: "list"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(empty, []byte(fmt.Sprintf(`{"v":%d,"ok":true}`, protoV))) {
		t.Fatalf("empty box response %s", empty)
	}
	if err := alice.Introduce(idOf(t, bobKey)); err != nil {
		t.Fatal(err)
	}
	bob := dial(t, addr, bobKey, srv.Pin())
	online, err := alice.roundTripRaw(request{Op: "put", Recipient: idOf(t, bobKey), Blob: []byte("a")})
	if err != nil {
		t.Fatal(err)
	}
	bob.Close()
	offline, err := alice.roundTripRaw(request{Op: "put", Recipient: idOf(t, bobKey), Blob: []byte("b")})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte(fmt.Sprintf(`{"v":%d,"ok":true}`, protoV))
	if !bytes.Equal(online, want) || !bytes.Equal(offline, want) {
		t.Fatalf("put revealed state online=%s offline=%s", online, offline)
	}
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := FormatID(priv.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	return priv
}

func idOf(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	id, err := FormatID(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func startBox(t *testing.T, owner ed25519.PrivateKey) (string, *Server, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := New(dir, idOf(t, owner))
	if err != nil {
		t.Fatal(err)
	}
	addr, err := s.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return dir, s, addr
}

func dial(t *testing.T, addr string, priv ed25519.PrivateKey, pin ed25519.PublicKey) *Client {
	t.Helper()
	c, err := Dial(addr, priv, pin)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustList(t *testing.T, c *Client) []Letter {
	t.Helper()
	got, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func signFrame(t *testing.T, c *Client, raw []byte) []byte {
	t.Helper()
	sig := ed25519.Sign(c.priv, reqSignBytes(c.nonce, raw))
	frame := make([]byte, ed25519.SignatureSize+len(raw))
	copy(frame, sig)
	copy(frame[ed25519.SignatureSize:], raw)
	return frame
}

func blobFiles(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if validBlobID(info.Name()) {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWaitFileIsInboundOrOutbound(t *testing.T) {
	owner := newKey(t)
	bobKey := newKey(t)
	dir, srv, addr := startBox(t, owner)
	defer srv.Close()
	alice := dial(t, addr, owner, srv.Pin())
	defer alice.Close()
	if err := alice.Introduce(idOf(t, bobKey)); err != nil {
		t.Fatal(err)
	}
	blob := []byte("sealed-bytes")
	if err := alice.Put(idOf(t, bobKey), blob); err != nil {
		t.Fatal(err)
	}
	inFiles := waitFiles(t, filepath.Join(dir, "in"))
	outFiles := waitFiles(t, filepath.Join(dir, "out"))
	if len(inFiles) != 1 || len(outFiles) != 1 {
		t.Fatalf("in %d out %d", len(inFiles), len(outFiles))
	}
	inWay, inFrom, inTo, inBlob := mustDecodeWait(t, inFiles[0])
	outWay, outFrom, outTo, outBlob := mustDecodeWait(t, outFiles[0])
	if inWay != "in" || outWay != "out" || inFrom != idOf(t, owner) || outFrom != inFrom || inTo != idOf(t, bobKey) || outTo != inTo {
		t.Fatalf("marks in=%s %s->%s out=%s %s->%s", inWay, inFrom, inTo, outWay, outFrom, outTo)
	}
	if !bytes.Equal(inBlob, blob) || !bytes.Equal(outBlob, blob) {
		t.Fatal("blob was rewritten")
	}
	if bytes.Contains(inFiles[0], []byte("sealed-bytes")) && bytes.HasPrefix(inFiles[0], []byte("sealed")) {
		t.Fatal("file is a raw blob, not a marked wait file")
	}
	bob := dial(t, addr, bobKey, srv.Pin())
	defer bob.Close()
	got := mustList(t, bob)
	if len(got) != 1 || !bytes.Equal(got[0].Blob, blob) {
		t.Fatalf("list %#v", got)
	}
	own := mustList(t, alice)
	if len(own) != 0 {
		t.Fatalf("outbound listed as mail %#v", own)
	}
	if err := bob.Ack([]string{got[0].ID}); err != nil {
		t.Fatal(err)
	}
	if n := blobFiles(t, dir); n != 0 {
		t.Fatalf("transient files left: %d", n)
	}
}

func mustDecodeWait(t *testing.T, b []byte) (way, from, to string, blob []byte) {
	t.Helper()
	way, from, to, blob, err := decodeWait(b)
	if err != nil {
		t.Fatal(err)
	}
	return way, from, to, blob
}

func waitFiles(t *testing.T, root string) [][]byte {
	t.Helper()
	var out [][]byte
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !validBlobID(info.Name()) {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out = append(out, b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestListPagesBeforeTheFrameCap(t *testing.T) {
	owner := newKey(t)
	_, srv, addr := startBox(t, owner)
	defer srv.Close()
	alice := dial(t, addr, owner, srv.Pin())
	defer alice.Close()
	blob := bytes.Repeat([]byte("a"), 40000)
	if err := alice.Put(idOf(t, owner), blob); err != nil {
		t.Fatal(err)
	}
	if err := alice.Put(idOf(t, owner), blob); err != nil {
		t.Fatal(err)
	}
	page, more, err := alice.ListAfter("")
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || !more {
		t.Fatalf("first page %d more %v", len(page), more)
	}
	got := mustList(t, alice)
	if len(got) != 2 || !bytes.Equal(got[0].Blob, blob) || !bytes.Equal(got[1].Blob, blob) {
		t.Fatalf("paged list %#v", len(got))
	}
}

func TestRemoveFriendDeletesLane(t *testing.T) {
	owner := newKey(t)
	bobKey := newKey(t)
	dir, srv, addr := startBox(t, owner)
	defer srv.Close()
	alice := dial(t, addr, owner, srv.Pin())
	defer alice.Close()
	if err := alice.Introduce(idOf(t, bobKey)); err != nil {
		t.Fatal(err)
	}
	if err := alice.Put(idOf(t, bobKey), []byte("for-bob")); err != nil {
		t.Fatal(err)
	}
	if err := alice.Remove(idOf(t, owner)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("remove owner err=%v", err)
	}
	bob := dial(t, addr, bobKey, srv.Pin())
	if err := bob.Remove(idOf(t, owner)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("friend remove err=%v", err)
	}
	bob.Close()
	if err := alice.Remove(idOf(t, bobKey)); err != nil {
		t.Fatal(err)
	}
	if _, err := Dial(addr, bobKey, srv.Pin()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("removed friend dial err=%v", err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "in"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("inbound lane left %d entries", len(entries))
	}
}

func TestPinMismatchIsProtocol(t *testing.T) {
	owner := newKey(t)
	_, srv, addr := startBox(t, owner)
	defer srv.Close()
	_, err := Dial(addr, owner, newKey(t).Public().(ed25519.PublicKey))
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("pin err=%v", err)
	}
}

func TestAllowlistRestoresBackupAndRefusesReset(t *testing.T) {
	owner := newKey(t)
	bobKey := newKey(t)
	dir, srv, addr := startBox(t, owner)
	alice := dial(t, addr, owner, srv.Pin())
	if err := alice.Introduce(idOf(t, bobKey)); err != nil {
		t.Fatal(err)
	}
	if err := alice.Put(idOf(t, bobKey), []byte("kept")); err != nil {
		t.Fatal(err)
	}
	alice.Close()
	srv.Close()
	path := filepath.Join(dir, "allowlist")
	if err := os.Rename(path, path+".bak"); err != nil {
		t.Fatal(err)
	}
	srv2, err := New(dir, idOf(t, owner))
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := srv2.Start("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Dial(addr2, bobKey, srv2.Pin()); err != nil {
		t.Fatalf("restored friend dial err=%v", err)
	}
	srv2.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(path + ".bak")
	_ = os.Remove(path + ".tmp")
	if _, err := New(dir, idOf(t, owner)); err == nil {
		t.Fatal("missing allowlist reset a mailbox that already held mail")
	}
}

func TestSourceRejectsPublic(t *testing.T) {
	if hostAllowed("8.8.8.8") || hostAllowed("1.1.1.1") {
		t.Fatal("public source was allowed")
	}
	for _, host := range []string{"127.0.0.1", "10.1.2.3", "192.168.1.5", "169.254.1.1"} {
		if !hostAllowed(host) {
			t.Fatalf("source %s rejected", host)
		}
	}
}

func TestDialRejectsStaleProtocol(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return
		}
		raw, err := json.Marshal(helloMsg{V: protoV + 1, Type: "hello", Nonce: nonce})
		if err != nil {
			return
		}
		_ = writeFrame(c, raw)
	}()
	_, err = Dial(ln.Addr().String(), newKey(t), newKey(t).Public().(ed25519.PublicKey))
	if !errors.Is(err, ErrProtocol) {
		t.Fatalf("stale dial err=%v", err)
	}
}
