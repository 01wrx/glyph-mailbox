# glyph-mailbox

A mailbox for one owner, on that owner's LAN. It holds sealed [glyph](https://github.com/01wrx/glyph) letters while the apps are closed. It cannot read them.

glyph is the program people run. This module is the box.

## Place

The listener accepts a private LAN address, loopback, or a link-local address. A public address, an unspecified address such as `0.0.0.0`, or a hostname is refused, and nothing is bound. A connection whose source address is public is closed. The listener does not advertise itself.

Clients speak TLS 1.3 and pin the public key in `box-pub`. A certificate that is not that key is rejected before any letter is sent.

## Who

The owner, and friends the owner has introduced by a full glyph ID. A glyph ID is `glyph:` plus the 64-character lowercase hex of one canonical Ed25519 public key. A short prefix is not an address. There is no open enrollment and no directory.

The mailbox stores the owner's public glyph ID. It is not given a private key, so it cannot open a letter or choose a sender. Each caller proves the glyph ID they claim. After that handshake, each request on the connection is signed and numbered.

## Letters

A stored letter is an opaque blob, at most 64 KiB, addressed to a glyph ID on the allowlist. Both people in a conversation have a lane here. Each recipient's lane holds at most 1024 letters that have not been acknowledged.

The box will:

- accept a sealed letter for an allowlisted recipient
- return that recipient's waiting letters, one page at a time
- forget a letter when that recipient acknowledges it or drops it
- remove a friend when the owner asks, and delete that friend's inbound lane

Order is inside the seal. The glyph app orders by the sender's counter and shows the sender's time. The mailbox does not decrypt, search, rewrite, or forward letters onto the internet. It does not learn who is online. It does not introduce people to each other.

## From glyph

glyph starts this process for its owner:

```powershell
glyph mailbox -dir C:\mailbox-data -owner glyph:... -addr 192.168.1.20:7420
```

The window's mailbox setup does that on this machine. A friend on the same LAN points glyph at that address and the `box-pub` key with `GLYPH_MAILBOX` and `GLYPH_MAILBOX_KEY`.

## Library

```go
box, err := mailbox.New(dir, ownerID)
addr, err := box.Start("192.168.1.20:7420")

client, err := mailbox.Dial(addr, privateKey, box.Pin())
err = client.Introduce(friendID)
err = client.Put(friendID, blob)
letters, err := client.List()
err = client.Ack(ids)
err = client.Drop(ids)
err = client.Remove(friendID)
```

`New` creates the directory and the box key. `LoadPub` reads `box-pub` later. The private key stays in the mailbox directory.

The Go module path is `glyph-mailbox`. The glyph app expects this checkout beside it, at `../glyph-mailbox`.

## Checks

```powershell
go test ./...
```
