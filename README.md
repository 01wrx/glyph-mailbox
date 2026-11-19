# glyph-mailbox

A mailbox for one owner, on that owner's LAN. It holds sealed glyph letters while apps are closed. It cannot read them.

[glyph](https://github.com/01wrx/glyph) is the app people use. This program is only the box.

## Who it talks to

The owner, and friends the owner has introduced by full glyph ID. No one else. There is no open enrollment and no directory.

The listener binds to the LAN and speaks TLS 1.3. Clients pin the public key in `box-pub`. A connection whose source address is public is closed. The listener does not advertise itself.

## What it stores

Opaque blobs. Each blob is addressed to a glyph ID on the allowlist. The mailbox does not look inside.

Both directions of a conversation live here. Alice's letters wait for Alice. Bob's letters wait for Bob.

## What it does

- Accept a sealed letter for an allowlisted recipient.
- Return that recipient's waiting letters, one page at a time, when their app asks.
- Forget a letter when that recipient's app acknowledges it or drops it.
- Remove a friend when the owner asks, and delete that friend's inbound lane.

Order is not decided here. Each letter's sender already put a counter and a send time inside the seal. The glyph app orders by the counter and shows the time.

## What it does not do

It does not decrypt, search, rewrite, or forward letters onto the internet. It does not learn who is online. It does not introduce people to each other. A glyph ID the owner has not added cannot drop mail and cannot pick mail up.
