# warren protocol, version 1

This document describes what travels between a node and the relay, and between
two nodes inside a private stream. All integers are big-endian.

## 1. Transport

Each node keeps one TLS connection to the relay on port 443 and upgrades it to
a WebSocket at `GET /v1/node` (Host: the relay's domain). Everything below
rides that WebSocket:

1. the relay sends a **challenge** (text message, JSON);
2. the node answers with **auth** or **join** (text, JSON);
3. the relay answers with a **verdict** (text, JSON);
4. after `welcome`, every message is a **binary message carrying exactly one
   frame**.

A binary message larger than `7 + 65535` bytes, a text message after the
handshake, or a frame whose length field does not match the message size
closes the connection.

The node reconnects with jittered exponential backoff: a random delay between
half and all of `min(1 s * 2^attempt, 60 s)`; the attempt counter resets after
a connection that lasted more than 30 s.

## 2. Authentication and enrollment

### Challenge

```json
{"type":"challenge","version":1,"challenge":"<64 hex chars: 32 random bytes>"}
```

A fresh challenge is generated for every connection.

### Auth (enrolled node)

```json
{"type":"auth","version":1,"node_id":"n3f...","sign_pub":"<hex>","signature":"<hex>"}
```

`signature` is Ed25519 over

```
"warren-v1-auth" || challenge (32 bytes) || relay_host (UTF-8)
```

where `relay_host` is the lower-case host part of the relay URL the node was
configured with (no port). The relay verifies it with the key it registered
for `node_id` and against its own configured domain, so a signature is useless
on another connection (fresh challenge) and on another relay (different host).
Unknown keys get `unknown_node`, revoked ones `revoked`, bad signatures
`bad_signature`.

### Join (new node)

```json
{"type":"join","version":1,"code":"7KQ4MWX9HD","name":"laptop",
 "sign_pub":"<hex>","static_pub":"<hex>","signature":"<hex>"}
```

`signature` is Ed25519 (with the new signing key) over

```
"warren-v1-join" || challenge || relay_host || static_pub (32 bytes)
```

which proves possession of the signing key and binds the X25519 static key to
it. The relay:

* refuses the attempt outright if the client IP has 5 failed attempts in the
  last 10 minutes (`rate_limited`);
* looks the code up by `SHA-256(code)` (codes are only ever stored hashed);
  unknown, expired (older than 10 minutes) or used codes count as a failure;
* uses the name bound to the invite, if any, else the requested name; names
  are `[a-z0-9-]{1,32}` and unique among active nodes;
* registers `{node_id, name, sign_pub, static_pub}` and marks the code used,
  in one transaction.

`node_id` is `"n"` followed by the first 10 bytes of `SHA-256(sign_pub)` in hex.

### Verdict

```json
{"type":"welcome","node_id":"...","name":"laptop","publish_domain":"relay.example.com","relay_version":"1.0.0"}
{"type":"joined","node_id":"...","name":"laptop","publish_domain":"relay.example.com"}
{"type":"error","code":"invalid_code","message":"..."}
```

After `joined` the relay closes the connection; the node then connects again
with `auth`.

## 3. Frames

```
 0        1                5          7
+--------+----------------+----------+-------------------+
| type   | stream id      | len      | payload (len)     |
| u8     | u32            | u16      |                   |
+--------+----------------+----------+-------------------+
```

| type | name | stream | payload |
|---:|---|---|---|
| 1 | OPEN | new id | open payload (below) |
| 2 | OPEN_OK | id | empty |
| 3 | OPEN_ERR | id | `code u8` then a UTF-8 message |
| 4 | DATA | id | bytes (1..65535) |
| 5 | WINDOW | id | `credit u32` |
| 6 | CLOSE | id | empty = FIN (half-close); `code u8` = reset |
| 7 | PING | 0 | up to 64 bytes, echoed |
| 8 | PONG | 0 | the PING payload |
| 9 | CTRL | 0 | JSON control message (section 6) |

**Stream ids.** Stream 0 is the connection itself. On each node-relay
connection, streams opened by the node use odd ids and streams opened by the
relay use even ids. A node that opens an even id, reuses a live id or sends
stream frames on id 0 is disconnected.

**Flow control.** Each direction of each stream starts with 256 KiB of credit.
A sender may only send DATA within its credit; the receiver returns credit
with WINDOW after consuming data (in practice every 64 KiB). Receiving more
than the window resets the stream with `window_overrun`. Credit above 64 MiB
is a protocol error.

**Closing.** CLOSE with an empty payload means "no more data from me". A
stream is finished when both sides have sent FIN, or when either side sends
CLOSE with a code (reset), which aborts both directions.

**Keepalive.** Nodes send PING every 15 s (and measure latency from the PONG);
the relay sends PING every 20 s. A side that sees no PONG for three intervals
drops the connection. PING replies are rate limited.

### Open payload

```
flags u8 | port u16 | dest (len u8, bytes) | src (len u8, bytes)
         | src_static (len u8 = 0 or 32, bytes) | client (len u8, bytes)
```

* `flags`: bit 0 = `PUBLIC` (a relay-terminated public connection).
* A node opening a private stream sets `port` and `dest` (the peer's name)
  and leaves the rest empty.
* When the relay forwards it, it sets `src` to the authenticated name of the
  opener and `src_static` to that node's registered X25519 key. These are
  claims; the destination verifies them (section 4).
* For public streams the relay sets `PUBLIC`, `dest` = the published name,
  `port` = 0, and `client` = the client's `ip:port` (informational).

### Error codes

| code | name | meaning |
|---:|---|---|
| 1 | `no_such_node` | no active node has that name |
| 2 | `node_offline` | the destination is not connected |
| 3 | `not_shared` | the destination does not share that port |
| 4 | `forbidden` | the port is shared, but not with the opener |
| 5 | `too_many_streams` | 1024 concurrent streams reached (either end) |
| 6 | `rate_limited` | more than 64 opens per second |
| 7 | `connect_failed` | nothing is listening on the destination port |
| 8 | `key_changed` | the destination has a different key pinned for the opener |
| 9 | `no_such_publish` | the node does not publish that name |
| 10 | `bad_request` | malformed OPEN |
| 11 | `internal` | internal error |
| 12 | `protocol` | protocol violation |
| 13 | `window_overrun` | a sender exceeded its credit |
| 14 | `aborted` | the stream was abandoned |
| 15 | `handshake_failed` | the Noise handshake failed or proved a different key |
| 16 | `link_closed` | the other side's connection went away |

## 4. Private streams

1. Node A sends `OPEN(dest=b, port=22)` with a fresh odd id.
2. The relay applies A's rate and stream limits, checks that `b` is enrolled
   and connected, allocates an even id on B's connection, and forwards the
   OPEN with `src=a` and `src_static` = A's registered key.
3. **B enforces its own policy** before anything else:
   * `shares.json` must contain the port (default deny) → else `not_shared`;
   * if the share has a `--to` list, `src` must be on it → else `forbidden`;
   * if B has pinned a key for `src`, `src_static` must equal it → else
     `key_changed`.

   Then B sends OPEN_OK. The relay forwards OPEN_OK/OPEN_ERR to A.
4. A and B run **`Noise_IK_25519_ChaChaPoly_BLAKE2s`** inside the stream,
   with prologue `warren-v1-private`. A is the initiator and uses B's static
   key: the key A pinned for `b`, or on first contact the key from the relay's
   registry (then pinned). Each handshake message is one DATA frame.
   * Message 1 (A→B) payload: `{"v":1,"src":"a","dest":"b","port":22}`.
   * Message 2 (B→A) payload: `{"v":1}`.
5. After message 1, B checks that the key the handshake proved equals
   `src_static`, and that `src`, `dest` and `port` in the encrypted payload
   match the OPEN; otherwise it resets the stream (`handshake_failed` or
   `forbidden`). On first contact B pins A's key. B connects to
   `127.0.0.1:port` (reset with `connect_failed` if that fails) and sends
   message 2.
6. Every later DATA frame is exactly one Noise transport message (at most
   65535 bytes, so at most 65519 bytes of plaintext), with nonces counting up
   from 0 in each direction. An **empty** transport message is the
   authenticated end of stream; the sender then sends FIN. A FIN without that
   marker is treated as truncation and the local connection is aborted.

The relay never holds a key for these streams. It forwards DATA, WINDOW and
CLOSE between the two ids unchanged apart from the stream id, and tracks credit
for each direction so that a node cannot make it buffer more than the window.

If A's handshake fails, A asks the relay for B's current key; if it differs
from the pinned one the user gets a `key_changed` error naming both
fingerprints and `warren trust b`.

Fingerprints are the first 16 bytes of `SHA-256(static_pub)` in hex, in groups
of four characters separated by colons.

## 5. Public streams

For each accepted public connection the relay opens a stream to the owning
node with `OPEN(flags=PUBLIC, dest=<name>)`. The node looks the name up in its
`publishes.json`, connects to `127.0.0.1:PORT` (else `connect_failed`) and
answers OPEN_OK; then bytes are copied both ways without further framing.
Public streams are plaintext between relay and node (inside the node's TLS
connection); this is the part of the system the relay can read.

The relay's HTTP handling for these streams:

* TLS handshake plus the first request head within 10 s; later request heads
  within 10 s of their first byte; no bytes in either direction for 5 minutes
  closes the connection;
* request heads over 32 KiB are refused with 431;
* `Transfer-Encoding` other than a single `chunked`, `Transfer-Encoding`
  together with `Content-Length`, conflicting `Content-Length` values, and
  missing or duplicate `Host` are refused with 400;
* `Host` must match the TLS server name (421 otherwise) and cannot change on a
  keep-alive connection;
* client `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`,
  `X-Forwarded-Port`, `X-Real-IP` and `Forwarded` headers are removed from
  every request and replaced by the relay's own `X-Forwarded-For` (client IP),
  `X-Forwarded-Proto: https` and `X-Forwarded-Host`;
* responses are framed (Content-Length, chunked, close-delimited, no body for
  HEAD/1xx/204/304) so that keep-alive works; `101 Switching Protocols` after
  an `Upgrade` request turns the connection into a byte pipe.

## 6. Control messages

CTRL frames on stream 0 carry JSON. Requests from a node:

```json
{"id":1,"op":"devices"}
{"id":2,"op":"lookup","name":"b"}
{"id":3,"op":"publish","name":"web","replace":false,"reclaim":false,"allow":["10.0.0.0/8"]}
{"id":4,"op":"unpublish","name":"web"}
{"id":5,"op":"publishes"}
```

Responses echo the id:

```json
{"id":2,"ok":true,"result":{"node_id":"...","name":"b","static_pub":"<hex>","sign_pub":"<hex>","online":true,"last_seen":1790000000,"created_at":1789990000}}
{"id":3,"ok":false,"code":"name_taken","error":"\"web\" is published by another node"}
```

Publish error codes: `bad_name`, `bad_cidr`, `name_taken` (held by another
node, regardless of `replace`), `already_published` (held by this node and
`replace` not set). `reclaim` is sent by the daemon after reconnecting to
re-announce its own publishes. Events pushed by the relay have no id, e.g.
`{"event":"revoked"}`. Control requests are rate limited (20 per second).

## 7. Relay state

The relay keeps one SQLite file (`relay.sqlite3`) in its state directory:
nodes (including revoked ones, whose names become reusable), invite hashes,
published names with their owner and allowlist, and custom domains. Admin
commands on the relay host write the same file and bump a revision counter the
running relay polls every second, so revocations take effect within about a
second: the node is disconnected, its streams are reset and its published
names are released.
