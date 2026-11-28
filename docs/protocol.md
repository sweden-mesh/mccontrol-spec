# The mccontrol protocol (mcc3)

This document describes the remote-control plane of the MeshCore-lou firmware, as its lou-21
branch implements it. It holds what a firmware, a tool or a command server needs to be
compatible, with no other document open. The scheme is named **mcc3**. It is the only scheme
in lou-21.

Where this document and the firmware differ, the firmware is right and this document has an
error. Section 20 lists the places where the sources it was written from differ from each other.

## Contents

1. Roles and trust
2. Notation
3. Keys
4. Topics
5. The signature
6. Messages on MQTT: command and result
7. Messages on the mesh road: request and response
8. What a node checks, in order
9. Budgets
10. The clock
11. Answering over the mesh
12. The alive message, the announce of a node without a connection, and the shared node store
13. Replacing the command key: `rekey`
14. What may be sent: the deny list
15. The relay
16. The command server
17. Worked examples
18. Conformance checklist
19. Version policy
20. Where the sources differ
21. History
22. Licence

The words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Roles and trust

| role | what it is |
|---|---|
| **node** | A MeshCore repeater. It has an Ed25519 identity. Its public key, `KEY`, names it everywhere in this protocol. |
| **owner** | The holder of the **command key**, an Ed25519 key pair. A node stores the public half of exactly one command key. One owner uses one command key for all of its nodes. |
| **command server** | An MQTT broker that carries the messages. |
| **relay** | A node with an MQTT connection that transmits its owner's request to another node over the radio and returns the answer over MQTT. |
| **target** | The node a relayed request is for. |
| **sender** | Whoever puts a request on the air for the owner: a companion radio, or a relay. |

The trust model:

- **The command server is hostile transport.** Anyone can log in to it. Any login can publish
  to any node's command topic. A node MUST NOT trust a message because of the topic it came on
  or the login that sent it.
- **The command server is blind.** It opens no message, checks no signature and holds no
  owner key. It sees topics, times and padded lengths, and so learns which node keys are on
  the plane. It does not learn which nodes share an owner.
- **Every check is on the node.** A command runs only when it opens under a key that only the
  node and its owner can derive, and carries the command key's signature over this node's key.
- **A relay is not trusted with content.** It cannot read the request it transmits or the
  answer it returns. It can drop them or delay them.
- **A valid signature is not enough.** A rate limit and a deny list apply to commands the
  owner really signed, so that a leaked command key cannot flood the mesh, change a node's
  identity or take the node off the plane.

There are two roads to a node. On the **MQTT road** the owner publishes a sealed command to
the command server and the node answers there. On the **mesh road** the same kind of command
travels over the radio as a MeshCore anonymous request, for a node that has no MQTT connection
or has lost it. A node keeps one counter for both roads.

## 2. Notation

- `‖` joins byte strings.
- Every integer is **little-endian** and unsigned unless a field says otherwise. `u32` is 4
  bytes, `u8` is 1 byte.
- Hex is upper case. `KEY` is a node's 32-byte Ed25519 public key written as 64 upper-case
  hex characters.
- `b64url` is base64 with the URL alphabet of RFC 4648 section 5, **without padding**. Every
  MQTT payload of a sealed message is b64url ASCII text. 182 bytes are 243 characters, 189 are
  252, 278 are 371, 285 are 380, 541 are 722.
- Unix time is seconds since 1970-01-01 UTC, as a `u32`.
- "Sealed" means ChaCha20-Poly1305 as in RFC 8439: a 32-byte key, a 12-byte nonce, additional
  data (AAD), and a 16-byte tag after the ciphertext.
- A **silent** refusal sends nothing, on any road. An **answered** refusal sends a result with
  a result code.

## 3. Keys

### 3.1 The shared secret

A node and its owner derive the same 32-byte secret `S` with X25519 (RFC 7748), each from its
own Ed25519 private key and the other's Ed25519 public key. This is MeshCore's own key
exchange (`ed25519_key_exchange`).

```
scalar = SHA-512(Ed25519 seed)[0:32]        X25519 clamps it
y      = the peer's Ed25519 public key as a little-endian integer, top bit cleared
u      = (1 + y) / (1 - y)  mod 2^255 - 19  the peer's Montgomery u coordinate, 32 bytes little-endian
S      = X25519(scalar, u)
```

The owner uses its command seed and the node's key. The node uses its identity and the command
key. An implementation that stores an expanded Ed25519 private key uses its first 32 bytes as
the scalar: they are `SHA-512(seed)[0:32]`.

### 3.2 The four keys

```
K_cmd    = HKDF-SHA256(ikm S, salt empty, info "mcc3/cmd/"   ‖ KEY, 32 bytes)
K_mesh   = HKDF-SHA256(ikm S, salt empty, info "mcc3/mesh/"  ‖ KEY, 32 bytes)
K_alive  = HKDF-SHA256(ikm S, salt empty, info "mcc3/alive/" ‖ KEY, 32 bytes)
K_fwd    = HKDF-SHA256(ikm S, salt empty, info "mcc3/fwd/"   ‖ KEY, 32 bytes)
```

HKDF is RFC 5869. An empty salt is 32 zero bytes. `info` is ASCII, and `KEY` in it is the
node's own key as 64 upper-case hex characters. For `K_fwd`, `KEY` is the relay's key.

From lou-21 there are two more. One is made the same way, for a node without an MQTT connection
(12.4); `S` and `KEY` are those of the node that announces:

```
K_malive = HKDF-SHA256(ikm S, salt empty, info "mcc3/malive/" ‖ KEY, 32 bytes)
```

The other, `K_gfwd`, is for a forward through a relay that is not the owner's, and is made from a
guest key instead of the command key (15.5).

| key | used for | cipher | nonce |
|---|---|---|---|
| `K_cmd` | commands and results on MQTT, responses on the mesh road | ChaCha20-Poly1305 | 12 random bytes, carried in clear |
| `K_mesh` | requests on the mesh road | ChaCha20, **no tag** | `00 × 8 ‖ counter (u32)`, not carried |
| `K_alive` | alive messages | ChaCha20-Poly1305 | 12 random bytes, carried in clear |
| `K_fwd` | forwards to a relay and their results | ChaCha20-Poly1305 | 12 random bytes, carried in clear |
| `K_malive` | the announce of a node without a connection | ChaCha20-Poly1305, tag cut to 8 bytes | `00 × 4 ‖ boot counter (u32) ‖ sequence (u32)`, both carried in clear |
| `K_gfwd` | guest forwards to a stranger's relay and their results | ChaCha20-Poly1305 | 12 random bytes, carried in clear |

A node derives the keys once per command key and keeps them in RAM. It derives them again
when the command key changes.

### 3.3 Nonces

- A sender draws 12 fresh random bytes for every sealed message.
- A node seals every result, response, forward result and alive message under a **fresh
  random** nonce. A nonce made from the counter would repeat, because a node answers a
  replayed or rate-limited command without taking a new counter.
- On the mesh road the nonce is made from the counter. A sender MUST use one mesh counter for
  exactly one request content. A resend sends the same 136 bytes.
- An announce's nonce is made from the boot counter and the sequence. A node MUST raise the
  sequence for every announce, and the boot counter at every boot, so that no nonce is used
  twice under `K_malive`.

## 4. Topics

| topic | written by | read by | QoS | retained | payload |
|---|---|---|---|---|---|
| `mcc/cmd/<KEY>` | any token login | the node `KEY` only | 1 | no | a sealed command, a sealed forward, or the command server's `pong` |
| `mcc/r/<RID>` | any token login | a subscriber to that exact topic | 1 | no | a sealed result or a sealed forward result |
| `mcc/alive/<KEY>` | the node `KEY` only | anyone; `mcc/alive/+` is allowed | 1 | **yes** | a sealed alive message, or empty |
| `mcc/ping/<KEY>` | the node `KEY` only | nobody; the command server consumes it | 1 | no | `ping\|<8 hex>` |
| `mcc/seen/<KEY>` | the Observer node `KEY` only | nobody; the command server consumes it | 1 | no | a signed announce it heard (12.5). From lou-21 |
| `mcc/node/<KEY>` | the command server only | anyone; `mcc/node/+` is allowed | 1 | **yes** | the shared node store's entry for the node `KEY` (12.6). From lou-21 |

- `RID`, the reply id, is 16 random bytes written as 32 upper-case hex characters. The owner's
  tool draws one per session with the command server. It travels only inside a sealed command
  or forward, so only the node learns where its answer goes.
- There is no topic for more than one node: no region, group, owner or broadcast topic. A
  change for many nodes is one sealed command to each.
- A node subscribes to its own `mcc/cmd/<KEY>` and to nothing else.
- A node sets its MQTT last will to `mcc/alive/<KEY>`, empty payload, QoS 1, retained. The will
  clears the alive message when the connection dies.
- A node MUST drop a **retained** message on its command topic before anything else looks at
  it. The server would replay it at every connect.

### 4.1 Ping

`ping` proves the plane end to end from the node's console. It is not a command.

1. The node publishes `ping|<nonce>` on `mcc/ping/<KEY>`. The nonce is 8 hex characters. One
   ping is in flight at a time.
2. The command server, and never another client, publishes `pong|<the same nonce>` on
   `mcc/cmd/<KEY>`.
3. The node recognises a payload that starts with `pong|` **before** any other parsing. It
   takes it only when it is exactly `pong|` and the nonce of the ping in flight (13 bytes,
   compared without case). It never runs, answers or counts a pong. A pong that does not
   match changes nothing. The node gives up after 10 s.

## 5. The signature

The command key signs with Ed25519 (RFC 8032, pure, no pre-hash) over these bytes:

| size | field |
|---|---|
| 9 | the ASCII label `mcc3/sig\|` (`6D 63 63 33 2F 73 69 67 7C`) |
| 32 | the node's public key, raw |
| 1 | road: `0x00` MQTT, `0x01` mesh |
| 1 | flags, as carried in clear |
| 4 | counter |
| 4 | expiry, unix seconds |
| 16 | RID, raw. **MQTT only**: absent on the mesh road |
| 1..160 | the command, UTF-8, without padding |

The node's key stops a command for one node from verifying on another. The road byte stops an
MQTT command from being replayed over the mesh, and the other way round.

Results, responses, alive messages, forwards and forward results are **not** signed. The seal
is their proof: only the node and the owner hold the key.

### 5.1 The command text

A command is 1 to 160 bytes (1 to 57 on the mesh road). A node accepts:

- ASCII `0x20` to `0x7E`, except `|` (`0x7C`);
- well-formed UTF-8 sequences of 2 to 4 bytes: no overlong form, no surrogate, no code point
  above U+10FFFF.

It refuses control characters, NUL, DEL, `|` and broken UTF-8. A command is zero-padded in
its field, so a zero byte ends it, and a non-zero byte after a zero makes the field invalid.
A sender MUST refuse to build a command outside this rule (vectors under `not_built`).

### 5.2 Flags

| bit | value | where | meaning |
|---|---|---|---|
| 0 | `0x01` | nowhere | Reserved for a delegation block. Its content is not defined. |
| 1 | `0x02` | mesh requests only | Answer with zero hops (section 11.3). |
| 2 to 7 | | | Reserved. |

The flags byte is in clear and inside the signed bytes. On MQTT, in a command and in a
forward, a sender writes 0 and a node refuses any other value. In a mesh request a node accepts
0 or `0x02` and refuses any other value. The refusal is silent, has the name `bad-version`, and
comes before anything is decrypted.

## 6. Messages on MQTT

### 6.1 Command, kind `C`, on `mcc/cmd/<KEY>`

| offset | size | field | AAD | sealed |
|---|---|---|---|---|
| 0 | 1 | kind `0x43` (`C`) | yes | |
| 1 | 1 | flags, 0 | yes | |
| 2 | 12 | nonce, random | yes | |
| 14 | 4 | counter | | yes |
| 18 | 4 | expiry | | yes |
| 22 | 16 | RID | | yes |
| 38 | 64 | signature, road `0x00` | | yes |
| 102 | 64 or 160 | command, zero-padded to 64, or to 160 when it is longer than 64 | | yes |
| 166 or 262 | 16 | Poly1305 tag | | |

Sealed with `K_cmd`. The AAD is bytes 0 to 13. A command is **182 or 278 bytes**, 243 or 371
characters. No other size is a command. The two sizes hide the length of the command.

### 6.2 Result, kind `R`, on `mcc/r/<RID>`

| offset | size | field |
|---|---|---|
| 0 | 1 | kind `0x52` (`R`), AAD |
| 1 | 12 | nonce, random, AAD |
| 13 | 256 or 512 | sealed with `K_cmd`, see below |
| 269 or 525 | 16 | Poly1305 tag |

The sealed part, zero-padded to 256 bytes, or to 512 when it is longer than 256:

| offset | size | field |
|---|---|---|
| 0 | 4 | the command's counter |
| 4 | 1 | result code (section 8.3) |
| 5 | 4 | the node's clock, unix seconds; 0 when the clock reads before 1735689600 |
| 9 | 1 | command length `n`, 0..160 |
| 10 | n | the command, echoed |
| 10 + n | | the reply, UTF-8 |

A result is **285 or 541 bytes**, 380 or 722 characters. The reply is cut on a UTF-8 character
boundary so that the whole fits 512 bytes. It is cut, never dropped. Trailing zero bytes are
padding.

The topic and the clear bytes name no node. The owner tries the `K_cmd` of every node it awaits
an answer from on this RID. The result that opens is that node's. The counter inside is the
one the owner chose, so it says which command was answered.

A node publishes a result at QoS 1, not retained.

### 6.3 Forward and forward result

A forward (kind `F`, `0x46`) also arrives on `mcc/cmd/<KEY>`, and a forward result (kind `f`,
`0x66`) also goes to `mcc/r/<RID>`. A forward is 278 bytes, as the larger command is. A
forward result is 285 bytes, as the smaller result is. The **kind byte** tells them apart,
after b64url decoding and before any key is used. Section 15 has their layouts.

## 7. Messages on the mesh road

A command on the mesh road is the content of a MeshCore **anonymous request** (payload type
`ANON_REQ`) addressed to the node's key. MeshCore encrypts that datagram between the sender's
key and the node's key as it does any anonymous request. The bytes below are what is inside
that encryption. A companion radio hands the node's answer to the owner's tool as a binary
response.

### 7.1 Request, sub-type `0xC2`

Always exactly 136 bytes, the most an anonymous request holds.

| offset | size | field | |
|---|---|---|---|
| 0 | 4 | tag. The sender's radio writes it. The node echoes it in the response | clear |
| 4 | 1 | sub-type `0xC2` | clear |
| 5 | 1 | flags: 0, or `0x02` | clear |
| 6 | 4 | counter | clear; it is the nonce |
| 10 | 4 | expiry | ChaCha20 under `K_mesh` |
| 14 | 64 | signature, road `0x01`, no RID | ChaCha20 |
| 78 | 58 | command of 1..**57** bytes, zero-padded. The last byte is always 0 | ChaCha20 |

The cipher is RFC 8439 ChaCha20 with key `K_mesh`, nonce `00 × 8 ‖ counter`, **starting at
block counter 1**. That is exactly the ciphertext of ChaCha20-Poly1305 with its tag left off,
so any library that has the AEAD can produce it. There is **no authentication tag**: the
request has no room for one. The signature inside is its integrity.

Why a changed bit cannot pass without a tag. ChaCha20 is malleable: a flipped ciphertext bit
flips the same plaintext bit. Every plaintext byte is covered. The expiry and the command are
in the signed bytes. The padding is covered because the unpadded command is a function of the
whole 58-byte field: a change in the padding either leaves a non-zero byte after a zero, which
the character rule refuses, or changes the signed command. A changed counter changes both the
keystream and the signed counter. A changed sub-type is refused before decryption. A changed
flags byte is refused before decryption, or, between 0 and `0x02`, fails the signature.

A node reads the first 136 bytes of the decrypted datagram and ignores MeshCore's block
padding after them. A request shorter than 136 bytes is refused.

An owner's tool that sends through a companion radio hands the radio the node's key and the
132 bytes from the sub-type on. The radio adds the tag.

### 7.2 Response

| offset | size | field |
|---|---|---|
| 0 | 4 | tag, echoed from the request |
| 4 | 1 | kind `0x52` (`R`), AAD |
| 5 | 12 | nonce, random, AAD |
| 17 | 9 + n | sealed with `K_cmd`: counter (u32) ‖ result code (u8) ‖ node clock (u32) ‖ reply (n bytes) |
| 26 + n | 16 | Poly1305 tag |

The AAD is bytes 4 to 16. The response is **not padded**, to save airtime. It has no command
echo. It keeps its tag, because the node does not sign it. The radio that carries it cannot
read it.

The reply is cut on a character boundary to fit the packet. A plain datagram holds 167 bytes,
so `n` is at most 125. A response that travels inside a flooded path return has 161 bytes less
the bytes of the path it carries back, so `n` is at most 119 less those bytes.

MeshCore carries a datagram in whole 16-byte cipher blocks and hands it over zero-filled to
the block edge. A receiver may therefore see up to 15 zero bytes after the tag. The opener
tries the length it was given, then drops one trailing zero byte at a time, at most 15 times.
The tag says which length is the response.

## 8. What a node checks, in order

The order matters for two reasons. Cheap checks come before expensive ones. Nothing is
answered, and no budget is spent, before the command key has vouched for the message.

### 8.1 On MQTT

| step | check | when it fails |
|---|---|---|
| 1 | The message is not retained | dropped |
| 2 | The payload does not start with `pong\|` | handled as a pong (4.1), never as a command |
| 3 | The plane is on (`cmd`) | dropped, not counted |
| 4 | A command key is set | silent, `no-owner-key` |
| 5 | The first byte after b64url decoding is not `0x46` | handled as a forward (section 15) |
| 6 | b64url of 182 or 278 bytes with kind `0x43` | silent, `bad-fields` |
| 7 | flags is 0 | silent, `bad-version` |
| 8 | The seal opens under `K_cmd` | silent, `sig-invalid` |
| 9 | The command field holds a valid command (5.1) | silent, `command-chars` |
| 10 | The signature verifies with the command key | silent, `sig-invalid` |
| | *The command is authentic. Every outcome from here is answered on `mcc/r/<RID>`.* | |
| 11 | counter > the stored counter | answered, `replay` (9) |
| 12 | The clock does not read 0 | answered, `no-clock` (12) |
| 13 | expiry ≥ now | answered, `expired` (10) |
| 14 | expiry − now ≤ 3600 | answered, `expiry-too-far` (11) |
| 15 | The command is admitted (section 14) | answered, `not-allowed` (14) |
| 16 | The rate limit has room (section 9.1) | answered, `rate-limited` (17) |
| 17 | **Store the counter**, then run the command | |
| 18 | Publish the sealed result with code 0 and the reply | |

Rules that go with the table:

- When steps 6 to 10 fail and a new key is waiting from `rekey`, the node tries the waiting
  key (section 13).
- The counter is compared strictly: an equal counter is a replay.
- The counter is stored in non-volatile memory **before** the command runs. A crash in the
  middle of a command then loses that command. It never runs it twice.
- An answered refusal does not store the counter. The same counter can be sent again after the
  cause is gone.
- The rate limiter is asked only after every check that needs no state, so that refused
  messages cannot use up the budget.
- A silent refusal is counted on the node for its owner to read locally. It is never sent.
- Code 0 means the command reached the node's command interpreter. The reply text says what
  the interpreter did with it, and can itself be an error text.

### 8.2 On the mesh road

| step | check | when it fails |
|---|---|---|
| 1 | Byte 4 is `0xC2` | not this protocol's. See below for `0xC1` |
| 2 | The plane is on, and `cmd.mesh` is not `off` | silent, not counted |
| 3 | At least 136 bytes | silent, `bad-fields` |
| 4 | flags is 0 or `0x02` | silent, `bad-version` |
| 5 | A command key is set | silent, `no-owner-key` |
| 6 | counter > the stored counter | silent, `replay`. Nothing is decrypted |
| 7 | Decrypt with `K_mesh`. The command field holds a valid command of 1..57 bytes | silent, `command-chars` |
| 8 | The signature verifies, over the flags as they arrived | silent, `sig-invalid` |
| 9 | counter > the newest counter already answered over the mesh since boot | silent, `replay` |
| 10 | The mesh answer budget has room (section 9.2) | silent, `rate-limited`. The command does not run |
| | *Every outcome from here is answered over the mesh. The counter is now remembered as answered.* | |
| 11 | The road is open (see below) | answered, `mesh-closed` (19) |
| 12 | The clock rule of section 10.2 | answered, `expired` (10) or `expiry-too-far` (11) |
| 13 | The command is admitted, with the mesh allowance (section 14.3) | answered, `not-allowed` (14) |
| 14 | The rate limit has room (section 9.1) | answered, `rate-limited` (17) |
| 15 | **Store the counter**, then run the command | |
| 16 | Send the sealed response with code 0 and the reply | |

Rules that go with the table:

- When step 7 or 8 fails and a new key is waiting from `rekey`, the node tries the waiting key.
- Steps 9 and 10 exist so that nobody who overheard a request can make the node transmit by
  sending it again. A request that was answered with a refusal is remembered by its counter
  until the next restart and is not answered a second time.
- **The road is open** when `cmd.mesh` is `on`; or when it is `auto` and the node's connection
  to the command server has been down for 15 minutes; or always on a node built without an
  MQTT connection. "Down" includes a connection that the command server accepts while it
  refuses the node its command topic. With `cmd.mesh off` the node does not listen at all.
- A node on which the MQTT road works therefore answers an authentic mesh request with
  `mesh-closed`. The owner sends over MQTT.
- **The old request.** Byte 4 `0xC1` was the request of lou-20 and older. A lou-21 node does
  not parse, verify or answer it. It SHOULD still take it away from MeshCore's login handler,
  which would otherwise count it as a failed password login against the sender's key.

### 8.3 Result codes

The numbers are fixed. New codes are appended. A reader MUST show an unknown code as unknown,
not guess. `data/results.json` has the same table with a text for a person.

| code | name | on MQTT | on the mesh road |
|---|---|---|---|
| 0 | `ok` | answered: the command ran; the reply holds its output | the same |
| 1 to 5 | `empty`, `too-long`, `no-signature`, `bad-sig-len`, `bad-sig-hex` | not used by mcc3 | not used |
| 6 | `bad-version` | silent | silent |
| 7 | `bad-fields` | silent | silent |
| 8 | `bad-counter` | not used by mcc3 | not used |
| 9 | `replay` | **answered** | silent |
| 10 | `expired` | answered | answered |
| 11 | `expiry-too-far` | answered | answered |
| 12 | `no-clock` | answered | does not occur |
| 13 | `command-chars` | silent | silent |
| 14 | `not-allowed` | answered | answered |
| 15 | `no-owner-key` | silent | silent |
| 16 | `sig-invalid` | silent | silent |
| 17 | `rate-limited` | answered | answered for the command budget; silent for the answer budget |
| 18 | `broadcast-transmit` | never returned; the number stays taken | never returned |
| 19 | `mesh-closed` | does not occur | answered |

A silent refusal never reaches the owner, so its code is seen only on the node itself. To the
owner, silence has many causes: a node that is off, another command key, a replay over the
mesh, a used-up answer budget. Silence is never a refusal the owner can rely on. The node may
have run the command and lost the answer.

## 9. Budgets

A node enforces all of these on commands that are validly signed. They are compiled in. They
are kept in RAM, so a restart resets them.

### 9.1 Commands

- **50 commands in any 3600 s**, for both roads together. The window slides: no span of 3600 s
  holds more than 50. The 51st is answered `rate-limited`.
- **2 transmit commands in any 3600 s**, on a separate count. A transmit command is one that
  starts with `trigger`: it makes the node originate a test on the air. A transmit command
  spends only this count. Any other command spends only the first.
- A refused command spends nothing.

### 9.2 Airtime of answers over the mesh

A node's answers on the mesh road have an airtime budget in two alternating quarters of an
hour:

- The first answer opens a **burst** of 900 s in which answers may use **45 s** of airtime
  (5 %).
- The 900 s after the burst are a **cooldown** with **9 s** (1 %).
- The answer after the cooldown opens the next burst.

Airtime is the radio's own estimate for each packet, so the shares hold on any radio setting.
A packet is allowed while any airtime is left, so the packet that crosses the line is the last
one sent. A request that arrives when nothing is left is not answered and not run (8.2,
step 10).

### 9.3 A relay's requests

A relay's transmissions have their own budget of the same shape as 9.2: a burst of 900 s with
45 s of airtime, then a cooldown of 900 s with 9 s. The path a relay sends back to a target
(section 11.2) is counted in it as well.

A flooded request also costs every repeater that hears it. Floods therefore have limits of
their own:

| limit | value |
|---|---|
| gap between two floods | 60 s; 300 s while the airtime budget is in a cooldown |
| floods in a day (86400 s from the first one counted) | 100 |
| wide floods in any 3600 s | 2 |
| forwards waiting for an answer at one time | 1 |

A flood is **wide** when it leaves the relay's region home: route 2, or route 1 on a relay
that has no region home. The relay asks the budget before it sends and spends it only for a
request that went out. A request that could not be queued costs nothing.

### 9.4 The arrivals queue

A lou-21 node holds four arriving MQTT messages and takes one per pass of its main loop. A
fifth that arrives while four wait is dropped without an answer. A payload over 512 characters
is never queued. A sender SHOULD send one command to a node and wait for its result.

## 10. The clock

### 10.1 On MQTT

A node with an MQTT connection has network time. The expiry is always judged against the
node's clock: `expired` when the expiry has passed, `expiry-too-far` when it is more than
3600 s ahead. A clock that reads 0 refuses every command as `no-clock`. `time` is denied on
this road.

### 10.2 On the mesh road

A node without a network has no time source.

- **A clock that was never set.** A clock that reads before 1735689600 (2025-01-01 UTC) is
  unset. So is a power-on placeholder that only counts up from a fixed date. For such a clock
  the expiry is **not checked**. The counter alone stops a replay.
- **A clock that was set** is used as on MQTT, without the `no-clock` case.
- **`time <epoch>`** mends a clock that has fallen behind. The mesh road admits it although
  the deny list refuses `time` (section 14). It is the command `time`, one space, and a decimal
  unix time of at least 1735689600 that fits a `u32`. It is judged **by its own word, not by
  the clock it is sent to mend**: the time it names MUST be at or before the command's own
  signed expiry, and at most 3600 s before it. If the expiry is before that time the result is
  `expired`. If it is more than 3600 s after, the result is `expiry-too-far`. The node's clock
  is not consulted. The counter still refuses a replay.
- The node moves its clock **forward only**. A `time` that is not later than the node's clock
  is answered with code 0 and an error text, and changes nothing. A clock that is ahead
  cannot be mended remotely.

An owner's tool signs "now" and an expiry a few minutes later, which passes on a node that is
years behind.

### 10.3 The clock in answers

Results, mesh responses, forward results and alive messages carry the node's clock, or 0 when
it reads before 1735689600. A reader uses it to see a node whose clock is wrong. A non-zero
value is not proof that the clock was ever synchronised.

## 11. Answering over the mesh

### 11.1 Delay and route

| the request arrived | the answer | delay before it is sent |
|---|---|---|
| flooded | a flooded MeshCore path return that carries the response | **15 to 30 s**, drawn at random |
| direct, and a way back is known | a direct datagram along that way | 300 ms |
| direct, and no way back is known | a flooded datagram | 300 ms |
| with flags `0x02` | one direct transmission with an empty path, whatever else holds | as above for how it arrived |

The delay for a flooded request lets the copies of the request die down around the node. An
answer sent at once goes out while the repeaters around are still repeating the request, and
is lost. The delay is random so that two nodes do not answer one flood in step.

A sender therefore waits long for an answer: the reference tool waits 90 s through a
companion, and a relay waits 120 s.

### 11.2 The way back

A request that came direct tells the node no path to its sender. The node learns one as
follows.

1. The answer to a flooded request is a flooded path return.
2. Whoever receives a flooded path return sends MeshCore's **reciprocal path** direct to the
   node: the path the answer took. A relay MUST do this. A MeshCore companion does it by
   itself.
3. For 300 s after it answers a sender, the node accepts that path from that sender. It keeps
   the path in RAM for the **3 senders** it answered last. A path is at most 64 bytes.
4. The node answers later direct requests from that sender along the path.

After a restart, or when a path has stopped working, a direct command stays unanswered. One
flooded command cures it: its answer is flooded and renews the path in both directions.

### 11.3 The zero-hop flag

Flags `0x02` in a mesh request says: answer with one direct transmission and an empty path.
The bit is inside the signature, so nobody on the way can set or clear it. A sender sets it
only in a request that a relay sends with route 0 and path length 0, where the target hears the
relay directly. The whole exchange is then two transmissions. A sender MUST NOT set it in a
request sent through a companion, whose stored path can be stale. If the link works in one
direction only, the answer is lost although the command ran.

## 12. The alive message

An alive message is how an owner finds its nodes that have an MQTT connection. A node without
one sends no alive message. From lou-21 it announces itself over the mesh, any lou-21 Observer
node hands the announce to the command server, and the owner finds it there (12.4 to 12.8).
There is no other discovery.

### 12.1 Layout, kind `A`, on `mcc/alive/<KEY>`, retained

| offset | size | field |
|---|---|---|
| 0 | 1 | kind `0x41` (`A`), AAD |
| 1 | 12 | nonce, random, AAD |
| 13 | 160 | sealed with `K_alive`, see below |
| 173 | 16 | Poly1305 tag |

Always **189 bytes, 252 characters**, whatever it says. The sealed part, zero-padded to 160:

| offset | size | field |
|---|---|---|
| 0 | 4 | boot counter. Stored on the node, +1 at every boot, before any alive message is sent |
| 4 | 4 | sequence since boot, from 1 |
| 8 | 4 | uptime, seconds |
| 12 | 4 | node clock (10.3) |
| 16 | 4 | the stored command counter |
| 20 | 4 | the alive interval in force, seconds |
| 24 | 1 | flags, below |
| 25 | 1 | `cmd.mesh`: 0 off, 1 on, 2 auto |
| 26 | 4 | command-key fingerprint: the key's first 4 bytes |
| 30 | 1 | how the command key was set: 0 local console, 1 a remote admin login, 2 `rekey` |
| 31 | 1 | reserved, 0 |
| 32 | 1 + n | firmware version: length, then n ≤ 31 bytes |
| … | 1 + n | region home, in lower case: length, then n ≤ 29 bytes. Length 0 when there is none |
| … | 1 + n | node name: length, then n ≤ 32 bytes |

Strings are UTF-8, cut on a character boundary.

| flags bit | value | meaning |
|---|---|---|
| 0 | `0x01` | Reserved, never set. lou-20 set it while it still accepted the older scheme |
| 1 | `0x02` | the node has an MQTT connection of its own |
| 2 | `0x04` | the node has the auto-reply feature |
| 3 | `0x08` | the clock field is not 0 |
| 4 | `0x10` | the node relays for its owner (`relay own`) |
| 5 to 7 | | reserved |

### 12.2 Cadence

- The first one 0 to 120 s after the first connect to the command server.
- Then one every `interval × U(0.5, 1.5)`, drawn afresh each time. The interval is
  `alive.interval`: 5 to 1440 minutes, 15 by default. There is no "off".
- One 5 to 60 s after a reconnect. The will cleared the topic when the link died.
- One within 5 to 60 s after the command key, the region home or the interval changed.
- **None while no command key is set**, and none while the plane is off. There is nobody to
  seal it to.

The random spread keeps a fleet that restarted together from announcing itself in step.

### 12.3 Reading

The owner subscribes to `mcc/alive/+`. For each node key it computes `S` once, derives
`K_alive` and tries to open the message. One that opens is the owner's node. One that does not
open is another owner's, or was sealed to a command key the node no longer has. An **empty
payload** is the will: the node is offline. A message with a higher `(boot counter, sequence)`
replaces a lower one. A lower one is a stale copy.

A node without an MQTT connection sends no alive message. Up to lou-20 its owner adds it to a
tool by its public key. From lou-21 it announces itself.

### 12.4 The announce, kind `M`, flooded over the mesh, signed (lou-21)

A node without an MQTT connection that has a command key, the plane on and a region sends an
announce. It is the payload of one `ANON_REQ` packet. Repeaters forward it as they forward any
`ANON_REQ`. They do not read it.

Always **165 bytes**:

| offset | size | field |
|---|---|---|
| 0 | 1 | the first byte of the node's key (where `ANON_REQ` has its destination hash) |
| 1 | 32 | the node's key (where `ANON_REQ` has its sender), AAD, signed |
| 33 | 1 | kind `0x4D` (`M`), AAD, signed |
| 34 | 4 | owner tag: `SHA-256("mcc3/own\|" ‖ command key ‖ node key ‖ boot counter ‖ sequence)[0:4]`, AAD, signed |
| 38 | 4 | boot counter, AAD, signed |
| 42 | 4 | sequence since boot, from 1, AAD, signed |
| 46 | 47 | sealed with `K_malive`, see below, signed |
| 93 | 8 | the first 8 bytes of the Poly1305 tag, signed |
| 101 | 64 | Ed25519 signature by the **node's identity key** over `"mcc3/ann\|" ‖ bytes 1 to 100` |

The nonce is `00 × 4 ‖ boot counter ‖ sequence`. The associated data is bytes 1 to 45. The
sealed part, zero-padded to 47:

| offset | size | field |
|---|---|---|
| 0 | 4 | uptime, seconds |
| 4 | 4 | node clock (10.3) |
| 8 | 4 | the stored command counter |
| 12 | 1 | flags, as in the alive message (12.1) |
| 13 | 2 | battery, millivolts. 0 when the board cannot read it |
| 15 | 1 + n | firmware version: length, then n ≤ 14 bytes |
| … | 1 + n | node name: length, then n ≤ 16 bytes, cut |

- **Anyone can check the signature**, so anyone can tell a real announce from a forged one. Who
  owns the node stays hidden: the owner tag and the seal need the owner's command key.
- The owner tag lets the owner skip other owners' announces with one SHA-256 and no X25519.
  Anyone who knows the owner's public command key can make a tag, so a tag proves nothing.
- A node sends one 5 to 60 s after it starts, after the command key is set and after the plane
  is switched on. Then every 23 hours, or every 12 hours while it reports reliably to an
  Observer node nearby (12.7), each with a spread of one tenth either way. A node with an MQTT
  connection never sends one.
- The flood stays inside the node's region home, or its default region when it has no home. A
  node with neither does not flood. It is about 1.6 s on the air at SF8, 62.5 kHz, CR 4:8. The
  node counts it in the airtime budget of its answers over the mesh (9.2).
- The 101 bytes that lou-21 first built, without the signature, are not an announce: every
  check below drops them.

### 12.5 The Observer hands it on: kind `S` on `mcc/seen/<KEY>` (lou-21)

An Observer node on lou-21 with the plane on looks at every `ANON_REQ` of exactly 165 bytes with
`0x4D` at offset 33, whoever owns the node, before the packet goes on as usual. It checks the
signature. One that fails is dropped in silence. A valid one it publishes **once, not retained**,
on `mcc/seen/<its own key>`:

| offset | size | field |
|---|---|---|
| 0 | 1 | kind `0x53` (`S`) |
| 1 | 164 | the announce, bytes 1 to 164 |
| 165 | 1 | SNR, signed, in quarter dB |
| 166 | 1 | hops the announce had travelled |
| 167 | 1 | via: 0 a zero-hop state packet (12.7), 1 direct along a path, 2 a flood |

Always **168 bytes, 224 characters**. The Observer node keeps nothing about other nodes:

- It skips a `(node key, boot counter, sequence)` it published in the last 600 s.
- It publishes at most one in 2 s. While the server cannot be reached it holds up to 8 in RAM,
  drops the oldest when full, and loses them at a restart.
- The server adds the time of arrival. The Observer node's clock is not trusted.

### 12.6 The shared node store: kind `N` on `mcc/node/<KEY>`, retained (lou-21)

The command server keeps one entry per node key. For each `mcc/seen/` it receives, it checks the
kind, the length and the node's signature, and drops a failure. It never opens the seal and holds
no owner key. The entry holds:

- the newest signed announce by `(boot counter, sequence)`. An older one is ignored;
- two lists of catchers: those of the current announce and those of the one before. Each list
  holds the **first 4** Observer nodes to report that announce. A later report of the same
  announce is not added. A newer announce moves the current list to the previous and starts a
  new one with its reporter.

The server publishes the entry, retained, on `mcc/node/<the node's KEY>` whenever it changes:

| offset | size | field |
|---|---|---|
| 0 | 1 | kind `0x4E` (`N`) |
| 1 | 164 | the announce, bytes 1 to 164 |
| 165 | 1 | count of catchers, 0 to 8 |
| 166 | 40 × count | per catcher: Observer key (32), arrival (u32, the server's clock), SNR (i8, quarter dB), hops (u8), via (u8), list (u8: 0 current, 1 previous) |

166 bytes and 40 for each catcher: 486 bytes with 8. Byte 0 of the announce is the first byte of
the node key and is not stored. An entry with no newer announce is dropped after 365 days.

### 12.7 Reporting nearby: the zero-hop state, the acks and the ladder (lou-21)

A node within direct range of an Observer node reports without a flood. These packets are
between nodes only. A tool never sends or reads them, and a stock or older node forwards or
ignores them.

**State, `0xA0`.** A MeshCore `PAYLOAD_TYPE_CONTROL` (0x0B) packet whose first byte has the top
bit set is zero-hop: it has no path and no repeater forwards it.

| offset | size | field |
|---|---|---|
| 0 | 1 | `0xA0` |
| 1 | 2 | the named Observer node's key, first 2 bytes; `00 00` names none |
| 3 | 164 | the signed announce, bytes 1 to 164 |

**167 bytes.** Every lou-21 Observer node that hears it publishes it (12.5, via 0) and acks it.

**Ack, `0xB0`**, the same packet type, zero-hop, **41 bytes**, unsigned:

| offset | size | field |
|---|---|---|
| 0 | 1 | `0xB0` |
| 1 | 4 | the reporting node's key, first 4 bytes |
| 5 | 4 | the report id: the first 4 bytes of the announce's signature |
| 9 | 32 | the Observer node's whole key |

The named Observer node acks 100 to 300 ms after the state packet. Another waits 3 s, and with
nobody named 0.5 to 3 s at random. Each drops its ack when it hears another's for the same report.
An ack needs `cmd on` but no command key, and counts in the airtime budget of answers (9.2).

**Direct report.** An `ANON_REQ` sent direct along a path the node learnt: the 165-byte announce,
then the Observer node it is for (its key's first 2 bytes), the path length (u8) and the path from
the node to that Observer node; at most 184 bytes. The trailer is outside the signature. Only the
named Observer node takes it (12.5, via 1).

**Path ack, kind `0x4B`.** An `ANON_REQ` sent direct along the path reversed, **55 bytes**:

| offset | size | field |
|---|---|---|
| 0 | 1 | the node's key, first byte (the destination hash) |
| 1 | 32 | the Observer node's key |
| 33 | 1 | kind `0x4B` (`K`) |
| 34 | 4 | the report id |
| 38 | 1 | path length |
| 39 | 16 | the path from the node to the Observer node, zero after it |

An Observer node path-acks a direct report, and a flood that came with 1 to 8 hops and at most 8
bytes of path; a flood heard with no hops is acked with `0xB0`. Of the Observer nodes that heard a
flood, the first to ack wins: each waits 100 ms + 3 s a hop + 5 ms for each quarter dB below
+15 dB (SNR clamped to −25..+15 dB) + 0 to 200 ms.

**The ladder**, for each report: up to 3 state packets 8 to 20 s apart, each naming the best
Observer node the node knows; with no ack, one direct report along a learnt path (30 s for its
path ack); then the flood of 12.4 (90 s for a path ack). The node keeps up to 4 Observer nodes on
its flash with the path each taught, and reports every 12 hours while one of them acked 3 of its
last 4 first tries. A board without room for the ladder floods every 23 hours.

### 12.8 Reading the store

The owner's tool subscribes to `mcc/node/+`. Nothing is sent, and no airtime is used. For each
entry, in this order:

1. The topic's key is the announce's node key, and the entry has the layout of 12.6.
2. Compute the owner tag with the owner's own command key and compare it with bytes 34 to 37 of
   the announce. Nearly every entry stops here: it is someone else's node.
3. Verify the node's signature (12.4).
4. Derive `S` and `K_malive` from the owner's key and the **node's** key. Decrypt the 47 bytes,
   compute the Poly1305 tag over the associated data and the ciphertext as RFC 8439 does, and
   compare its first 8 bytes with bytes 93 to 100.

An entry that fails is skipped in silence. A tool MUST NOT show an announce it has not verified.
It SHOULD remember the `(node key, boot counter, sequence)` of every entry tried, so that it
opens only new or changed ones. The catchers of an entry are the relays that can reach the node
(15.5); the battery reading is as old as the announce and is shown with its arrival time.

Because a tool checks the tag before the signature, an announce whose boot counter or node key
was changed fails at step 2 in a tool and at the signature in an Observer node or the server.
Both drop it; the vectors give the Observer node's word.

Known weaknesses, left as they are: the store is public, so anyone can see that a node is a lou
node without Wi-Fi and which Observer nodes hear it how well. An ack is unsigned: a forged one
makes a node skip its fallback for one round. A node that loses its stored boot counter uses
`(boot counter, sequence)` nonces again under the same key.

## 13. Replacing the command key: `rekey`

`rekey <new key>` replaces the command key without physical access. It is a command like any
other: signed by the key in use, on either road, inside the budgets.

- The new key is the new **public** key, 32 bytes as 43 b64url characters. The spare two bits
  of the last character MUST be zero. The command is 49 bytes and fits the mesh road.
- **Step 1.** The node answers code 0. The new key only **waits**, in RAM. The key in use
  stays the key and keeps working.
- The wait ends after **60 minutes**, or at the next restart. Then the offer is gone and
  nothing has changed.
- **Step 2.** A message arrives that does not verify under the key in use. The node tries it
  under the waiting key's `K_cmd` or `K_mesh` and the waiting key's signature. If it is a
  valid command of the waiting key, the waiting key **takes over** at that moment: the node
  stores it, records that it was set by `rekey`, and derives its four keys.
- That command then runs through the remaining checks as usual. Its counter MUST still be
  above the stored one: the counter is not reset. Its answer is sealed under the new keys. A
  new alive message follows within 5 to 60 s.
- From then on the old key verifies nothing.

A mistyped or lost key changes nothing, because no command signed by it ever arrives. A second
`rekey` in the window replaces the waiting key and starts the 60 minutes again. A `rekey` that
names the key in use, or a malformed one, is answered with code 0 and an error text.

A forward does not complete a rekey: a relay opens forwards under the key in use only. The
local console has no `rekey`. Setting the key there is `set cmd.pubkey`.

`rekey` cannot stop one thing: whoever holds a node's command key can replace it before the
owner does.

## 14. What may be sent: the deny list

The plane is a command centre for a node's owner. Every command the node's console answers
may be sent, **except** what the deny list refuses. `data/denylist.json` holds the list in a
form a tool can load. Note that it also lists the setting names of firmware before lou-20
(`mqtt.cmd…`), which lou-21 does not know.

### 14.1 The rule

A command is admitted when all of these hold, tested in this order:

1. It passes the character rule (5.1).
2. It matches no **denied family**. A family matches when the command starts with it, without
   regard to case, and then ends or continues with a space or a dot. So `set radio` denies
   `set radio.rxgain`, and `set tx` does not deny `set txdelay`.
3. It starts with no **secret prefix**, without regard to case and with no boundary at all.
4. It is not a read of a server slot's credentials: `get mqtt<digit>.password`, `.token` or
   `.username`.
5. On a node without the auto-reply feature, it does not start with `trigger`,
   `set autoreply` or `get autoreply`.
6. It is not a bare `set` or `get`.
7. It starts with an **admitted verb**.

Anything else is answered `not-allowed`.

| denied family | why |
|---|---|
| `set prv.key`, `set public.key` | identity: a changed key is a different node |
| `set cmd` (so also `set cmd.pubkey`, `set cmd.slot`, `set cmd.mesh`), `get cmd.pubkey` | the plane itself: it would take the node out of its owner's reach |
| `set wifi.pwd`, `get wifi.pwd`, `set wifi.ssid`, `get wifi.ssid`, `set password`, `get password`, `password`, `set guest.password`, `get guest.password`, `set alert.psk`, `get alert.psk`, `set bridge.secret`, `get bridge.secret`, `set snmp.community`, `get snmp.community`, `set tls`, `get tls`, `tls.bundletest`, `get prv.key` | credentials, read and written |
| `set mqtt.email`, `get mqtt.email`, `set mqtt.owner`, `get mqtt.owner`, `set owner.info`, `get owner.info` | whose the node is |
| `erase`, `start`, `poweroff`, `shutdown`, `set bootloader.ver` | destructive, or no way back |
| `set lat`, `set lon`, `get lat`, `get lon`, `set role`, `set repeat` | position and role. `set repeat off` would let a leaked key silence a region |
| `set freq`, `set radio`, `set tx`, `set extra.sf`, `set dutycycle`, `tempradio` | the radio: a wrong value takes the node off the mesh |
| `advert`, `alert`, `set advert.interval`, `set flood.advert.interval` | transmissions and airtime |
| `time` | it steps the clock that judges expiry (the mesh road's exception: 10.2) |
| `log`, `stats-core`, `stats-packets`, `stats-radio`, `stats-radio-diag` | local console only |

Secret prefixes: `get prv`, `set prv`, `get password`, `set password`, `get guest.password`,
`get wifi.pwd`, `set wifi.pwd`, `get alert.psk`, `set alert.psk`, `get bridge.secret`,
`set bridge.secret`, `get snmp.community`, `set snmp.community`, `get cmd.pubkey`, `set cmd`,
`get tls`, `set tls`.

Admitted verbs, as families (boundary rule): `set`, `get`, `region`, `trigger test`,
`trigger private`, `neighbor.remove`, `sensor`, `gps`, `powersaving`, `clock`, `rekey`.
Admitted exactly, with nothing after: `ver`, `reboot`, `clkreboot`, `neighbors`, `board`,
`memory`, `clear stats`, `ota check`, `ota update`, `cmd ping`.

A verb that a firmware adds later does not travel until it is added to the list.

### 14.2 The second gate

The deny list is one of two independent gates. The other: a command from the plane MUST NOT
run with the privilege of the local console. In MeshCore's command interpreter that privilege
is a sender timestamp of 0, so a plane command runs with a non-zero timestamp, even when the
node's clock reads 0. Either gate alone MUST keep these out of the plane's reach: reading or
changing the node's private key, erasing the node, and setting the command key.

The command key can be set in three ways only: at the local console; by `rekey`; and, for a
node that has **no** key yet, by a remote admin who logged in over the mesh with the admin
password. That is allowed only while the admin password is not the factory default, has at
least 8 characters and differs from the guest password. The plane cannot present itself as
that admin.

### 14.3 What the mesh road alone admits

On a node with an MQTT connection, the mesh road also admits the repair of that connection.
The match is case-sensitive and needs a value:

- `set wifi.ssid <name>`
- `set wifi.pwd <password>`
- `set cmd on` and `set cmd on <host>`

and `time <epoch>` under the rule of section 10.2. They are admitted here only, because a mesh
request is encrypted to the node. Everything else the deny list refuses stays refused.

A node built **without** an MQTT connection has nothing to repair. There the allowance does
not apply, and these are refused as `not-allowed`: `ota check`, `ota update`, `cmd ping`, and
`set mqtt<digit>.…`. `time <epoch>` is admitted there too.

### 14.4 The settings' names

These names are part of the protocol, because tools send them and the deny list is written in
them.

| setting | values | who may change it |
|---|---|---|
| `cmd` | `set cmd on`, `set cmd on <host>`, `set cmd off`; `get cmd` reads the state | local console; a mesh admin; the mesh road for the two `on` forms. Never over MQTT |
| `cmd.pubkey` | 64 hex characters, the **public** command key | section 14.2. Never the plane |
| `cmd.slot` | which of the node's MQTT connections carries the plane | local console; a mesh admin |
| `cmd.mesh` | `off`, `on`, `auto` (default) | local console; a mesh admin |
| `relay` | `off`, `own` (default up to lou-20), `any` (lou-21, its default) | anyone above, **and the plane** on both roads. The name is outside `cmd` for this reason |
| `relay.guest` | 0 to 100, default 10: the floods a day one guest key may have (15.5). From lou-21 | anyone above, and the plane |
| `alive.interval` | 5 to 1440 minutes, default 15 | anyone above, and the plane |

`set cmd on <host>` points the plane at a command server by host name: letters, digits, `.`
and `-`, at most 50 characters, for example `set cmd on broker.example`. The node then
connects to `mqtts://<host>:8883` and signs in with a token whose audience is that host
(section 16.1). `set cmd on` alone selects the firmware's built-in default server.

`cmd ping` starts a ping (4.1). `get relay`, `get relay.guest`, `get cmd.mesh`, `get alive.interval`, `get stats`
and `get sensors` are reads that tools send. Their reply texts are not part of this protocol
(section 18.5).

## 15. The relay

A relay lets an owner reach a node that has no MQTT connection without a companion radio near
it. The owner builds an ordinary mesh request for the target (section 7.1), wraps it in a
**forward** and publishes it on the relay's `mcc/cmd/<RELAY KEY>`. The relay transmits the
request as its own anonymous request, waits for the answer, and publishes a **forward result**
on the `mcc/r/<RID>` that the forward names.

- A forward is from the holder of **the relay's own** command key. That is what opening under
  its `K_fwd` proves. From lou-21 a relay with `relay any` also takes a guest forward from
  anyone (15.5). Up to lou-20 a node without a command key never relays.
- A forward runs nothing on the relay. It never reaches the relay's command interpreter. The
  relay's command counter, deny list and command budget are not involved. On the target they
  apply to the request as to any mesh request.
- The relay cannot read the request or the response: they are sealed between the target and
  its owner.
- A forward and its result are authenticated by the seal under `K_fwd` alone. They are not
  signed.

### 15.1 Forward, kind `F`

| offset | size | field | |
|---|---|---|---|
| 0 | 1 | kind `0x46` (`F`) | clear, AAD |
| 1 | 1 | flags, 0 | clear, AAD |
| 2 | 12 | nonce, random | clear, AAD |
| 14 | 4 | forward counter | sealed with the relay's `K_fwd` |
| 18 | 4 | expiry, at most 300 s ahead of the relay's clock | sealed |
| 22 | 16 | RID: the result goes to `mcc/r/<RID>` | sealed |
| 38 | 32 | the target's public key | sealed |
| 70 | 1 | route, below | sealed |
| 71 | 1 | path length, in MeshCore's encoding, below | sealed |
| 72 | 57 | path, zero-padded. Used only with route 0 | sealed |
| 129 | 1 | body length: 132 | sealed |
| 130 | 132 | body: the mesh request from its sub-type byte on, as a companion would be handed it | sealed |
| 262 | 16 | Poly1305 tag | |

The AAD is bytes 0 to 13. **278 bytes, 371 characters.**

| route | name | what the relay sends |
|---|---|---|
| 0 | direct | along the path given. Path length 0 is one transmission with no hops: the target is the relay's neighbour |
| 1 | flood | a flood in the relay's region home, or in its default scope when it has no region home |
| 2 | flood-wide | a flood in the relay's default scope, or without a scope when it has none |

**Path length** is one byte: bits 6 and 7 are the hash size minus 1, bits 0 to 5 are the
number of hashes. It is valid when the hash size is 1, 2 or 3 bytes and size × count fits the
field: 57 bytes in a forward, 64 in a result.

**The forward counter** is the owner's, one per relay, apart from the relay's command counter.
The reference tool uses `max(unix now, last + 1)` and stores it before it sends.

### 15.2 What a relay checks, in order

| step | check | when it fails |
|---|---|---|
| 1 | A command key is set | silent, `no-owner-key` |
| 2 | b64url of 278 bytes with kind `0x46` | silent, `bad-fields` |
| 3 | flags is 0 | silent, `bad-version` |
| 4 | The seal opens under `K_fwd` | silent, `sig-invalid` |
| | *The forward is the owner's. Every outcome from here is answered on `mcc/r/<RID>`.* | |
| 5 | `relay` is `own`, or `any` (lou-21) | status `off` |
| 6 | The relay's clock is set (10.2) | `clock-unset` |
| 7 | now ≤ expiry ≤ now + 300 | `expired` |
| 8 | forward counter > the last accepted one. **It is accepted here**, before the body is judged | `replay` |
| 9 | The body's first byte is `0xC2` and its length is 132; the route is 0, 1 or 2; the path length is valid; the target is not the relay itself | `bad-body` |
| 10 | No other forward is waiting | `busy` |
| 11 | The budget of section 9.3 has room | `rate-limited` |
| 12 | The request is built and queued for transmission | `send-failed`; no budget is spent |
| 13 | An answer from the target arrives within 120 s | `no-answer` |

Rules that go with the table:

- The relay keeps the last forward counter in RAM. The 300 s limit on the expiry bounds what a
  restart reopens to one forward from the last 300 s, and the target's own counter then
  refuses the request inside.
- The relay sends the body as the content of **its own** anonymous request to the target: a
  fresh random 4-byte tag, then the 132 bytes. The target therefore answers the relay.
- The relay takes as the answer a MeshCore response from the target, or a path return that
  carries one, whose first 4 bytes are the tag it wrote.
- While a forward waits, the relay answers every other forward `busy`.
- When the answer came in a flooded path return, the relay sends the target the reciprocal
  path (11.2).
- A body that is not a whole `0xC2` request is a `bad-body`. That includes the `0xC1` request
  of older firmware.

### 15.3 Forward result, kind `f`

| offset | size | field |
|---|---|---|
| 0 | 1 | kind `0x66` (`f`), AAD |
| 1 | 12 | nonce, random, AAD |
| 13 | 256 | sealed with the relay's `K_fwd`, see below, zero-padded |
| 269 | 16 | Poly1305 tag |

**285 bytes, 380 characters.** The sealed part:

| offset | size | field |
|---|---|---|
| 0 | 4 | forward counter, echoed |
| 4 | 1 | status, below |
| 5 | 4 | the relay's clock (10.3) |
| 9 | 1 | sent: 0 nothing, 1 direct, 2 flood |
| 10 | 1 | SNR of the answer as the relay heard it: signed, in quarter-dB. `0x80` = none |
| 11 | 1 | path length of the path the answer taught, in MeshCore's encoding. `0xFF` = none |
| 12 | 64 | that path, zero-padded: from the relay to the target, for a later forward with route 0 |
| 76 | 1 | response length, 0..167 |
| 77 | 167 | the target's response after its 4-byte tag: `0x52 ‖ nonce ‖ sealed under the target's K_cmd ‖ tag` |
| 244 | 12 | zero |

| status | name | meaning |
|---|---|---|
| 0 | `answered` | the response is in the result |
| 1 | `no-answer` | sent; nothing came back in 120 s. **Not a refusal**: the target may have run the command |
| 2 | `off` | `relay off` |
| 3 | `expired` | the expiry has passed, or is more than 300 s ahead |
| 4 | `replay` | the forward counter was not above the last one |
| 5 | `bad-body` | the body, route, path or target was refused |
| 6 | `busy` | another forward is waiting |
| 7 | `rate-limited` | no airtime left for now, or a flood limit |
| 8 | `clock-unset` | the relay has no time yet |
| 9 | `send-failed` | no packet could be built or queued |
| 10 | `guest-cap` | a guest forward (15.5): this guest key's floods for the day are spent |
| 11 | `guests-full` | a guest forward: the guests' half of the relay's floods or airtime is spent |
| 12 | `target-cap` | a guest forward: the target has had its floods from guests for the day |

With status 2 and up, nothing was sent. Status numbers are fixed, and new ones are appended.
The response is copied as the relay received it, so it may end in up to 15 zero bytes of
MeshCore's block padding.

The owner reads a forward result as follows. The kind is `0x66`. It tries the `K_fwd` of every
relay it awaits on this RID and matches the forward counter. It then puts four zero bytes in
front of the response and opens it as a mesh response (7.2) under the **target's** `K_cmd`.

### 15.4 What a relay must refuse

- A forward that does not open under its own `K_fwd`: silently.
- Any forward while `relay` is `off`, while its clock is unset, or over its budget.
- A body other than one whole `0xC2` request.
- Itself as the target.
- A second forward while one waits.

A relay never forwards on its own initiative. It transmits only a request its owner, or a guest
(15.5), sealed for it, one at a time.

### 15.5 Relaying for anyone: the guest forward, kind `G` (lou-21)

From lou-21 a relay with `relay any`, the default there, also transmits for owners other than
its own, within caps that keep half of its budget for its own owner. The owner of a node finds
the relays that can reach it in the node's store entry (12.6).

A stranger's relay cannot open a forward under its own `K_fwd`. A **guest forward** carries a
public key in clear instead, and is sealed under a key that only the holder of that key and the
relay can derive:

```
K_gfwd = HKDF-SHA256(ikm X25519(guest key, relay identity), salt empty, info "mcc3/gfwd/" ‖ relay KEY, 32 bytes)
```

`KEY` is the relay's key as 64 upper-case hex characters, as for `K_fwd`. `X25519` is the
shared secret of 3.1 with the guest key in place of the command key.

**The guest key.** A tool MUST NOT put its command key in a guest forward: a stranger's relay
would learn whose nodes it reaches. The reference tools derive a separate key pair from the
command seed:

```
guest seed = HKDF-SHA256(ikm command seed, salt empty, info "mcc3/guestkey/", 32 bytes)
guest key  = the Ed25519 public key of the guest seed
```

It is derived again each time, never stored and never shown. The same command key always gives
the same guest key, and nobody without the command seed can link the two. The firmware takes any
valid Ed25519 key, so the derivation is between tools; both reference tools use this one.

| offset | size | field | |
|---|---|---|---|
| 0 | 1 | kind `0x47` (`G`) | clear, AAD |
| 1 | 32 | the guest key | clear, AAD |
| 33 | 12 | nonce, random | clear, AAD |
| 45 | 248 | the fields of a forward (15.1) from the counter to the body | sealed with `K_gfwd` |
| 293 | 16 | Poly1305 tag | |

The AAD is bytes 0 to 44. **309 bytes, 412 characters.** The result
is a forward result (15.3), kind `0x66`, sealed under the same `K_gfwd`.

A relay opens a guest forward after it fails to open the message as its owner's forward, and
then checks as in 15.2 with these changes:

- Step 5: a guest is refused `off` unless `relay` is `any`. The owner's forward needs `own` or
  `any`.
- Step 8: the forward counter is counted per guest key, in a ring of the last 16 keys. A key
  pushed out of the ring starts again; the 300 s expiry bounds a replay.
- After step 9, the guest caps, all in RAM, new at midnight UTC and at a restart:

| status | name | cap |
|---|---|---|
| 10 | `guest-cap` | this guest key has had `relay.guest` floods today (default 10, 0 to 100) |
| 11 | `guests-full` | all guests together have had half the day's floods (50 of 100), or half of the current quarter hour's airtime is spent, by anyone |
| 12 | `target-cap` | the target has had 10 floods from guests today |

Direct sends count only against the airtime. A guest forward never takes the last of the four
arrival places (9.4), and while one is held the owner's forward waits behind it instead of being
refused `busy`. A relay without a command key of its own still relays for guests.

## 16. The command server

The command server is an MQTT broker with a small set of topic rules. It needs no knowledge of
the message formats beyond their lengths. `mcbroker`, a Mosquitto plugin, is one
implementation. Any broker that keeps the rules in 16.2 is compatible.

### 16.1 Login

A node and a tool sign in the same way, with a token that their own key signs. The key is the
identity. There is no account to create.

```
username   v1_<64 upper-case hex of the login's Ed25519 public key>
password   <b64url(header)>.<b64url(payload)>.<128 hex characters: the Ed25519 signature>
header     {"alg":"Ed25519","typ":"JWT"}
payload    {"publicKey":"<64 hex>","aud":"<the server's host name>","iat":<unix secs>,"exp":<unix secs>, ...}
signed     the ASCII text "<b64url(header)>.<b64url(payload)>"
```

Note that the third part is **hex**, not b64url. The JSON is compact. The server checks:

- the header is exactly the bytes above;
- `publicKey` is the key in the username;
- `aud` equals one of the server's own configured names, whole;
- `exp` is later than now, and `iat` is at most 3600 s ahead of now;
- the signature verifies with that key.

A node signs in with its identity key. The reference tool signs in with a **throwaway key**
that it draws for each session, never with the command key, so the server cannot tell which
session belongs to which owner. The command key never touches the server.

### 16.2 What a server must and must not do

For a login with key `K`:

| the server MUST | |
|---|---|
| let `K` subscribe to `mcc/cmd/K` and deliver to it only what was published there | a node whose subscription is refused treats its connection as down (8.2) |
| let any token login publish to `mcc/cmd/<any key>` | commands and forwards |
| let any token login publish to `mcc/r/<RID>` and subscribe to one exact `mcc/r/<RID>` | results |
| let `K` publish **retained** to `mcc/alive/K`, and set a will there | alive messages |
| let any token login subscribe to `mcc/alive/+` or `mcc/alive/<any key>` and receive the retained messages | discovery |
| answer `ping\|<8 hex>` on `mcc/ping/K` from `K` with `pong\|<the same>` on `mcc/cmd/K`, published by the server itself | 4.1 |
| let `K` publish, not retained, to `mcc/seen/K`; check the kind, the length and the node's signature of each; keep the newest announce per node by `(boot counter, sequence)` with its catchers as in 12.6; publish the entry **retained** on `mcc/node/<node key>` when it changes; and let any token login subscribe to `mcc/node/+` or `mcc/node/<any key>` | the shared node store, from lou-21. A server without it refuses the publish, and nothing else changes |
| pass payloads unchanged | |

| the server MUST NOT | why |
|---|---|
| deliver `mcc/cmd/K` to any login but `K`, or allow `mcc/cmd/+`, `mcc/#` or any wildcard over commands | who commands whom stays private |
| allow a wildcard over `mcc/r/` | a result's topic is known only to the two ends |
| let a login write `mcc/alive/`, `mcc/seen/` or `mcc/ping/` for another key, or write `mcc/node/` at all | an alive message must be the node's own, and a store entry the server's |
| deliver a ping to any subscriber | the nonce is what a forged pong would need |
| accept a payload that starts with `pong\|` on `mcc/cmd/` from a client | only the server answers a ping |
| retain anything but an alive message or a store entry | a retained command would be replayed at every connect |
| need to open a message, check a command's signature or keep a list of owners | the plane is blind by design; an announce's signature is the node's, and checking it needs no owner |

### 16.3 What mcbroker adds

These are one implementation's choices. They protect the server and are not needed for
compatibility. A client SHOULD stay inside them.

- **Shape checks without opening.** `mcc/cmd/` takes 243 or 371 b64url characters; `mcc/r/`
  380 or 722; `mcc/alive/` 252, or empty; `mcc/ping/` exactly `ping|` and 8 hex characters;
  `mcc/seen/` at most 224, and 120 an hour for one key.
- **Commands on the TLS listener only.** A token read off a plaintext connection cannot be used
  to publish commands.
- **Password logins get nothing under `mcc/`.** Only token logins use the plane.
- **Limits per login key**, rolling: 10 commands a minute and 60 an hour to one node, 600
  commands an hour in all, 120 results an hour, 20 alive messages an hour, 1 ping per 10 s.
  There is deliberately no limit per node across logins: with free keys it would let anyone
  lock an owner out of a node.
- **At most 4 sessions per login key**, and a limit on new login keys per source address per
  hour (60 by default).
- **A sweep.** At most 20 000 retained alive topics. One not written for 72 h is cleared. A
  store entry with no newer announce for 365 days is dropped. The store is kept in the server's
  state file, so a restart keeps it.
- A publish over a limit is dropped. It never counts against the login.

An owner's commands to one node therefore meet three limits: the server's 60 an hour, the
node's 50 an hour, and for a relay its airtime.

## 17. Worked examples

Every byte below comes from `vectors/mcc3-vectors.json` and was rebuilt from its inputs with
the reference implementation (`mccontrol-cli`, `mccontrol/mcc3.py`). The keys are made from
counting bytes and are on no node. The nonces are fixed for the vectors; a real sender draws
them at random. One example is given for each kind of message. There is no vector for the
ping, whose whole format is in section 4.1.

### 17.1 Keys

| what | value |
|---|---|
| owner command seed (test only) | `1112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30` |
| owner command key (public) | `ED54A59FB1AC3A51239351362941B868E85A60E3D7B2485D828821DC7A69C279` |
| node identity seed (test only) | `A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF` |
| node key `KEY` (public) | `4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C4` |
| second node key (public) | `DDE3BCCEC7F3A66A1115F45D720F4DC135C3AE7C4E22DCA38FDB1EFD6A495FF8` |
| `S` (the same from both sides) | `FDF129BEF36C89EE567613FAE911D1019A495F941F6CC5024336A28488CE1B41` |
| `K_cmd` | `75A338AE650E9DD3FA883459F41CE6635941A259538CC48B0FFB8BEBA66227A2` |
| `K_mesh` | `6570868EF9F1A89F14F669ADD6970DD7027CB63827F4D907C7BF666B6C47072F` |
| `K_alive` | `3C76F7735057A079C4FCEF5B5BD1EA0AF7F32F426488CF66A67CE2FD434AAD60` |
| `K_fwd` | `6E15AB5656952AC410F37F7A6EB39007A9977DC968847D6E6AE07AF2FA8F3282` |

The HKDF `info` for `K_cmd` is the 73 ASCII bytes `mcc3/cmd/4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C4`.

### 17.2 Command, kind `C` (vector `V1 get name`)

Command `get name`, counter 7, expiry 1795000000, RID `000102030405060708090A0B0C0D0E0F`, nonce `202122232425262728292A2B`.
Topic `mcc/cmd/4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C4`. The result goes to `mcc/r/000102030405060708090A0B0C0D0E0F`.

The signed bytes (75):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 9 | label `mcc3/sig\|` | `6D6363332F7369677C` |
| 9 | 32 | node key | `4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C4` |
| 41 | 1 | road (MQTT) | `00` |
| 42 | 1 | flags | `00` |
| 43 | 4 | counter | `07000000` |
| 47 | 4 | expiry | `C086FD6A` |
| 51 | 16 | RID | `000102030405060708090A0B0C0D0E0F` |
| 67 | 8 | command | `676574206E616D65` |

The plaintext that is sealed (152 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 4 | counter | `07000000` |
| 4 | 4 | expiry | `C086FD6A` |
| 8 | 16 | RID | `000102030405060708090A0B0C0D0E0F` |
| 24 | 64 | signature | `F69C9A621ECB8771F82305CDC2A888227457A33543A28B850E162EE51BEE95CE`<br>`291DE864AD6C698F28A8FB53C6AB805CE9736C8017A0805A462128FA9BD0D70E` |
| 88 | 8 | command `get name` | `676574206E616D65` |
| 96 | 56 | padding to 64 | `00` × 56 |

The message (182 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 1 | kind | `43` |
| 1 | 1 | flags | `00` |
| 2 | 12 | nonce | `202122232425262728292A2B` |
| 14 | 152 | ciphertext | `C482F1648834524A0C1FA859BDB906D8` … `DC57ECB96918B5B0` |
| 166 | 16 | Poly1305 tag | `11C628EFDC4DC6FCBCBD27681E604872` |

All 182 bytes:

```
4300202122232425262728292A2BC482F1648834524A0C1FA859BDB906D825AC
7C23AC2DD7DDA2844B7A5AA55407ACBB24F01486386173F9EEB869AFC3B3966A
62FA5B76E01E04C5BC355A81AE49C87DC81C03C2F66369BE41D6BDB78DCE8401
01B1872D2B0C4F7EA820F6FB0105530630FF84A5D381393F43A8568B033F47B8
17B8271EDCBABAF48184A524D8943C7D243A7296E5A05CF427B483CC9016DC57
ECB96918B5B011C628EFDC4DC6FCBCBD27681E604872
```

The MQTT payload (243 characters):

```
QwAgISIjJCUmJygpKivEgvFkiDRSSgwfqFm9uQbYJax8I6wt192ihEt6WqVUB6y7JPAUhjhhc_nu
uGmvw7OWamL6W3bgHgTFvDVaga5JyH3IHAPC9mNpvkHWvbeNzoQBAbGHLSsMT36oIPb7AQVTBjD_
hKXTgTk_Q6hWiwM_R7gXuCce3Lq69IGEpSTYlDx9JDpyluWgXPQntIPMkBbcV-y5aRi1sBHGKO_c
Tcb8vL0naB5gSHI
```

### 17.3 Result, kind `R` (vector `a refusal after authentication: replay`)

The node answers a command whose counter (7) was not above its stored one: code 9 (`replay`), node clock 1795000006, no reply text, nonce `3132333435363738393A3B3C`. Topic `mcc/r/000102030405060708090A0B0C0D0E0F`.

The plaintext (256 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 4 | counter | `07000000` |
| 4 | 1 | code | `09` |
| 5 | 4 | node clock | `C686FD6A` |
| 9 | 1 | command length | `08` |
| 10 | 8 | command `get name` | `676574206E616D65` |
| 18 | 238 | reply (empty) and padding to 256 | `00` × 238 |

The message (285 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 1 | kind | `52` |
| 1 | 12 | nonce | `3132333435363738393A3B3C` |
| 13 | 256 | ciphertext | `5607E47578BF2CD811A1A5BA0ECAA9EB` … `88098603074859CF` |
| 269 | 16 | Poly1305 tag | `75052EC985496034F68B278ECDF37610` |

The MQTT payload (380 characters):

```
UjEyMzQ1Njc4OTo7PFYH5HV4vyzYEaGlug7KqeunXbz-RNKYU4Syng5V2cYHA4GPSjfAWD-Y3gCe
0RVJBCayIltJ0slBv2eTp7UMlIUs62u7PxquvtOIIV6BCFke-fn-aIAGDlAXUfo_8dQAQ1EIlNB0
LP5BKCW6NdYerU1DfB2VcLiaGOjSyRhL8SSzVgyGZjIrifCPTlKiz70lGgk6-K9CxewhDmncnHfv
fOJYfULKdQo__Hcc9CrehoOAekUCTyQYIM7bdV4oQkCoReRgzuiwQsoffwDMrX1MhrMQUb36dwok
8ccp_mjAVL2czRSOcU9eH_ccuMDWJeEdzmi8QQu4sVIpiAmGAwdIWc91BS7JhUlgNPaLJ47N83YQ
```

The vector `V2 to V1` is the success case for the same command: code 0 and the reply text.

### 17.4 Mesh request, sub-type `0xC2` (vector `V3 set wifi.ssid`)

Command `set wifi.ssid HomeNet`, counter 7, expiry 1795000000, flags 0, sender tag 1700000000.

The signed bytes (72); no RID on this road:

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 9 | label `mcc3/sig\|` | `6D6363332F7369677C` |
| 9 | 32 | node key | `4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C4` |
| 41 | 1 | road (mesh) | `01` |
| 42 | 1 | flags | `00` |
| 43 | 4 | counter | `07000000` |
| 47 | 4 | expiry | `C086FD6A` |
| 51 | 21 | command | `73657420776966692E7373696420486F6D654E6574` |

The plaintext under the stream cipher (126 bytes). The nonce is `000000000000000007000000`:

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 4 | expiry | `C086FD6A` |
| 4 | 64 | signature | `B6B5D6861BEC26B47285037371DBDF6DA8F6F28C8A7929AC4374ED92B518444A`<br>`9A13FE6AF4E912B46D9CB702344D3424E87DB27BE3C730D81CF25E1290BCBD0B` |
| 68 | 21 | command | `73657420776966692E7373696420486F6D654E6574` |
| 89 | 37 | padding to 58 | `00` × 37 |

The request (136 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 4 | tag | `00F15365` |
| 4 | 1 | sub-type | `C2` |
| 5 | 1 | flags | `00` |
| 6 | 4 | counter | `07000000` |
| 10 | 126 | ChaCha20 ciphertext | `FA5C421E7AB84644B33C7E8680B83524` … `7AE04D836DE6DDAC` |

All 136 bytes:

```
00F15365C20007000000FA5C421E7AB84644B33C7E8680B83524B2C5D93D6041
71406AECF3691C349FC93C6DDE8C3894E3925AB26ADA27B88FED000F45C58BBB
D26DD44E8A443F3FA18C4B0C79A5450A2D07FE5AC9ED384CAE1B5967B1810BB6
0E678A961BA1AA2087A33464610A9E65886ED6FAFC49AAF353E45EAD2AE15B4A
7AE04D836DE6DDAC
```

The vector `V3z: V3 asking for a zero-hop answer` is the same request with flags `0x02`. Byte 5 is `02`, the signature differs, and so only ciphertext bytes 14 to 77 differ.

### 17.5 Mesh response (vector `V4 to V3`)

Code 0, reply `OK`, nonce `505152535455565758595A5B`. The plaintext (11 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 4 | counter | `07000000` |
| 4 | 1 | code | `00` |
| 5 | 4 | node clock | `EF934466` |
| 9 | 2 | reply `OK` | `4F4B` |

The response (44 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 4 | tag, echoed | `00F15365` |
| 4 | 1 | kind | `52` |
| 5 | 12 | nonce | `505152535455565758595A5B` |
| 17 | 11 | ciphertext | `26ABE43386991ADD110260` |
| 28 | 16 | Poly1305 tag | `8FDA5CA2C735EAB61A9A8598DC19BEA6` |

The clock in this vector is 1715770351, which is below 1735689600. It shows the layout only: a node writes 0 for such a clock (section 10).

### 17.6 Forward, kind `F` (vector `F1 direct, no hops, a 0xC2 request with the zero-hop flag`)

The node of 17.1 is the relay. The target is the second node. Forward counter 9, expiry 1795000000, route 0 (direct), path length 0, nonce `606162636465666768696A6B`. It is sealed under the relay's `K_fwd`. Topic `mcc/cmd/4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C4`.

The plaintext (248 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 4 | forward counter | `09000000` |
| 4 | 4 | expiry | `C086FD6A` |
| 8 | 16 | RID | `000102030405060708090A0B0C0D0E0F` |
| 24 | 32 | target's key | `DDE3BCCEC7F3A66A1115F45D720F4DC135C3AE7C4E22DCA38FDB1EFD6A495FF8` |
| 56 | 1 | route | `00` |
| 57 | 1 | path length | `00` |
| 58 | 57 | path | `00` × 57 |
| 115 | 1 | body length (132) | `84` |
| 116 | 132 | body: a `0xC2` request from its sub-type byte on | `C20207000000FA5C421E7FE0648D0A46` … `7AE04D836DE6DDAC` |

The message (278 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 1 | kind | `46` |
| 1 | 1 | flags | `00` |
| 2 | 12 | nonce | `606162636465666768696A6B` |
| 14 | 248 | ciphertext | `E58AF958FAB6C72049B8CA79101DC7CB` … `60CDB6675198952E` |
| 262 | 16 | Poly1305 tag | `7BD7EAE3EC7691A19357684C851FED85` |

The MQTT payload (371 characters):

```
RgBgYWJjZGVmZ2hpamvlivlY-rbHIEm4ynkQHcfLG2zf7SpsEwnVP4QSOjba_UCEKe42qHM0aosU
_q4xRrFiiFIrBP15Rcf6k06yvuqQI4KOftxd4AQx5UFSVkBuEyHLnhpFIqxHgTqWBYN5FuVLVsQu
gGC2ufgNgqbqkWrZHH1TQSKdNuvHdBjCAW2_n87XVZeFcvd5S-FwJo5kE94FybvLbTtGoE6IDsrA
gejp45hsiYTITOzZ4eaej6EV8TozCAYpSuUER6BMrOcZ7O-zZNZjnyG1w-AF35WBL1tFsLx3wQnk
fuAHBToMyK6G8bD9Kt91Ezt6Eu7x8QWe23hgzbZnUZiVLnvX6uPsdpGhk1doTIUf7YU
```

The body in this vector is the 132 bytes of `V3z` after its tag. `V3z` is sealed and signed for the first node, which is the relay here, so the second node would refuse it. The vector shows the layout. A real forward carries a request built for the target with the target's `K_mesh`.

### 17.7 Forward result, kind `f` (vector `F3 to F1: answered, V4 after its tag`)

Status 0 (`answered`), relay clock 1795000005, sent 1 (direct), SNR 22 quarter-dB (5.5 dB), no path taught, nonce `707172737475767778797A7B`. Topic `mcc/r/000102030405060708090A0B0C0D0E0F`.

The plaintext (256 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 4 | forward counter | `09000000` |
| 4 | 1 | status | `00` |
| 5 | 4 | relay clock | `C586FD6A` |
| 9 | 1 | sent | `01` |
| 10 | 1 | SNR | `16` |
| 11 | 1 | path length (none) | `FF` |
| 12 | 64 | path | `00` × 64 |
| 76 | 1 | response length (40) | `28` |
| 77 | 40 | response: `V4` after its 4-byte tag | `52505152535455565758595A5B26ABE43386991ADD1102608FDA5CA2C735EAB6`<br>`1A9A8598DC19BEA6` |
| 117 | 139 | padding to 256 | `00` × 139 |

The message (285 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 1 | kind | `66` |
| 1 | 12 | nonce | `707172737475767778797A7B` |
| 13 | 256 | ciphertext | `F5641CCD8318057369B226B8767A2052` … `523CEF2E1285782F` |
| 269 | 16 | Poly1305 tag | `E1EEBA8704DE44C036D847F3FA940A07` |

The MQTT payload (380 characters):

```
ZnBxcnN0dXZ3eHl6e_VkHM2DGAVzabImuHZ6IFLnG9m6Q5tEvmMGgaaSr8dmpiGWnmWh8scQwLJC
ovUn98Qpl57ecLFvOUONFmSEweMS6EXW8REM2Q1x9NSNAz3dTx4sQDHa7Sg4bzj3hzN99JU1s8ZW
c3NdJT8dNvgpLV3kJawq_B18x6l5cQ5TeBnCpgNjIuJoMFoiO0NmjMzOuqbDIMf_6ytCPrNmjSpk
3I7ZXYBSnCbDi3qG731FQe-Rn54SZDwYoqOg9GIzUPtra1-wfPatfBisNDIoAXRUVLKRAvDQFpUY
PIZUDNw5G9o-KNVFE9Wm5jkghqaPxEP-0KGr95p7SjUFUjzvLhKFeC_h7rqHBN5EwDbYR_P6lAoH
```

The owner puts four zero bytes in front of the response and opens it as a mesh response under the target's `K_cmd`. In this vector the response is `V4`, which opens under the first node's `K_cmd`.

### 17.8 Alive, kind `A` (vector `V5`)

Boot 3, sequence 1, uptime 3600 s, clock 1795000000, last counter 7, interval 900 s, `cmd.mesh` auto, key set over USB, version `lou-20`, region home `se-jkp`, nonce `404142434445464748494A4B`. Topic `mcc/alive/4FD099CCD47D7893DFE9EC24414ECB0D9B5420232AAD30D91C465BE33CBE65C4`.

The plaintext (160 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 4 | boot counter | `03000000` |
| 4 | 4 | sequence | `01000000` |
| 8 | 4 | uptime | `100E0000` |
| 12 | 4 | node clock | `C086FD6A` |
| 16 | 4 | last command counter | `07000000` |
| 20 | 4 | interval | `84030000` |
| 24 | 1 | flags | `0B` |
| 25 | 1 | `cmd.mesh` (2 = auto) | `02` |
| 26 | 4 | command-key fingerprint | `ED54A59F` |
| 30 | 1 | key set via (0 = USB) | `00` |
| 31 | 1 | reserved | `00` |
| 32 | 7 | version: length, then `lou-20` | `066C6F752D3230` |
| 39 | 7 | region home: length, then `se-jkp` | `0673652D6A6B70` |
| 46 | 1 | node name: length | `0E` |
| 47 | 14 | node name | 14 bytes, the vector's `fields.name` |
| 61 | 99 | padding to 160 | `00` × 99 |

The message (189 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 1 | kind | `41` |
| 1 | 12 | nonce | `404142434445464748494A4B` |
| 13 | 160 | ciphertext | `CD6F28E8B3E392B83FAAE71B35C42D17` … `AB45CC8A0E293124` |
| 173 | 16 | Poly1305 tag | `0387C785B4FFC28F44333C2E6D2A3E04` |

The MQTT payload (252 characters), published retained:

```
QUBBQkNERUZHSElKS81vKOiz45K4P6rnGzXELRcNCMeyYRI2INJVt6EWcsuTzIHSAU0fsLkNX5gt
FlUiVYJoOyuK1CfpUeig6IAUiM0x4t4OPqrG-Kue1sUBKbI-VDboZC11pyXoEcJPWM6SahDivENx
K8FeagaT-zph7F_61EtGzHuuK7qfj-JuSqUcVfVrldyztJg_nl2hRsL2HaUjdwvT-63Cq0XMig4p
MSQDh8eFtP_Cj0QzPC5tKj4E
```

The flags byte `0B` is bits 0, 1 and 3. Bit 0 was set by lou-20 only; a lou-21 node with the same state writes `0A`. The vector `relaying on: flags bit 4` is the same node with `relay own` and sequence 2 (flags `1B`).

### 17.9 The signed announce, kind `M`, and what carries it (vectors `A1`, `S1`, `P1` to `P5`)

These are in `vectors/malive-vectors.json`, which the firmware's own generator writes. The
owner is the command key of 17.1, the announcing node is the node of 17.1, and the Observer
node that catches the announce is the other node of `vectors/mcc3-vectors.json`:

| | value |
|---|---|
| the Observer node's key | `DDE3BCCEC7F3A66A1115F45D720F4DC135C3AE7C4E22DCA38FDB1EFD6A495FF8` |
| `S` of the owner and the announcing node | `FDF129BEF36C89EE567613FAE911D1019A495F941F6CC5024336A28488CE1B41` |
| `K_malive` of the announcing node | `2968EE3BC0DE469759ADCB36CE66599684F33FD1FCE85AAB69F9F2E76E18BDCE` |

The announce: boot 7, sequence 1, uptime 42 s, clock 1795000000, last counter 12, flags `0C`,
battery 3987 mV, version `lou-21-arrc`. The sealed part (47 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 4 | uptime | `2A000000` |
| 4 | 4 | node clock | `C086FD6A` |
| 8 | 4 | last command counter | `0C000000` |
| 12 | 1 | flags | `0C` |
| 13 | 2 | battery, 3987 mV | `930F` |
| 15 | 12 | version: length, then `lou-21-arrc` | `0B6C6F752D32312D61727263` |
| 27 | 1 | node name: length | `0F` |
| 28 | 15 | node name | 15 bytes, the vector's `fields.name` |
| 43 | 4 | padding to 47 | `00` × 4 |

The announce (165 bytes):

| offset | size | field | bytes |
|---|---|---|---|
| 0 | 1 | the key's first byte | `4F` |
| 1 | 32 | the node's key | `4FD099CCD47D7893` … `1C465BE33CBE65C4` |
| 33 | 1 | kind | `4D` |
| 34 | 4 | owner tag | `86B8A37F` |
| 38 | 4 | boot counter | `07000000` |
| 42 | 4 | sequence | `01000000` |
| 46 | 47 | ciphertext | `0A8929E75030C7B6` … `ACA1BD1D6715D3F7` |
| 93 | 8 | the tag's first 8 bytes | `C52A87DDAC809D1B` |
| 101 | 64 | the node's signature over `"mcc3/ann\|"` and bytes 1 to 100 | `B633F252A657F66CD04673BB52C57EFD4A45468AA2F07553551EF5FA7AA1F202`<br>`AD9CC579CFE313B6A8C03C42AD04EFBF883AE666CD16D6B2E2D4E35005760F0F` |

The nonce is `000000000700000001000000`. The whole Poly1305 tag is `C52A87DDAC809D1B7A90A1ABE5DB5C79`; its last 8 bytes
are not sent. The report id is `B633F252`.

`S1`: the Observer node heard it as a flood of 2 hops at −22 quarter dB (−5.5 dB), and publishes
on `mcc/seen/DDE3BCCEC7F3A66A1115F45D720F4DC135C3AE7C4E22DCA38FDB1EFD6A495FF8` (168 bytes, 224 characters):

```
U0_QmczUfXiT3-nsJEFOyw2bVCAjKq0w2RxGW-M8vmXETYa4o38HAAAAAQAAAAqJKedQMMe2HHLt
kvz_HyS0c8lQ0OokeNQqhpTK9hHz-cMT7mTWe6yhvR1nFdP3xSqH3ayAnRu2M_JSplf2bNBGc7tS
xX79SkVGiqLwdVNVHvX6eqHyAq2cxXnP4xO2qMA8Qq0E77-IOuZmzRbWsuLU41AFdg8P6gIC
```

`P1`, the state packet naming that Observer node (167 bytes) starts `A0DDE3` and goes on with the
announce from byte 1. `P3`, its ack (41 bytes):

```
B04FD099CCB633F252DDE3BCCEC7F3A66A1115F45D720F4DC135C3AE7C4E22DCA38FDB1EFD6A495FF8
```

`P4`, the direct report along a path of two one-byte hashes `11 22`, is the announce followed by
`DDE3 02 1122` (170 bytes). `P5`, its path ack (55 bytes):

```
4FDDE3BCCEC7F3A66A1115F45D720F4DC135C3AE7C4E22DCA38FDB1EFD6A495FF84BB633F2520211220000000000000000000000000000
```

The vector's `refusals` are announces that must be dropped, each with the word an Observer node
gives (12.8 says where a tool's word differs).

### 17.10 Guest forward, kind `G` (vectors `G1`)

`vectors/malive-vectors.json` holds the firmware's `G1`: the other owner's key of
`vectors/mcc3-vectors.json` used as the guest key as it stands, through the Observer node of 17.9,
flooded in its region home to the announcing node. `K_gfwd` is
`4D1A64FE086B0D48833C87D769EDDE0B79CE1A0F24D013CDB76EC1CC7382317A`; the 309 bytes are, with nonce `707172737475767778797A7B`:

```
R2wo_QWMGMiMbM4q-YHS0RyFGxI-1babeHZ3PtCZ6j-DcHFyc3R1dnd4eXp7BMVj9UTz1LH0VVY3
YAteLTN3I1EJ1way9D5wfyJ7QQVen7UA85jjByt54cI61yTwxFDbI7L-jB4C7XeAgPSXvz8JU16s
C7CFgz7-wixuJyLCxO-4bhKATm7EFYPnstwA_JnMNzRCWW-GubYHaxkyD2R_YeDIQGnBZg7cpJBf
oRTCygqR_-yGxFY8YVrpKMtdZTJfxQKP9XjYmVxOC41KeeT8sz9I1o_RtBGE_e3kVo2TTs0MAAcu
vp1sdpbcnhQB1bqY41L1Fk51lnoQjso0e2E1QcsA2gvKQ58JiXWFLFWs75eXYOOiJ00uQNROyyoV
cX9K3EkxA3B6UIxnT0VWRQ6xmcme_-2K
```

and the relay's `guest-cap` answer opens under the same `K_gfwd` with status 10.

`vectors/mcc3-vectors.json` holds the tools' `G1`, made with the guest key derived from the
command seed of 17.1 (15.5):

| | value |
|---|---|
| guest seed, `HKDF-SHA256(command seed, "", "mcc3/guestkey/")` | `E6BB3242B97C123E5D9649F5B2BEBA8C232068E8C902EBBD58A87AAC4301899C` |
| guest key | `CE91C3FE7050EC6881C9803989768080814ADA7FC90F4E9341F23E8797894852` |
| `S` of the guest key and the relay | `5F39E9DE5170164E4DEC8F44BA6F3B4EE8EED2B751A6DD518463085CEE4DAD19` |
| `K_gfwd` | `9F518025C8CFE00D01F3D63FB7C881C73348D08239B129A442E2D4D3AA05BD4A` |

The guest key appears in clear at bytes 1 to 32 of the forward; the command key appears nowhere.

## 18. Conformance checklist

An implementation is compatible when it passes every item that applies to its role. "Vector"
names an entry of `vectors/mcc3-vectors.json` by its `name`. An entry under `refusals` gives an
input and the outcome the opener must reach. Items without a vector are behaviour that bytes
alone cannot pin; they must be tested against the rules of the section named.

### 18.1 What a node MUST do

**Keys and formats**

1. Derive `S` from its identity and the command key, and the four keys from `S`. Vectors:
   `keys.shared_secret_from_node_side`, `keys.node_side`.
2. Open a command of either size and recover counter, expiry, RID and command. Vectors:
   `V1 get name`, `exactly the first pad`, `spills into the second pad`, `UTF-8`,
   `the longest`.
3. Build the signed bytes exactly as in section 5. Vectors: the `signed` field of every entry
   under `commands` and `mesh_requests`.
4. Seal a result in the layout of 6.2, pad to 256 or 512, and cut a long reply on a character
   boundary. Vectors: `V2 to V1`, `a refusal after authentication: replay`,
   `a long reply, cut to fit the second pad`.
5. Open a mesh request, with flags 0 and with flags `0x02`. Vectors: `V3 set wifi.ssid`,
   `the longest: 57 bytes`, `V3z: V3 asking for a zero-hop answer`.
6. Seal a mesh response in the layout of 7.2, unpadded. Vector: `V4 to V3`.
7. Seal an alive message in the layout of 12.1, always 189 bytes. Vectors: `V5`,
   `no region, clock unset, every field at its longest`, `relaying on: flags bit 4`. A lou-21
   node never sets flags bit 0, which `V5` has set.
8. Use a fresh random nonce for every result, response, forward result and alive message.

**Refusals before the command is authentic: all silent**

9. Refuse a wrong kind byte, a wrong length and text that is not b64url. Vectors:
   `command: kind byte flipped`, `command: one byte short`, `command: not base64url`.
10. Refuse any non-zero flags byte on MQTT. Vectors:
    `command: flags bit 0 (delegation, reserved)`, `command: flags reserved bit 1`.
11. Refuse a command that does not open under its own `K_cmd`. Vectors:
    `command: nonce bit flipped`, `command: ciphertext bit flipped (counter)`,
    `command: ciphertext bit flipped (command)`, `command: tag bit flipped`,
    `command: V1 at another node`, `command: sealed and signed by another owner's key`.
12. Check the signature even when the seal opened, and check the road byte. Vectors:
    `command: sealed with the right key, signed by another owner's key`,
    `command: the V1 signature made with road 0x01`.
13. Refuse a command text outside the rule of 5.1. Vector: `command: a '|' in the command`.
14. On the mesh road, refuse a sub-type other than `0xC2` and any flags but 0 and `0x02`,
    before decrypting. Vectors: `mesh: sub-type 0xC1 (the v1 road)`,
    `mesh: flags bit 0 (delegation, reserved)`,
    `mesh: flags 0x03 (zero-hop with the reserved delegation bit)`,
    `mesh: flags a reserved bit (0x04)`.
15. On the mesh road, refuse a counter that is not above the stored one, before decrypting.
    Vector: `mesh: counter not above the last accepted`.
16. On the mesh road, refuse every altered byte. Vectors:
    `mesh: counter bit flipped (another keystream: the command field decrypts to noise)`,
    `mesh: ciphertext bit flipped in the expiry fails the signature`,
    `mesh: ciphertext bit flipped in the signature fails the signature`,
    `mesh: ciphertext bit flipped in the command fails the signature`,
    `mesh: ciphertext bit flipped in the padding (a NUL inside the command)`,
    `mesh: the last byte (always zero) flipped`,
    `mesh: V3 at another node (decrypts to noise)`.
17. On the mesh road, verify the signature over the road byte `0x01` and over the flags as
    they arrived. Vectors: `mesh: the V3 signature made with road 0x00`,
    `mesh: the V3 signature (flags 0) under flags 0x02`,
    `mesh: the V3z signature (flags 0x02) under flags 0`.
18. Send nothing, on any road, for any refusal in items 9 to 17, and spend no budget on it.
19. Drop a retained message on the command topic. Treat a payload that starts with `pong|` as
    a pong and never as a command (4.1).

**After the command is authentic**

20. Apply the checks of 8.1 or 8.2 in the order given.
21. Refuse a counter that is not strictly above the stored one. Keep **one** counter for both
    roads.
22. Store the counter in non-volatile memory before the command runs. Do not store it for a
    refusal.
23. On MQTT, answer every outcome after authentication on `mcc/r/<RID>`, with the RID taken
    from inside the command, at QoS 1 and not retained.
24. Judge the expiry as in section 10: both bounds on MQTT; skipped on the mesh road while the
    clock was never set; `time <epoch>` judged against the command's own expiry.
25. Never move the clock backwards on a remote command.
26. Enforce the deny list of section 14, and never run a plane command with local privilege.
    Keep the private key, an erase and the command key out of the plane's reach by both gates.
27. Admit the repair commands of 14.3 on the mesh road only, and `time <epoch>` on the mesh
    road only.
28. Enforce 50 commands in any 3600 s, and 2 transmit commands in any 3600 s if the node has
    a transmit command.
29. Use the result codes of 8.3 with their numbers.

**The mesh road's own rules**

30. Not answer a counter it has already answered over the mesh since boot (8.2, step 9).
31. Enforce the airtime budget of 9.2, and neither answer nor run a request that is over it.
32. Answer `mesh-closed` (19) when the road is closed, and listen to nothing when `cmd.mesh`
    is `off`.
33. Delay the answer to a flooded request by 15 to 30 s, drawn at random.
34. With flags `0x02`, answer with one direct transmission and an empty path.
35. Accept the reciprocal path from a sender it answered, for 300 s, and answer that sender's
    later direct requests along it (11.2).

**Alive and rekey**

36. Publish the alive message retained, with the cadence of 12.2, and set the will that clears
    it. Publish none without a command key.
37. Raise the boot counter by one at every boot, before the first alive message.
38. Implement `rekey` as in section 13: the new key waits at most 60 minutes in RAM, takes
    over only when a command it signed arrives, and the counter is not reset.

### 18.2 What a relay MUST do

39. Derive `K_fwd` with its own key in the `info`. Vector: `keys.node_side.fwd`.
40. Open a forward and recover every field. Vector:
    `F1 direct, no hops, a 0xC2 request with the zero-hop flag` (its `opened` field).
41. Refuse silently what is not a forward of its owner. Vectors:
    `forward: a command (kind 0x43) is not a forward`, `forward: one byte short`,
    `forward: flags 1`, `forward: flags byte altered in F1`,
    `forward: nonce bit flipped (header)`, `forward: ciphertext bit flipped (counter)`,
    `forward: ciphertext bit flipped (body)`, `forward: tag bit flipped`,
    `forward: F1 at another node (its K_fwd does not open it)`,
    `forward: sealed by another owner's key`.
42. Answer `bad-body` for a body, route, path or target it may not send. Vectors:
    `forward: body's first byte 0xC3`, `forward: body length 73 (0xC1)`,
    `forward: a 0xC2 body with length 131`, `forward: body length 133`, `forward: route 3`,
    `forward: path length 58 one-byte hashes overruns 57`,
    `forward: path length 0x5D, 29 two-byte hashes overrun 57`,
    `forward: path length with the reserved hash size (0xC1)`,
    `forward: the target is the relay itself`.
43. Answer `bad-body` for a `0xC1` body. Vector: the forward named `F2 flood in the region
    home, a 0xC1 request of 81 bytes; …`. A lou-20 relay sent it; a relay from lou-21 opens it
    and answers `bad-body`.
44. Apply the checks of 15.2 in the order given, and take the forward counter before the body
    is judged.
45. Seal a forward result in the layout of 15.3, always 285 bytes. Vectors:
    `F3 to F1: answered, V4 after its tag`,
    `F4 no answer to a flood; the path is two one-byte hashes`.
46. Hold one forward at a time, wait 120 s, and answer `no-answer` after that.
47. Enforce the airtime and flood limits of 9.3.
48. Send the reciprocal path to a target whose answer came flooded.
49. Run nothing from a forward, and transmit nothing that its owner, or a guest, did not seal
    for it.
49a. From lou-21, with `relay any`: open a guest forward under `K_gfwd` with the guest key in
    the `info` as 15.5 gives, and answer it under the same key; refuse with 10 to 12 as the caps
    say. Vectors, in `vectors/malive-vectors.json`: `guest_forwards` (`G1`, its `k_gfwd`, its
    payload and its result).

### 18.3 What an owner's tool MUST do

50. Derive `S` and the keys from the command seed and the node's key. Vectors:
    `keys.shared_secret`, `keys.owner`, `keys.other_node`, `keys.other_owner`.
51. Build every command, mesh request and forward byte for byte from the vector's inputs.
52. Refuse to build what a node would refuse. Vectors: every entry under `not_built`.
53. Refuse a result, forward result, alive message or mesh response that is altered or is
    another node's. Vectors: the `refusals` whose names start with `result:`,
    `forward result:`, `alive:` and `mesh response:`.
54. Open a mesh response that has up to 15 trailing zero bytes (7.2).
55. Never reuse a mesh counter for different content, and never send a counter that is not
    above the last one it used for that node.
56. Treat `no-answer` and every silence as "unknown", never as "refused".
57. Never set flags `0x02` in a request sent through a companion (11.3).
58. When it reads the store: check each entry as in 12.8 (owner tag, then signature, then seal)
    and skip one that fails. Vectors, in `vectors/malive-vectors.json`: `announces` open to
    their `opened` fields, `seen` holds them as an Observer node sends them, and every entry
    under `refusals` is dropped.
58a. Put a guest key in a guest forward, never the command key, and make `K_gfwd` with it as
    15.5 gives. Vectors: `guest_forwards` in `vectors/mcc3-vectors.json` (the guest key from the
    command seed, `K_gfwd`, the payload) and `G1` in `vectors/malive-vectors.json` (the payload
    with a given guest key).

### 18.4 What a command server MUST do

59. Keep every rule of section 16.2.

### 18.5 Not required

These belong to the MeshCore-lou firmware or to the reference tools. A compatible
implementation may do them differently or not at all.

- **The wording of replies.** The reply texts of `get cmd`, `get cmd.mesh`, `get relay`,
  `get stats`, `get sensors`, `cmd ping` and of every `OK` and `Err` line. The reference tools
  read facts out of some of these texts (`data/facts.json`); that is between those tools and
  that firmware.
- **Debug lines.** `set cmd.debug on|off`, its `mcc: …` lines on the serial console, and the
  counts of silent refusals that `get cmd` shows.
- **The texts for a person** in `data/results.json` and `data/help.json`.
- **How the node picks its MQTT connection**: the slot numbers, the built-in default server,
  the repair of an old login at start, the per-connection client id.
- **The size of the arrivals queue** (four).
- **`get stats` and `get sensors`** as commands, and the auto-reply feature and its
  `trigger` commands.
- **The announce, the store and reporting nearby** (12.4 to 12.8), and relaying for guests
  (15.5). A node that does not announce is added to a tool by its key, and a relay that is
  never `any` takes no guest. A node, a server or a tool that does take part keeps the layouts
  and the checks given there.
- **The settings file layout** on the node.
- **The owner's bookkeeping**: how a tool stores counters, keys and history, and its waiting
  times (20 s on MQTT, 90 s through a companion, 135 s for a forward).
- **The command server's limits** in 16.3.
- **Marking a new firmware image as good** when the first verified command arrives.

## 19. Version policy

This section states what follows from the rules above when the protocol grows. It is what an
old node does today, so it is what a new design can rely on.

- **A new flag bit.** A node refuses every flag bit it does not know, silently. A message
  that uses a new bit is therefore invisible to old nodes: no answer, no error. A sender MUST
  know that a node understands a bit before it sets it, for example from the version in the
  node's alive message. Bit 0 is reserved for delegation and has no meaning yet. Bit 1 has a
  meaning on the mesh road only.
- **A new message kind** takes a new kind byte. An old node drops an unknown kind silently.
- **A new size** of an existing kind is not that kind to an old node. It is dropped silently.
- **A new field** cannot be added inside an existing sealed layout: every layout has a fixed
  size and fixed offsets. Two places have spare room that readers ignore today: the zero
  padding after the last string of an alive message, and the 12 zero bytes at the end of a
  forward result. Byte 31 of the alive plaintext is reserved and is 0. A reader MUST ignore
  alive flag bits it does not know and MUST NOT fail on non-zero bytes in these places.
- **A new result code, forward status or key-set value** is appended. Numbers are never
  reused or renumbered. A reader shows an unknown number as unknown.
- **A new command.** An old node answers it `not-allowed` (14) when its verb is not admitted,
  or with code 0 and its interpreter's "unknown" text when the verb is admitted and the rest
  is not known. Neither is an error of the protocol.
- **A new scheme.** The label `mcc3` is in every HKDF `info` and in the signature label, and
  the topics are under `mcc/`. A change that is not compatible takes a new label, so that no
  message of one scheme can verify in another.
- **A mixed fleet is the normal state.** Flashing takes months. A design that works only when
  every node has the new firmware is not a workable design. A sender degrades per node.

## 20. Where the sources differ

This document was written from the firmware source, the firmware's own documentation, the
reference tool, the command server's plugin, and this repository's wire-format document, data
files and vectors. The firmware source decides. These are the places where the others differ
from it or from each other.

| subject | the firmware (lou-21 branch) | the other source |
|---|---|---|
| How the command key was set, alive byte 30 | 0, 1 or 2; 2 is `rekey` | `docs/wire-format-mcc3.md` lists 0 and 1 only |
| `rekey` | implemented on both roads | `docs/wire-format-mcc3.md` does not describe it |
| Alive flags bit 0 | reserved, never set | `docs/wire-format-mcc3.md` describes it as lou-20 does; the vector `V5` has it set |
| Reply length in a mesh response | at most 125 bytes in a datagram; at most 119 less the path bytes in a path return | `docs/wire-format-mcc3.md` gives 125 only |
| `time <epoch>` on the mesh road | the time must also be at least 1735689600, or the command is an ordinary denied `time` | `docs/wire-format-mcc3.md` and `data/denylist.json` give ten digits and the expiry rule, without that floor |
| A forward's body | one whole `0xC2` request, 132 bytes | the reference tool's `seal_forward` and `open_forward` also take a `0xC1` body of 74 to 132 bytes, as lou-20 did; `data/protocol.json` keeps `min_body` 74 and both sub-types, with a `body_subtypes_from` note |
| Old setting names | `mqtt.cmd…` is unknown; the deny list and the mesh allowance name `cmd…` only | `data/denylist.json` lists both the old and the new names, for older nodes |
| Characters of a command | any well-formed UTF-8 above `0x7F` | the reference tool also refuses characters that Unicode does not class as printable. The sender is stricter than the node |
| "Its own topic" as a check on MQTT | none beyond the topic prefix; the node's key in the signed bytes and in `K_cmd` binds the command to the node | `docs/wire-format-mcc3.md` lists it as a step |
| The 2 transmit commands an hour | enforced | `docs/wire-format-mcc3.md` does not mention it |
| Text for result code 14 | a deny list | `data/results.json` says "allowlist" |
| The mesh road's constants | sub-type `0xC2`, command 57 bytes | the `mesh` block of `data/protocol.json` describes the older `0xC1` request (59 bytes); the `0xC2` constants are in the vectors' `constants` |
| Firmware table | lou-21 exists as a branch | `data/firmware.json` ends at lou-20 |

Three vectors show a layout with inputs that a lou-21 node would not produce. They are correct
as bytes:

- `V4 to V3` carries a node clock of 1715770351. A node writes 0 for a clock below 1735689600.
- `the longest: 57 bytes` uses the command `set mqtt.cmd on …`, a name from before lou-20.
- `F1 …` carries `V3z` as its body, which is sealed for the relay of that example and not for
  its target (section 17.6).

## 21. History

mcc3 arrived in lou-20. Firmware before lou-20 used a different scheme: topics under
`meshcore/<region>/<node>/`, a text envelope signed over its topic, a broadcast topic for a
whole region, key registration at the command server, and a mesh request of sub-type `0xC1`
that was signed and not encrypted. lou-20 accepts both schemes. lou-21 accepts mcc3 only: it
subscribes to nothing under `meshcore/` for commands, and it drops a `0xC1` request without an
answer. The setting names changed from `mqtt.cmd…` to `cmd…` in lou-20, with the stored
settings carried over. `docs/wire-format.md` describes the older scheme.

lou-21 adds the announce of a node without an MQTT connection and the heard entry (12.4 to
12.6, spec v0.5.0). A lou-20 node sends neither and reads neither.

Spec v0.6.0 replaces the heard entry, which was never released, with the signed announce of 165
bytes, the Observer node's `mcc/seen/`, the command server's shared node store on `mcc/node/`,
the zero-hop state and acks and the path ack (12.4 to 12.8), and adds relaying for anyone: `relay
any`, `relay.guest`, the guest forward under `K_gfwd` with a guest key derived from the command
key, and statuses 10 to 12 (15.5). `K_heard` and `mcc/heard/` are gone. A lou-20 Observer node
hands nothing to the store and relays only for its owner; a lou-21 node next to one gets no ack
and floods every 23 hours.

## 22. Licence

The text of this document is licensed under Creative Commons Attribution 4.0 International
(CC BY 4.0, https://creativecommons.org/licenses/by/4.0/). The data files and test vectors in
this repository are under the MIT licence, see [LICENSE](../LICENSE).
