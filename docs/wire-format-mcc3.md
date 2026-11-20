# mcc3: the control plane keyed by the node, sealed to the owner

The scheme from lou-20 on. lou-20 also accepts the old one ([wire-format.md](wire-format.md));
lou-21 accepts only this one. No IATA anywhere: not in a topic, a key, a signature or a gate.
Every format below has worked examples, and the refusals a node or an owner must give, in
[`vectors/mcc3-vectors.json`](../vectors/mcc3-vectors.json). An implementation is correct when it
rebuilds every vector byte for byte from its inputs and gives every refusal its outcome.

Notation: `‖` is concatenation; hex is upper case; every integer is **little-endian**;
`b64url` is base64url without padding. `KEY` is the node's 32-byte Ed25519 public key as 64
upper-case hex characters. The owner's **command key** is the Ed25519 key the node holds in
`mqtt.cmd.pubkey`; exactly one per node.

## Topics

| topic | publisher | subscribers | QoS | retained | payload |
|---|---|---|---|---|---|
| `mcc/cmd/<KEY>` | any login (TLS listener only) | that node only | 1 | no | a sealed command, a sealed forward, or the broker's `pong\|<8 hex>` |
| `mcc/r/<RID>` | any login | an exact `RID` only (no `+` or `#`) | 1 | no | a sealed result, or a sealed forward result |
| `mcc/alive/<KEY>` | that node only | anyone, `mcc/alive/+` allowed | 1 | **yes** | a sealed alive message, or empty |
| `mcc/ping/<KEY>` | that node only | nobody (the broker answers `pong` on `mcc/cmd/<KEY>`) | 1 | no | `ping\|<8 hex>` |

- `RID`, the reply id: 16 random bytes drawn by mccontrol once per broker session, written as 32
  upper-case hex. It travels only inside sealed commands.
- The node's last will: `mcc/alive/<KEY>`, empty, QoS 1, retained. It clears the alive message
  when the link dies.
- There is no broadcast, region, county or owner topic. A node subscribes to its own
  `mcc/cmd/<KEY>` only. A county act is one sealed command per node.
- MQTT payloads are b64url ASCII (the firmware's bridge hands the plane a C string).

## Keys

```
S        = X25519(node identity, command key)          MeshCore's ed25519_key_exchange on the node;
         = X25519(SHA-512(command seed)[0:32], u(node key))   on the owner's side, u = (1+y)/(1-y)
K_cmd    = HKDF-SHA256(ikm S, salt empty, info "mcc3/cmd/"   ‖ KEY, 32 bytes)
K_mesh   = HKDF-SHA256(ikm S, salt empty, info "mcc3/mesh/"  ‖ KEY, 32 bytes)
K_alive  = HKDF-SHA256(ikm S, salt empty, info "mcc3/alive/" ‖ KEY, 32 bytes)
K_fwd    = HKDF-SHA256(ikm S, salt empty, info "mcc3/fwd/"   ‖ KEY, 32 bytes)
```

`info` is ASCII with `KEY` in upper-case hex; an empty salt is RFC 5869's 32 zero bytes.

| key | used for | cipher | nonce |
|---|---|---|---|
| `K_cmd` | MQTT commands, MQTT results, mesh responses | ChaCha20-Poly1305 (RFC 8439) | 12 random bytes, carried |
| `K_mesh` | mesh requests only | ChaCha20 (RFC 8439), **no tag** | `00 × 8 ‖ counter (u32)` |
| `K_alive` | alive messages | ChaCha20-Poly1305 | 12 random bytes, carried |
| `K_fwd` | forwards through a relay and their results; `KEY` is the relay's | ChaCha20-Poly1305 | 12 random bytes, carried |

A sender uses a mesh counter for exactly one request content; a resend sends the same bytes. A
node seals every result with a fresh random nonce.

## The signature

Ed25519 (RFC 8032, pure) by the command key over

```
"mcc3/sig|" (9 bytes ASCII) ‖ node key (32 raw) ‖ road (0x00 MQTT, 0x01 mesh) ‖ flags (1)
  ‖ counter (u32) ‖ expiry (u32, unix seconds) ‖ RID (16 raw, MQTT only) ‖ command (UTF-8, unpadded)
```

The node key stops a command for one node verifying on another; the road byte stops an MQTT
envelope being read as a mesh one.

## Flags

| bit | value | where | meaning |
|---|---|---|---|
| 0 | `0x01` | nowhere yet | reserved: a delegation block follows in clear (`dlen (u8) ‖ block`), in the AAD and in the signed bytes after `flags`. Its content is not defined |
| 1 | `0x02` | mesh requests only | answer with zero hops (below) |
| 2-7 | | | reserved |

The flags byte is in clear and inside the signed bytes. **On MQTT (a command, a forward) a
sender always writes 0 and a node refuses any other value. In a mesh request a node takes 0 or
`0x02` and refuses any other value.** A refusal for flags is silent, counted as `bad-version`,
and comes before anything is opened.

## Command on MQTT (`mcc/cmd/<KEY>`)

| offset | size | field | AAD | sealed |
|---|---|---|---|---|
| 0 | 1 | kind `0x43` (`C`) | yes | |
| 1 | 1 | flags, 0 | yes | |
| 2 | 12 | nonce, random | yes | |
| 14 | 4 | counter | | yes |
| 18 | 4 | expiry | | yes |
| 22 | 16 | RID | | yes |
| 38 | 64 | signature (road 0x00) | | yes |
| 102 | 64 or 160 | command, zero-padded to 64, or to 160 when longer | | yes |
| 166 or 262 | 16 | Poly1305 tag | | |

AAD is bytes 0-13. **182 or 278 bytes, 243 or 371 characters**; nothing else is a command. The
command is 1..160 bytes of printable UTF-8 with no `|` and no control character (the same rule
as v1), so trailing zeros are padding.

The node, in order: a retained message is dropped; `pong|` is the ping; plane on and a command
key set (else `no-owner-key`); its own topic; b64url of 182 or 278 bytes with kind `0x43` (else
`bad-fields`); flags 0 (else `bad-version`); the AEAD opens under `K_cmd` (else `sig-invalid`);
the command field holds a valid command (else `command-chars`); the signature verifies (else
`sig-invalid`). All of these are silent: nothing is answered before the command is authentic.
From there every outcome is answered on `mcc/r/<RID>`: counter above the last accepted
(`replay`), expiry (`expired`, `no-clock`, `expiry-too-far`), deny list, rate limit, then the
counter is persisted and the command runs.

## Result on MQTT (`mcc/r/<RID>`)

| offset | size | field |
|---|---|---|
| 0 | 1 | kind `0x52` (`R`), AAD |
| 1 | 12 | nonce, random, AAD |
| 13 | 256 or 512 | sealed with `K_cmd`: counter (u32) ‖ code (u8, [results.json](../data/results.json)) ‖ node clock (u32, 0 unset) ‖ command length (u8) ‖ command ‖ reply, zero-padded to 256, or 512 when longer |
| +256/512 | 16 | tag |

**285 or 541 bytes, 380 or 722 characters.** The reply is cut to fit 512, on a UTF-8 character
boundary. No node id in clear: the owner tries the `K_cmd` of each node it awaits on this RID and
matches the counter. Results are not signed: only the node and the owner hold `K_cmd`.

## The mesh road: request (ANON_REQ sub-type `0xC2`)

A MeshCore anonymous request to the node's key through the owner's companion, always exactly the
136-byte maximum. **No AEAD tag** (operator decision 2026-11-18): the content is encrypted, and
its integrity and authenticity are the signature inside.

| offset | size | field | |
|---|---|---|---|
| 0 | 4 | tag (the companion writes it; the app sends the other 132) | clear |
| 4 | 1 | sub-type `0xC2` | clear |
| 5 | 1 | flags: 0, or `0x02` (answer with zero hops) | clear |
| 6 | 4 | counter | clear; the nonce |
| 10 | 4 | expiry | ChaCha20 under `K_mesh` |
| 14 | 64 | signature (road 0x01, no RID) | ChaCha20 |
| 78 | 58 | command (1..**57** bytes), zero-padded; the last byte is always 0 | ChaCha20 |

The keystream is RFC 8439 ChaCha20 under `K_mesh`, nonce `00 × 8 ‖ counter`, **starting at block
counter 1**: exactly ChaCha20-Poly1305's ciphertext with its tag dropped, so every library that
has the AEAD has this too. The node reads the first 136 bytes of the decrypted datagram.

The node, in order, all silent: `0xC2`, plane on, `mqtt.cmd.mesh` not off; flags 0 or `0x02`
(`bad-version`); a command key set; counter above the last accepted (`replay`, before any
decryption); decrypt; the field ends in 0 and holds a valid 1..57-byte command (`command-chars`);
the signature (`sig-invalid`); the mesh answer budget. Answered from there: road open (else
`mesh-closed`, 19), expiry (skipped while the clock is unset), deny list and mesh allowance, rate
limit, persist, run.

**Why a flipped bit cannot pass without a tag.** ChaCha20 is malleable: flipping a ciphertext
bit flips the same plaintext bit. Every plaintext byte after the counter is under the signature:
the expiry and the command are in the signed bytes, and the signature is the signature. Padding
is the command field's fixed length, so the unpadded command is a function of the whole field: a
change in the padding either puts a non-zero byte after a zero (the character rule refuses it)
or changes the signed command. A changed counter changes both the keystream and the signed
counter; a changed sub-type is refused before decryption, and so is a changed flags byte, except
between 0 and `0x02`, which the signature covers. The vectors flip a bit in
each region; mccontrol-cli's suite flips two bits of every byte from the counter to the end.

**Flags `0x02`: answer with zero hops.** With the bit set, every answered outcome goes back as
one direct transmission with an empty path to the sender, however the request arrived. Without
it nothing changes. The bit is signed, so nobody on the way can set or clear it. A sender sets
it only in a request it forwards through a relay with route 0 and path length 0 (below), where
the node is known to hear the relay; never through a companion, whose stored path can be stale.
If the link works one way only, the answer is lost though the command ran: that reads as no
answer, as any silence does.

## The mesh road: response

| offset | size | field |
|---|---|---|
| 0 | 4 | tag, echoed |
| 4 | 1 | kind `0x52`, AAD |
| 5 | 12 | nonce, random, AAD |
| 17 | 9 + n | sealed with `K_cmd`: counter (u32) ‖ code (u8) ‖ node clock (u32) ‖ reply (n ≤ 125 bytes) |
| 26 + n | 16 | tag |

Not padded (airtime). The response keeps its tag: the node does not sign it. The companion that
carries it cannot read it.

## A forward through a relay (`mcc/cmd/<RELAY KEY>`)

A **relay** is a node on MQTT that transmits its owner's mesh request to another node, the
**target**, and returns the answer over MQTT. The request inside is an ordinary mesh request,
signed by the owner for the target; the relay cannot read a `0xC2` request or its response. A
forward runs nothing on the relay. A relay serves only the holder of its own command key.

A forward and its result are authenticated by the AEAD under the relay's `K_fwd` alone. They are
not signed.

| offset | size | field | |
|---|---|---|---|
| 0 | 1 | kind `0x46` (`F`) | clear, AAD |
| 1 | 1 | flags, 0 | clear, AAD |
| 2 | 12 | nonce, random | clear, AAD |
| 14 | 4 | forward counter | sealed with `K_fwd` |
| 18 | 4 | expiry, at most 300 s ahead of the relay's clock | sealed |
| 22 | 16 | RID: the result goes to `mcc/r/<RID>` | sealed |
| 38 | 32 | the target's public key | sealed |
| 70 | 1 | route (below) | sealed |
| 71 | 1 | path length, MeshCore's encoding: bits 6-7 hash size − 1, bits 0-5 hash count; 0 = no hops | sealed |
| 72 | 57 | path, zero-padded; used only with route 0 | sealed |
| 129 | 1 | body length: 132 for `0xC2`, 74..132 for `0xC1` | sealed |
| 130 | 132 | body, zero-padded: the mesh request from its sub-type byte on, exactly what a companion is handed | sealed |
| 262 | 16 | Poly1305 tag | |

AAD is bytes 0-13. **278 bytes, 371 characters.** A command can be 278 bytes too: the kind byte
tells them apart, after b64url decoding and before any key is used.

| route | name | what the relay sends |
|---|---|---|
| 0 | direct | along the path given. Path length 0 is one transmission with no hops: the target is the relay's neighbour |
| 1 | flood | a flood in the relay's region home (its default scope when it has no region home) |
| 2 | flood-wide | a flood in the relay's default scope (un-scoped when it has no scope at all) |

A path length is valid when its hash size is 1, 2 or 3 bytes and hash size × hash count fits the
field (57 bytes here, 64 in a result).

The sender keeps one forward counter per relay, `max(unix now, last + 1)`, stored before it
sends and apart from the relay's command counter.

The relay, in order:

| check | else |
|---|---|
| b64url of 278 bytes with kind `0x46` | not a forward |
| flags 0 | silent, `bad-version` |
| a command key set | silent, `no-owner-key` |
| the AEAD opens under `K_fwd` | silent, `sig-invalid` |
| *authentic: every outcome from here is answered on `mcc/r/<RID>`* | |
| `mqtt.relay` is `own` | status `off` |
| the clock is set | `clock-unset` |
| now ≤ expiry ≤ now + 300 | `expired` |
| forward counter above the last accepted one (kept in RAM; accepted here, before the body is judged) | `replay` |
| body: length 132 and first byte `0xC2`, or length 74..132 and first byte `0xC1`; route 0, 1 or 2; a valid path length; the target is not the relay itself | `bad-body` |
| no other forward waiting | `busy` |
| budget: 10 forwards an hour, of which 2 floods | `rate-limited` |
| the request is built and queued | `send-failed` (no budget spent) |
| a response from the target within 120 s | `no-answer` |

The deny list, the command counter and the command rate limit are not involved: on the target
they apply to the request as to any mesh request.

## Forward result (`mcc/r/<RID>`)

| offset | size | field |
|---|---|---|
| 0 | 1 | kind `0x66` (`f`), AAD |
| 1 | 12 | nonce, random, AAD |
| 13 | 256 | sealed with `K_fwd`, below, zero-padded |
| 269 | 16 | tag |

**285 bytes, 380 characters.** A result can be 285 bytes too: the kind byte tells them apart.

| offset | size | field |
|---|---|---|
| 0 | 4 | forward counter, echoed |
| 4 | 1 | status (below) |
| 5 | 4 | relay clock, 0 unset |
| 9 | 1 | sent: 0 nothing, 1 direct, 2 flood |
| 10 | 1 | SNR of the answer as the relay heard it, signed, in quarter-dB; `0x80` = none |
| 11 | 1 | path length of the path the answer taught, MeshCore's encoding; `0xFF` = none |
| 12 | 64 | that path, zero-padded: from the relay to the target, for the next forward with route 0 |
| 76 | 1 | response length, 0..167 |
| 77 | 167 | the target's response after its 4-byte tag: for `0xC2`, `0x52 ‖ nonce ‖ sealed under the target's K_cmd`; for `0xC1`, the plain v1 response |

| status | name | meaning |
|---|---|---|
| 0 | `answered` | the response is in the result |
| 1 | `no-answer` | sent, nothing came back in 120 s. **Not a refusal**: the target may have run the command |
| 2 | `off` | `mqtt.relay off` |
| 3 | `expired` | the expiry has passed, or is more than 300 s ahead |
| 4 | `replay` | the forward counter was not above the last |
| 5 | `bad-body` | the body, route, path or target was refused |
| 6 | `busy` | another forward is waiting |
| 7 | `rate-limited` | 10 an hour, 2 floods |
| 8 | `clock-unset` | the relay has no time yet |
| 9 | `send-failed` | no packet could be built or queued |

Their texts for a person are in [results.json](../data/results.json) under `forward`. With
status 2 and up nothing was sent.

The owner tries the `K_fwd` of each relay it awaits on this RID when the kind is `0x66`, matches
the forward counter, then reads the response exactly as a companion's: put four zero bytes in
front and open a `0xC2` response under the **target's** `K_cmd`; read a `0xC1` response as the v1
mesh response.

## Relay settings

- `set mqtt.relay off|own`, `get mqtt.relay`. Default `own`, on Observer images with the plane;
  other images do not know the setting. An ordinary command: not on the deny list.
- `get mqtt.relay` answers `> own, forwarded <n>, answered <n>, refused <n>, <n> of 10 left this
  hour (<n> of 2 floods)`, or `> off`.
- Fixed: 10 forwards an hour of which 2 floods, one waiting at a time, a 120 s wait, a 300 s
  expiry window.

## Alive (`mcc/alive/<KEY>`, retained)

| offset | size | field |
|---|---|---|
| 0 | 1 | kind `0x41` (`A`), AAD |
| 1 | 12 | nonce, random, AAD |
| 13 | 160 | sealed with `K_alive`, below |
| 173 | 16 | tag |

**189 bytes, 252 characters**, whatever the content. Plaintext, zero-padded to 160:

| offset | size | field |
|---|---|---|
| 0 | 4 | boot counter, persisted, +1 every boot |
| 4 | 4 | sequence since boot, from 1 |
| 8 | 4 | uptime, seconds |
| 12 | 4 | node clock, 0 unset |
| 16 | 4 | last accepted command counter |
| 20 | 4 | alive interval in force, seconds |
| 24 | 1 | flags: bit 0 old scheme still accepted (lou-20), bit 1 Observer uplink build, bit 2 auto-reply build, bit 3 clock set, bit 4 relaying is on (`mqtt.relay own`, on an image that can relay) |
| 25 | 1 | `mqtt.cmd.mesh`: 0 off, 1 on, 2 auto |
| 26 | 4 | command-key fingerprint: its first 4 bytes |
| 30 | 1 | key set via: 0 USB, 1 admin login |
| 31 | 1 | reserved, 0 |
| 32 | 1 + n | firmware version, n ≤ 31 |
| … | 1 + n | region home, lower case, n ≤ 29, 0 when none |
| … | 1 + n | node name, n ≤ 32 |

Strings are length-prefixed UTF-8, cut on a character boundary. Sent after the plane connects
(+ 0-120 s), then every `interval × U(0.5, 1.5)` (`set alive.interval`, 5..1440 minutes, default
15), and 5-60 s after a reconnect, a key change, `region home` or an interval change. No key set:
no alive.

The owner subscribes `mcc/alive/+`, computes and caches `S` per node key, and tries `K_alive`:
what opens is its node; what does not is someone else's (or rekeyed away). An empty payload is the
will: offline. A higher `(boot counter, sequence)` replaces a lower one.

## What the vectors hold

`vectors/mcc3-vectors.json`, made from fixed seeds (counting bytes; on no node) and fixed nonces:

| section | what |
|---|---|
| `constants` | topics, labels, kinds, sizes |
| `keys` | the seeds, public keys, `S` from both sides, `K_cmd`/`K_mesh`/`K_alive`/`K_fwd` for the node, a second node and a second owner |
| `commands` | MQTT commands: signed bytes, signature, payload (both pads, UTF-8, the longest) |
| `results` | MQTT results: a success, an answered refusal, a reply cut to 512 |
| `mesh_requests` | the 136 bytes and the 132 the app sends, the plaintext, the signature; V3z is V3 with flags `0x02` |
| `mesh_responses` | a sealed mesh response |
| `forwards` | F1 (direct, no hops, V3z as its body) and F2 (a flood, a `0xC1` body of 81 bytes): every field, the payload, and what the relay opens. The node of the vectors is the relay, the second node the target |
| `forward_results` | F3 (answered, V4 as its response) and F4 (no answer, a taught path) |
| `alive` | two alive messages and their opened fields |
| `refusals` | a bit flipped in each region of each message, flags that are refused, the wrong node, the wrong owner, the wrong road in the signature, a replay, a forward's body, route, path and target rules, with the outcome |
| `not_built` | commands a sender must refuse before signing |
