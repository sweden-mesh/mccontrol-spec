# The control plane on the wire

What mccontrol sends to a MeshCore Observer repeater and what the repeater sends back, byte for
byte. The firmware is the authority on what a node accepts
([MeshCore-lou, docs/mqtt-control.md](https://github.com/sweden-mesh/MeshCore-lou/blob/fork/observer/docs/mqtt-control.md));
this page describes the same formats from the sender's side. The constants are in
[`data/protocol.json`](../data/protocol.json), the result codes in
[`data/results.json`](../data/results.json), and every format below has worked examples in
[`vectors/vectors.json`](../vectors/vectors.json).

Notation: `|` is a literal `|` (the field separator); `\n` is one line feed; hex is upper case;
`b64url` is base64url without padding; `LE`/`BE` are little/big endian.

## Topics

```
meshcore/{IATA}/{NODE}/cmd     one node          NODE: the first 8 hex of its public key (firmware up to ar-10)
                                                       or the whole 64 hex (ar-11 and later)
meshcore/{IATA}/all/cmd        every node in IATA
meshcore/{IATA}/{NODE}/res     the node's answers
meshcore/mesh/{KEY}/cmd        the topic a mesh-only node (no Wi-Fi, no IATA) signs for
```

`IATA` is upper case. The topic is inside every signature, so a command for one node cannot be
replayed at another, nor a per-node command as a broadcast.

## v1: a signed command

```
payload  v1|{counter}|{expiry}|{command}|{128 hex Ed25519 signature}
signed   "{topic}\n" + "v1|{counter}|{expiry}|{command}"        (RFC 8032 Ed25519, the owner's key)
```

- `counter`: 0 to 2^32-1, strictly greater than the last one the node accepted. Unix seconds
  serve without bookkeeping.
- `expiry`: unix seconds; at most 3600 s ahead of the node's clock. mccontrol uses now + 300.
- `command`: 1 to 160 bytes of printable UTF-8, no `|`. Payload at most 512 bytes, topic at most 160.

The node checks, in this order: a signature is present (code 3), 128 hex (4, 5), it verifies
(16), four fields with `v1` (7), numbers (8), counter greater than the last (9), a clock (12),
not expired (10), not too far ahead (11). Past those it may still refuse: rate limited (17), a
command its firmware does not admit (14), a command that transmits sent as a broadcast (18). The deny list in
[`data/denylist.json`](../data/denylist.json) is what a sender checks before signing.

## Results: r1, r2, r3

```
r1   r1|{counter}|{code}|{command}|{reply}                     unsigned (firmware before ar-11)
r2   r2|{counter}|{code}|{command}|{reply}|{128 hex sig}       signed by the NODE's key over
                                                               "{res topic}\n" + everything before the last |
r3   r3|{counter}|{b64url(sealed)}                              v2's answer, below
```

`reply` is the last field and may contain `|`. An r2 that does not verify is a forgery, not a
result. Silence is never a refusal.

## v2: the command end to end encrypted (ar-13 and later, one node only)

```
shared   X25519(SHA-512(owner seed)[0:32] clamped, Montgomery u of the node's Ed25519 key)
         -- MeshCore's ed25519_key_exchange; the node gets the same from its seed and the owner's key
key      HKDF-SHA256(shared, salt empty, info "mccontrol-v2|" + command topic, 32 bytes)
nonce    direction (1: 00 command, 01 result) | 7 zero bytes | counter (4, BE)
command  v2|{counter}|{expiry}|{b64url(ChaCha20-Poly1305(command zero-padded to 64 or 160 bytes,
             AAD "v2|{counter}|{expiry}"))}|{128 hex Ed25519 over "{topic}\n" + everything before}
result   r3|{counter}|{b64url(ChaCha20-Poly1305("{code}|{command}|{reply}" zero-padded to 256 or 512,
             AAD "r3|{counter}"))}                             same key (the command topic's), direction 01
```

The sealed text is ciphertext followed by the 16-byte tag. The outer signature lets the broker
drop junk before fan-out without reading the command; the node checks the tag. Broadcasts stay v1.

## The mesh road: the same signature over LoRa (lou-19)

A MeshCore anonymous request (`CMD_SEND_ANON_REQ`, 57) to the node's key, through the owner's
companion radio. After the companion's own 4-byte tag:

```
request   C1 | counter (4, LE) | expiry (4, LE) | Ed25519 signature (64, raw) | command (1..59 bytes UTF-8)
response  node clock (4, LE) | counter (4, LE) | code (1) | reply (UTF-8, may be cut inside a character)
```

The signature is the v1 one, for the command topic with the node's whole key
(`meshcore/{IATA}/{KEY}/cmd`, or `meshcore/mesh/{KEY}/cmd` on a mesh-only node), so one
signature is valid on both roads and whichever arrives first runs. A node clock below
1735689600 (2025-01-01) is unset. The response is encrypted to the sender by MeshCore itself.
Code 19 (`mesh-closed`): the node takes the mesh road only while its MQTT link has been down for
15 minutes.

## Broker login: a token, the key is the identity

```
username   v1_{64 hex public key}
password   {b64url(header)}.{b64url(payload)}.{128 hex Ed25519 signature over the first two parts, ASCII}
header     {"alg":"Ed25519","typ":"JWT"}
payload    {"publicKey":"{64 hex}","aud":"{broker host}","iat":{secs},"exp":{secs},"client":"mccontrol"}
```

Compact JSON in this key order; the third part is hex, not base64url (what the firmware writes).
Lifetime 86400 s.

## Registering a key with the command broker

```
topic    mccontrol/register
payload  reg1|{64 hex public key}|{unix secs}|{128 hex sig}
signed   "mccontrol/register\n" + "reg1|{key}|{secs}"
answer   mccontrol/register/{64 hex key}/ack     ok | refused {reason}
```

## The key backup file

The one form in which a seed leaves a machine; the CLI and the web app read each other's.

```
{"format": "mccontrol-key-backup", "version": 1,
 "public_key": "{64 hex}", "created": "{ISO 8601, informational}",
 "kdf": {"name": "PBKDF2-SHA256", "iterations": 600000, "salt": "{16 bytes hex}"},
 "cipher": {"name": "AES-256-GCM", "nonce": "{12 bytes hex}"},
 "ciphertext": "{32-byte seed + 16-byte tag, hex}"}
```

Key: PBKDF2-HMAC-SHA256 over the NFC-normalised UTF-8 passphrase. AAD:
`format|version|kdf name|iterations|salt|cipher name|nonce|public_key`, so a changed header
fails like a wrong passphrase. At most 10,000,000 iterations are accepted. A file holding only
the 64 hex of a seed is read too. Vectors: [`vectors/key-backup-vectors.json`](../vectors/key-backup-vectors.json).
