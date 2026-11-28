# mccontrol-spec

The part of mccontrol that is the same in every implementation: the wire format of the signed
command plane for MeshCore repeaters running lou firmware, the tables both apps act on, and test vectors
that prove an implementation gives byte-identical results.

No code. Nothing here runs, connects or sends.

## What is here

| path | what |
|---|---|
| [`docs/protocol.md`](docs/protocol.md) | the whole protocol in one document, for building compatible firmware, a tool or a command server: roles, keys, every message, the node's checks and budgets, the relay, a conformance checklist, worked examples |
| [`docs/wire-format-mcc3.md`](docs/wire-format-mcc3.md) | mcc3 (lou-20 on): `mcc/` topics keyed by the node, commands and results sealed node↔owner and signed inside, the mesh road's 0xC2 request, forwards through a relay and guest forwards through anyone's, alive messages, the shared node store |
| [`docs/wire-format.md`](docs/wire-format.md) | the envelope (v1 signed, v2 encrypted), the results (r1, r2, r3), the mesh road, the broker token, key registration, the key backup file |
| `data/commands.json` | the command table the apps offer: groups, kinds, choices, examples, read or write |
| `data/denylist.json` | what never travels over the control plane, and the mesh road's allowance |
| `data/cautions.json` | commands that get a warning before they are sent |
| `data/results.json` | result codes and what each means to a person (`help`, every code, English; `help_sv` where a Swedish text exists); under `forward`, a relay's statuses and their texts |
| `data/protocol.json` | the protocol's constants: tags, limits, pads, topics, the mesh road's layout |
| `data/firmware.json` | which firmware admits which command and speaks which envelope |
| `data/facts.json` | how a reply becomes a fact about a node |
| `data/brokers.json`, `data/areas.json` | the default command broker, counties and their IATA codes |
| `data/help.json` | the help topics both apps show |
| `vectors/vectors.json` | fixed inputs and the exact outputs: envelopes, results, token, registration, the checks before signing, the mesh road |
| `vectors/mcc3-vectors.json` | mcc3: keys, commands, results, mesh requests and responses, forwards and their results, a guest forward with the guest key derived from the command key, alive, and the refusals, byte for byte |
| `vectors/key-backup-vectors.json` | a sealed key backup file and how it opens |
| `vectors/malive-vectors.json` | lou-21: the signed announce of a node without Wi-Fi, the `mcc/seen` forwards an Observer node publishes for it, the packets between nodes (state, ack, direct report, path ack) and a guest forward with its result, with their keys, opened fields and refusals. Written by the firmware's `scripts/malive-vectors.py` and copied here unchanged |
| `MANIFEST.sha256` | SHA-256 of every data and vector file; consumers pin against it |

Every key and seed in the vectors is made from a fixed phrase or a counting byte sequence. None
of them is on any node.

## How the four repositories relate

- [mccontrol-cli](https://github.com/sweden-mesh/mccontrol-cli): the Python CLI and terminal
  interfaces. It is the reference implementation: `python -m mccontrol.webexport --out <this
  clone>` writes `data/`, `vectors/vectors.json` and `vectors/mcc3-vectors.json` from its code.
- [mccontrol-web](https://github.com/sweden-mesh/mccontrol-web): the same tool in the browser,
  written in JavaScript; its tests run against these vectors.
- mccontrol-spec (this repository): the contract between the two.
- [mccontrol](https://github.com/sweden-mesh/mccontrol): a landing page that points at all three.

Both apps keep a copy of these files pinned to a tag, with a test that fails when a copy
differs from its line in `MANIFEST.sha256`, so their tests need no network. Each has a sync
script that fetches a tag, checks every file against the manifest and writes the copy.

## Changing the spec

1. Change the behaviour in mccontrol-cli; `python -m mccontrol.webexport --out ../mccontrol-spec`.
2. Here: `sha256sum data/*.json vectors/*.json > MANIFEST.sha256`, commit, tag (`v0.2.0`).
3. In mccontrol-cli: `python scripts/spec_sync.py v0.2.0`. In mccontrol-web:
   `node scripts/spec-sync.mjs v0.2.0`. Both suites must pass before the tag is used.

The firmware ([MeshCore-lou](https://github.com/sweden-mesh/MeshCore-lou)) is the authority on
what a node accepts; this repository follows it.

## Licence

MIT, see [LICENSE](LICENSE). The text of [docs/protocol.md](docs/protocol.md) is CC BY 4.0.
