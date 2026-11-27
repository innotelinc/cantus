# CANTUS in the Innotel Platform Stack

**Role: Voice** — a realtime voice standard, and the reference stack that proves it:
one socket, traversal always on, no silent calls.

Part of the [Innotel Platform Stack](https://github.com/innotelinc/innotel-platform-stack).
The canonical definition of the stack, its shared layers and their owners lives
there; this file records only what CANTUS does inside it.

## Boundaries

### Owns

- the Cantus 1.0 wire format: framing, typed fields, datagram kinds, signing input
- the call state machine and its timers, reason codes and idempotent teardown
- capability negotiation as ordered data, without SDP
- **Reach**: candidate handling, path probing, commitment, failover and recovery —
  the layer that makes a call work behind NAT or say why it cannot
- media framing, the conformance codec, and the `FEEDBACK` quality report
- the routing-document language and its offline evaluator
- the reference implementation (`lib/Cantus`), the CLI, and the conformance suite
- the relay: registration, observed-address reporting, name-addressed forwarding

### Consumes

- **Cerulean Vault** (SecretOps) — relay and node secrets for anything actually
  deployed; the repository itself needs no credentials to run or to test
- **Cerulean** (TrustOps) — DNS and TLS for a relay published on a real hostname
- **NPM Edge** — the static landing page at
  [innotelinc.github.io/cantus](https://innotelinc.github.io/cantus/)
- **Authentik** (Identity) — only if a deployment puts a control surface in front
  of the relay; the protocol does not depend on it

### Does not own

- identity as a platform concern (Authentik owns it; Cantus carries a key-bound
  *call* identity, which is a different thing)
- secret storage or rotation (Cerulean Vault)
- object storage, mail, billing, or the edge
- codec implementations (Opus is normative; the reference ships a test codec)
- transport encryption and its keying (TLS 1.3 / DTLS 1.3 binding)

## Place in the mesh

Cantus is a protocol first and a program second: two nodes and an optional relay,
on one UDP port each. A relay is a forwarder that holds no call state and cannot
read media, which is what makes it acceptable to operate next to the trust and
storage layers rather than inside them.

## The SIP edge: what a peer INVITE carries

Cantus has no opinion about SIP, but a deployment needs one place where the two
meet. That is the gateway, and a routing rule can hand a call to a SIP PBX instead
of a Cantus line: `forward to sip:<extension>`. The gateway dials that extension at
the configured peer, so the call rides Cantus up to the gateway and SIP after it.

A peer INVITE is an ordinary SIP request with one addition:

```
INVITE sip:101@<peer host> SIP/2.0
From: <sip:4132642700@<realm>>;tag=…
To:   <sip:101@<realm>>
X-Cantus-DID: 4132642700
```

- **Request-URI and `To`** name the extension the rule chose. That is the whole ask:
  route the call to extension 101 on that switch.
- **`From`** is the number the carrier dialled, which is also the extension the
  inbound Cantus leg registered.
- **`X-Cantus-DID`** carries that dialled number explicitly. The peer is addressed
  by extension, so a PBX writing a call record from its own CDR would name the line
  that answered (`101`) and never the number the caller dialled — the gateway is the
  only party that still knows it. The header is informational: routing is settled
  by the request-URI, and a peer that ignores it still receives a correct call.
- It is stamped on the peer INVITE **and** on the authenticated retry after a `401`,
  so it is present whichever attempt the peer accepts.

Recording the number is the receiving switch's business, not the protocol's. In the
Innotel deployment the peer's dialplan copies the header into the CDR's user field
and the control plane reads it back; see telno's `docs/ARCHITECTURE.md`,
"Inbound calls through the gateway edge", for that half of the contract.

## Interoperability posture

The standard is the product. The Perl stack exists to prove the standard is
implementable without a dependency tree, and to keep every claim in
[spec/CANTUS-1.0.md](../spec/CANTUS-1.0.md) measured rather than asserted. A
conformant implementation in another language is the intended outcome, and
[§15](../spec/CANTUS-1.0.md) lists what it must pass.
