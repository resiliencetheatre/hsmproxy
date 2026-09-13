# AGENTS.md

## Project goal

Build a proof-of-concept security proxy for `gtk-pipe` that adds:

- SmartCard-HSM-rooted peer identity
- Mutual peer authentication
- Authenticated ephemeral key exchange
- Symmetric session key derivation
- Authenticated encryption for all `gtk-pipe` UDP traffic
- Replay protection
- Rekey support
- Strict fail-closed behavior

The initial PoC MUST keep `gtk-pipe` itself unchanged.

The proxy sits between two unmodified `gtk-pipe` instances and carries their three UDP channels through one authenticated and encrypted tunnel.

This file describes the intended architecture and design constraints. Do not start by modifying `gtk-pipe`.

---

## Existing `gtk-pipe` traffic model

Assume `gtk-pipe` currently uses three UDP channels:

- UDP 5000: video
- UDP 5002: audio
- UDP 5004: text/control

The exact ports should remain configurable.

The PoC proxy should preserve the semantics of these channels without needing to understand GTK, GStreamer, video codecs, audio codecs, or application-level text/control messages.

The proxy should treat each incoming UDP datagram as opaque payload.

---

## Target architecture

Plaintext `gtk-pipe` traffic exists only between `gtk-pipe` and the local proxy.

Across the network, only authenticated encrypted tunnel packets are sent.

Conceptually:

```text
 GTK PIPE A                                      GTK PIPE B
 unchanged                                       unchanged
  │ │ │                                             ▲ ▲ ▲
  │ │ │ plaintext localhost UDP                    │ │ │
  ▼ ▼ ▼                                             │ │ │
┌────────────────┐                            ┌────────────────┐
│ HSM proxy A    │                            │ HSM proxy B    │
│                │                            │                │
│ video ingress  │                            │ video egress   │
│ audio ingress  │                            │ audio egress   │
│ text ingress   │                            │ text egress    │
│                │                            │                │
│ SmartCard ID ──┼── authenticated ECDH ─────┼── SmartCard ID │
│                │                            │                │
│ AEAD + replay  │                            │ AEAD + replay  │
└───────┬────────┘                            └────────┬───────┘
        │                                             ▲
        └========== encrypted UDP tunnel =============┘
```

The proxy should preferably use one network-facing UDP tunnel socket rather than exposing three encrypted network ports.

Example:

```text
gtk-pipe A
  5000 / 5002 / 5004
        |
        v
proxy A
        |
        | UDP 5500, encrypted/authenticated
        |
proxy B
        |
        v
gtk-pipe B
  5000 / 5002 / 5004
```

The tunnel port must be configurable.

---

## Core security model

The SmartCard-HSM is the hardware root of trust for peer identity.

Do NOT use the HSM to encrypt each media packet.

The HSM should only perform low-rate identity operations, such as signing handshake material.

The per-packet data path should use normal symmetric cryptography in host memory.

Model:

```text
SmartCard / HSM identity key
        |
        | signs/authenticates
        v
ephemeral session key exchange
        |
        v
shared secret
        |
        v
HKDF
        |
        v
symmetric TX/RX session keys
        |
        v
AEAD-encrypted UDP traffic
```

The long-term private identity key must never leave the HSM.

---

## Identity

Initial identity should be based on a key stored in SmartCard-HSM and accessed via PKCS#11.

Preferred identity options:

1. HSM-resident EC signing key
2. X.509 certificate associated with that key
3. Peer certificate/public-key fingerprint pinning

For the first PoC, prefer explicit peer pinning over building a large CA/PKI system.

Example configuration concept:

```text
local_identity = "site-a"
pkcs11_module = "/path/to/module.so"
pkcs11_token = "SmartCard-HSM"
pkcs11_key_id = "..."
local_certificate = "/path/to/site-a.crt"

peer_name = "site-b"
peer_certificate_fingerprint = "SHA256:..."
```

Later, CA-based trust may be added.

The critical first property is:

> A tunnel must not become active unless the peer proves possession of the private key corresponding to the expected SmartCard-HSM identity.

---

## Handshake

Use an authenticated ephemeral key exchange.

The long-term HSM identity key authenticates an ephemeral software-generated key.

Do not require the SmartCard-HSM to support X25519.

A reasonable model is:

```text
A                                           B
|                                           |
|---- hello, cert A, ephemeral pub A ------>|
|<--- hello, cert B, ephemeral pub B --------|
|                                           |
|---- HSM signature over transcript -------->|
|<--- HSM signature over transcript ---------|
|                                           |
|        authenticated shared secret         |
|                    |                      |
|                   HKDF                    |
|                    |                      |
|          independent TX/RX keys           |
```

A first PoC may use:

- X25519 for ephemeral ECDH, if convenient
- P-256 ECDH if library/platform constraints make that preferable
- ECDSA or RSA signatures according to the actual HSM identity key

Avoid inventing custom cryptographic primitives.

Use established crypto libraries.

---

## Handshake transcript

The identity signature must bind the important session parameters.

At minimum, the signed transcript should cover:

- protocol identifier
- protocol version
- local identity
- peer identity if known
- initiator/responder role
- local ephemeral public key
- remote ephemeral public key
- fresh nonce(s)
- selected cipher suite
- session parameters that affect security

Conceptual example:

```text
protocol = "gtk-pipe-hsm-proxy"
version = 1
role = initiator
identity = site-a
peer = site-b
ephemeral_local = ...
ephemeral_remote = ...
nonce_local = ...
nonce_remote = ...
cipher = CHACHA20-POLY1305
```

The exact serialization must be deterministic and unambiguous.

Prefer a well-defined binary encoding or a canonical structured representation.

Do not sign loosely concatenated strings.

---

## Key derivation

After authenticated ECDH, derive session keys using HKDF-SHA-256.

Derive independent directional keys.

For example:

```text
shared_secret
    |
    v
HKDF-SHA-256
    |
    +-- A->B AEAD key
    +-- B->A AEAD key
    +-- optional nonce base(s)
    +-- optional rekey material
```

Do not reuse the same key in both directions.

Bind the handshake transcript/session context into HKDF `salt` and/or `info`.

---

## Data plane encryption

Preferred initial AEAD:

- ChaCha20-Poly1305

AES-256-GCM is also acceptable if there is a strong implementation/platform reason.

Do not implement the cipher primitives manually.

Every network tunnel packet must provide:

- confidentiality
- integrity
- authentication
- replay resistance

Plaintext `gtk-pipe` datagrams must never be sent to the network as fallback behavior.

---

## Tunnel packet model

The three `gtk-pipe` UDP streams should become logical channels inside one encrypted session.

Suggested logical channels:

```text
0 = video
1 = audio
2 = text/control
```

Conceptual outer packet:

```text
+---------+---------+------------+------------------+
| version | channel | sequence   | ciphertext + tag |
+---------+---------+------------+------------------+
```

Only fields that genuinely need to be visible before decryption should remain outside the ciphertext.

Anything outside the ciphertext that affects interpretation or security must be authenticated as AEAD associated data.

Do not expose unnecessary metadata.

---

## Sequence numbers and replay protection

Each logical channel should have an independent sequence space.

Example:

```text
video sequence:  851231
audio sequence:  125928
text sequence:       47
```

This avoids heavy packet loss or reordering on video invalidating unrelated text/control traffic.

Use 64-bit sequence numbers unless there is a compelling reason not to.

Implement an anti-replay sliding window per receiving channel.

The implementation must tolerate normal UDP reordering.

Do not require globally in-order UDP delivery.

Do not retransmit media packets unless a later application-specific design explicitly requires it.

---

## UDP semantics

The proxy must preserve UDP-style behavior.

The video/audio path especially must remain loss tolerant and low latency.

Do not turn the tunnel into a TCP-like reliable stream.

Do not create head-of-line blocking across:

- video
- audio
- text/control

A lost video packet must not block later audio or text packets.

---

## Local proxying

The initial PoC should avoid requiring changes to `gtk-pipe`.

There are two possible interposition models.

### Option A: separate local port sets

Example:

```text
gtk-pipe -> proxy ingress:
5000 / 5002 / 5004

proxy -> gtk-pipe local delivery:
6000 / 6002 / 6004
```

This is simple to reason about but may require changing `gtk-pipe` runtime configuration.

### Option B: loopback address separation

Prefer this if `gtk-pipe` can independently configure bind and peer addresses.

Example:

```text
gtk-pipe binds:
127.0.0.1

gtk-pipe peer:
127.0.0.2

proxy listens:
127.0.0.2:5000
127.0.0.2:5002
127.0.0.2:5004

proxy delivers:
127.0.0.1:5000
127.0.0.1:5002
127.0.0.1:5004
```

This preserves the familiar port numbers and keeps the proxy transparent at the application level.

Before implementing, inspect the actual `gtk-pipe` bind/send behavior and choose the least invasive reliable arrangement.

Do not assume that bind ports and destination ports behave identically without verifying the current source.

---

## Fail-closed behavior

This is mandatory.

The proxy must not pass network traffic when:

- the SmartCard-HSM is absent
- the correct key cannot be accessed
- PIN/authentication to the HSM fails
- the peer certificate/public key does not match policy
- peer signature verification fails
- handshake transcript validation fails
- protocol versions are incompatible
- session key establishment fails
- AEAD authentication fails
- replay checks fail

There must be no automatic plaintext fallback.

Security failure should result in no tunnel.

---

## HSM interaction

Use PKCS#11 where practical.

The HSM should be used for:

- locating the configured identity key
- proving possession of the private key
- signing handshake transcript material

The HSM should NOT be used for:

- encrypting every UDP packet
- decrypting every UDP packet
- storing high-rate media session state
- performing a PKCS#11 operation per media packet

The high-rate data plane must remain independent of smartcard latency.

Keep HSM operations off the hot packet path.

---

## PIN handling

Do not hardcode PINs.

Do not log PINs.

Do not include PINs in command-line arguments if avoidable because process listings may expose them.

For the PoC, acceptable approaches include:

- interactive PIN prompt
- protected file descriptor/input mechanism
- integration with a PKCS#11 login/session mechanism
- environment variable only for short-lived development testing, clearly marked as unsuitable for production

Prefer secure interactive entry for the first working version.

---

## Session establishment state machine

Keep the state machine explicit.

Example:

```text
DISCONNECTED
    |
    v
WAITING_FOR_HSM
    |
    v
HSM_READY
    |
    v
HANDSHAKE
    |
    v
PEER_AUTHENTICATED
    |
    v
SESSION_ESTABLISHED
    |
    +--> REKEYING
    |
    +--> DISCONNECTED on failure
```

Network packet forwarding is allowed only in `SESSION_ESTABLISHED`.

---

## Rekeying

Design for rekeying from the beginning even if the first PoC only performs it manually or on reconnect.

Eventually support rekey based on one or more of:

- elapsed time
- packet count
- byte count
- sequence-number threshold
- administrative request

Rekeying should use fresh ephemeral key material.

Do not derive long-term traffic keys directly from the HSM identity private key.

The identity key authenticates ephemeral sessions; it is not the bulk-encryption key.

---

## Forward secrecy

The intended security model should provide forward secrecy for traffic sessions.

This is why ephemeral ECDH is preferred.

If an HSM identity key is compromised in the future, previously recorded tunnel traffic should not become decryptable solely from that long-term identity key.

---

## Peer trust model

Start simple.

Recommended PoC trust model:

```text
peer identity -> explicitly pinned certificate/public-key fingerprint
```

Example:

```text
expected peer:
site-b

expected SHA-256 fingerprint:
AA:BB:CC:...
```

A later phase may add:

- local CA trust anchors
- certificate chains
- name constraints
- certificate expiry policy
- certificate revocation policy
- multiple authorized peers

Do not make complex PKI a prerequisite for demonstrating the core HSM-rooted tunnel.

---

## Status and observability

Provide concise status output.

Useful events include:

```text
WAITING FOR HSM
HSM FOUND
HSM LOGIN SUCCESS
LOCAL IDENTITY LOADED
WAITING FOR PEER
HANDSHAKE STARTED
PEER CERTIFICATE ACCEPTED
PEER SIGNATURE VERIFIED
SESSION ESTABLISHED
REKEY STARTED
REKEY COMPLETE
SESSION CLOSED
```

Useful established-session status:

```text
peer: site-b
identity: site-a
cipher: ChaCha20-Poly1305
session id: ...
video rx/tx packets: ...
audio rx/tx packets: ...
text rx/tx packets: ...
replay drops: ...
auth failures: ...
uptime: ...
```

Never log:

- private keys
- PINs
- session traffic keys
- ECDH shared secrets
- raw decrypted application payload by default

Debug logging must not silently weaken the security model.

---

## Configuration

Prefer a small explicit configuration file plus CLI overrides.

Possible configuration structure:

```ini
[identity]
pkcs11_module = /usr/lib/...
token = SmartCard-HSM
key_id = ...
certificate = /etc/hsmproxy/site-a.crt

[peer]
name = site-b
fingerprint_sha256 = ...

[local]
video_listen = 127.0.0.2:5000
audio_listen = 127.0.0.2:5002
text_listen  = 127.0.0.2:5004

video_target = 127.0.0.1:5000
audio_target = 127.0.0.1:5002
text_target  = 127.0.0.1:5004

[tunnel]
bind = 0.0.0.0:5500
peer = 192.0.2.20:5500
```

This is illustrative only.

Do not freeze config syntax before validating the actual runtime needs.

---

## Networking considerations

The tunnel should work over ordinary IP/UDP.

Potential later concerns:

- NAT
- roaming/address changes
- IPv4 and IPv6
- MTU
- fragmentation
- DSCP/QoS
- keepalives
- path migration

For the first PoC, prefer a simple fixed peer address.

Support IPv4 first if that reduces scope, but avoid architectural assumptions that prevent IPv6 later.

---

## MTU

The proxy adds encapsulation overhead.

Do not assume a full-size incoming UDP datagram can always be encapsulated without fragmentation.

The design must account for:

- tunnel header
- sequence number
- AEAD authentication tag
- nonce material if transmitted
- underlying IP/UDP headers

For the PoC, document the maximum safe plaintext datagram size.

Later, consider explicit MTU configuration or discovery.

Do not create a complicated fragmentation protocol unless actual `gtk-pipe` packet sizes demonstrate that it is needed.

---

## Handshake denial-of-service considerations

Do not overengineer this for the first PoC, but avoid obvious mistakes.

An unauthenticated remote host should not be able to force unlimited expensive HSM signing operations.

Possible later defenses:

- basic source rate limiting
- stateless cookie/challenge
- handshake retry limits
- cooldown after repeated failures

The first implementation may be simple, but structure the code so handshake admission control can be added later.

---

## Protocol versioning

Include an explicit protocol version from the start.

Example:

```text
magic = HSP1
version = 1
```

Do not rely on packet length alone for protocol identification.

Unknown major versions should fail closed.

---

## Cryptographic implementation rules

Do:

- use established crypto libraries
- use established AEAD algorithms
- use established ECDH algorithms
- use HKDF
- use cryptographically secure random generation
- authenticate all security-relevant packet fields
- separate TX/RX keys
- separate channel sequence state

Do NOT:

- invent a new block cipher
- invent a new MAC
- XOR plaintext with a generated stream
- use raw ECDH output directly as the encryption key
- reuse nonces with the same AEAD key
- derive packet keys directly from the HSM private key
- disable authentication because "it is only a PoC"
- fall back to plaintext
- put the HSM on the packet fast path

---

## Suggested code architecture

Keep transport, crypto, HSM, and local proxy logic separated.

Possible modules:

```text
src/
    main.*
    config.*
    proxy_local.*
    tunnel_udp.*
    protocol.*
    handshake.*
    session.*
    replay_window.*
    crypto.*
    hkdf.*
    hsm_pkcs11.*
    identity.*
    logging.*
```

Responsibilities:

### `proxy_local`

- receives plaintext UDP from `gtk-pipe`
- assigns logical channel
- forwards plaintext datagram to active tunnel session
- receives decrypted tunnel payload
- delivers payload to correct local `gtk-pipe` UDP endpoint

### `tunnel_udp`

- owns network-facing UDP socket
- sends/receives protocol packets
- does not know GTK/GStreamer semantics

### `protocol`

- packet encoding/decoding
- protocol version
- message types
- channel IDs

### `handshake`

- state machine
- hello exchange
- peer identity validation
- transcript construction
- HSM signature verification
- ephemeral ECDH

### `session`

- active session lifecycle
- TX/RX keys
- sequence counters
- rekey state

### `replay_window`

- per-channel receive anti-replay logic

### `hsm_pkcs11`

- PKCS#11 provider loading
- token selection
- login
- identity key lookup
- signing

Do not mix PKCS#11 code throughout the rest of the application.

---

## Potential reusable component

Although the first target is `gtk-pipe`, design the security layer so it could later be reused by:

- `udpptt`
- `utxtrelay`
- other UDP-based tools

Longer-term conceptual direction:

```text
             ┌────────────────────────┐
             │ HSM peer security core │
             │                        │
             │ PKCS#11 identity       │
             │ authenticated ECDH     │
             │ HKDF                   │
             │ AEAD                   │
             │ replay protection      │
             │ rekey                  │
             └────────────┬───────────┘
                          │
          ┌───────────────┼────────────────┐
          │               │                │
       gtk-pipe          udpptt        utxtrelay
       video/audio       voice         text/files
```

A future reusable library or daemon may be named something like:

```text
libhsmpeer
```

Do not prematurely extract a library before the GTK Pipe proxy demonstrates the API boundaries.

First build one clear working implementation.

Then refactor shared security/session logic if the boundaries are proven.

---

## Initial PoC scope

The first milestone should be intentionally small.

Recommended scope:

1. Two Linux hosts
2. One SmartCard-HSM on each host
3. One fixed peer per proxy
4. PKCS#11 identity key access
5. Explicit peer fingerprint pinning
6. One authenticated ephemeral handshake
7. HKDF-derived directional session keys
8. ChaCha20-Poly1305 data encryption
9. One network UDP tunnel
10. Three logical channels
11. Independent 64-bit sequence numbers
12. Per-channel replay protection
13. Local UDP forwarding
14. No plaintext fallback
15. Basic status logging

Explicitly out of scope for the first milestone:

- GUI
- `gtk-pipe` source modifications
- certificate enrollment
- automatic CA management
- multi-peer mesh
- relay servers
- NAT traversal protocol
- ICE/STUN/TURN
- automatic discovery
- complex roaming
- packet retransmission
- FEC
- HSM-backed packet encryption
- kernel integration
- WireGuard integration
- TLS/DTLS integration

---

## Development order

Before writing code:

1. Inspect current `gtk-pipe` UDP bind/send behavior.
2. Confirm exact video/audio/text port semantics.
3. Decide local loopback interposition layout.
4. Confirm SmartCard-HSM PKCS#11 module and supported signature algorithms.
5. Confirm actual identity key/certificate representation.
6. Write a short protocol specification.
7. Write handshake state transitions.
8. Write tunnel packet format.
9. Write threat assumptions.

Then implement in this order:

1. Plain UDP 3-channel proxy without crypto
2. Single UDP tunnel multiplexing three channels
3. Packet sequence numbers
4. Software-only ephemeral authenticated test handshake
5. AEAD encryption
6. Replay protection
7. PKCS#11 HSM identity signing
8. Peer fingerprint pinning
9. Fail-closed HSM behavior
10. Rekey skeleton
11. Robust error handling and logs

This order makes networking bugs distinguishable from cryptographic/HSM bugs.

---

## Testing requirements

Add tests for protocol behavior, not only happy-path connectivity.

At minimum test:

- correct peer establishes a session
- wrong peer identity is rejected
- invalid signature is rejected
- modified ciphertext is rejected
- modified authenticated header is rejected
- replayed packet is rejected
- duplicate packet is rejected
- moderate packet reordering is tolerated
- packet loss does not stall other packets
- video sequence state does not affect audio
- audio sequence state does not affect text
- missing HSM prevents tunnel establishment
- wrong PIN prevents tunnel establishment
- removed HSM tears down or disables the session according to defined policy
- malformed handshake packets do not crash the daemon
- malformed tunnel packets do not crash the daemon
- unknown protocol version fails safely
- restart produces fresh ephemeral keys/session state

Also perform an end-to-end test with real `gtk-pipe` instances.

---

## Threat assumptions for the PoC

Assume an attacker may:

- observe all network packets
- inject packets
- modify packets
- replay packets
- spoof IP addresses where the network allows it
- run another proxy implementation
- possess a certificate/public key but not the expected HSM private key

The protocol should protect against those cases.

The first PoC does not need to protect against:

- a fully compromised endpoint OS while the session is active
- memory scraping of live symmetric session keys
- malicious HSM firmware
- physical extraction attacks against the SmartCard-HSM
- traffic analysis
- endpoint malware reading plaintext before encryption or after decryption

Be explicit about this boundary.

The HSM protects long-term peer identity keys. It does not magically make a compromised host trustworthy.

---

## Important design principle

Keep identity and packet encryption conceptually separate:

```text
SmartCard = peer identity
ECDH = session establishment
HKDF = key derivation
ChaCha20-Poly1305 / AES-GCM = packet encryption
sequence numbers = replay protection
periodic rekey = long-session hygiene
```

The SmartCard-HSM anchors trust.

Ephemeral ECDH provides session secrecy and forward secrecy.

Symmetric AEAD provides high-rate packet protection.

---

## Key architectural invariant

The desired end state is:

> `gtk-pipe` remains unaware of cryptography, no plaintext `gtk-pipe` packet crosses the network, and neither proxy establishes the data path until the opposite endpoint proves possession of its expected SmartCard-HSM-backed identity key.

Any implementation choice that weakens this invariant should be treated as suspect.

---

## Instructions for Codex

When working on this project:

- do not modify `gtk-pipe` unless explicitly asked
- do not start coding before inspecting the current repository and networking behavior
- keep the proxy as a separate component
- keep PKCS#11/HSM code isolated from packet forwarding code
- prefer simple, auditable code over framework-heavy abstractions
- do not invent cryptography
- do not silently relax authentication for development convenience
- do not add plaintext fallback
- do not put HSM operations in the per-packet hot path
- preserve UDP loss/reordering semantics
- keep video/audio/text sequence spaces independent
- use one authenticated session for all three logical channels
- make protocol formats explicit and versioned
- document security-sensitive choices before implementing them
- ask before making a design change that alters the trust model
- keep the first milestone narrowly focused on a two-peer PoC

Before implementing anything substantial, produce a short plan covering:

1. observed `gtk-pipe` socket behavior
2. proposed local port/address layout
3. proposed handshake messages
4. proposed tunnel packet format
5. selected crypto primitives/libraries
6. PKCS#11 integration approach
7. failure behavior
8. test plan

Do not proceed from assumptions when repository inspection can answer the question.
