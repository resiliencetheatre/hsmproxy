# Proposed hsmproxy design

Status: protocol/design baseline, 2026-09-12; validation updated 2026-09-13.
The C implementation and automated tests exist. Operator-reported two-host
real-card diagnostics passed at 1100-byte payloads, including rekey from
both roles and card-removal/restart recovery; see `TESTING.md`. The operator also reports stable operation after gtk-pipe verification. The requirements in `agents.md` govern
this design.

Implementation choices for the first version:

- Local addresses are restricted to the verified 127.0.0.2/127.0.0.1 layout;
  the three ports remain configurable.
- Nonblocking sends drop immediately on congestion. There is no userspace
  packet queue; each socket receives at most 16 datagrams per event-loop pass.
- Missing hardware at startup exits without opening data sockets. Card loss,
  reinsertion, or monitoring failure during operation disables forwarding and
  exits. Recovery requires a new process and PIN; automatic PIN retry is absent.
- The worker checks token/session validity once per second when idle; the
  independent PC/SC monitor enforces card-presence freshness. Middleware calls
  can delay shutdown, but traffic keys are erased and sockets closed first.
- Public material is loaded from PEM files and key pins are verified locally;
  there is no certificate transport or provisioning command.
- `--test-channels` adds local application sockets that stand in for gtk-pipe
  on both hosts. It generates session-bound probe/echo datagrams through the
  unchanged forwarding path, requiring the same provisioned hardware identities
  and pinned handshake. Probe payloads carry a test marker, channel/role,
  session ID, sequence, random challenge and checked filler. They are opaque
  to the tunnel; no wire-protocol, identity policy or key-exchange change is
  introduced. See README for PASS criteria and continuous-run behavior.
- Tests use isolated software signers and simulated card adapters, never an
  installed daemon bypass. See `TESTING.md` for coverage and acceptance gaps.

Build a separate C11 daemon for two fixed Linux peers. Each daemon multiplexes
three opaque UDP channels over one encrypted UDP socket. SmartCard-HSM signs
session handshakes through OpenSC PKCS#11 backed by Linux PC/SC. OpenSSL 3
performs ephemeral key agreement and packet encryption in host memory.

## 1. Reference findings and local interposition

The inspected reference is `gtk-pipe/gtk-pipe.c`, SHA-256
`b93f910a4e737efbf4bdf78cec31cdb6787c3b914e86adec6dfc18572733b221`.
These findings are recorded here so the reference directory can later be removed.
Nothing in the proxy build, tests, installation, or runtime may depend on it.

| Channel | Default port | Observed behavior |
| --- | --- | --- |
| Video | 5000 | `make_pipeline()` uses separate GStreamer `udpsink` and `udpsrc`; VP8 RTP; no explicit sender bind or payload MTU |
| Audio | 5002 | Same arrangement; Opus RTP |
| Text/control | 5004 | `start_text_channel()` binds and connects one UDP socket; both send and receive use that socket |

`--bind` sets the text bind address and both media receiver addresses.
`--peer` sets all destinations. Each channel has one configurable port used for
both listening and sending; independent receive/destination ports are absent.
Without `--bind`, receivers use wildcard addresses. Text starts before media and
carries heartbeats, messages, and stream controls. The proxy must not parse them.
Media sender source ports are not configured by the reference; do not require
them to equal the destination ports.

Use the same local layout on both computers:

```text
gtk-pipe --bind 127.0.0.1 --peer 127.0.0.2

channel       gtk-pipe receives      proxy binds and sends from
video         127.0.0.1:5000         127.0.0.2:5000
audio         127.0.0.1:5002         127.0.0.2:5002
text/control  127.0.0.1:5004         127.0.0.2:5004

proxy A physical IP:5500 <---- encrypted UDP ----> proxy B physical IP:5500
```

The proxy uses each bound local socket for ingress and for `sendto()` delivery
to its configured gtk-pipe target. In particular, text must arrive at gtk-pipe
from **127.0.0.2:5004** because its connected socket filters other sources.
Do not create an ephemeral-port egress socket. Do not connect the proxy's media
sockets: media ingress can originate from an ephemeral source port.

Bind explicitly, without `SO_REUSEPORT` or permissive bind sharing; fail on a
collision. Require loopback listen and target addresses, distinct listen/target
endpoints, and three distinct channel ports. Accept local ingress only from
127.0.0.1, with the configured source port additionally required for text.
The loopback media source-address assumption must be checked in integration
testing on the target Linux/GStreamer installation.

The deployment launcher must retain these bind/peer arguments; gtk-pipe's peer
field remains editable. The proxy cannot prevent a user from deliberately
configuring gtk-pipe to send directly to a physical address. Host firewall
policy should permit physical-interface tunnel UDP only for this deployment
and block direct media/control traffic. Do not copy the reference README's
instructions to expose all three plaintext ports.

## 2. C implementation and smartcard stack

```text
hsmproxy (C11)
  ├─ OpenSSL 3 libcrypto: X25519, SHA-256, HKDF, ECDSA verification, AEAD
  ├─ OpenSC opensc-pkcs11.so: identity key lookup, login, signing
  │    └─ libpcsclite → pcscd → reader driver (normally CCID) → SmartCard-HSM
  └─ libpcsclite: reader/card presence monitoring
```

PC/SC supplies standard Linux smartcard transport; PKCS#11 supplies key-object
and signing operations above it. Use OpenSC configured for its PC/SC backend.
No custom USB driver or hand-written SmartCard-HSM APDU implementation is needed.
OpenSC documents SmartCard-HSM support and its PKCS#11 integration in its
[SmartCardHSM documentation](https://github.com/OpenSC/OpenSC/wiki/SmartCardHSM).
Reader monitoring uses the
[PC/SC API](https://pcsclite.apdu.fr/api/group__API.html), including
`SCardGetStatusChange()` and cancellation on shutdown.

Use one nonblocking `epoll` event loop for local/tunnel sockets, bounded queues,
and timers. A serialized HSM worker owns PKCS#11 sessions and signing operations.
A separate monitor waits for PC/SC events. Notify the event loop using `eventfd`
and bounded result queues; never wait for a card operation on the data path.
Associate results with a session-generation number so late signatures cannot
revive a closed session. A monitor failure or stale health report disables
forwarding; a hung HSM worker times out the handshake.

Select an absolute configured module path, exact token serial, reader name,
and binary `CKA_ID`, not a changing slot number or token label alone. Require
one matching private signing key and a configured local certificate/public key.
Reject ambiguity. Check `CKA_SIGN`, EC parameters, and mechanism support.
Require nonextractable hardware-generated key provisioning; runtime attributes
alone do not prove provenance to a remote peer.

The initial suite requires a P-256 identity key and `CKM_ECDSA`. Hash the
specified signature input once in software, and pass its 32-byte SHA-256 digest
to the HSM. PKCS#11 ECDSA results use fixed-width `r || s` (64 bytes here);
convert to the representation OpenSSL expects at the adapter boundary.
Verify a startup challenge against the configured public key before declaring
the identity ready. Do not silently switch algorithms if the card lacks support.

Prompt for the PIN on a terminal with echo disabled, or read from an explicitly
provided protected file descriptor. No PIN in config, argv, logs, or persistent
environment. Erase the buffer after login; do not automatically retry a wrong
PIN. Reinserted cards require a new login and handshake. Support any required
context-specific authentication explicitly or reject such keys in the PoC.

Provisioning is external: do not initialize cards, generate keys, alter PINs,
or write certificates as part of daemon startup. Before implementation against
hardware, inventory the actual module, reader/token mapping, mechanisms, key
curve/ID, and certificate association. Real-card startup and signing checks subsequently passed on both operator
hosts (2026-09-13). The detailed hardware/mechanism inventory was not supplied;
retain it as a deployment record alongside the results in `TESTING.md`.

## 3. Trust and handshake proposal

One configured initiator and one responder avoid simultaneous-open ambiguity.
Each stores the other's public key locally and pins SHA-256 of its DER
SubjectPublicKeyInfo. A certificate may supply that public key, but certificate
names, validity, and CA chains are not an additional trust mechanism in v1.
Provision and compare pins through a trusted external channel; never learn a
pin from the first network connection. Wire identities are the 32-byte pins;
site names are display labels. Both peers must prove possession.

Suite 1 is X25519 + ECDSA-P256/SHA-256 + HKDF-SHA-256 +
ChaCha20-Poly1305. No suite negotiation or downgrade fallback in v1.
This is a proposed application protocol using standard primitives, not a
reviewed standard protocol. Obtain protocol review before use beyond the PoC;
TLS/DTLS integration is excluded by `agents.md`.

### Encoding

All integers are unsigned big-endian. Encode bytes explicitly; never transmit
C structs. Reject truncated packets, trailing bytes, unsupported values, and
nonzero reserved fields before processing. Each handshake message occupies one
UDP datagram with a 28-byte prefix:

```text
magic[4]="HSP1" | version:u8=1 | type:u8 | body_length:u16
attempt_id[16] | reserved:u32=0
```

Message types: 1 INIT, 2 RESPONSE, 3 AUTH, 4 FINISH_I, 5 FINISH_R;
16 DATA. Handshake bodies are fixed-layout, not TLV or concatenated strings.
For DATA, use the separate header specified below.

```text
INIT body:
  suite:u16=1, initiator_pin[32], responder_pin[32], nonce_I[32], eph_I[32],
  max_payload:u16, replay_window:u16=1024

RESPONSE body:
  nonce_R[32], eph_R[32], selected_max_payload:u16, signature_R[64]

AUTH body:
  signature_I[64]

FINISH_I / FINISH_R body:
  confirmation[32]
```

The initiator generates a random attempt ID, nonce, and X25519 key pair. The
responder chooses its fresh nonce/key pair and the smaller permitted payload
limit. The initiator checks that selection is within its proposal. The channel
mapping and replay-window size are fixed by v1. No certificates cross the wire.

Define `LP(x)` as `u16(length(x)) || x`. Let `R0` be the first 66 bytes of the
RESPONSE body, before the signature. The transcript is exactly:

```text
T = LP(ASCII("gtk-pipe-hsm-proxy/transcript/v1"))
    || LP(entire INIT packet) || LP(R0)
H = SHA256(T)
signature_R = ECDSA_SHA256(LP(ASCII("hsp1/responder")) || H)
signature_I = ECDSA_SHA256(LP(ASCII("hsp1/initiator")) || H)
```

Both role signatures bind the two pins, ephemerals, nonces, attempt ID, suite,
version, and payload/window parameters. The response and all subsequent
headers must reference the exact pending attempt. Verify pins before signing;
the initiator verifies RESPONSE before requesting its own signature. Reject
invalid X25519 inputs/derivation failures, including an all-zero shared secret.

Derive `PRK = HKDF-Extract(salt=H, IKM=X25519_shared_secret)`. Each expansion
uses `info = LP(ASCII(label)) || H` with distinct labels:

```text
hsp1/finish/I, hsp1/finish/R       → 32-byte HMAC keys
hsp1/session-id                  → 16-byte session ID
hsp1/data/I-to-R/0 ... /3         → independent 32-byte AEAD keys
hsp1/data/R-to-I/0 ... /3         → independent 32-byte AEAD keys
```

Use OpenSSL's [HKDF implementation](https://docs.openssl.org/3.5/man7/EVP_KDF-HKDF/).
Channels 0–2 are application channels; 3 is tunnel control. Explicit per-channel
keys prevent nonce collisions between independent channel counters.

FINISH_I is `HMAC-SHA256(K_finish_I, LP(ASCII("hsp1/confirmed/I")) || H)`;
FINISH_R uses the R equivalents. The responder verifies AUTH and FINISH_I
before returning FINISH_R and entering ESTABLISHED. The initiator enters
ESTABLISHED only after verifying FINISH_R. Compare confirmations in constant
time. Receiving AUTH alone never activates forwarding. Early data is dropped.

Handshake messages contain public establishment metadata; application payload
is sent only inside AEAD DATA packets. Unauthenticated handshake input never
changes an established session's keys or replay state.

### UDP loss, retries, and admission

Only accept handshake traffic from the configured numeric peer IP and port.
This is admission filtering, not identity authentication. Maintain at most one
pending attempt. New responder attempts are admitted at most once per second,
burst one, with at most one HSM signature per admitted attempt. Cache responses
and signatures; identical retries resend bytes without another HSM operation.
Conflicting content under the same attempt ID is rejected.

Retry each outstanding flight after 0.5, 1, 2, and 4 seconds; abandon the whole
attempt after 15 seconds. The initiator retries INIT until RESPONSE, then AUTH
and FINISH_I until FINISH_R. If FINISH_I arrives before AUTH, discard it and
rely on retries. Retain completed handshake responses for 15 seconds so a lost
FINISH_R can be recovered. No application retransmission is added. Limit
logging and input work independently of the signing limit. A spoofed allowed
source can still cause bounded denial of service; cookies are a future defense.

## 4. Data packets, nonce construction, and replay

One DATA datagram carries exactly one original UDP datagram:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 4 | Magic `HSP1` |
| 4 | 1 | Version 1 |
| 5 | 1 | Type 16 (DATA) |
| 6 | 1 | Channel: 0 video, 1 audio, 2 text, 3 tunnel control |
| 7 | 1 | Flags, zero in v1 |
| 8 | 16 | Derived session ID |
| 24 | 8 | Per-direction, per-channel sequence number |
| 32 | N | ChaCha20-Poly1305 ciphertext |
| 32+N | 16 | Authentication tag |

All 32 header bytes are AEAD associated data. The channel is visible to select
its key and replay window; sizes and traffic timing also remain visible.
Payload length follows from UDP length; reject lengths below 48 or above the
negotiated limit plus 48. No transmitted nonce or padding is needed in v1.

For each direction/channel key, nonce = `0x00000000 || u64be(sequence)`.
Counters start at zero for each fresh session. Allocate a sequence once before
encryption; failed sends consume it. Never encrypt different content under a
previous counter, wrap a counter, restore old keys after restart, or share
counters between producers without serialization.

Keep a 1024-bit sliding replay bitmap per incoming channel. Precheck duplicates
and packets too old; authenticate admissible candidates, then advance/mark the
window. A forged high sequence must not move the window. Deliver at most once,
even if local delivery fails. Reordering within the window is accepted. Larger
reordering and ordinary packet loss cause drops, never a wait for missing data.

Each local input is opaque, including empty datagrams. Use `recvmsg()` and
detect `MSG_TRUNC`; never encrypt or deliver a truncated prefix. Maintain
bounded per-channel queues and round-robin service with bounded work per event
loop iteration. Drop on queue overflow and count it. Do not let video fill all
audio/text queue capacity or run unbounded batches. Kernel socket congestion
can still cause loss; independent queues do not promise QoS.

## 5. MTU and compatibility

Overhead is 48 bytes inside UDP, plus 8 UDP and normally 20 IPv4 bytes.
For path MTU M, safe application payload is **M − 76** for IPv4 without IP
options. A 1500-byte IPv4 path permits 1424 bytes. IPv6 without extension headers
would permit M − 96 (1404 at 1500), but v1 implements IPv4 first.

Set the initial configured payload maximum to 1400 and require a verified IPv4
path MTU of at least 1476. The reference does not set an RTP MTU;
[GStreamer RTP base payload](https://gstreamer.freedesktop.org/documentation/rtplib/gstrtpbasepayload.html)
exposes an MTU property, but the installed value and resulting packet sizes
must be measured. The 1400-byte limit is a proposed deployment budget, not an
observed packet capture. Measure all three channels on the target installation. Text is approximately
1 KiB with small framing; exact bytes remain irrelevant to the proxy.

Set IPv4 PMTU discovery to prohibit outer fragmentation. Handle `EMSGSIZE`,
count oversize local datagrams, and report a clear path/payload mismatch.
Do not truncate payloads or silently enable IP fragmentation. A smaller path
can be configured with a smaller limit, but unchanged gtk-pipe may still emit
larger packets and lose video. Such a path is unsupported until packet sizing
or a separately specified authenticated fragmentation scheme is addressed.
There is no fragmentation/reassembly protocol in this PoC. Handshake datagrams
are small (INIT is 162 bytes; RESPONSE is 158 bytes).

## 6. Lifecycle and failure policy

```text
DISCONNECTED → WAITING_FOR_HSM → HSM_READY → HANDSHAKE
             → PEER_AUTHENTICATED → ESTABLISHED
ESTABLISHED → REKEYING → HANDSHAKE → ... → ESTABLISHED
any state → DISCONNECTED / WAITING_FOR_HSM on local fatal failure
```

Forward only while ESTABLISHED and the local card-health gate is valid.
Discard local datagrams while unavailable; do not accumulate stale media to
release after authentication. Card removal, reader loss, PC/SC failure, token
failure, or identity mismatch closes the gate and erases all session keys and
pending data. Monitor the selected reader and bind it unambiguously to the
configured token; if that mapping cannot be established, fail startup.

Use finite monitor waits and a health report at least every 250 ms; fail the
gate if no report is processed for one second. Removal notifications close the
gate as soon as processed. This bounds intended detection latency under normal
scheduling, not physical instant detection or a hard real-time guarantee.
No packet operation talks to the card. Reappearance requires token/key checks,
login, and fresh ephemeral authentication; previous session state is unusable.

Bad signatures/pins/confirmations abort the pending handshake. Bad tags,
malformed packets, wrong versions/session IDs, and replays are dropped without
delivery or state mutation. A forged packet must not remotely tear down an
otherwise healthy established session. There is no plaintext fallback.

Tunnel channel 3 uses the same authenticated packet and replay rules. Define
fixed control payloads: PING = opcode 1 plus random 8-byte token; PONG = opcode
2 plus the echoed token; CLOSE = opcode 3 only; REKEY_REQUEST = opcode 4 only.
Unknown opcodes or wrong lengths are discarded. Send PING every two seconds;
only a valid PONG matching a recent outstanding token refreshes liveness.
Close after ten seconds without a valid response. Never synthesize gtk-pipe
heartbeats. Remote card removal is learned through authenticated CLOSE when
possible, otherwise through this timeout; the local proxy gates immediately
on detection even if the remote side is temporarily unaware.

For the first PoC, rekey is break-before-make: discard old traffic state,
pause forwarding, and run the full HSM-authenticated handshake with fresh
ephemerals. No overlapping epochs or old-key receive grace. Responder requests
rekey through authenticated control; only the initiator starts a new attempt.
If that request is lost, responder closes its old session and liveness timeout
causes the initiator to reconnect. Do not reuse old traffic keys after failure.

Trigger rekey at 30 minutes, 2^30 sent packets on any channel, or an
administrative request, whichever comes first. Receive counters enforce the
same packet ceiling; reaching the limit disables that session. These are
conservative PoC limits pending cryptographic review. Erase ephemeral private
keys, shared secret, and PRK after derivation; keep confirmation material only
for the bounded retry cache. Erase all remaining secrets on close. Disable
core dumps; handle process termination through the event loop.

## 7. Configuration and module boundaries

Illustrative site A configuration; site B reverses pins/addresses and takes
the responder role. These are proposed settings, not an implemented CLI.

```ini
[identity]
name = site-a
pkcs11_module = /absolute/path/to/opensc-pkcs11.so
token_serial = REPLACE_WITH_REAL_SERIAL
reader = REPLACE_WITH_EXACT_PCSC_READER
key_id_hex = 01
certificate = /etc/hsmproxy/site-a.crt

[peer]
name = site-b
public_key = /etc/hsmproxy/site-b.pub.pem
spki_sha256 = REPLACE_WITH_64_HEX_DIGITS

[local]
listen_address = 127.0.0.2
target_address = 127.0.0.1
video_port = 5000
audio_port = 5002
text_port = 5004

[tunnel]
role = initiator
bind = 192.0.2.10:5500
peer = 192.0.2.20:5500
max_payload = 1400
```

Parse strictly: reject unknown/duplicate keys, malformed pins, invalid limits,
ambiguous token selection, and missing trust settings. CLI overrides may cover
config path and explicit nonsecret settings; a PIN descriptor is separate.
Keep endpoint configuration fixed for the lifetime of a session. Run as an
unprivileged user with pcscd access; no root or network administration capability
is required by the daemon itself.

| Proposed C files | Responsibility |
| --- | --- |
| `main.c`, `config.c`, `logging.c` | Startup, strict config, event loop, redacted status |
| `proxy_local.c`, `tunnel_udp.c` | Opaque datagrams, socket policy, bounded queues |
| `protocol.c` | Checked wire encoding/decoding and constants |
| `handshake.c`, `identity.c` | Transcript, pins, retries, authentication |
| `crypto.c` | OpenSSL EVP operations and secret destruction |
| `session.c`, `replay_window.c` | Keys, counters, replay, liveness, rekey |
| `hsm_pkcs11.c`, `hsm_monitor.c` | Isolated signing adapter and PC/SC health |

Use a small Makefile, `pkg-config`, C11 warnings, libcrypto, libpcsclite,
PKCS#11 headers, libdl, and pthreads. No GTK/GStreamer dependency in hsmproxy.
The configured PKCS#11 module is loaded at runtime. Record lifecycle events,
session/peer labels, per-channel packet/byte counts, replay/auth/oversize/queue
drops, and uptime. Never log PINs, secrets, signatures' input buffers containing
secrets, or application plaintext. Rate-limit hostile-input logs.

## 8. Threat boundary and verification plan

Protect against passive interception, modification, spoofing, replay, wrong
peers, and possession of only the expected public certificate. Forward secrecy
depends on fresh ephemeral generation and secret erasure. Pinning proves key
possession, not remote hardware attestation; trusted provisioning establishes
the association between that key and a SmartCard-HSM.

A compromised endpoint can read plaintext/session keys or misuse an unlocked
card. Physical attacks, malicious firmware, traffic analysis, and availability
under network flooding are outside scope. Other local processes are within the
trusted endpoint boundary; loopback addresses do not authenticate processes.

Implementation milestones and their acceptance criteria:

1. Capture the observed socket tuples and payload sizes using the unchanged
   reference on two hosts. Confirm connected text works only with the correct
   source tuple. Complete read-only card/mechanism inventory and a controlled
   sign/verify check with the provisioned identity.
2. Build protocol encoding, local forwarding, and multiplexing harnesses.
   Any temporary plaintext/software-identity harness must remain test-only,
   loopback-bound, and absent from the installed daemon. No production bypass
   flag or auto-selection of a software identity.
3. Implement exact transcript vectors, HKDF/nonce vectors, signature conversion,
   mutual authentication and Finished checks. Reject changed roles, pins,
   attempts, parameters, invalid keys, and reordered/conflicting flights.
   Verify retry recovery when each flight, including FINISH_R, is lost.
4. Test tag/header/ciphertext modification, duplicates, stale packets, moderate
   reordering, forged high counters, independent channel windows, counter
   exhaustion, fresh restart keys, zero-length UDP, truncation, queue overflow,
   and oversize/EMSGSIZE behavior. Loss must not stall unrelated packets.
5. Integrate real PC/SC/OpenSC signing. Test missing/wrong card, wrong PIN with
   controlled retry counts, mismatched certificate/key, removal while streaming
   and signing, quick removal/reinsertion, pcscd failure, stale monitor, and
   late worker results. Measure detection-to-gate latency and remote timeout.
6. Test rekey and reconnect under loss, simultaneous requests, stale old-session
   packets, and unreachable peers. Fuzz parsers and state transitions with
   ASan/UBSan; malformed input must not crash or grow memory without bound.
7. End-to-end with two real HSMs and gtk-pipe: video/audio/text and controls,
   media stop/start, packet loss/reordering via a test network, and card removal.
   Capture on physical interfaces: only tunnel packets may carry application
   traffic; no original plaintext UDP may appear. Confirm CPU/latency, maximum
   datagram sizes, and channel fairness at the highest reference media setting.
8. Remove the reference directory from a disposable build copy and repeat
   proxy build/tests/install checks. Keep the reference unchanged until the
   requested project cleanup; retain these findings and independent fixtures.

Operator-reported real-card diagnostics passed at 1100-byte payloads, followed
by gtk-pipe verification with apparently stable operation. See `TESTING.md`
for the evidence and remaining measurement and fault-injection coverage.


## 9. Optional desktop supervision

The implemented optional local supervision interface and GTK secure mode are
specified in [FRONTEND.md](FRONTEND.md). They extend the initial UI scope while
preserving this network protocol, peer pinning, cryptography, and fail-closed
card gate. GTK Pipe retains its standalone mode; each project builds and
installs independently. Current GTK Pipe also supports `--rtp-mtu`, superseding
the older source-reference observation in sections 1 and 5.
