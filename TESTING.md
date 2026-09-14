# Verification and remaining acceptance work

## Successful two-host test — 2026-09-13

Evidence: operator-provided terminal logs and confirmation of tests performed
on both physical hosts. These results were reported by the operator, not
independently captured by the development test harness.

| Setting | Site A | Site B |
| --- | --- | --- |
| Host | `host-a` | `host-b` |
| Smartcard | `card-a` | `card-b` |
| Role | Initiator | Responder |
| Configuration | `examples/site-a.ini` | `examples/site-b.ini` |
| Mode | `--test-channels` | `--test-channels` |
| Configured maximum payload | 1100 bytes | 1100 bytes |

The hosts communicated over a WireGuard path. The supplied `wg0` interface
output showed MTU **1200**. No gtk-pipe instance, camera, or microphone was
needed for these tests. Exact software/firmware versions, card serials, and
the complete endpoint configuration were not supplied with the results.

Confirmed outcomes:

- Both real cards passed login and local identity sign/verify checks. Peer
  signature verification and session establishment succeeded.
- Both hosts reported **CHANNEL TEST PASS**, covering bidirectional video,
  audio, and text logical channels through local UDP sockets and the encrypted
  tunnel, with 64-, 256-, and 1100-byte probes.
- The successful supplied snapshots showed zero rejected packets, oversize or
  truncated packets, send/delivery/source/MTU drops, and diagnostic timeouts,
  send errors, invalid replies, or stale replies. Sample RTTs were approximately
  **22–27 ms**, including the post-rekey and later removal-test logs. This is a sample from diagnostic
  probes, not a sustained media performance measurement.
- Manual rekey succeeded when initiated from **either host**. The supplied
  rekey log showed session closure, a new authenticated handshake, restarted
  diagnostic counters, and another PASS on all three channels. Proxy packet
  totals remained cumulative, as intended.
- The operator confirmed successful card-removal and restart/recovery tests
  on **both hosts**, returning to channel PASS. Exact removal-to-shutdown and
  remote-timeout measurements were not supplied; removal during signing and
  rapid remove/reinsert were not separately confirmed.

### Reader disconnects and recovery

Unattended diagnostics initially stopped after USB reader disconnects and loss
of the PKCS#11 login session. Restarting the proxy restored channel PASS.
The operator reported stable operation after disabling runtime autosuspend for
the affected reader. See [USB reader power saving](README.md#usb-reader-power-saving).

A separate health-check timing race was corrected: a monitor heartbeat newer
than the caller's sampled time is treated as age zero. Regression tests cover
this ordering and latched authentication loss. Card-health failures still close
the forwarding gate.

### gtk-pipe verification

The operator subsequently verified operation with gtk-pipe and reported that
hsmproxy appears stable. Exact duration, media settings, packet captures, and
performance measurements were not supplied; the acceptance procedure below
retains those checks for future verification.

### MTU failure and correction

The initial 1400-byte configuration established authenticated sessions, but
both hosts accumulated `mtu_drops`/`send_drops` and stayed PENDING. Smaller
probes succeeded while the maximum-size probes could not complete.

For this IPv4 tunnel, the maximum payload that fits a 1200-byte interface MTU
is `1200 - 20 (IPv4) - 8 (UDP) - 48 (hsmproxy) = 1124` bytes. Setting
`max_payload = 1100` on both hosts produced PASS without MTU drops in the
supplied successful snapshots. A 1100-byte probe requires 1176 bytes at this
IP layer. WireGuard's external encapsulation is not subtracted again from
the already configured `wg0` interface MTU.

The diagnostic result validates the tested packet sizes. The operator later
reported successful gtk-pipe verification as recorded above. Applications must
still keep datagrams within the negotiated limit; hsmproxy does not fragment
or repacketize them. The generic examples use 1400 bytes; reduce that limit
when the actual path requires it.

## Automated tests

`make check` builds the daemon with C11, `-Wall -Wextra -Wpedantic -Werror`, then
runs:

- Core protocol tests with disposable software identities: mutual
  authentication, independent directional/channel keys, key derivation checked
  against independent expected bytes, all-zero X25519 rejection, loss of each
  handshake message, reordered Finished/AUTH, early-data blocking, wrong pins,
  invalid signatures, and cached signing rather than repeated card operations.
- Packet tests: every authenticated-header/payload/tag byte modified in turn,
  zero-length and maximum payload, oversize rejection, duplicate/replay drops,
  reorder acceptance, forged sequences without replay-window advancement,
  replay-window boundaries, independent channel windows, and sequence ceiling.
- Lifecycle tests: local card-health gate, remote liveness timeout, rekey from
  either role, fresh session IDs, old-session packet rejection, and malformed
  packet noise against a live session.
- Actual loopback UDP sockets carrying handshake/encrypted channel traffic,
  including a lost handshake flight; a connected text socket verifying that
  delivery must use the proxy's exact source address and port.
- Built-in `--test-channels` diagnostics through actual local application
  sockets and the authenticated core: all channels and size classes, missing
  audio while video/text work, recovery after loss, delayed/reordered/duplicate
  echoes, corrupted replies, stale-session replies, port conflicts, fresh
  results after rekey, and no probing after card-health loss. CLI checks reject
  incompatible option combinations and confirm the mode cannot bypass HSM
  initialization failure.
- HSM adapter tests using a test-only PKCS#11 module and linked PC/SC simulator:
  wrong PIN, missing token, extractable key rejection, public/private key
  mismatch, sign failure, worker completion, removal, quick reinsertion,
  PC/SC service failure, and latched stale-health failure.
- CLI/config tests: valid public pins, unknown/duplicate/missing settings,
  malformed bounds/addresses/key IDs, wrong peer pin, missing module/token,
  and interruption while waiting for PIN input.

`make sanitize` runs protocol and HSM tests under AddressSanitizer and
UndefinedBehaviorSanitizer, with leak detection. Test mocks are never installed.
They validate adapter/state behavior, not the actual card's mechanisms or
OpenSC attribute reporting. `tests/test_config.py` needs Python 3 and the
OpenSSL command-line tool.

## Full acceptance procedure and remaining coverage

Basic real-card authentication, channel diagnostics, rekey from each role,
and card-removal/restart recovery have passed as recorded above. The procedure
below also includes checks not fully documented by the reported runs: detailed media measurements,
packet captures, injected network faults, precise removal timing, removal
during signing, pcscd failure, rapid reinsertion, concurrent rekeys, and
sustained-load measurements. Retain it for completion and future regression
testing; it is not a claim that every step has passed.

1. Record OS/OpenSSL/OpenSC/pcsc-lite versions; reader names, token serials,
   signing mechanisms, curve, ID, and certificate association. Do not initialize
   or alter an existing card as part of testing. Confirm the configured key
   satisfies the required PKCS#11 attributes and startup sign/verify check.
2. Verify pins independently, configure one initiator/responder, and run both
   daemons. Confirm SESSION ESTABLISHED at both peers. Test wrong-pin rejection
   only with a known retry budget; never repeatedly guess a real card PIN.
3. First run both daemons with `--test-channels`, leaving gtk-pipe stopped.
   Confirm key exchange and an overall CHANNEL TEST PASS on both hosts. Observe
   per-channel echoes/timeouts/RTT, test rekey with SIGUSR1, then stop both.
   This is the hardware/network check that requires no GTK, camera or microphone.
   Launch unchanged gtk-pipe with the documented loopback arguments. Verify
   video, audio, text, reachability heartbeats, and media stop/start in both
   directions. Confirm media sender IP/source ports in a loopback capture.
4. Capture the physical interface and loopback separately. Physical traffic
   must use the single tunnel port and contain no plaintext application
   datagrams. Record the maximum RTP/control UDP sizes and verify path MTU.
   Test a too-small path and confirm oversize/MTU counters and packet drops.
5. On a disposable test network, inject loss, duplication, delay and reordering
   (for example with `tc netem`). Expect media glitches/missing text from loss,
   but no protocol head-of-line wait or cross-channel replay-window interference.
6. Remove the local card during streaming and during signing. Measure local
   forwarding cessation and remote keepalive timeout. Verify local exit and
   zero forwarding on reinsertion until a fresh process/login/handshake.
   Repeat for pcscd loss and quick remove/reinsert. Check for middleware shutdown
   stalls; the network gate must already be closed even if cleanup hangs.
7. Send SIGUSR1 to each role, separately and concurrently. Verify fresh sessions,
   temporary media loss, rejection of old packets, and recovery under handshake
   loss. Restart either peer and verify fresh ephemeral/session state.
8. Run sustained traffic at gtk-pipe's highest selected setting. Record CPU,
   latency, channel counters and kernel/socket drops; UDP delivery is not
   guaranteed. Verify no payloads, PINs, shared secrets or traffic keys appear
   in ordinary logs.

The automated suites and sanitizer/leak checks passed on this workspace.
A separate copy containing no `gtk-pipe/` directory also built successfully
and installed into a temporary staging directory.


## Optional desktop integration (2026-09-13)

The new frontend is covered separately from the earlier operator-reported
hardware run. Backend tests cover read-only discovery, PIN-error classification,
private supervision IPC, stale/closed supervisor gates, backpressure, duplicate
managed launch rejection, and supervised startup errors. GTK parser and headless
controller tests cover PIN cancel/submit, buffer clearing, bad PIN, session
refresh, disconnect/reconnect, stale/malformed status and dialog teardown.
See [FRONTEND.md](FRONTEND.md) for commands and real-card acceptance requirements.
No real-card two-host graphical test was claimed at initial implementation.

### Operator follow-up and middleware reload regression (2026-09-14)

The operator reports working smartcard authentication, tunnel establishment and
video through the secure frontend, with repeated `OBJ_create: oid exists` and
`objects.c:677: Error adding objects` messages. Detailed media measurements and
fault-injection coverage remain as described above.

Discovery loaded/unloaded OpenSC once per poll. OpenSC's module-unload cleanup
resets OpenPACE's object-registration state while OpenSSL retains the registered
OIDs; subsequent initialization attempts register the same objects again. This
matches the [upstream OpenSC report](https://github.com/OpenSC/OpenSC/discussions/3563).
The adapter now uses `RTLD_NODELETE` so the configured module and dependencies
stay mapped until process exit. Session closure, logout, `C_Finalize`, and
secret erasure still happen normally; no errors are filtered from the log.

A mock provider regression registers a real test OID in OpenSSL and tracks
initialization/finalization/login calls. Two discovery probes without another
module reference failed before this change and pass afterward, with both probes
finalized and no PIN login. Existing login/signing/card-removal tests continue
to exercise the adapter afterward. Real-hardware confirmation that the reported
messages have stopped is still pending.
