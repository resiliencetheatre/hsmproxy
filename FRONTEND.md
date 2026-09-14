# GTK Pipe desktop integration

Secure mode is optional. Plain `gtk-pipe` retains its standalone UDP behavior.
`gtk-pipe --secure --ini-file FILE` uses a separately installed hsmproxy process
without opening a chooser; `gtk-pipe --secure` opens a configuration chooser.
The older `--secure-config FILE` spelling remains supported. No build-time
source-tree dependency is introduced between the projects.

## Implementation plan and boundaries

- Preserve the three existing UDP channels and connected text socket's exact
  source tuple. Secure mode fixes GTK to 127.0.0.1 and its peer to 127.0.0.2.
- Keep the existing handshake, packet format, OpenSSL primitives, peer pinning,
  isolated PKCS#11 worker, and card-health enforcement unchanged.
- Add read-only card discovery before requesting a PIN. One user submission
  causes at most one login; removal/reinsertion requires a fresh process/login.
- GTK owns a child backend, an anonymous PIN pipe, and a private Unix
  SOCK_SEQPACKET supervision socket. There is no public IPC listener, shell
  command construction, PIN persistence, or GTK dependency in hsmproxy.
- Versioned complete status snapshots convey card/login/tunnel state, configured
  ports, negotiated payload size, generation, and diagnostic counters. Writes
  are nonblocking; losing the supervisor closes the backend. GTK clears secure
  status on stale/malformed messages, child death, or socket closure.
- GTK gates text and media controls on backend forwarding state; the backend
  remains the security authority. Physical-interface firewall policy remains
  necessary to prevent deliberate direct use of standalone UDP mode.
- Stop stream preserves text/tunnel. Disconnect stops capture and the child.
  Rekey temporarily gates sending; card failure stops capture and needs a new
  PIN. Closing/crashing the frontend closes its owned backend.
- Test protocol validation and lifecycle with local sockets and mock adapters;
  run existing core/HSM/config checks, GTK build/plugin checks, and sanitizers.
  Real-card/two-host graphical acceptance remains a hardware test.

This extends the original PoC's UI scope without changing its trust model.

## Run and install

Build each project independently:

```sh
make
make -C gtk-pipe
```

From this workspace, run the combined interface without installing:

```sh
./gtk-pipe/gtk-pipe --secure --ini-file /absolute/path/to/site-a.ini \
  --hsmproxy "$PWD/hsmproxy"
```

On the other host select its own site-b profile. Use existing provisioned INI
files with absolute paths to public keys and the PKCS#11 module. Do not launch
another hsmproxy manually for the same connection. GTK starts and stops its own
child. Profile files contain no PINs and retain the existing peer trust policy.

For installation, install hsmproxy to a directory on the desktop session's PATH
and run gtk-pipe's existing `make install`. For example, a user installation:

```sh
make install PREFIX="$HOME/.local"
make -C gtk-pipe install
```

Ensure `~/.local/bin` is on the GNOME session's PATH. Alternatively configure
`--hsmproxy /absolute/path/to/hsmproxy` in the secure desktop entry. GTK Pipe
installation now supplies two launchers: **GTK Pipe** (original standalone
mode) and **GTK Pipe Secure** (`--secure`, which opens a profile chooser).
An administrator can set a fixed default and prevent the chooser by changing
the secure launcher's Exec line to
`gtk-pipe --secure --ini-file /etc/hsmproxy/site-a.ini`.

The two source trees can be separated again. Neither Makefile refers to the
other source tree, and neither project's installation copies test fixtures.

## Daily operation

1. Open the secure launcher and choose a provisioned profile. Read-only discovery
   checks the exact configured reader and token serial, without asking for a PIN
   or opening a data tunnel. Card discovery continues while this process waits.
2. Insert the configured card and press **Connect…**. Enter the **user PIN**.
   Cancellation leaves the card locked. One submission makes one login attempt;
   incorrect PINs are never retried automatically. Provider-supplied low/final
   attempt warnings and blocked-PIN status are displayed without guessing counts.
3. Identity verification and mutual peer authentication happen in hsmproxy.
   Only an established, locally healthy session enables text and Start stream.
   The separate peer-app dot reports GTK Pipe heartbeat reachability.
4. **Stop stream** releases the camera/microphone and keeps text and the tunnel.
   **Refresh session** asks hsmproxy to rekey. This first integration stops media
   when it observes any interruption of forwarding, including rekey: press
   Start stream again after establishment. It never automatically restarts
   capture after an interruption. Very short transitions between status
   snapshots may complete without an observed media stop.
5. **Disconnect & lock** terminates this application's backend/login session.
   It does not lock other applications' sessions. **Check card / reconnect**
   starts a fresh read-only discovery process; a new PIN is required. After
   disconnect or a fatal error the card label explicitly says it is not monitored.
6. **Change profile…** is available after the old backend exits. Closing the
   window closes its backend; a crashed or unresponsive frontend also causes
   the backend to stop. There is no background tray service or saved PIN.

Local card removal, reader failure, and monitor loss remain backend-enforced
fail-closed conditions. The frontend clears security state on error, EOF,
malformed/incompatible status, or four seconds without a snapshot. A backend
ignoring graceful termination is killed after two seconds. Remote card presence
is not claimed: remote closure/timeout conveys connection loss, not its cause.

Secure mode fixes loopback addresses and obtains ports and the negotiated RTP
payload budget from backend snapshots. Explicit `--peer`, `--bind`, port, and
`--rtp-mtu` overrides are rejected in secure mode. Oversize text is rejected
before sending. The video payloader uses the negotiated MTU; audio packet size
still needs real-media verification, especially with very small payload limits.
Secure mode can open without a camera for card management and text; standalone
camera requirements remain as before.

The host firewall must still prevent direct plaintext media/control traffic on
physical interfaces. Standalone GTK Pipe intentionally remains available.

## Local supervision protocol: HSPUI1

This is a local IPC contract, not a change to HSP1 tunnel packets. Both programs
keep their own small implementation; no shared source checkout is needed.

The parent supplies `--supervise-fd N --pin-fd M`, with distinct descriptors.
N must be a connected Unix SOCK_SEQPACKET socket. M supplies one PIN line through
an anonymous pipe and is closed after use. Supervision cannot be combined with
`--test-channels`, `--check-config`, or `--fingerprint`. Ordinary CLI behavior
without supervision is preserved.

Parent packets are exactly `PING`, `REKEY`, or `STOP` (ASCII, no newline).
EOF, malformed commands, or four seconds without PING disable forwarding and
terminate the child. GTK sends PING every 500 ms. The forwarding callbacks also
check the supervisor gate; no GTK callback or IPC operation performs crypto.
Managed instances reserve per-user/per-port abstract Unix socket names before
asking for a PIN, so overlapping managed windows fail before another login.
These sockets serve only as kernel-lifetime locks and have no command handler.

Child snapshots are ASCII, one complete packet each, at most 511 bytes:

```text
HSPUI1 state reason video_port audio_port text_port payload generation tx_v tx_a tx_t rx_v rx_a rx_t rejected oversize mtu_drops
```

Numbers are unsigned decimal; no trailing newline, embedded NUL, or extra fields.
Snapshots are sent every 500 ms and at selected startup/failure transitions.
A full nonblocking socket drops a snapshot rather than delaying the data path.
The next snapshot is complete. Generations cannot decrease within a child
process; a new process starts a new generation domain. Payload is the configured
limit until establishment, then the negotiated limit. Diagnostic counters are
cumulative during operation; terminal snapshots may clear counters.

| State | Value |
| --- | --- |
| Waiting for configured card/service | 0 |
| PIN required; card detected but identity not yet verified | 1 |
| Authenticating local card | 2 |
| Waiting for peer / reconnecting | 3 |
| Handshake in progress | 4 |
| Established and forwarding permitted | 5 |
| Error | 6 |
| Stopped | 7 |

| Reason | Value |
| --- | --- |
| No error | 0 |
| Configured card/reader not found | 1 |
| Card middleware/service unavailable | 2 |
| User PIN blocked | 3 |
| Incorrect PIN | 4 |
| Session/login failure | 5 |
| Identity/mechanism verification failure | 6 |
| Runtime card/reader health lost | 7 |
| Invalid profile/public key/pin | 8 |
| Backend startup/shutdown failure | 9 |
| Another managed instance owns a local port | 10 |
| Provider reports few PIN attempts remaining | 11 |
| Provider reports final PIN attempt | 12 |

No PIN, traffic key, payload, or private identity material appears in snapshots.
Logs remain on stderr. GTK uses fixed-size PIN storage, erases deleted text and
its transmission buffer, and disables core dumps before accepting a PIN.
This does not change the documented trusted-endpoint threat boundary.

## Verification

- `make check`: existing crypto/protocol/HSM tests, read-only discovery and PIN
  warning checks, supervision socket/type/timeout/EOF/backpressure tests, and
  daemon startup/duplicate-instance/frontend-death tests.
- `make sanitize`: core, HSM adapter, and supervision AddressSanitizer/UndefinedBehaviorSanitizer
  checks with leak detection.
- In gtk-pipe: `make check` validates build, installed media plugins, and the
  strict local status parser. `make check-ui` starts an isolated GTK3 Broadway
  display and exercises the real controller using a test-only fake backend.
  It uses no camera, real smartcard, or remote peer. `broadwayd` and Python 3 are
  required for this optional UI check. `make check-ui-sanitize` repeats the
  controller and actual application-gating tests under AddressSanitizer and
  UndefinedBehaviorSanitizer. GTK tests disable leak detection because of
  toolkit/process-global allocations; backend tests retain leak detection.
  UI tests also cover an immediate-exit error-delivery race, standalone text,
  negotiated video MTU, oversize text, and synthetic media capture teardown.

Hardware acceptance remains: launch both secure profiles with real cards, test
wrong-PIN feedback within a known retry budget, removal/reinsertion, rekey,
remote timeout, frontend/backend crash, text and media, and measure RTP sizes
and physical-interface traffic. The original two-host test record predates this
frontend and does not certify its real-card graphical workflow.
