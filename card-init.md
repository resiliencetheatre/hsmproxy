# Provisioning and recovering SmartCard-HSM cards

This guide prepares **two separate SmartCard-HSM cards**, one per hsmproxy peer.
It covers cards that have never been initialized, PIN maintenance, and
intentional destructive reinitialization. Commands target Debian 13 with
OpenSC 0.26.1, as installed for this project. They have been checked against
the tool help, manuals, and source; no card was provisioned while writing this
guide. Run card-changing commands individually and inspect each result.

The resulting identity is a hardware-generated P-256 signing key with ID `01`.
The private key stays on its card. Only its public key and fingerprint are
exchanged between peers. No CA or X.509 certificate is required for this PoC.

## 1. Understand and protect the two PINs

| Credential | Purpose | Value to record |
| --- | --- | --- |
| User PIN | Routine card login, including hsmproxy signing | A distinct secret for each card; the initialization tool accepts 6–16 characters |
| SO-PIN (Security Officer PIN, also called initialization code) | Administrative recovery and reinitialization | Exactly **16 hexadecimal characters**, representing 8 bytes; preserve leading zeroes |

**On a never-initialized card, the SO-PIN you supply becomes its SO-PIN. On an
already initialized card, initialization requires its current SO-PIN.** Supplying
a new value is not a way to override an unknown existing one. OpenSC documents
an SO-PIN retry limit of 15 and no unblock procedure once it is locked. Read
the actual remaining count rather than assuming all attempts remain.
[OpenSC SmartCard-HSM initialization and PIN documentation](https://github.com/OpenSC/OpenSC/wiki/SmartCardHSM#initialize-the-device)

Create independent, randomly generated SO-PINs for A and B in a trusted password
manager, restricted to the hexadecimal alphabet `0–9a–f` and length 16. Store
and verify the record **before** initializing. Do not use example PINs from
online tutorials. The tool's first-initialization prompt does not ask you to
enter the SO-PIN twice, so accurate entry and a retrievable record matter.

For each card, maintain a protected administrative record containing:

- Physical card/asset identifier and, once available, token serial.
- Site/owner and date of initialization.
- Exact current SO-PIN, explicitly labeled **16 hex characters**.
- User-PIN recovery policy and the location/custodian of that credential.
- Key ID `01`, public-key file, and SHA-256 SPKI fingerprint.
- Whether backup was enabled; this guide uses **no DKEK backup**.

Keep the SO-PIN in an encrypted administrative vault with a separately protected
recovery copy or sealed offline record. Test access to that record, not repeated
PIN guesses against the card. Restrict who can retrieve it, and keep it separate
from the card and routine proxy configuration. Do not put either PIN in this
repository, a ticket, chat, shell history, service unit, or command-line
argument. All commands below use interactive prompts for secrets.

This is a recovery credential with substantial authority: the OpenSC
initialization path used below enables resetting the user PIN through the
SO-PIN. Someone holding the card and SO-PIN may therefore reset the user PIN
and use existing identity keys, as well as erase the card. The proxy never needs
the SO-PIN. The default recovery setting is visible in the
[OpenSC 0.26.1 initialization implementation](https://github.com/OpenSC/OpenSC/blob/0.26.1/src/tools/sc-hsm-tool.c).

**Losing the SO-PIN does not automatically stop a working user PIN**, but it
removes your administrative recovery path. If user access is later lost too,
the card may be permanently unusable. There is no general factory-reset bypass
for a lost initialization code; this is explicitly explained by
[CardContact's SmartCard-HSM support guidance](https://www.smartcard-hsm.com/support.html).
Never deliberately exhaust PIN retries hoping to enable a reset.

## 2. Identify the card before any write

Stop hsmproxy and other software using the card. Provision one card at a time;
remove other cards to reduce the chance of selecting the wrong one.

```sh
sudo systemctl start pcscd.socket
opensc-tool --list-readers
pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --list-slots
```

An `empty` reader means **no card is detected**, not an uninitialized card.
Insert the card and repeat inventory. See [TESTING.md](TESTING.md) for
reported real-card verification.

The following Bash variables contain only nonsecret selection information.
Replace the reader number and slot ID with the values from your inventory;
these are different identifiers even if both happen to be zero.

```sh
HSM_MODULE=/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
HSM_READER=0
HSM_SLOT=0
```

Read the selected card's status without initializing it:

```sh
sc-hsm-tool --reader "$HSM_READER"
```

Confirm it is a SmartCard-HSM. A never-initialized card should be reported as
such. If it instead reports existing PINs or keys, treat it as provisioned and
use the maintenance sections below. Do not infer that a card is fresh simply
because you cannot see private objects without logging in. Do not use
`pkcs15-init` or an OpenPGP/PIV factory-reset recipe for this device.

Use a trusted terminal without session recording or shell tracing. Do not add
`--pin`, `--so-pin`, or `--new-pin` values to these commands, and do not enable
verbose APDU debugging while entering credentials.

## 3. First initialization — sets SO-PIN and user PIN

**This command erases existing application keys, certificates and files if the
card was previously initialized and you authenticate successfully.** Proceed
only after confirming that this is the intended new/erasable card and that its
SO-PIN record is saved.

For site A:

```sh
sc-hsm-tool --reader "$HSM_READER" --initialize \
  --label hsmproxy-site-a --pin-retry 3
```

At the hidden prompts:

1. Enter the new, saved **16-character hexadecimal SO-PIN**.
2. Enter the initial **user PIN**, 6–16 characters. A separately generated
   12-digit PIN is one suitable choice for this PoC.

For the other card, repeat the procedure separately with label
`hsmproxy-site-b` and different credentials.

This recipe omits `--dkek-shares`, which disables DKEK key wrapping/backup.
**Card loss or erasure will require a new identity and new peer pinning.**
Do not add `--dkek-shares 0` as a substitute: it requests a card-local random
DKEK and has different behavior. A portable backup needs a separately designed
DKEK/share custody and restore policy, established before valuable keys are
created. See the [OpenSC sc-hsm-tool manual](https://github.com/OpenSC/OpenSC/blob/0.26.1/doc/tools/sc-hsm-tool.1.xml).

Check status again and rediscover the slot after initialization:

```sh
sc-hsm-tool --reader "$HSM_READER"
pkcs11-tool --module "$HSM_MODULE" --list-slots
```

Confirm initialization, label/serial, and user-PIN retry state. On applicable
firmware, status also reports whether SO-PIN user-PIN reset is enabled. Read
stderr as well: OpenSC 0.26.1's initialization helper can print a card-command
failure without returning a failing exit status. Do not automatically chain
key generation based only on `$?` or `&&`.

Update `HSM_SLOT` if the slot changed. Copy the token serial into your asset
record. Leave the SO-PIN in the vault; the following identity operations use
the **user PIN**.

## 4. Generate the hsmproxy identity on the card

First confirm the selected slot contains the intended card and supports
EC key generation and ECDSA signing:

```sh
pkcs11-tool --module "$HSM_MODULE" --slot "$HSM_SLOT" --list-mechanisms
pkcs11-tool --module "$HSM_MODULE" --slot "$HSM_SLOT" \
  --login --list-objects
```

Check that key ID `01` is unused. Then generate site A's identity:

```sh
pkcs11-tool --module "$HSM_MODULE" --slot "$HSM_SLOT" \
  --login --keypairgen --key-type EC:prime256v1 \
  --id 01 --label hsmproxy-site-a-identity --usage-sign --sensitive
```

For site B, use its own card and label `hsmproxy-site-b-identity`; using ID `01`
on both separate cards is fine. Do not repeat key generation if the ID already
exists, import a software private key, or pass `--extractable` or `--always-auth`.
The latter requires a PIN per signature and is unsupported by this daemon.
The installed [pkcs11-tool options](https://github.com/OpenSC/OpenSC/blob/0.26.1/doc/tools/pkcs11-tool.1.xml)
define these key-generation and attribute controls.

Inspect the resulting private object:

```sh
pkcs11-tool --module "$HSM_MODULE" --slot "$HSM_SLOT" \
  --login --list-objects --type privkey --id 01
```

Expect EC/P-256, signing usage and sensitive, nonextractable, locally generated
attributes. hsmproxy additionally checks `CKA_ALWAYS_SENSITIVE`,
`CKA_NEVER_EXTRACTABLE`, and that `CKA_ALWAYS_AUTHENTICATE` is false, then verifies
a real signature against the configured public key. A failure of those checks
is a provisioning/provider compatibility issue; do not weaken the daemon's
checks to make a card appear usable.

## 5. Export public material and configure both peers

Use a dedicated working directory for this card's public files. For site A:

```sh
umask 077
mkdir -p "$HOME/hsmproxy-provision/site-a"
cd "$HOME/hsmproxy-provision/site-a"

pkcs11-tool --module "$HSM_MODULE" --slot "$HSM_SLOT" \
  --login --read-object --type pubkey --id 01 --output-file site-a.spki.der
openssl pkey -pubin -inform DER -in site-a.spki.der -out site-a.pub.pem
openssl pkey -pubin -in site-a.pub.pem -text -noout
```

Repeat with `site-b` filenames for card B. The DER export is public SPKI, not a
private-key backup. OpenSC makes public-key export available even before you
install an X.509 certificate, using the on-card key-generation metadata.
[OpenSC public-key generation/export documentation](https://github.com/OpenSC/OpenSC/wiki/SmartCardHSM#generate-key-pair)

From the project directory, or using an absolute path to the built binary:

```sh
./hsmproxy --fingerprint "$HOME/hsmproxy-provision/site-a/site-a.pub.pem"
```

Record the printed fingerprint. Transfer only public files to the opposite
host and independently verify their fingerprints through a trusted channel.
Do not copy an SO-PIN or user PIN along with the public key.

The configuration field named `certificate` also accepts a PEM public key.
For example, after placing the public files under `/etc/hsmproxy/`, site A's
identity and peer sections should include these values, alongside the other
required settings in [examples/site-a.ini](examples/site-a.ini):

```ini
[identity]
name = site-a
pkcs11_module = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
token_serial = ACTUAL_SITE_A_SERIAL
reader = EXACT_SITE_A_PCSC_READER_NAME
key_id_hex = 01
certificate = /etc/hsmproxy/site-a.pub.pem

[peer]
name = site-b
public_key = /etc/hsmproxy/site-b.pub.pem
spki_sha256 = VERIFIED_SITE_B_64_HEX_DIGIT_FINGERPRINT
```

On B, reverse local/remote identities and use **A's** pin as the expected peer
pin. Preserve public-file integrity with normal administrator-controlled
ownership; public keys are not secret, but replacing them and their configured
pins changes who is trusted.

```sh
./hsmproxy --check-config /path/to/site-a.ini
./hsmproxy --config /path/to/site-a.ini
```

The second command performs a card sign/verify check using the user PIN. Confirm
local identity verification and, with both peers running, session establishment.
`--check-config` alone does not test card access. See [TESTING.md](TESTING.md)
for full two-host acceptance.

## 6. Change a known user PIN without deleting keys

Stop the proxy, select the correct card, and run:

```sh
pkcs11-tool --module "$HSM_MODULE" --slot "$HSM_SLOT" \
  --login --change-pin
```

Enter the current **user PIN** at login and again if the tool asks for the
current PIN, then enter and confirm the new user PIN. Keep it 6–16 characters
and the same length or longer to avoid card-specific shortening restrictions.
Restart the proxy with the new user PIN. The identity key and peer pins do not
change. Update any protected credential record used by your supervisor.

## 7. Recover a forgotten or blocked user PIN without erasing keys

This requires the **known, unblocked SO-PIN** and a card initialized with
SO-PIN user-PIN reset enabled. The initialization recipe above enables that
policy. Check `sc-hsm-tool --reader "$HSM_READER"` first; a differently
provisioned card may prohibit it.

```sh
pkcs11-tool --module "$HSM_MODULE" --slot "$HSM_SLOT" \
  --login --login-type so --init-pin
```

Enter the current SO-PIN, then the new user PIN twice. This resets user access;
it is **not** `--init-token` or `sc-hsm-tool --initialize`. Verify a fresh user
login and the existing public-key fingerprint afterward. Key-preserving PIN
recovery should not require changing any peer pins. If SO authentication fails,
stop and check your vault record and remaining retries; do not script retries.
The interactive prompts are implemented in
[OpenSC 0.26.1 pkcs11-tool](https://github.com/OpenSC/OpenSC/blob/0.26.1/src/tools/pkcs11-tool.c).

## 8. Reinitialize a provisioned card — destructive

Use this when you intentionally want to discard the card's existing identity
and application data. Use user-PIN recovery above if you need to retain keys.

Before the destructive command, stop the proxy, positively identify the card,
retrieve its **current** SO-PIN, and record which peer configurations trust its
old fingerprint. With this guide's no-DKEK policy, the erased private keys
cannot be restored. A saved certificate or SPKI file cannot recreate them.

```sh
sc-hsm-tool --reader "$HSM_READER" --initialize \
  --label hsmproxy-site-a --pin-retry 3
```

At the SO-PIN prompt, supply the **existing current SO-PIN**, not a newly
invented one. Supply your chosen initial user PIN at the next prompt.
Reinitialization retains the SO-PIN used for administrative authentication;
SO-PIN rotation is a separate operation. This command is not a return to a
never-initialized state with no administrative credential.

Then inspect status and objects, generate a fresh P-256 key, export its public
key, and calculate its new fingerprint using sections 4–5. Replace the local
public-key file, distribute the new public key, and deliberately replace the
old pin on every authorized peer. Even with the same card, serial, label, and
ID `01`, the new identity has a different key and fingerprint. Remove the old
trust entry, especially if reinitialization follows suspected compromise.

If the SO-PIN is lost or blocked, this command cannot bypass it. Consult the
vendor for your precise model/firmware, but plan on replacement rather than
assuming a recovery backdoor. A still-working user PIN may permit continued
use of existing keys while you arrange a new identity; it does not replace
SO authorization for this reset.

## 9. Rotate a known SO-PIN

For supported SmartCard-HSM firmware, this changes the administrative secret
without erasing the identity. First save a distinct new 16-hex-character value
in your vault as **pending**, retain the current value until success is
confirmed, and stop other card users.

```sh
pkcs11-tool --module "$HSM_MODULE" --slot "$HSM_SLOT" \
  --login --login-type so --change-pin
```

Enter the current SO-PIN at login and again at any current-PIN prompt; enter
the new SO-PIN twice at the new-PIN prompts. All SO-PIN entries here use the
16-character hexadecimal representation, including leading zeroes.

After reported success, verify one fresh SO login using the new value:

```sh
pkcs11-tool --module "$HSM_MODULE" --slot "$HSM_SLOT" \
  --login --login-type so --session-rw --list-objects
```

Mark the new vault value current and synchronize the protected recovery copy.
If the command or connection fails ambiguously, inspect status and investigate
before further authentication attempts. Do not alternate guesses until the
retry counter is exhausted. A successful SO-PIN change does not change the
user PIN, signing key, or peer fingerprint.
