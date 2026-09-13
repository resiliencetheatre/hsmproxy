• Use card-a on host-a (site-a, initiator) and card-b on host-b (site-b, responder). Each host needs its own
  card’s public key and the other card’s public key.

  1. Collect the card details on each host

  With the appropriate card inserted:

  opensc-tool --list-readers
  pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --list-slots

  Record the exact reader name, token serial, and slot ID. The token_serial setting is the card/token
  serial, not the reader’s serial.

  If initialization only set the PINs, generate the P-256 identity first using section 4 of card-init.md.
  The following assumes that key already exists with ID 01.

  2. Export each card’s public key

  Run from the project directory. Replace 0 with the actual slot ID.

  On host-a, with card-a:

  pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
    --slot 0 --login --read-object --type pubkey --id 01 \
    --output-file site-a.spki.der

  openssl pkey -pubin -inform DER \
    -in site-a.spki.der -out site-a.pub.pem

  ./hsmproxy --fingerprint site-a.pub.pem

  On host-b, with card-b:

  pkcs11-tool --module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so \
    --slot 0 --login --read-object --type pubkey --id 01 \
    --output-file site-b.spki.der

  openssl pkey -pubin -inform DER \
    -in site-b.spki.der -out site-b.pub.pem

  ./hsmproxy --fingerprint site-b.pub.pem

  Exchange the .pub.pem files so both hosts have both public keys. Verify the fingerprints against the
  values printed on their originating hosts.

  On each host, install those public files:

  sudo install -d -m 0755 /etc/hsmproxy
  sudo install -m 0644 site-a.pub.pem site-b.pub.pem /etc/hsmproxy/

3. Edit the configurations

  On host-a, use this for examples/site-a.ini. Replace the uppercase placeholders with actual values:

  [identity]
  name = site-a
  pkcs11_module = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
  token_serial = CARD_A_TOKEN_SERIAL
  reader = EXACT_READER_NAME_ON_HOST_A
  key_id_hex = 01
  certificate = /etc/hsmproxy/site-a.pub.pem

  [peer]
  name = site-b
  public_key = /etc/hsmproxy/site-b.pub.pem
  spki_sha256 = CARD_B_FINGERPRINT

  [local]
  listen_address = 127.0.0.2
  target_address = 127.0.0.1
  video_port = 5000
  audio_port = 5002
  text_port = 5004

  [tunnel]
  role = initiator
  bind = HOST_A_IPV4:5500
  peer = HOST_B_IPV4:5500
  max_payload = 1400

  On host-b, use this for examples/site-b.ini:

  [identity]
  name = site-b
  pkcs11_module = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
  token_serial = CARD_B_TOKEN_SERIAL
  reader = EXACT_READER_NAME_ON_HOST_B
  key_id_hex = 01
  certificate = /etc/hsmproxy/site-b.pub.pem

  [peer]
  name = site-a
  public_key = /etc/hsmproxy/site-a.pub.pem
  spki_sha256 = CARD_A_FINGERPRINT

  [local]
  listen_address = 127.0.0.2
  target_address = 127.0.0.1
  video_port = 5000
  audio_port = 5002
  text_port = 5004

  [tunnel]
  role = responder
  bind = HOST_B_IPV4:5500
  peer = HOST_A_IPV4:5500
  max_payload = 1400

  Important details:

  - spki_sha256 always contains the other card’s fingerprint: exactly 64 hexadecimal characters, without
    colons or a SHA256: prefix.

  - Use numeric, mutually reachable IPv4 addresses—not host-a or host-b hostnames.
  - Keep the loopback addresses identical on both machines.
  - certificate accepts the exported PEM public key; no certificate creation is needed.
  - Neither PIN belongs in these files.

  4. Validate and run

  On host-a:

  ./hsmproxy --check-config examples/site-a.ini
  ./hsmproxy --config examples/site-a.ini --test-channels

  On host-b:

  ./hsmproxy --check-config examples/site-b.ini
  ./hsmproxy --config examples/site-b.ini --test-channels

  Enter each card’s user PIN. Keep gtk-pipe stopped and allow UDP 5500 between the hosts. The default
  payload requires a path MTU of at least 1476 bytes.

  Wait for CHANNEL TEST PASS on both hosts, then stop with Ctrl-C.
