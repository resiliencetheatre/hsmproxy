#!/usr/bin/env python3
"""CLI/config failure tests. Ephemeral software identities exist only here."""
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXE = ROOT / 'hsmproxy'

def run(*args, **kw):
    return subprocess.run(args, capture_output=True, timeout=10, **kw)

with tempfile.TemporaryDirectory(prefix='hsmproxy-test-') as tmp:
    tmp = pathlib.Path(tmp)
    for name in ('local', 'remote'):
        assert run('openssl', 'genpkey', '-algorithm', 'EC', '-pkeyopt',
                   'ec_paramgen_curve:P-256', '-out', str(tmp / (name + '.key'))).returncode == 0
        assert run('openssl', 'pkey', '-in', str(tmp / (name + '.key')), '-pubout',
                   '-out', str(tmp / (name + '.pub'))).returncode == 0
    pin = run(str(EXE), '--fingerprint', str(tmp / 'remote.pub'))
    assert pin.returncode == 0 and len(pin.stdout.strip()) == 64
    # Tests must not depend on deployment examples, which operators edit.
    source = """[identity]
name = site-a
pkcs11_module = /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so
token_serial = REPLACE_SERIAL
reader = REPLACE_EXACT_PCSC_READER
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
"""
    source = source.replace('/etc/hsmproxy/site-a.crt', str(tmp / 'local.pub'))
    source = source.replace('/etc/hsmproxy/site-b.pub.pem', str(tmp / 'remote.pub'))
    source = source.replace('REPLACE_WITH_64_HEX_DIGITS', pin.stdout.decode().strip())
    config = tmp / 'test.ini'
    config.write_text(source)
    result = run(str(EXE), '--check-config', str(config))
    assert result.returncode == 0, result.stderr
    mutations = [
        source + '\nmax_payload = 1400\n',
        source + '\nunknown = yes\n',
        source.replace('max_payload = 1400', 'max_payload = 65536'),
        source.replace('max_payload = 1400', 'max_payload = -1'),
        source.replace('max_payload = 1400', 'max_payload = 63'),
        source.replace('audio_port = 5002', 'audio_port = 5000'),
        source.replace('127.0.0.2', '0.0.0.0'),
        source.replace('role = initiator', 'role = auto'),
        source.replace('role = initiator', ''),
        source.replace('192.0.2.20:5500', 'example.org:5500'),
        source.replace('192.0.2.20:5500', '224.0.0.1:5500'),
        source.replace('key_id_hex = 01', 'key_id_hex = xyz'),
        source.replace('key_id_hex = 01', 'key_id_hex = 1'),
        source.replace(pin.stdout.decode().strip(), '00' * 32),
        source.replace('name = site-a', 'name = ' + 'x' * 1300),
        source.replace('[identity]', '[mystery]'),
    ]
    for i, text in enumerate(mutations):
        config.write_text(text)
        result = run(str(EXE), '--check-config', str(config))
        assert result.returncode == 2, (i, result.stdout, result.stderr)
    config.write_text(source)
    for args in [('--check-config', str(config), '--test-channels'),
                 ('--fingerprint', str(tmp / 'remote.pub'), '--test-channels'),
                 ('--config', str(config), '--test-channels', '--test-channels')]:
        assert run(str(EXE), *args).returncode == 2
    # Missing module is a local fatal failure: no sockets or fallback path.
    config.write_text(source.replace('/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so', '/nonexistent/hsmproxy-test.so'))
    result = run(str(EXE), '--config', str(config), '--pin-fd', '0', input=b'test-only\n')
    assert result.returncode == 1 and b'module load failed' in result.stderr, result.stderr
    result = run(str(EXE), '--config', str(config), '--test-channels', '--pin-fd', '0', input=b'test-only\n')
    assert result.returncode == 1 and b'module load failed' in result.stderr, result.stderr
    # A deliberately nonexistent reader/token can never log in to a real card.
    config.write_text(source)
    result = run(str(EXE), '--config', str(config), '--pin-fd', '0', input=b'test-only\n')
    assert result.returncode == 1 and b'no unique configured token/reader' in result.stderr, result.stderr
    # Normal termination while waiting for PIN input exits without hanging.
    proc = subprocess.Popen([str(EXE), '--config', str(config), '--pin-fd', '0'],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    import time
    time.sleep(0.1)
    proc.terminate()
    proc.wait(timeout=3)
    proc.communicate(timeout=3)
    assert proc.returncode != 0
print('config: strict parsing, pins, missing module/token, and interrupted PIN tests passed')
