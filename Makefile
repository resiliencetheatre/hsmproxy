CC ?= cc
PKGS = openssl libpcsclite p11-kit-1
CPPFLAGS += -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -Isrc $(shell pkg-config --cflags $(PKGS))
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror
LDLIBS += $(shell pkg-config --libs $(PKGS)) -ldl -pthread
CORE = src/crypto.c src/packet.c src/peer.c
DAEMON = src/main.c src/config.c src/hsm.c src/channel_test.c src/supervisor.c
PREFIX ?= /usr/local
.PHONY: all check sanitize clean install
all: hsmproxy
hsmproxy: $(CORE) $(DAEMON) src/core.h src/config.h src/hsm.h src/channel_test.h src/supervisor.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(CORE) $(DAEMON) $(LDLIBS)
tests/test_core: tests/test_core.c $(CORE) src/channel_test.c src/channel_test.h src/core.h src/config.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/test_core.c $(CORE) src/channel_test.c $(LDLIBS)
tests/mock_pkcs11.so: tests/mock_pkcs11.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared -o $@ $< $(LDLIBS)
tests/test_hsm: tests/test_hsm.c src/hsm.c src/config.c $(CORE) src/hsm.h tests/mock_pkcs11.so
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/test_hsm.c src/hsm.c src/config.c $(CORE) $(LDLIBS)
tests/test_supervisor: tests/test_supervisor.c src/supervisor.c src/supervisor.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ tests/test_supervisor.c src/supervisor.c $(LDLIBS)
check: hsmproxy tests/test_core tests/test_hsm tests/test_supervisor
	./tests/test_core
	./tests/test_hsm
	./tests/test_supervisor
	python3 tests/test_config.py
	./hsmproxy --help
sanitize: tests/mock_pkcs11.so
	$(CC) $(CPPFLAGS) -std=c11 -g -O1 -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -o tests/test_sanitize tests/test_core.c $(CORE) src/channel_test.c $(LDLIBS)
	ASAN_OPTIONS=detect_leaks=1 ./tests/test_sanitize
	$(CC) $(CPPFLAGS) -std=c11 -g -O1 -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -o tests/test_hsm_sanitize tests/test_hsm.c src/hsm.c src/config.c $(CORE) $(LDLIBS)
	ASAN_OPTIONS=detect_leaks=1 ./tests/test_hsm_sanitize
	$(CC) $(CPPFLAGS) -std=c11 -g -O1 -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -o tests/test_supervisor_sanitize tests/test_supervisor.c src/supervisor.c $(LDLIBS)
	ASAN_OPTIONS=detect_leaks=1 ./tests/test_supervisor_sanitize
install: hsmproxy
	install -Dm755 hsmproxy $(DESTDIR)$(PREFIX)/bin/hsmproxy
clean:
	rm -f tests/test_supervisor tests/test_supervisor_sanitize hsmproxy tests/test_core tests/test_hsm tests/mock_pkcs11.so tests/test_sanitize tests/test_hsm_sanitize
