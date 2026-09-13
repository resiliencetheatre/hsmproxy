#ifndef HSP_CHANNEL_TEST_H
#define HSP_CHANNEL_TEST_H
#include "config.h"
#include <stdio.h>

#define CHANNEL_TEST_PENDING 8u
struct channel_probe {
    bool pending;
    uint64_t sequence, sent_at;
    size_t length;
    uint8_t reply[HSP_MAX_PAYLOAD];
};
struct channel_results {
    uint64_t sent, echoed, requests, timed_out, send_errors, invalid, stale, rtt_ms;
    unsigned sizes;
    struct replay requests_seen;
    struct channel_probe probes[CHANNEL_TEST_PENDING];
};
struct channel_test {
    int fd[3];
    bool active, initiator, announced, completed, failed;
    uint8_t session[16];
    uint16_t max_payload;
    uint64_t next_send, sequence;
    struct channel_results channels[3];
    FILE *log;
};
/* These sockets stand in for gtk-pipe, not for the tunnel. They connect from
 * the configured local application targets to the existing proxy listeners. */
bool channel_test_open(struct channel_test *, const struct config *, FILE *);
void channel_test_close(struct channel_test *);
void channel_test_session(struct channel_test *, bool, const uint8_t *, uint16_t, uint64_t);
bool channel_test_tick(struct channel_test *, uint64_t);
void channel_test_receive(struct channel_test *, unsigned, uint64_t);
bool channel_test_passed(const struct channel_test *);
void channel_test_report(const struct channel_test *);
#endif
