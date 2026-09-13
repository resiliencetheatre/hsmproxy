#ifndef HSP_CORE_H
#define HSP_CORE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <openssl/evp.h>

#define HSP_MAX_PAYLOAD 1400u
#define HSP_MAX_PACKET (HSP_MAX_PAYLOAD + 48u)
#define HSP_WINDOW 1024u
#define HSP_LIMIT (UINT64_C(1) << 30)
#define HSP_INIT_LEN 162u
#define HSP_RESPONSE_LEN 158u

struct replay { uint64_t top; uint64_t bits[16]; bool initialized; };
struct traffic {
    uint8_t id[16], tx[4][32], rx[4][32];
    uint64_t seq[4];
    struct replay replay[4];
    uint16_t max_payload;
};
bool replay_allowed(const struct replay *, uint64_t);
void replay_commit(struct replay *, uint64_t);
void put16(uint8_t *, uint16_t);
uint16_t get16(const uint8_t *);
void put64(uint8_t *, uint64_t);
uint64_t get64(const uint8_t *);
bool hash256(const void *, size_t, uint8_t[32]);
bool p256_key(EVP_PKEY *);
EVP_PKEY *load_public(const char *);
bool public_pin(EVP_PKEY *, uint8_t[32]);
bool verify_digest(EVP_PKEY *, const uint8_t[32], const uint8_t[64]);
EVP_PKEY *ephemeral(uint8_t[32]);
bool derive_traffic(EVP_PKEY *, const uint8_t[32], const uint8_t[32],
                    bool, uint16_t, struct traffic *, uint8_t[2][32]);
bool transcript(const uint8_t[HSP_INIT_LEN], const uint8_t[66], uint8_t[32]);
bool signature_digest(const uint8_t[32], bool, uint8_t[32]);
bool confirmation(const uint8_t[32], const uint8_t[32], bool, uint8_t[32]);
size_t seal_packet(struct traffic *, unsigned, const void *, size_t, uint8_t *);
bool open_packet(struct traffic *, const uint8_t *, size_t, unsigned *, uint8_t *, size_t *);

enum phase { HS_IDLE, HS_INIT, HS_SIGN_R, HS_WAIT_AUTH, HS_SIGN_I,
             HS_WAIT_FINISH_R, HS_ESTABLISHED };
/* Callbacks are synchronous except sign: it queues a request and returns.
 * Completion must be delivered to peer_signed() on the owner's event loop.
 * send must copy/use the buffer before returning. No callback may reenter. */
struct peer_io {
    void (*send)(void *, const uint8_t *, size_t);
    bool (*sign)(void *, uint64_t, const uint8_t[32]);
    void (*deliver)(void *, unsigned, const uint8_t *, size_t);
    void (*event)(void *, const char *);
    void *arg;
};
struct peer {
    bool initiator, healthy, authed;
    enum phase phase;
    uint16_t max_payload;
    uint8_t local_pin[32], peer_pin[32];
    EVP_PKEY *remote_key, *eph;
    struct peer_io io;
    uint64_t generation, now, started, established, retry_at, next_attempt;
    uint64_t next_ping, last_pong, cache_until, last_admission;
    unsigned retries;
    uint8_t init[HSP_INIT_LEN], response[HSP_RESPONSE_LEN], auth[92];
    uint8_t h[32], finish[2][32], ping[5][8];
    uint64_t ping_at[5];
    unsigned ping_slot;
    struct traffic traffic;
    uint64_t tx[3], rx[3], rejected, unavailable, oversize;
};
bool peer_init(struct peer *, bool, uint16_t, EVP_PKEY *, EVP_PKEY *, struct peer_io);
void peer_destroy(struct peer *);
void peer_health(struct peer *, bool, uint64_t);
void peer_tick(struct peer *, uint64_t);
void peer_receive(struct peer *, const uint8_t *, size_t, uint64_t);
void peer_signed(struct peer *, uint64_t, bool, const uint8_t[64], uint64_t);
void peer_local(struct peer *, unsigned, const uint8_t *, size_t);
void peer_rekey(struct peer *, uint64_t);
void peer_close(struct peer *, uint64_t);
#endif
