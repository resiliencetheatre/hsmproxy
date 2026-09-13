#ifndef HSP_HSM_H
#define HSP_HSM_H
#include "config.h"
#include <pthread.h>
#include <stdatomic.h>
#include <p11-kit/pkcs11.h>
#include <winscard.h>
enum hsm_discovery { HSM_READY, HSM_NO_CARD, HSM_UNAVAILABLE, HSM_PIN_LOCKED,
                     HSM_PIN_INCORRECT, HSM_LOGIN_ERROR, HSM_IDENTITY_ERROR,
                     HSM_PIN_LOW, HSM_PIN_FINAL };
struct hsm {
    enum hsm_discovery open_error;
    CK_FLAGS token_flags;
    void *module;
    CK_FUNCTION_LIST_PTR api;
    CK_SLOT_ID slot;
    CK_SESSION_HANDLE session;
    CK_OBJECT_HANDLE key;
    SCARDCONTEXT pcsc;
    DWORD reader_state;
    char reader[65];
    char serial[32];
    EVP_PKEY *public_key;
    pthread_t worker, monitor;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool worker_started, monitor_started, initialized, logged_in;
    bool pending, result, success;
    uint64_t generation;
    uint8_t digest[32], signature[64];
    atomic_bool stop, failed;
    atomic_uint_fast64_t monitor_at, failure_detail;
    int event_fd;
};
uint64_t monotonic_ms(void);
enum hsm_discovery hsm_probe(const struct config *);
bool hsm_open(struct hsm *,const struct config *,EVP_PKEY *,const uint8_t *,size_t,char *,size_t);
bool hsm_start(struct hsm *,char *,size_t);
bool hsm_submit(struct hsm *,uint64_t,const uint8_t[32]);
bool hsm_result(struct hsm *,uint64_t *,bool *,uint8_t[64]);
bool hsm_healthy(struct hsm *,uint64_t);
void hsm_close(struct hsm *);
void hsm_failure_message(struct hsm *,char *,size_t,uint64_t);
#endif
