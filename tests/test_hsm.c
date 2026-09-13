/* PC/SC simulator linked only into this test executable, never the daemon. */
#include "hsm.h"
#include <assert.h>
#include <dlfcn.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static atomic_int pcsc_mode;
LONG SCardEstablishContext(DWORD scope,LPCVOID a,LPCVOID b,LPSCARDCONTEXT out) {
    (void)scope; (void)a; (void)b; *out=1; return SCARD_S_SUCCESS;
}
LONG SCardReleaseContext(SCARDCONTEXT c) { (void)c; return SCARD_S_SUCCESS; }
LONG SCardCancel(SCARDCONTEXT c) { (void)c; return SCARD_S_SUCCESS; }
LONG SCardGetStatusChange(SCARDCONTEXT c,DWORD timeout,LPSCARD_READERSTATE states,DWORD n) {
    (void)c; assert(n==1); assert(!strcmp(states[0].szReader,"Test Reader"));
    if(timeout) { struct timespec pause={0,1000000}; nanosleep(&pause,NULL); }
    int mode=atomic_load(&pcsc_mode);
    if(mode==3) return SCARD_E_NO_SERVICE;
    states[0].dwEventState=SCARD_STATE_PRESENT | ((mode==2?2u:1u)<<16);
    if(mode==1) states[0].dwEventState=SCARD_STATE_EMPTY | (2u<<16);
    return SCARD_S_SUCCESS;
}
static void wait_health(struct hsm *h,bool expected) {
    uint64_t end=monotonic_ms()+2000;
    while(monotonic_ms()<end) {
        if(hsm_healthy(h,monotonic_ms())==expected) return;
        struct pollfd fd={.fd=h->event_fd,.events=POLLIN}; (void)poll(&fd,1,20);
        uint64_t n; (void)read(h->event_fd,&n,sizeof(n));
    }
    assert(!"health transition timed out");
}
int main(void) {
    char path[512]; assert(realpath("tests/mock_pkcs11.so",path));
    void *module=dlopen(path,RTLD_NOW|RTLD_LOCAL); assert(module);
    void (*configure)(EVP_PKEY *,int)=NULL; void *symbol=dlsym(module,"mock_configure");
    assert(symbol); memcpy(&configure,&symbol,sizeof(configure));
    EVP_PKEY *key=EVP_PKEY_Q_keygen(NULL,NULL,"EC","prime256v1"); assert(key);
    struct config c={0}; strcpy(c.module,path); strcpy(c.serial,"TEST123"); strcpy(c.reader,"Test Reader"); strcpy(c.key_id,"01");
    char error[256]; struct hsm h;
    configure(key,0);
    assert(hsm_probe(&c)==HSM_READY);
    configure(key,5); assert(hsm_probe(&c)==HSM_PIN_LOCKED);
    configure(key,6); assert(hsm_probe(&c)==HSM_PIN_LOW);
    configure(key,7); assert(hsm_probe(&c)==HSM_PIN_FINAL);
    configure(key,0);
    atomic_store(&pcsc_mode,1); assert(hsm_probe(&c)==HSM_NO_CARD);
    atomic_store(&pcsc_mode,0);
    configure(key,1); assert(hsm_probe(&c)==HSM_NO_CARD);
    configure(key,0);
    assert(!hsm_open(&h,&c,key,(const uint8_t *)"wrong",5,error,sizeof(error)));
    assert(strstr(error,"login failed"));
    assert(h.open_error==HSM_PIN_INCORRECT);
    configure(key,1); assert(!hsm_open(&h,&c,key,(const uint8_t *)"1234",4,error,sizeof(error)));
    configure(key,2); assert(!hsm_open(&h,&c,key,(const uint8_t *)"1234",4,error,sizeof(error)));
    configure(key,3); assert(!hsm_open(&h,&c,key,(const uint8_t *)"1234",4,error,sizeof(error)));
    configure(key,0);
    EVP_PKEY *wrong=EVP_PKEY_Q_keygen(NULL,NULL,"EC","prime256v1"); assert(wrong);
    assert(!hsm_open(&h,&c,wrong,(const uint8_t *)"1234",4,error,sizeof(error))); EVP_PKEY_free(wrong);
    for(int mode=1;mode<=3;mode++) {
        atomic_store(&pcsc_mode,0);
        assert(hsm_open(&h,&c,key,(const uint8_t *)"1234",4,error,sizeof(error)));
        assert(hsm_start(&h,error,sizeof(error))); wait_health(&h,true);
        uint8_t digest[32]={42},signature[64]; assert(hsm_submit(&h,123,digest));
        uint64_t generation=0,end=monotonic_ms()+2000; bool ok=false,ready=false;
        while(monotonic_ms()<end && !(ready=hsm_result(&h,&generation,&ok,signature))) {
            struct pollfd fd={.fd=h.event_fd,.events=POLLIN}; (void)poll(&fd,1,20);
            uint64_t n; (void)read(h.event_fd,&n,sizeof(n));
        }
        assert(ready && ok && generation==123 && verify_digest(key,digest,signature));
        atomic_store(&pcsc_mode,mode); wait_health(&h,false);
        hsm_failure_message(&h,error,sizeof(error),monotonic_ms());
        assert(strstr(error,mode==1?"card/reader state":mode==2?"insertion counter":"SCardGetStatusChange"));
        atomic_store(&pcsc_mode,0); assert(!hsm_healthy(&h,monotonic_ms()));
        assert(!hsm_submit(&h,124,digest)); hsm_close(&h);
    }
    atomic_store(&pcsc_mode,0);
    assert(hsm_open(&h,&c,key,(const uint8_t *)"1234",4,error,sizeof(error)));
    assert(hsm_start(&h,error,sizeof(error))); wait_health(&h,true);
    configure(key,4); wait_health(&h,false);
    hsm_failure_message(&h,error,sizeof(error),monotonic_ms());
    assert(strstr(error,"session no longer logged in"));
    assert(strstr(error,"detail=0x00000000"));
    configure(key,0);
    assert(!hsm_healthy(&h,monotonic_ms()));
    uint8_t blocked_digest[32]={0}; assert(!hsm_submit(&h,125,blocked_digest));
    hsm_close(&h);
    assert(hsm_open(&h,&c,key,(const uint8_t *)"1234",4,error,sizeof(error)));
    uint64_t sampled=monotonic_ms();
    atomic_store(&h.monitor_at,sampled+1);
    assert(hsm_healthy(&h,sampled)); /* Concurrent monitor timestamp must not close a healthy session. */
    assert(!atomic_load(&h.failed));
    atomic_store(&h.monitor_at,monotonic_ms()-2000);
    assert(!hsm_healthy(&h,monotonic_ms()));
    hsm_failure_message(&h,error,sizeof(error),monotonic_ms());
    assert(strstr(error,"heartbeat exceeded"));
    atomic_store(&h.monitor_at,monotonic_ms()); assert(!hsm_healthy(&h,monotonic_ms())); hsm_close(&h);
    EVP_PKEY_free(key); dlclose(module);
    puts("hsm: wrong PIN, missing/unsafe key, signature mismatch, worker, removal/reinsert, login loss, PCSC failure and stale monitor tests passed");
    return 0;
}
