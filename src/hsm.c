#include "hsm.h"
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>
#include <openssl/rand.h>

uint64_t monotonic_ms(void) {
    struct timespec ts; if(clock_gettime(CLOCK_MONOTONIC,&ts)) return 0;
    return (uint64_t)ts.tv_sec*1000+(uint64_t)ts.tv_nsec/1000000;
}
static void notify(struct hsm *h) { uint64_t one=1; (void)write(h->event_fd,&one,sizeof(one)); }
enum failure_reason { F_PCSC=1, F_STATE, F_COUNTER, F_STALE, F_SESSION,
    F_LOGIN_STATE, F_TOKEN, F_SERIAL, F_SIGN_INIT, F_SIGN, F_VERIFY };
static void record_failure(struct hsm *h,unsigned reason,uint32_t detail) {
    uint_fast64_t expected=0;
    uint_fast64_t value=((uint64_t)reason<<32)|detail;
    (void)atomic_compare_exchange_strong(&h->failure_detail,&expected,value);
    atomic_store(&h->failed,true);
}
void hsm_failure_message(struct hsm *h,char *out,size_t cap,uint64_t now) {
    uint64_t value=atomic_load(&h->failure_detail),last=atomic_load(&h->monitor_at);
    unsigned reason=(unsigned)(value>>32),code=(uint32_t)value;
    const char *names[]={"monitor startup/health unavailable","SCardGetStatusChange failed",
        "PC/SC card/reader state unavailable","PC/SC insertion counter changed",
        "monitor heartbeat exceeded 1000 ms","C_GetSessionInfo failed",
        "PKCS#11 session no longer logged in","C_GetTokenInfo failed",
        "token serial mismatch","C_SignInit failed","C_Sign failed","signature self-verification failed"};
    const char *name=reason<sizeof(names)/sizeof(names[0])?names[reason]:"unknown health failure";
    snprintf(out,cap,"%s; detail=0x%08x; monitor_age_ms=%llu; initial_reader_state=0x%08lx",
             name,code,(unsigned long long)(last && now>last?now-last:0),(unsigned long)h->reader_state);
}
static bool padded_equal(const CK_UTF8CHAR *s,size_t n,const char *value) {
    while(n && s[n-1]==' ') n--;
    return strlen(value)==n && !memcmp(s,value,n);
}
static bool attr_bool(struct hsm *h,CK_ATTRIBUTE_TYPE type,bool expected) {
    CK_BBOOL b=0; CK_ATTRIBUTE a={type,&b,sizeof(b)};
    return h->api->C_GetAttributeValue(h->session,h->key,&a,1)==CKR_OK &&
        a.ulValueLen==sizeof(b) && b==(expected?CK_TRUE:CK_FALSE);
}
static bool sign_digest(struct hsm *h,const uint8_t digest[32],uint8_t signature[64]) {
    CK_MECHANISM mechanism={CKM_ECDSA,NULL,0}; CK_ULONG len=64;
    CK_RV rv=h->api->C_SignInit(h->session,&mechanism,h->key);
    if(rv!=CKR_OK) { record_failure(h,F_SIGN_INIT,(uint32_t)rv); return false; }
    rv=h->api->C_Sign(h->session,(CK_BYTE_PTR)digest,32,signature,&len);
    if(rv!=CKR_OK) { record_failure(h,F_SIGN,(uint32_t)rv); return false; }
    if(len!=64 || !verify_digest(h->public_key,digest,signature)) {
        record_failure(h,F_VERIFY,(uint32_t)len); return false;
    }
    return true;
}
bool hsm_open(struct hsm *h,const struct config *c,EVP_PKEY *key,const uint8_t *pin,size_t pin_len,char *error,size_t cap) {
    memset(h,0,sizeof(*h)); h->session=CK_INVALID_HANDLE; h->event_fd=-1;
    atomic_init(&h->failed,false); atomic_init(&h->stop,false); atomic_init(&h->monitor_at,0); atomic_init(&h->failure_detail,0);
    if(pthread_mutex_init(&h->mutex,NULL)) { snprintf(error,cap,"mutex initialization failed"); return false; }
    if(pthread_cond_init(&h->cond,NULL)) { pthread_mutex_destroy(&h->mutex); snprintf(error,cap,"condition initialization failed"); return false; }
    h->initialized=true; const char *why="PKCS#11 module load failed";
    h->module=dlopen(c->module,RTLD_NOW|RTLD_LOCAL); if(!h->module) goto bad;
    CK_C_GetFunctionList get=NULL; void *symbol=dlsym(h->module,"C_GetFunctionList");
    _Static_assert(sizeof(get)==sizeof(symbol),"function pointer representation");
    memcpy(&get,&symbol,sizeof(get));
    if(!get || get(&h->api)!=CKR_OK || !h->api) goto bad;
    CK_C_INITIALIZE_ARGS args={0}; args.flags=CKF_OS_LOCKING_OK;
    if(h->api->C_Initialize(&args)!=CKR_OK) { h->api=NULL; goto bad; }
    CK_SLOT_ID slots[64]; CK_ULONG count=64;
    why="no unique configured token/reader found";
    if(h->api->C_GetSlotList(CK_TRUE,slots,&count)!=CKR_OK || count>64) goto bad;
    unsigned matches=0;
    for(CK_ULONG i=0;i<count;i++) {
        CK_TOKEN_INFO ti; CK_SLOT_INFO si;
        if(h->api->C_GetTokenInfo(slots[i],&ti)==CKR_OK && h->api->C_GetSlotInfo(slots[i],&si)==CKR_OK &&
           (si.flags&CKF_HW_SLOT) && padded_equal(ti.serialNumber,sizeof(ti.serialNumber),c->serial) &&
           padded_equal(si.slotDescription,sizeof(si.slotDescription),c->reader)) {
            h->slot=slots[i]; matches++;
        }
    }
    if(matches!=1) goto bad;
    /* Capture the insertion counter before signing. The monitor must reject
     * even a remove/reinsert between startup verification and its first wait. */
    why="PC/SC configured reader unavailable";
    if(SCardEstablishContext(SCARD_SCOPE_SYSTEM,NULL,NULL,&h->pcsc)!=SCARD_S_SUCCESS) goto bad;
    strcpy(h->reader,c->reader); strcpy(h->serial,c->serial);
    SCARD_READERSTATE initial={0}; initial.szReader=h->reader;
    if(SCardGetStatusChange(h->pcsc,0,&initial,1)!=SCARD_S_SUCCESS ||
       !(initial.dwEventState&SCARD_STATE_PRESENT) ||
       (initial.dwEventState&(SCARD_STATE_UNKNOWN|SCARD_STATE_UNAVAILABLE|SCARD_STATE_MUTE))) goto bad;
    h->reader_state=initial.dwEventState & ~SCARD_STATE_CHANGED;
    CK_MECHANISM_INFO mi; why="P-256 ECDSA signing unsupported";
    if(h->api->C_GetMechanismInfo(h->slot,CKM_ECDSA,&mi)!=CKR_OK || !(mi.flags&CKF_SIGN) ||
       mi.ulMinKeySize>256 || mi.ulMaxKeySize<256) goto bad;
    why="PKCS#11 session/login failed (PIN will not be retried)";
    if(h->api->C_OpenSession(h->slot,CKF_SERIAL_SESSION,NULL,NULL,&h->session)!=CKR_OK ||
       h->api->C_Login(h->session,CKU_USER,(CK_UTF8CHAR_PTR)pin,(CK_ULONG)pin_len)!=CKR_OK) goto bad;
    h->logged_in=true;
    uint8_t id[64]; size_t id_len=sizeof(id); (void)parse_hex(c->key_id,id,&id_len);
    CK_OBJECT_CLASS klass=CKO_PRIVATE_KEY; CK_KEY_TYPE kind=CKK_EC;
    CK_ATTRIBUTE attrs[]={{CKA_CLASS,&klass,sizeof(klass)},{CKA_KEY_TYPE,&kind,sizeof(kind)},
                          {CKA_ID,id,(CK_ULONG)id_len}};
    why="no unique configured private EC key";
    if(h->api->C_FindObjectsInit(h->session,attrs,3)!=CKR_OK) goto bad;
    CK_OBJECT_HANDLE objects[2]; CK_ULONG found=0;
    CK_RV rv=h->api->C_FindObjects(h->session,objects,2,&found);
    CK_RV final=h->api->C_FindObjectsFinal(h->session);
    if(rv!=CKR_OK || final!=CKR_OK || found!=1) goto bad;
    h->key=objects[0]; why="key must be hardware-generated, sensitive, nonextractable P-256 signing key";
    if(!attr_bool(h,CKA_SIGN,true) || !attr_bool(h,CKA_LOCAL,true) ||
       !attr_bool(h,CKA_SENSITIVE,true) || !attr_bool(h,CKA_ALWAYS_SENSITIVE,true) ||
       !attr_bool(h,CKA_EXTRACTABLE,false) || !attr_bool(h,CKA_NEVER_EXTRACTABLE,true) ||
       !attr_bool(h,CKA_ALWAYS_AUTHENTICATE,false)) goto bad;
    static const uint8_t p256_oid[]={0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};
    uint8_t params[32]; CK_ATTRIBUTE ec={CKA_EC_PARAMS,params,sizeof(params)};
    if(h->api->C_GetAttributeValue(h->session,h->key,&ec,1)!=CKR_OK ||
       ec.ulValueLen!=sizeof(p256_oid) || memcmp(params,p256_oid,sizeof(p256_oid))) goto bad;
    if(EVP_PKEY_up_ref(key)!=1) goto bad;
    h->public_key=key;
    uint8_t challenge[32],signature[64]; why="HSM sign/verify self-check failed";
    if(RAND_bytes(challenge,32)!=1 || !sign_digest(h,challenge,signature)) goto bad;
    h->event_fd=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
    if(h->event_fd<0) { why="eventfd failed"; goto bad; }
    return true;
bad:
    snprintf(error,cap,"%s",why); hsm_close(h); return false;
}
static void *worker(void *arg) {
    struct hsm *h=arg;
    pthread_mutex_lock(&h->mutex);
    while(!atomic_load(&h->stop)) {
        while(!h->pending && !atomic_load(&h->stop)) {
            struct timespec deadline; clock_gettime(CLOCK_REALTIME,&deadline); deadline.tv_sec++;
            int rc=pthread_cond_timedwait(&h->cond,&h->mutex,&deadline);
            if(rc==ETIMEDOUT) {
                pthread_mutex_unlock(&h->mutex);
                CK_SESSION_INFO si; CK_TOKEN_INFO ti;
                CK_RV rv=h->api->C_GetSessionInfo(h->session,&si);
                bool valid=false;
                if(rv!=CKR_OK) record_failure(h,F_SESSION,(uint32_t)rv);
                else if(si.state!=CKS_RO_USER_FUNCTIONS) record_failure(h,F_LOGIN_STATE,(uint32_t)si.state);
                else {
                    rv=h->api->C_GetTokenInfo(h->slot,&ti);
                    if(rv!=CKR_OK) record_failure(h,F_TOKEN,(uint32_t)rv);
                    else if(!padded_equal(ti.serialNumber,sizeof(ti.serialNumber),h->serial)) record_failure(h,F_SERIAL,0);
                    else valid=true;
                }
                if(!valid) notify(h);
                pthread_mutex_lock(&h->mutex);
                if(!valid) break;
            }
        }
        if(atomic_load(&h->stop)) break;
        if(atomic_load(&h->failed) && !h->pending) break;
        uint8_t digest[32],sig[64]={0}; memcpy(digest,h->digest,32);
        pthread_mutex_unlock(&h->mutex);
        bool ok=!atomic_load(&h->failed) && sign_digest(h,digest,sig);
        if(!ok) atomic_store(&h->failed,true);
        pthread_mutex_lock(&h->mutex);
        memcpy(h->signature,sig,64); h->success=ok; h->result=true; h->pending=false;
        OPENSSL_cleanse(digest,sizeof(digest)); OPENSSL_cleanse(sig,sizeof(sig)); notify(h);
    }
    pthread_mutex_unlock(&h->mutex); return NULL;
}
static void *monitor(void *arg) {
    struct hsm *h=arg; SCARD_READERSTATE state={0}; state.szReader=h->reader;
    state.dwCurrentState=h->reader_state;
    state.dwEventState=h->reader_state;
    DWORD previous=h->reader_state;
    while(!atomic_load(&h->stop)) {
        LONG rv=SCardGetStatusChange(h->pcsc,250,&state,1);
        if(rv!=SCARD_S_SUCCESS && rv!=SCARD_E_TIMEOUT) {
            if(!atomic_load(&h->stop)) record_failure(h,F_PCSC,(uint32_t)rv);
            break;
        }
        DWORD flags=state.dwEventState;
        if(!(flags&SCARD_STATE_PRESENT) || (flags&(SCARD_STATE_EMPTY|SCARD_STATE_UNKNOWN|SCARD_STATE_UNAVAILABLE|SCARD_STATE_MUTE))) {
            record_failure(h,F_STATE,(uint32_t)flags); break;
        }
        if((flags>>16)!=(previous>>16)) { record_failure(h,F_COUNTER,(uint32_t)flags); break; }
        previous=flags; state.dwCurrentState=flags & ~SCARD_STATE_CHANGED;
        atomic_store(&h->monitor_at,monotonic_ms()); notify(h);
    }
    if(!atomic_load(&h->stop)) atomic_store(&h->failed,true);
    notify(h); return NULL;
}
bool hsm_start(struct hsm *h,char *error,size_t cap) {
    if(pthread_create(&h->worker,NULL,worker,h)) { snprintf(error,cap,"HSM worker creation failed"); return false; }
    h->worker_started=true;
    if(pthread_create(&h->monitor,NULL,monitor,h)) { snprintf(error,cap,"PC/SC monitor creation failed"); return false; }
    h->monitor_started=true; return true;
}
bool hsm_submit(struct hsm *h,uint64_t generation,const uint8_t digest[32]) {
    pthread_mutex_lock(&h->mutex);
    bool ok=!h->pending && !h->result && !atomic_load(&h->failed) && !atomic_load(&h->stop);
    if(ok) { h->pending=true; h->generation=generation; memcpy(h->digest,digest,32); pthread_cond_signal(&h->cond); }
    pthread_mutex_unlock(&h->mutex); return ok;
}
bool hsm_result(struct hsm *h,uint64_t *generation,bool *ok,uint8_t sig[64]) {
    pthread_mutex_lock(&h->mutex); bool ready=h->result;
    if(ready) { *generation=h->generation; *ok=h->success; memcpy(sig,h->signature,64); h->result=false; }
    pthread_mutex_unlock(&h->mutex); return ready;
}
bool hsm_healthy(struct hsm *h,uint64_t now) {
    uint64_t last=atomic_load(&h->monitor_at);
    /* The caller samples now before this atomic load. A concurrent monitor
     * update may be newer than now; that is fresh evidence, not health loss. */
    uint64_t age=now>last?now-last:0;
    if(last && age>=1000) record_failure(h,F_STALE,(uint32_t)(age>UINT32_MAX?UINT32_MAX:age));
    return !atomic_load(&h->failed) && last && age<1000;
}
void hsm_close(struct hsm *h) {
    atomic_store(&h->stop,true);
    if(h->initialized) { pthread_mutex_lock(&h->mutex); pthread_cond_signal(&h->cond); pthread_mutex_unlock(&h->mutex); }
    if(h->pcsc) SCardCancel(h->pcsc);
    if(h->monitor_started) pthread_join(h->monitor,NULL);
    if(h->worker_started) pthread_join(h->worker,NULL);
    if(h->api) {
        if(h->session!=CK_INVALID_HANDLE) {
            if(h->logged_in) h->api->C_Logout(h->session);
            h->api->C_CloseSession(h->session);
        }
        h->api->C_Finalize(NULL);
    }
    if(h->pcsc) SCardReleaseContext(h->pcsc);
    EVP_PKEY_free(h->public_key);
    if(h->module) dlclose(h->module);
    if(h->event_fd>=0) close(h->event_fd);
    if(h->initialized) { pthread_cond_destroy(&h->cond); pthread_mutex_destroy(&h->mutex); }
    OPENSSL_cleanse(h,sizeof(*h)); h->event_fd=-1;
}
