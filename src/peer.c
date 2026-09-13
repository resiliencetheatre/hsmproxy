#include "core.h"
#include <string.h>
#include <openssl/rand.h>

static void event(struct peer *p,const char *s) { if(p->io.event) p->io.event(p->io.arg,s); }
static void send_bytes(struct peer *p,const uint8_t *b,size_t n) { p->io.send(p->io.arg,b,n); }
static void header(uint8_t *b,unsigned type,unsigned n,const uint8_t id[16]) {
    memset(b,0,28); memcpy(b,"HSP1",4); b[4]=1; b[5]=(uint8_t)type;
    put16(b+6,(uint16_t)n); memcpy(b+8,id,16);
}
static void reset(struct peer *p) {
    EVP_PKEY_free(p->eph); p->eph=NULL; p->phase=HS_IDLE; p->authed=false;
    OPENSSL_cleanse(&p->traffic,sizeof(p->traffic)); OPENSSL_cleanse(p->finish,sizeof(p->finish));
    OPENSSL_cleanse(p->h,sizeof(p->h)); memset(p->ping_at,0,sizeof(p->ping_at));
    p->generation++; p->retries=0; p->next_attempt=p->now+1000;
}
static void fail(struct peer *p) { event(p,"SESSION CLOSED"); reset(p); }
static void send_finish(struct peer *p,bool initiator) {
    uint8_t b[60]; header(b,initiator?4:5,32,p->init+8);
    if(confirmation(p->finish[initiator?0:1],p->h,initiator,b+28)) send_bytes(p,b,sizeof(b));
    else fail(p);
}
static void flight(struct peer *p) {
    if(p->phase==HS_INIT) send_bytes(p,p->init,sizeof(p->init));
    else if(p->phase==HS_WAIT_AUTH) send_bytes(p,p->response,sizeof(p->response));
    else if(p->phase==HS_WAIT_FINISH_R) {
        send_bytes(p,p->auth,sizeof(p->auth)); send_finish(p,true);
    }
}
static void established(struct peer *p) {
    p->phase=HS_ESTABLISHED; p->established=p->now; p->last_pong=p->now;
    p->next_ping=p->now; p->cache_until=p->now+15000;
    event(p,"SESSION ESTABLISHED");
}
static bool derive(struct peer *p) {
    bool ok=transcript(p->init,p->response+28,p->h) &&
        derive_traffic(p->eph,p->initiator?p->response+60:p->init+126,p->h,p->initiator,
                       get16(p->response+92),&p->traffic,p->finish);
    EVP_PKEY_free(p->eph); p->eph=NULL; return ok;
}
static void request_signature(struct peer *p,bool initiator) {
    uint8_t digest[32];
    if(!signature_digest(p->h,initiator,digest) || !p->io.sign(p->io.arg,p->generation,digest)) fail(p);
}
static void start(struct peer *p) {
    uint8_t id[16]; reset(p);
    if(RAND_bytes(id,16)!=1) return;
    header(p->init,1,134,id); put16(p->init+28,1);
    memcpy(p->init+30,p->local_pin,32); memcpy(p->init+62,p->peer_pin,32);
    if(RAND_bytes(p->init+94,32)!=1 || !(p->eph=ephemeral(p->init+126))) { fail(p); return; }
    put16(p->init+158,p->max_payload); put16(p->init+160,HSP_WINDOW);
    p->phase=HS_INIT; p->started=p->now; p->retry_at=p->now+500;
    event(p,"HANDSHAKE STARTED"); flight(p);
}
bool peer_init(struct peer *p,bool initiator,uint16_t max,EVP_PKEY *local,EVP_PKEY *remote,struct peer_io io) {
    memset(p,0,sizeof(*p));
    if(!p256_key(local) || !p256_key(remote) || max<64 || max>HSP_MAX_PAYLOAD || !io.send || !io.sign ||
       !public_pin(local,p->local_pin) || !public_pin(remote,p->peer_pin) ||
       !CRYPTO_memcmp(p->local_pin,p->peer_pin,32) || EVP_PKEY_up_ref(remote)!=1) return false;
    p->remote_key=remote; p->initiator=initiator; p->max_payload=max; p->io=io; return true;
}
void peer_destroy(struct peer *p) {
    EVP_PKEY_free(p->remote_key); EVP_PKEY_free(p->eph); OPENSSL_cleanse(p,sizeof(*p));
}
void peer_health(struct peer *p,bool healthy,uint64_t now) {
    p->now=now;
    if(p->healthy && !healthy) fail(p);
    if(!p->healthy && healthy) { event(p,"HSM READY"); p->next_attempt=now; }
    p->healthy=healthy;
}
static void control(struct peer *p,const uint8_t *b,size_t n) {
    uint8_t out[HSP_MAX_PACKET]; size_t len=seal_packet(&p->traffic,3,b,n,out);
    if(len) send_bytes(p,out,len); else fail(p);
}
void peer_close(struct peer *p,uint64_t now) {
    p->now=now;
    if(p->healthy && p->phase==HS_ESTABLISHED) { uint8_t b=3; control(p,&b,1); }
    fail(p);
}
void peer_rekey(struct peer *p,uint64_t now) {
    p->now=now;
    if(p->phase!=HS_ESTABLISHED) return;
    event(p,"REKEY STARTED"); uint8_t b=p->initiator?3:4; control(p,&b,1); fail(p);
    if(p->initiator && p->healthy) start(p);
}
void peer_tick(struct peer *p,uint64_t now) {
    p->now=now; if(!p->healthy) return;
    if(p->phase==HS_IDLE) { if(p->initiator && now>=p->next_attempt) start(p); return; }
    if(p->phase==HS_ESTABLISHED) {
        if(now-p->last_pong>=10000) { fail(p); return; }
        bool exhausted=false;
        for(unsigned i=0;i<4;i++) if(p->traffic.seq[i]>=HSP_LIMIT-1 ||
            (p->traffic.replay[i].initialized && p->traffic.replay[i].top>=HSP_LIMIT-2)) exhausted=true;
        if(now-p->established>=1800000 || exhausted) { peer_rekey(p,now); return; }
        if(p->cache_until && now>=p->cache_until) {
            OPENSSL_cleanse(p->finish,sizeof(p->finish)); p->cache_until=0;
        }
        if(now>=p->next_ping) {
            uint8_t b[9]={1}; unsigned i=p->ping_slot++%5;
            if(RAND_bytes(b+1,8)!=1) { fail(p); return; }
            memcpy(p->ping[i],b+1,8); p->ping_at[i]=now; p->next_ping=now+2000;
            control(p,b,sizeof(b));
        }
        return;
    }
    if(now-p->started>=15000) { fail(p); return; }
    if(now>=p->retry_at && p->retries<4) {
        static const unsigned delay[]={1000,2000,4000,4000};
        flight(p); p->retry_at=now+delay[p->retries++];
    }
}
void peer_signed(struct peer *p,uint64_t generation,bool ok,const uint8_t sig[64],uint64_t now) {
    p->now=now;
    if(generation!=p->generation || !p->healthy ||
       (p->phase!=HS_SIGN_I && p->phase!=HS_SIGN_R)) return;
    if(!ok || now-p->started>=15000) { fail(p); return; }
    if(p->phase==HS_SIGN_R) {
        memcpy(p->response+94,sig,64); p->phase=HS_WAIT_AUTH;
    } else {
        header(p->auth,3,64,p->init+8); memcpy(p->auth+28,sig,64); p->phase=HS_WAIT_FINISH_R;
    }
    p->retries=0; p->retry_at=now+500; flight(p);
}
static void data_received(struct peer *p,const uint8_t *b,size_t n) {
    unsigned ch; size_t len; uint8_t plain[HSP_MAX_PAYLOAD];
    if(p->phase!=HS_ESTABLISHED || !open_packet(&p->traffic,b,n,&ch,plain,&len)) { p->rejected++; return; }
    if(ch<3) { p->rx[ch]++; if(p->io.deliver) p->io.deliver(p->io.arg,ch,plain,len); }
    else if(len==9 && plain[0]==1) { plain[0]=2; control(p,plain,len); }
    else if(len==9 && plain[0]==2) {
        for(unsigned i=0;i<5;i++) if(p->ping_at[i] && p->now-p->ping_at[i]<10000 &&
            !CRYPTO_memcmp(plain+1,p->ping[i],8)) {
            p->last_pong=p->now; p->ping_at[i]=0; break;
        }
    } else if(len==1 && plain[0]==3) fail(p);
    else if(len==1 && plain[0]==4 && p->initiator) peer_rekey(p,p->now);
    OPENSSL_cleanse(plain,sizeof(plain));
}
void peer_receive(struct peer *p,const uint8_t *b,size_t n,uint64_t now) {
    p->now=now;
    if(!p->healthy || n<6 || memcmp(b,"HSP1",4) || b[4]!=1) { p->rejected++; return; }
    if(b[5]==16) { data_received(p,b,n); return; }
    if(n<28 || get16(b+6)!=n-28 || b[24] || b[25] || b[26] || b[27]) { p->rejected++; return; }
    unsigned type=b[5];
    if(type==1 && !p->initiator && n==HSP_INIT_LEN) {
        if(p->phase!=HS_IDLE) {
            if(!memcmp(b,p->init,n) && p->phase==HS_WAIT_AUTH && now>=p->retry_at) {
                send_bytes(p,p->response,sizeof(p->response)); p->retry_at=now+500;
            }
            return;
        }
        if(now<p->next_attempt || (p->last_admission && now-p->last_admission<1000) ||
           get16(b+28)!=1 || CRYPTO_memcmp(b+30,p->peer_pin,32) ||
           CRYPTO_memcmp(b+62,p->local_pin,32) || get16(b+158)<64 ||
           get16(b+158)>HSP_MAX_PAYLOAD || get16(b+160)!=HSP_WINDOW) { p->rejected++; return; }
        reset(p); p->last_admission=now; memcpy(p->init,b,n);
        header(p->response,2,130,b+8);
        if(RAND_bytes(p->response+28,32)!=1 || !(p->eph=ephemeral(p->response+60))) { fail(p); return; }
        uint16_t max=get16(b+158); if(max>p->max_payload) max=p->max_payload;
        put16(p->response+92,max); p->started=now;
        if(!derive(p)) { fail(p); return; }
        p->phase=HS_SIGN_R; event(p,"HANDSHAKE STARTED"); request_signature(p,false); return;
    }
    if(p->phase==HS_IDLE || CRYPTO_memcmp(b+8,p->init+8,16)) { p->rejected++; return; }
    if(type==2 && p->initiator && n==HSP_RESPONSE_LEN) {
        if(p->phase!=HS_INIT) return;
        uint16_t max=get16(b+92); uint8_t digest[32];
        if(max<64 || max>p->max_payload) { fail(p); return; }
        memcpy(p->response,b,n);
        if(!transcript(p->init,b+28,p->h) || !signature_digest(p->h,false,digest) ||
           !verify_digest(p->remote_key,digest,b+94) || !derive(p)) { fail(p); return; }
        event(p,"PEER SIGNATURE VERIFIED"); p->phase=HS_SIGN_I; request_signature(p,true); return;
    }
    if(type==3 && !p->initiator && n==92 && p->phase==HS_WAIT_AUTH) {
        if(p->authed) { if(memcmp(b,p->auth,n)) p->rejected++; return; }
        uint8_t digest[32];
        if(!signature_digest(p->h,true,digest) || !verify_digest(p->remote_key,digest,b+28)) { fail(p); return; }
        memcpy(p->auth,b,n); p->authed=true; event(p,"PEER SIGNATURE VERIFIED"); return;
    }
    if(type==4 && !p->initiator && n==60 &&
       ((p->phase==HS_WAIT_AUTH && p->authed) || (p->phase==HS_ESTABLISHED && p->cache_until))) {
        uint8_t expected[32];
        if(!confirmation(p->finish[0],p->h,true,expected) || CRYPTO_memcmp(expected,b+28,32)) {
            if(p->phase!=HS_ESTABLISHED) fail(p);
            return;
        }
        if(p->phase==HS_ESTABLISHED) {
            if(now>=p->retry_at) { send_finish(p,false); p->retry_at=now+500; }
        } else { send_finish(p,false); if(p->phase==HS_WAIT_AUTH) established(p); }
        return;
    }
    if(type==5 && p->initiator && n==60 && p->phase==HS_WAIT_FINISH_R) {
        uint8_t expected[32];
        if(!confirmation(p->finish[1],p->h,false,expected) || CRYPTO_memcmp(expected,b+28,32)) { fail(p); return; }
        established(p); return;
    }
    p->rejected++;
}
void peer_local(struct peer *p,unsigned ch,const uint8_t *b,size_t n) {
    if(ch>2) return;
    if(!p->healthy || p->phase!=HS_ESTABLISHED) { p->unavailable++; return; }
    if(n>p->traffic.max_payload) { p->oversize++; return; }
    uint8_t out[HSP_MAX_PACKET]; size_t len=seal_packet(&p->traffic,ch,b,n,out);
    if(!len) { peer_rekey(p,p->now); return; }
    send_bytes(p,out,len); p->tx[ch]++;
}
