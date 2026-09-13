#include "core.h"
#include "channel_test.h"
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>

static bool software_sign(EVP_PKEY *key,const uint8_t digest[32],uint8_t raw[64]) {
    EVP_PKEY_CTX *c=EVP_PKEY_CTX_new(key,NULL); uint8_t der[80]; size_t n=sizeof(der);
    bool ok=c && EVP_PKEY_sign_init(c)>0 && EVP_PKEY_CTX_set_signature_md(c,EVP_sha256())>0 &&
        EVP_PKEY_sign(c,der,&n,digest,32)>0;
    EVP_PKEY_CTX_free(c); if(!ok) return false;
    const unsigned char *p=der; ECDSA_SIG *s=d2i_ECDSA_SIG(NULL,&p,(long)n);
    if(!s) return false;
    const BIGNUM *r,*b; ECDSA_SIG_get0(s,&r,&b);
    ok=BN_bn2binpad(r,raw,32)==32 && BN_bn2binpad(b,raw+32,32)==32;
    ECDSA_SIG_free(s); return ok;
}
struct harness;
struct endpoint {
    struct harness *h; struct peer p; EVP_PKEY *key;
    unsigned index, signatures, delivered[3];
    struct channel_test *test; int proxy_fd[3]; struct sockaddr_in target[3];
    uint8_t last[HSP_MAX_PAYLOAD]; size_t last_len;
    bool pending, bad_sign; uint64_t generation; uint8_t digest[32];
};
struct message { unsigned target; size_t n; uint8_t b[HSP_MAX_PACKET]; };
struct harness {
    struct endpoint e[2]; struct message queue[512]; size_t read,write;
    uint64_t now; unsigned drop_type,drop_count,drop_channels; bool drop_all, reverse_finish, udp; int fd[2];
};
static void send_cb(void *arg,const uint8_t *b,size_t n) {
    struct endpoint *e=arg; struct harness *h=e->h;
    assert(n<=HSP_MAX_PACKET);
    if(b[5]==16 && b[6]<3 && (h->drop_channels & (1u<<b[6]))) return;
    if(b[5]==h->drop_type && (h->drop_count || h->drop_all)) {
        if(h->drop_count) h->drop_count--;
        return;
    }
    if(h->udp) { assert(send(h->fd[e->index],b,n,0)==(ssize_t)n); return; }
    assert(h->write-h->read<512);
    struct message *m=&h->queue[h->write++%512]; m->target=1-e->index; m->n=n; memcpy(m->b,b,n);
}
static bool sign_cb(void *arg,uint64_t generation,const uint8_t digest[32]) {
    struct endpoint *e=arg; assert(!e->pending); e->pending=true; e->generation=generation;
    memcpy(e->digest,digest,32); e->signatures++; return true;
}
static void deliver_cb(void *arg,unsigned ch,const uint8_t *b,size_t n) {
    struct endpoint *e=arg; assert(ch<3); e->delivered[ch]++; e->last_len=n; memcpy(e->last,b,n);
    if(e->test) assert(sendto(e->proxy_fd[ch],b,n,0,(struct sockaddr *)&e->target[ch],sizeof(e->target[ch]))==(ssize_t)n);
}
static void setup(struct harness *h) {
    memset(h,0,sizeof(*h)); h->now=1000;
    for(unsigned i=0;i<2;i++) {
        h->e[i].h=h; h->e[i].index=i; h->e[i].key=EVP_PKEY_Q_keygen(NULL,NULL,"EC","prime256v1");
        assert(h->e[i].key);
    }
    for(unsigned i=0;i<2;i++) {
        struct peer_io io={send_cb,sign_cb,deliver_cb,NULL,&h->e[i]};
        assert(peer_init(&h->e[i].p,i==0,HSP_MAX_PAYLOAD,h->e[i].key,h->e[1-i].key,io));
        peer_health(&h->e[i].p,true,h->now);
    }
}
static void cleanup(struct harness *h) {
    if(h->udp) { close(h->fd[0]); close(h->fd[1]); }
    for(unsigned i=0;i<2;i++) {
        if(h->e[i].test) { channel_test_close(h->e[i].test); for(unsigned ch=0;ch<3;ch++) close(h->e[i].proxy_fd[ch]); }
        peer_destroy(&h->e[i].p); EVP_PKEY_free(h->e[i].key);
    }
}
static void sync_channel_tests(struct harness *h) {
    for(unsigned i=0;i<2;i++) if(h->e[i].test) {
        struct peer *p=&h->e[i].p;
        channel_test_session(h->e[i].test,p->healthy && p->phase==HS_ESTABLISHED,
                             p->traffic.id,p->traffic.max_payload,h->now);
    }
}
static void pump(struct harness *h) {
    for(unsigned cycles=0;cycles<100;cycles++) {
        bool work=false;
        for(unsigned i=0;i<2;i++) if(h->e[i].pending) {
            struct endpoint *e=&h->e[i]; uint8_t sig[64];
            assert(software_sign(e->key,e->digest,sig)); if(e->bad_sign) sig[0]^=1;
            e->pending=false; peer_signed(&e->p,e->generation,true,sig,h->now); work=true;
        }
        sync_channel_tests(h);
        for(unsigned i=0;i<2;i++) if(h->e[i].test) for(unsigned ch=0;ch<3;ch++) {
            for(unsigned j=0;j<16;j++) {
                uint8_t payload[HSP_MAX_PAYLOAD];
                ssize_t got=recv(h->e[i].proxy_fd[ch],payload,sizeof(payload),MSG_DONTWAIT);
                if(got<0) { assert(errno==EAGAIN || errno==EWOULDBLOCK); break; }
                peer_local(&h->e[i].p,ch,payload,(size_t)got); work=true;
            }
        }
        if(h->udp) for(unsigned i=0;i<2;i++) {
            while(true) {
                struct message m={.target=i};
                ssize_t n=recv(h->fd[i],m.b,sizeof(m.b),MSG_DONTWAIT);
                if(n<0) { assert(errno==EAGAIN || errno==EWOULDBLOCK); break; }
                assert(h->write-h->read<512); m.n=(size_t)n;
                h->queue[h->write++%512]=m;
            }
        }
        while(h->read<h->write) {
            struct message m=h->queue[h->read++%512];
            if(h->reverse_finish && m.b[5]==3 && h->read<h->write && h->queue[h->read%512].b[5]==4) {
                struct message f=h->queue[h->read++%512];
                peer_receive(&h->e[f.target].p,f.b,f.n,h->now); h->reverse_finish=false;
            }
            peer_receive(&h->e[m.target].p,m.b,m.n,h->now); work=true;
        }
        sync_channel_tests(h);
        for(unsigned i=0;i<2;i++) if(h->e[i].test)
            for(unsigned ch=0;ch<3;ch++) channel_test_receive(h->e[i].test,ch,h->now);
        if(!work) return;
    }
    assert(!"pump did not quiesce");
}
static void advance(struct harness *h,unsigned milliseconds) {
    for(unsigned elapsed=0;elapsed<milliseconds;elapsed+=100) {
        h->now+=100; peer_tick(&h->e[0].p,h->now); peer_tick(&h->e[1].p,h->now); pump(h);
        sync_channel_tests(h);
        for(unsigned i=0;i<2;i++) if(h->e[i].test) assert(channel_test_tick(h->e[i].test,h->now));
        pump(h);
    }
}
static void connect_peers(struct harness *h) {
    advance(h,100);
    assert(h->e[0].p.phase==HS_ESTABLISHED && h->e[1].p.phase==HS_ESTABLISHED);
    assert(!memcmp(h->e[0].p.traffic.id,h->e[1].p.traffic.id,16));
    for(unsigned i=0;i<4;i++) {
        assert(!memcmp(h->e[0].p.traffic.tx[i],h->e[1].p.traffic.rx[i],32));
        assert(memcmp(h->e[0].p.traffic.tx[i],h->e[0].p.traffic.rx[i],32));
        if(i) assert(memcmp(h->e[0].p.traffic.tx[0],h->e[0].p.traffic.tx[i],32));
    }
}
static void test_replay(void) {
    struct replay r={0}; assert(replay_allowed(&r,0)); replay_commit(&r,0);
    assert(!replay_allowed(&r,0)); replay_commit(&r,1023);
    assert(!replay_allowed(&r,0)); assert(replay_allowed(&r,1)); replay_commit(&r,1);
    assert(!replay_allowed(&r,1)); replay_commit(&r,1024); assert(!replay_allowed(&r,0));
    replay_commit(&r,UINT64_MAX); assert(replay_allowed(&r,UINT64_MAX-1023));
    assert(!replay_allowed(&r,UINT64_MAX-1024)); assert(!replay_allowed(&r,UINT64_MAX));
}
static void test_packets(void) {
    struct harness h; setup(&h); connect_peers(&h);
    struct traffic *tx=&h.e[0].p.traffic,*rx=&h.e[1].p.traffic;
    uint8_t b[HSP_MAX_PACKET],saved[HSP_MAX_PACKET],out[HSP_MAX_PAYLOAD]; size_t len,n; unsigned ch;
    n=seal_packet(tx,0,"first",5,b); assert(n==53); memcpy(saved,b,n);
    /* Every header field, payload and tag byte is integrity protected. */
    for(size_t i=0;i<n;i++) { b[i]^=1; assert(!open_packet(rx,b,n,&ch,out,&len)); b[i]^=1; }
    assert(!rx->replay[0].initialized);
    assert(open_packet(rx,b,n,&ch,out,&len)); assert(ch==0 && len==5 && !memcmp(out,"first",5));
    assert(!open_packet(rx,b,n,&ch,out,&len));
    uint8_t early[HSP_MAX_PACKET]; size_t early_n=seal_packet(tx,0,"early",5,early);
    for(unsigned i=0;i<20;i++) n=seal_packet(tx,0,"later",5,b);
    assert(open_packet(rx,b,n,&ch,out,&len)); assert(open_packet(rx,early,early_n,&ch,out,&len));
    uint8_t text[HSP_MAX_PACKET]; size_t text_n=seal_packet(tx,2,"text",4,text);
    for(unsigned i=0;i<1100;i++) n=seal_packet(tx,0,"v",1,b);
    assert(open_packet(rx,b,n,&ch,out,&len)); assert(!open_packet(rx,saved,53,&ch,out,&len));
    assert(open_packet(rx,text,text_n,&ch,out,&len)); assert(ch==2);
    n=seal_packet(tx,1,"",0,b); assert(n==48); assert(open_packet(rx,b,n,&ch,out,&len) && len==0);
    uint8_t max[HSP_MAX_PAYLOAD]; memset(max,42,sizeof(max));
    n=seal_packet(tx,1,max,sizeof(max),b); assert(n==HSP_MAX_PACKET);
    assert(open_packet(rx,b,n,&ch,out,&len) && len==sizeof(max) && !memcmp(out,max,len));
    assert(!seal_packet(tx,1,max,HSP_MAX_PAYLOAD+1,b));
    tx->seq[1]=HSP_LIMIT; assert(!seal_packet(tx,1,"a",1,b));
    cleanup(&h);
}
static void test_handshake_loss(void) {
    for(unsigned type=1;type<=5;type++) {
        struct harness h; setup(&h); h.drop_type=type; h.drop_count=1;
        advance(&h,8500);
        assert(h.e[0].p.phase==HS_ESTABLISHED && h.e[1].p.phase==HS_ESTABLISHED);
        assert(h.e[0].signatures==1 && h.e[1].signatures==1);
        peer_local(&h.e[0].p,2,(const uint8_t *)"hello",5); pump(&h);
        assert(h.e[1].delivered[2]==1 && h.e[1].last_len==5);
        cleanup(&h);
    }
    struct harness h; setup(&h); h.reverse_finish=true; advance(&h,2000);
    assert(h.e[0].p.phase==HS_ESTABLISHED && h.e[1].p.phase==HS_ESTABLISHED);
    cleanup(&h);
}
static void test_failures(void) {
    struct harness h; setup(&h); h.e[0].p.peer_pin[0]^=1; advance(&h,1000);
    assert(h.e[0].p.phase!=HS_ESTABLISHED && h.e[1].signatures==0); cleanup(&h);
    setup(&h); h.e[1].bad_sign=true; advance(&h,1000);
    assert(h.e[0].p.phase!=HS_ESTABLISHED && h.e[0].signatures==0); cleanup(&h);
    setup(&h); h.e[0].bad_sign=true; advance(&h,1000);
    assert(h.e[1].p.phase!=HS_ESTABLISHED); cleanup(&h);
    setup(&h); peer_health(&h.e[0].p,false,h.now); advance(&h,2000);
    peer_local(&h.e[0].p,0,(const uint8_t *)"blocked",7); assert(h.e[0].signatures==0 && h.e[0].p.unavailable==1);
    cleanup(&h);
    setup(&h); h.drop_type=5; h.drop_all=true; advance(&h,5000);
    assert(h.e[0].p.phase!=HS_ESTABLISHED);
    peer_local(&h.e[0].p,0,(const uint8_t *)"blocked",7); assert(!h.e[1].delivered[0]); cleanup(&h);
    setup(&h); connect_peers(&h); peer_health(&h.e[0].p,false,h.now);
    uint8_t zeros[sizeof(struct traffic)]={0}; assert(!memcmp(&h.e[0].p.traffic,zeros,sizeof(zeros)));
    peer_local(&h.e[0].p,0,(const uint8_t *)"blocked",7); assert(!h.e[1].delivered[0]);
    advance(&h,11000); assert(h.e[1].p.phase==HS_IDLE); cleanup(&h);
}
static void test_rekey(void) {
    for(unsigned who=0;who<2;who++) {
        struct harness h; setup(&h); connect_peers(&h); uint8_t old[16],packet[HSP_MAX_PACKET];
        memcpy(old,h.e[0].p.traffic.id,16);
        size_t n=seal_packet(&h.e[0].p.traffic,2,"old",3,packet);
        peer_rekey(&h.e[who].p,h.now); pump(&h); advance(&h,3000);
        assert(h.e[0].p.phase==HS_ESTABLISHED && h.e[1].p.phase==HS_ESTABLISHED);
        assert(memcmp(old,h.e[0].p.traffic.id,16));
        peer_receive(&h.e[1].p,packet,n,h.now); assert(!h.e[1].delivered[2]); cleanup(&h);
    }
}
static void test_loss_and_reorder(void) {
    struct harness h; setup(&h); connect_peers(&h);
    uint8_t packet[4][HSP_MAX_PACKET]; size_t n[4];
    for(unsigned i=0;i<4;i++) n[i]=seal_packet(&h.e[0].p.traffic,0,&i,sizeof(i),packet[i]);
    /* Packet 1 lost; 3 arrives before 0 and 2. No head-of-line wait. */
    peer_receive(&h.e[1].p,packet[3],n[3],h.now);
    peer_receive(&h.e[1].p,packet[0],n[0],h.now);
    peer_receive(&h.e[1].p,packet[2],n[2],h.now);
    peer_receive(&h.e[1].p,packet[2],n[2],h.now);
    assert(h.e[1].delivered[0]==3);
    peer_local(&h.e[0].p,1,(const uint8_t *)"audio",5);
    peer_local(&h.e[0].p,2,(const uint8_t *)"text",4); pump(&h);
    assert(h.e[1].delivered[1]==1 && h.e[1].delivered[2]==1); cleanup(&h);
}
static void test_parser_noise(void) {
    struct harness h; setup(&h); connect_peers(&h);
    uint8_t b[HSP_MAX_PACKET]; uint32_t seed=12345;
    for(unsigned i=0;i<10000;i++) {
        size_t n=i%sizeof(b);
        for(size_t j=0;j<n;j++) { seed=1664525*seed+1013904223; b[j]=(uint8_t)(seed>>24); }
        if(i%2==0 && n>=6) { memcpy(b,"HSP1",4); b[4]=1; b[5]=(uint8_t)(i%17); }
        peer_receive(&h.e[1].p,b,n,h.now);
    }
    assert(h.e[1].p.phase==HS_ESTABLISHED); cleanup(&h);
}

static void unhex(const char *s,uint8_t *out,size_t n) {
    for(size_t i=0;i<n;i++) { unsigned value; assert(sscanf(s+2*i,"%2x",&value)==1); out[i]=(uint8_t)value; }
}
static void test_derivation_vector(void) {
    /* RFC 7748 Alice private/Bob public; HKDF expected values calculated
     * independently with Python's hashlib/hmac using the documented encoding. */
    uint8_t priv[32],pub[32],h[32],finish[2][32],expected[32]; struct traffic t;
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",priv,32);
    unhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",pub,32);
    assert(hash256("hsmproxy test vector",sizeof("hsmproxy test vector")-1,h));
    EVP_PKEY *key=EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519,NULL,priv,32); assert(key);
    assert(derive_traffic(key,pub,h,true,1400,&t,finish));
    unhex("1388de5a4f4e1f46c8b54ac65a3e5308",expected,16); assert(!memcmp(t.id,expected,16));
    unhex("d04f57e3661d73b6414c6b50c0a3df190bc4b9bc0e2aebbac48bbf0c12e7a731",expected,32);
    assert(!memcmp(t.tx[0],expected,32));
    unhex("30cf83ff707928768acbe261a52b431ee4b97fe88c35e3d4b19bb0e7b8c75baf",expected,32);
    assert(!memcmp(finish[0],expected,32));
    memset(pub,0,32); assert(!derive_traffic(key,pub,h,true,1400,&t,finish));
    EVP_PKEY_free(key); OPENSSL_cleanse(priv,sizeof(priv));
}
static void test_udp_sockets(void) {
    struct harness h; setup(&h); struct sockaddr_in addresses[2];
    for(unsigned i=0;i<2;i++) {
        h.fd[i]=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0); assert(h.fd[i]>=0);
        addresses[i]=(struct sockaddr_in){.sin_family=AF_INET,.sin_addr={htonl(INADDR_LOOPBACK)}};
        assert(bind(h.fd[i],(struct sockaddr *)&addresses[i],sizeof(addresses[i]))==0);
        socklen_t len=sizeof(addresses[i]); assert(getsockname(h.fd[i],(struct sockaddr *)&addresses[i],&len)==0);
    }
    for(unsigned i=0;i<2;i++) assert(connect(h.fd[i],(struct sockaddr *)&addresses[1-i],sizeof(addresses[0]))==0);
    h.udp=true; h.drop_type=4; h.drop_count=1; advance(&h,2000);
    assert(h.e[0].p.phase==HS_ESTABLISHED && h.e[1].p.phase==HS_ESTABLISHED);
    for(unsigned i=0;i<3;i++) { peer_local(&h.e[0].p,i,(const uint8_t *)"udp",3); pump(&h); assert(h.e[1].delivered[i]==1); }
    cleanup(&h);
    /* Reproduce gtk-pipe's connected text socket and source-port filtering. */
    int proxy=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0),app=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0);
    int wrong=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC,0); assert(proxy>=0 && app>=0 && wrong>=0);
    struct sockaddr_in pa={.sin_family=AF_INET},aa={.sin_family=AF_INET};
    assert(inet_pton(AF_INET,"127.0.0.2",&pa.sin_addr)==1);
    assert(inet_pton(AF_INET,"127.0.0.1",&aa.sin_addr)==1);
    assert(bind(proxy,(struct sockaddr *)&pa,sizeof(pa))==0);
    socklen_t len=sizeof(pa); assert(getsockname(proxy,(struct sockaddr *)&pa,&len)==0);
    aa.sin_port=pa.sin_port; assert(bind(app,(struct sockaddr *)&aa,sizeof(aa))==0);
    assert(connect(app,(struct sockaddr *)&pa,sizeof(pa))==0);
    assert(send(app,"PING",4,0)==4); uint8_t b[32];
    assert(recv(proxy,b,sizeof(b),MSG_DONTWAIT)==4);
    assert(sendto(wrong,"bad",3,0,(struct sockaddr *)&aa,sizeof(aa))==3);
    assert(recv(app,b,sizeof(b),MSG_DONTWAIT)==-1 && (errno==EAGAIN || errno==EWOULDBLOCK));
    assert(sendto(proxy,"PONG",4,0,(struct sockaddr *)&aa,sizeof(aa))==4);
    assert(recv(app,b,sizeof(b),MSG_DONTWAIT)==4 && !memcmp(b,"PONG",4));
    close(proxy); close(app); close(wrong);
}


static void attach_channel_tests(struct harness *h,struct channel_test tests[2]) {
    for(unsigned i=0;i<2;i++) {
        struct config config={0}; strcpy(config.role,i==0?"initiator":"responder");
        for(unsigned ch=0;ch<3;ch++) {
            int fd=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0); assert(fd>=0);
            struct sockaddr_in address={.sin_family=AF_INET};
            assert(inet_pton(AF_INET,"127.0.0.2",&address.sin_addr)==1);
            assert(bind(fd,(struct sockaddr *)&address,sizeof(address))==0);
            socklen_t len=sizeof(address); assert(getsockname(fd,(struct sockaddr *)&address,&len)==0);
            h->e[i].proxy_fd[ch]=fd; config.local[ch]=address;
            assert(inet_pton(AF_INET,"127.0.0.1",&address.sin_addr)==1);
            config.delivery[ch]=address; h->e[i].target[ch]=address;
        }
        assert(channel_test_open(&tests[i],&config,NULL)); h->e[i].test=&tests[i];
        struct channel_test collision;
        assert(!channel_test_open(&collision,&config,NULL)); /* gtk-pipe/second tester owns target */
    }
}
static void test_channel_diagnostics(void) {
    struct harness h; struct channel_test tests[2];
    setup(&h); attach_channel_tests(&h,tests); connect_peers(&h); advance(&h,4000);
    assert(channel_test_passed(&tests[0]) && channel_test_passed(&tests[1]));
    uint8_t old_session[16]; memcpy(old_session,tests[0].session,16);
    peer_rekey(&h.e[0].p,h.now); pump(&h);
    assert(!channel_test_passed(&tests[0]) && !channel_test_passed(&tests[1]));
    advance(&h,6000); assert(channel_test_passed(&tests[0]) && channel_test_passed(&tests[1]));
    assert(memcmp(old_session,tests[0].session,16));
    peer_health(&h.e[0].p,false,h.now); sync_channel_tests(&h);
    uint64_t sent=tests[0].channels[0].sent;
    assert(channel_test_tick(&tests[0],h.now+10000));
    assert(tests[0].channels[0].sent==sent && !channel_test_passed(&tests[0])); cleanup(&h);

    setup(&h); attach_channel_tests(&h,tests); h.drop_channels=2; connect_peers(&h); advance(&h,6500);
    for(unsigned i=0;i<2;i++) {
        assert(!channel_test_passed(&tests[i]));
        assert(tests[i].channels[0].echoed>=3 && tests[i].channels[2].echoed>=3);
        assert(!tests[i].channels[1].echoed && tests[i].channels[1].timed_out);
    }
    h.drop_channels=0; advance(&h,4000);
    assert(channel_test_passed(&tests[0]) && channel_test_passed(&tests[1])); cleanup(&h);

    setup(&h); attach_channel_tests(&h,tests); connect_peers(&h);
    /* Stop network forwarding so a fresh challenge remains pending. */
    h.drop_channels=7; advance(&h,1000);
    struct channel_probe *p=&tests[0].channels[0].probes[1]; assert(p->pending);
    uint8_t reply[HSP_MAX_PAYLOAD]; memcpy(reply,p->reply,p->length); reply[p->length-1]^=1;
    assert(sendto(h.e[0].proxy_fd[0],reply,p->length,0,(struct sockaddr *)&h.e[0].target[0],sizeof(h.e[0].target[0]))==(ssize_t)p->length);
    channel_test_receive(&tests[0],0,h.now);
    assert(tests[0].channels[0].invalid==1 && !channel_test_passed(&tests[0]));
    memcpy(reply,p->reply,p->length); reply[12]^=1;
    assert(sendto(h.e[0].proxy_fd[0],reply,p->length,0,(struct sockaddr *)&h.e[0].target[0],sizeof(h.e[0].target[0]))==(ssize_t)p->length);
    channel_test_receive(&tests[0],0,h.now); assert(tests[0].channels[0].stale==1);
    h.drop_channels=0; advance(&h,4000);
    assert(!channel_test_passed(&tests[0])); /* Content errors remain visible until a fresh session. */
    cleanup(&h);

    setup(&h); attach_channel_tests(&h,tests); connect_peers(&h);
    h.drop_channels=7; advance(&h,2000);
    /* Outstanding echoes can arrive in either order, but count only once. */
    for(unsigned i=0;i<3;i++) {
        unsigned seq=i==1?1:2;
        struct channel_probe *probe=&tests[0].channels[0].probes[seq];
        assert(sendto(h.e[0].proxy_fd[0],probe->reply,probe->length,0,
                      (struct sockaddr *)&h.e[0].target[0],sizeof(h.e[0].target[0]))==(ssize_t)probe->length);
        channel_test_receive(&tests[0],0,h.now);
    }
    assert(tests[0].channels[0].echoed==3 && tests[0].channels[0].stale==1);
    assert(!channel_test_passed(&tests[0])); /* A single working channel is insufficient. */
    cleanup(&h);
}

int main(void) {
    test_channel_diagnostics();
    test_derivation_vector(); test_udp_sockets();
    test_replay(); test_packets(); test_handshake_loss(); test_failures();
    test_rekey(); test_loss_and_reorder(); test_parser_noise();
    puts("core: replay, AEAD, mutual authentication, loss/reorder, rekey, health and parser tests passed");
    return 0;
}
