#include "channel_test.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <openssl/rand.h>

static const char *names[]={"video","audio","text"};
static const uint8_t magic[8]={'H','S','P','T','E','S','T','1'};
#define PROBE_TIMEOUT 5000u

bool channel_test_open(struct channel_test *t,const struct config *c,FILE *log) {
    memset(t,0,sizeof(*t));
    for(unsigned ch=0;ch<3;ch++) t->fd[ch]=-1;
    t->log=log; t->initiator=!strcmp(c->role,"initiator");
    for(unsigned ch=0;ch<3;ch++) {
        t->fd[ch]=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
        if(t->fd[ch]<0 || bind(t->fd[ch],(const struct sockaddr *)&c->delivery[ch],sizeof(c->delivery[ch])) ||
           connect(t->fd[ch],(const struct sockaddr *)&c->local[ch],sizeof(c->local[ch]))) {
            int saved=errno; channel_test_close(t); errno=saved; return false;
        }
    }
    if(log) fprintf(log,"hsmproxy: CHANNEL TEST waiting for HSM-authenticated session; keep gtk-pipe stopped\n");
    return true;
}
void channel_test_close(struct channel_test *t) {
    for(unsigned ch=0;ch<3;ch++) { if(t->fd[ch]>=0) close(t->fd[ch]); t->fd[ch]=-1; }
    t->active=false;
}
void channel_test_session(struct channel_test *t,bool active,const uint8_t *id,uint16_t max,uint64_t now) {
    if(!active) {
        if(t->active && t->log) fprintf(t->log,"hsmproxy: CHANNEL TEST paused: session unavailable\n");
        t->active=false; t->announced=false; return;
    }
    if(t->active && !memcmp(id,t->session,16)) return;
    memset(t->channels,0,sizeof(t->channels)); memcpy(t->session,id,16);
    t->max_payload=max; t->active=true; t->announced=false; t->sequence=0; t->next_send=now;
    if(t->log) fprintf(t->log,"hsmproxy: CHANNEL TEST started: authenticated key exchange complete; testing 64/%u/%u-byte datagrams\n",
                      max<256?max:256,max);
}
static bool send_probe(struct channel_test *t,unsigned ch,const uint8_t *b,size_t n) {
    if(send(t->fd[ch],b,n,MSG_DONTWAIT)==(ssize_t)n) return true;
    t->channels[ch].send_errors++; return false;
}
bool channel_test_passed(const struct channel_test *t) {
    if(!t->active) return false;
    for(unsigned ch=0;ch<3;ch++) {
        const struct channel_results *r=&t->channels[ch];
        if(r->echoed<3 || r->requests<3 || r->sizes!=7 || r->invalid) return false;
    }
    return true;
}
static void announce(struct channel_test *t) {
    if(!t->announced && channel_test_passed(t)) {
        t->announced=true; t->completed=true;
        if(t->log) fprintf(t->log,"hsmproxy: CHANNEL TEST PASS: video, audio and text verified in both directions; continuing until Ctrl-C\n");
    }
}
bool channel_test_tick(struct channel_test *t,uint64_t now) {
    if(!t->active) return true;
    for(unsigned ch=0;ch<3;ch++) for(unsigned i=0;i<CHANNEL_TEST_PENDING;i++) {
        struct channel_probe *p=&t->channels[ch].probes[i];
        if(p->pending && now-p->sent_at>=PROBE_TIMEOUT) {
            p->pending=false; t->channels[ch].timed_out++;
        }
    }
    if(now<t->next_send) return true;
    t->next_send=now+1000;
    if(t->sequence==UINT64_MAX || t->max_payload<64 || t->max_payload>HSP_MAX_PAYLOAD) return false;
    uint64_t seq=t->sequence++;
    size_t size=seq%3==0?64:seq%3==1?(t->max_payload<256?t->max_payload:256):t->max_payload;
    for(unsigned ch=0;ch<3;ch++) {
        struct channel_probe *p=&t->channels[ch].probes[seq%CHANNEL_TEST_PENDING];
        if(p->pending) { t->channels[ch].timed_out++; p->pending=false; }
        uint8_t *b=p->reply; memcpy(b,magic,8); b[8]=1; b[9]=(uint8_t)ch;
        b[10]=t->initiator?0:1; b[11]=0; memcpy(b+12,t->session,16); put64(b+28,seq);
        if(RAND_bytes(b+36,16)!=1) return false;
        for(size_t j=52;j<size;j++) b[j]=(uint8_t)(b[36+j%16]^(uint8_t)(j*31));
        p->sequence=seq; p->length=size; p->sent_at=now;
        p->pending=send_probe(t,ch,b,size);
        if(p->pending) t->channels[ch].sent++;
        b[8]=2; /* Store the exact expected response, including all payload bytes. */
    }
    return true;
}
static void invalid(struct channel_test *t,unsigned ch) {
    t->failed=true;
    if(t->channels[ch].invalid++==0 && t->log)
        fprintf(t->log,"hsmproxy: CHANNEL TEST ERROR: invalid %s test payload; this session cannot pass\n",names[ch]);
}
void channel_test_receive(struct channel_test *t,unsigned ch,uint64_t now) {
    if(ch>2) return;
    for(unsigned count=0;count<16;count++) {
        uint8_t b[HSP_MAX_PAYLOAD]; struct iovec iov={b,sizeof(b)};
        struct msghdr msg={.msg_iov=&iov,.msg_iovlen=1};
        ssize_t got=recvmsg(t->fd[ch],&msg,MSG_DONTWAIT);
        if(got<0) {
            if(errno==EINTR) continue;
            if(errno!=EAGAIN && errno!=EWOULDBLOCK) t->channels[ch].send_errors++;
            return;
        }
        if(!t->active) continue;
        size_t n=(size_t)got;
        if((msg.msg_flags&MSG_TRUNC) || n<64 || n>t->max_payload || memcmp(b,magic,8) ||
           (b[8]!=1 && b[8]!=2) || b[9]!=ch || b[10]>1 || b[11]) { invalid(t,ch); continue; }
        if(memcmp(b+12,t->session,16)) { t->channels[ch].stale++; continue; }
        uint64_t seq=get64(b+28); unsigned role=t->initiator?0:1;
        if(b[8]==1) {
            if(b[10]==role) { invalid(t,ch); continue; }
            bool valid=true;
            for(size_t j=52;j<n;j++) if(b[j]!=(uint8_t)(b[36+j%16]^(uint8_t)(j*31))) valid=false;
            if(!valid) { invalid(t,ch); continue; }
            if(!replay_allowed(&t->channels[ch].requests_seen,seq)) { t->channels[ch].stale++; continue; }
            replay_commit(&t->channels[ch].requests_seen,seq); t->channels[ch].requests++;
            b[8]=2; (void)send_probe(t,ch,b,n);
        } else {
            if(b[10]!=role) { invalid(t,ch); continue; }
            struct channel_probe *p=&t->channels[ch].probes[seq%CHANNEL_TEST_PENDING];
            if(!p->pending || p->sequence!=seq) { t->channels[ch].stale++; continue; }
            if(now-p->sent_at>=PROBE_TIMEOUT) {
                p->pending=false; t->channels[ch].timed_out++; continue;
            }
            if(n!=p->length || memcmp(b,p->reply,n)) { invalid(t,ch); continue; }
            p->pending=false; t->channels[ch].echoed++;
            t->channels[ch].sizes|=1u<<(seq%3); t->channels[ch].rtt_ms=now-p->sent_at;
        }
        announce(t);
    }
}
void channel_test_report(const struct channel_test *t) {
    if(!t->log) return;
    for(unsigned ch=0;ch<3;ch++) {
        const struct channel_results *r=&t->channels[ch];
        const char *status=!t->active?"WAITING":r->invalid?"ERROR":
            r->echoed>=3 && r->requests>=3 && r->sizes==7?"PASS":"PENDING";
        fprintf(t->log,"hsmproxy: CHANNEL TEST %s %s sent=%llu echoed=%llu peer_probes=%llu "
                "timeouts=%llu send_errors=%llu invalid=%llu stale=%llu last_rtt_ms=%llu\n",
                names[ch],status,(unsigned long long)r->sent,(unsigned long long)r->echoed,
                (unsigned long long)r->requests,(unsigned long long)r->timed_out,
                (unsigned long long)r->send_errors,(unsigned long long)r->invalid,
                (unsigned long long)r->stale,(unsigned long long)r->rtt_ms);
    }
}
