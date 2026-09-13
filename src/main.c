#include "core.h"
#include "config.h"
#include "hsm.h"
#include "channel_test.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/timerfd.h>
#include <termios.h>
#include <unistd.h>

struct app {
    struct config config;
    struct hsm hsm;
    struct peer peer;
    int tunnel, local[3];
    bool test_channels;
    struct channel_test test;
    uint64_t send_drops, local_drops, source_drops, truncations, mtu_drops;
};
static void log_event(void *arg,const char *message) { (void)arg; fprintf(stderr,"hsmproxy: %s\n",message); }
static bool health(struct app *a) {
    uint64_t now=monotonic_ms(); bool ok=hsm_healthy(&a->hsm,now);
    peer_health(&a->peer,ok,now);
    if(a->test_channels) channel_test_session(&a->test,ok && a->peer.phase==HS_ESTABLISHED,
                                             a->peer.traffic.id,a->peer.traffic.max_payload,now);
    return ok;
}
static void net_send(void *arg,const uint8_t *b,size_t n) {
    struct app *a=arg;
    /* The core gates state; this final gate also covers a removal event that
     * happened during encryption. Never call into the core from this callback. */
    if(!hsm_healthy(&a->hsm,monotonic_ms())) { a->send_drops++; return; }
    if(send(a->tunnel,b,n,MSG_DONTWAIT)!=(ssize_t)n) {
        a->send_drops++; if(errno==EMSGSIZE) a->mtu_drops++;
    }
}
static bool sign_request(void *arg,uint64_t generation,const uint8_t digest[32]) {
    struct app *a=arg; return hsm_submit(&a->hsm,generation,digest);
}
static void local_deliver(void *arg,unsigned ch,const uint8_t *b,size_t n) {
    struct app *a=arg;
    if(!hsm_healthy(&a->hsm,monotonic_ms()) ||
       sendto(a->local[ch],b,n,MSG_DONTWAIT,(struct sockaddr *)&a->config.delivery[ch],
              sizeof(a->config.delivery[ch]))!=(ssize_t)n) a->local_drops++;
}
static int udp_bind(const struct sockaddr_in *addr) {
    int fd=socket(AF_INET,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if(fd<0) return -1;
    if(bind(fd,(const struct sockaddr *)addr,sizeof(*addr))) { close(fd); return -1; }
    return fd;
}
static bool watch(int ep,int fd,uint32_t id) {
    struct epoll_event event={.events=EPOLLIN,.data.u32=id};
    return epoll_ctl(ep,EPOLL_CTL_ADD,fd,&event)==0;
}
static void read_datagrams(struct app *a,unsigned which) {
    int fd=which<3?a->local[which]:a->tunnel;
    for(unsigned count=0;count<16;count++) {
        uint8_t b[HSP_MAX_PACKET]; struct sockaddr_in from={0};
        struct iovec iov={b,sizeof(b)};
        struct msghdr msg={.msg_name=&from,.msg_namelen=sizeof(from),.msg_iov=&iov,.msg_iovlen=1};
        ssize_t n=recvmsg(fd,&msg,MSG_DONTWAIT);
        if(n<0) { if(errno==EINTR) continue; return; }
        if(msg.msg_flags&MSG_TRUNC) { a->truncations++; continue; }
        if(!health(a)) continue;
        if(which<3) {
            if(from.sin_family!=AF_INET || from.sin_addr.s_addr!=a->config.delivery[which].sin_addr.s_addr ||
               (which==2 && from.sin_port!=a->config.delivery[2].sin_port)) { a->source_drops++; continue; }
            peer_local(&a->peer,which,b,(size_t)n);
        } else peer_receive(&a->peer,b,(size_t)n,monotonic_ms());
        OPENSSL_cleanse(b,sizeof(b));
    }
}
static bool read_pin(int supplied,uint8_t pin[128],size_t *length) {
    int fd=supplied; bool terminal=false; struct termios old;
    if(fd<0) { fd=open("/dev/tty",O_RDWR|O_CLOEXEC); if(fd<0) return false; }
    if(isatty(fd)) {
        if(tcgetattr(fd,&old)) goto bad;
        struct termios hidden=old; hidden.c_lflag &= (tcflag_t)~ECHO;
        if(tcsetattr(fd,TCSAFLUSH,&hidden)) goto bad;
        terminal=true; (void)write(fd,"SmartCard-HSM PIN: ",18);
    }
    size_t n=0; bool ok=false;
    while(n<127) {
        sigset_t pending;
        if(sigpending(&pending) || sigismember(&pending,SIGINT) || sigismember(&pending,SIGTERM)) break;
        struct pollfd input={.fd=fd,.events=POLLIN};
        int ready=poll(&input,1,100);
        if(ready<0 && errno==EINTR) continue;
        if(ready<0 || (ready>0 && (input.revents&POLLNVAL))) break;
        if(!ready) continue;
        uint8_t c; ssize_t got=read(fd,&c,1);
        if(got<0) { if(errno==EINTR) continue; break; }
        if(!got || c=='\n') { ok=n>0; break; }
        if(c==0 || c=='\r') break;
        pin[n++]=c;
    }
    if(terminal) { (void)tcsetattr(fd,TCSAFLUSH,&old); (void)write(fd,"\n",1); }
    if(supplied<0) close(fd);
    *length=n; return ok;
bad:
    if(supplied<0) close(fd);
    return false;
}
static void usage(void) {
    puts("Usage: hsmproxy --config FILE [--pin-fd FD] [--test-channels]\n"
         "       hsmproxy --check-config FILE\n"
         "       hsmproxy --fingerprint PUBLIC_KEY_OR_CERTIFICATE\n"
         "--test-channels: replace gtk-pipe with local UDP probes on all three channels.\n"
         "Run on both hosts with provisioned cards and peer pins; Ctrl-C after both report PASS.\n"
         "SIGUSR1: rekey; SIGINT/SIGTERM: close. No plaintext or software-key mode.");
}
static void stats(const struct app *a) {
    fprintf(stderr,"hsmproxy: tx=%llu/%llu/%llu rx=%llu/%llu/%llu rejected=%llu unavailable=%llu "
        "oversize=%llu truncation=%llu send_drops=%llu delivery_drops=%llu source_drops=%llu mtu_drops=%llu\n",
        (unsigned long long)a->peer.tx[0],(unsigned long long)a->peer.tx[1],(unsigned long long)a->peer.tx[2],
        (unsigned long long)a->peer.rx[0],(unsigned long long)a->peer.rx[1],(unsigned long long)a->peer.rx[2],
        (unsigned long long)a->peer.rejected,(unsigned long long)a->peer.unavailable,
        (unsigned long long)a->peer.oversize,(unsigned long long)a->truncations,
        (unsigned long long)a->send_drops,(unsigned long long)a->local_drops,
        (unsigned long long)a->source_drops,(unsigned long long)a->mtu_drops);
}
int main(int argc,char **argv) {
    const char *path=NULL,*fingerprint=NULL; int pin_fd=-1; bool check=false,test_channels=false;
    for(int i=1;i<argc;i++) {
        if(!strcmp(argv[i],"--help")) { usage(); return 0; }
        if(!strcmp(argv[i],"--config") && i+1<argc && !path) path=argv[++i];
        else if(!strcmp(argv[i],"--check-config") && i+1<argc && !path) { path=argv[++i]; check=true; }
        else if(!strcmp(argv[i],"--fingerprint") && i+1<argc && !fingerprint) fingerprint=argv[++i];
        else if(!strcmp(argv[i],"--test-channels") && !test_channels) test_channels=true;
        else if(!strcmp(argv[i],"--pin-fd") && i+1<argc && pin_fd<0) {
            char *end; errno=0; long n=strtol(argv[++i],&end,10);
            if(errno || !*argv[i] || *end || n<0 || n>1048576) { usage(); return 2; } pin_fd=(int)n;
        } else { usage(); return 2; }
    }
    if(fingerprint && !path && pin_fd<0 && !test_channels) {
        EVP_PKEY *key=load_public(fingerprint); uint8_t pin[32];
        bool ok=key && public_pin(key,pin); EVP_PKEY_free(key);
        if(!ok) { fputs("Cannot read a P-256 public key/certificate\n",stderr); return 1; }
        for(unsigned i=0;i<32;i++) printf("%02x",pin[i]);
        puts(""); return 0;
    }
    if(!path || fingerprint || (check && (pin_fd>=0 || test_channels))) { usage(); return 2; }
    struct app a={.tunnel=-1,.local={-1,-1,-1},.test_channels=test_channels,.test={.fd={-1,-1,-1}}}; char error[512];
    if(!config_load(path,&a.config,error,sizeof(error))) { fprintf(stderr,"%s\n",error); return 2; }
    EVP_PKEY *local=load_public(a.config.certificate), *remote=load_public(a.config.public_key);
    uint8_t expected[32],actual[32]; size_t len=32;
    if(!local || !remote || !parse_hex(a.config.pin_hex,expected,&len) || !public_pin(remote,actual) ||
       CRYPTO_memcmp(expected,actual,32)) {
        fputs("Invalid local/peer public key or peer SPKI pin mismatch\n",stderr);
        EVP_PKEY_free(local); EVP_PKEY_free(remote); return 2;
    }
    struct peer_io io={net_send,sign_request,local_deliver,log_event,&a};
    if(!peer_init(&a.peer,!strcmp(a.config.role,"initiator"),a.config.max_payload,local,remote,io)) {
        EVP_PKEY_free(local); EVP_PKEY_free(remote); return 2;
    }
    EVP_PKEY_free(remote);
    if(check) { puts("Configuration and public-key pins valid (hardware not checked)"); peer_destroy(&a.peer); EVP_PKEY_free(local); return 0; }
    struct rlimit no_core={0,0};
    if(setrlimit(RLIMIT_CORE,&no_core) || prctl(PR_SET_DUMPABLE,0)) { perror("disable core dumps"); peer_destroy(&a.peer); EVP_PKEY_free(local); return 1; }
    sigset_t mask; sigemptyset(&mask); sigaddset(&mask,SIGINT); sigaddset(&mask,SIGTERM); sigaddset(&mask,SIGUSR1);
    /* The PIN reader polls pending stop signals and restores terminal echo. */
    if(pthread_sigmask(SIG_BLOCK,&mask,NULL)) { peer_destroy(&a.peer); EVP_PKEY_free(local); return 1; }
    uint8_t pin[128]={0}; size_t pin_len=0;
    bool got_pin=read_pin(pin_fd,pin,&pin_len);
    bool opened=got_pin && hsm_open(&a.hsm,&a.config,local,pin,pin_len,error,sizeof(error));
    OPENSSL_cleanse(pin,sizeof(pin)); EVP_PKEY_free(local);
    if(!opened) {
        fprintf(stderr,"hsmproxy: %s\n",got_pin?error:"cannot read PIN; use a terminal or protected --pin-fd");
        peer_destroy(&a.peer); return 1;
    }
    int ep=-1,timer=-1,signals=-1,result=1;
    for(unsigned i=0;i<3;i++) if((a.local[i]=udp_bind(&a.config.local[i]))<0) { perror("local bind"); goto end; }
    if(a.test_channels && !channel_test_open(&a.test,&a.config,stderr)) {
        perror("channel test local bind/connect (stop gtk-pipe and other local listeners)"); goto end;
    }
    a.tunnel=udp_bind(&a.config.tunnel_bind); if(a.tunnel<0) { perror("tunnel bind"); goto end; }
    int pmtu=IP_PMTUDISC_DO;
    if(setsockopt(a.tunnel,IPPROTO_IP,IP_MTU_DISCOVER,&pmtu,sizeof(pmtu)) ||
       connect(a.tunnel,(struct sockaddr *)&a.config.tunnel_peer,sizeof(a.config.tunnel_peer))) { perror("tunnel setup"); goto end; }
    ep=epoll_create1(EPOLL_CLOEXEC); timer=timerfd_create(CLOCK_MONOTONIC,TFD_CLOEXEC|TFD_NONBLOCK);
    signals=signalfd(-1,&mask,SFD_CLOEXEC|SFD_NONBLOCK);
    if(ep<0 || timer<0 || signals<0) { perror("event loop"); goto end; }
    struct itimerspec interval={.it_interval={0,100000000},.it_value={0,100000000}};
    if(timerfd_settime(timer,0,&interval,NULL)) goto end;
    for(unsigned i=0;i<3;i++) if(!watch(ep,a.local[i],i)) goto end;
    if(a.test_channels) for(unsigned i=0;i<3;i++) if(!watch(ep,a.test.fd[i],7+i)) goto end;
    if(!watch(ep,a.tunnel,3) || !watch(ep,timer,4) || !watch(ep,signals,5) || !watch(ep,a.hsm.event_fd,6)) goto end;
    if(!hsm_start(&a.hsm,error,sizeof(error))) { fprintf(stderr,"%s\n",error); goto end; }
    log_event(NULL,"HSM LOGIN SUCCESS; LOCAL IDENTITY VERIFIED");
    uint64_t status_at=monotonic_ms()+10000,monitor_deadline=monotonic_ms()+1000;
    bool running=true;
    while(running) {
        struct epoll_event events[10]; int n=epoll_wait(ep,events,10,100);
        if(n<0) { if(errno==EINTR) continue; perror("epoll_wait"); break; }
        uint64_t now=monotonic_ms(); bool healthy=health(&a);
        if(!healthy && (atomic_load(&a.hsm.failed) || now>=monitor_deadline)) {
            char detail[256]; hsm_failure_message(&a.hsm,detail,sizeof(detail),monotonic_ms());
            fprintf(stderr,"hsmproxy: HSM/PCSC HEALTH LOST: %s; restart with a fresh PIN after recovery\n",detail); break;
        }
        for(int i=0;i<n;i++) {
            unsigned id=events[i].data.u32;
            if(id<4) read_datagrams(&a,id);
            else if(id>=7 && id<=9 && a.test_channels) {
                (void)health(&a); channel_test_receive(&a.test,id-7,monotonic_ms());
            }
            else if(id==4) { uint64_t ticks; (void)read(timer,&ticks,sizeof(ticks)); }
            else if(id==5) {
                struct signalfd_siginfo si;
                while(read(signals,&si,sizeof(si))==(ssize_t)sizeof(si)) {
                    if(si.ssi_signo==SIGUSR1) peer_rekey(&a.peer,monotonic_ms());
                    else { running=false; result=0; }
                }
            } else if(id==6) {
                uint64_t count; (void)read(a.hsm.event_fd,&count,sizeof(count));
                uint64_t generation; bool ok; uint8_t sig[64];
                if(hsm_result(&a.hsm,&generation,&ok,sig)) {
                    (void)health(&a); peer_signed(&a.peer,generation,ok,sig,monotonic_ms());
                    OPENSSL_cleanse(sig,sizeof(sig));
                }
            }
        }
        (void)health(&a); peer_tick(&a.peer,monotonic_ms());
        if(a.test_channels) {
            (void)health(&a);
            if(!channel_test_tick(&a.test,monotonic_ms())) { log_event(NULL,"CHANNEL TEST generation failed"); result=1; break; }
        }
        if(now>=status_at) {
            stats(&a); if(a.test_channels) channel_test_report(&a.test); status_at=now+10000;
        }
    }
    if(a.test_channels) {
        channel_test_report(&a.test);
        if(!a.test.completed || a.test.failed) result=1;
    }
    peer_close(&a.peer,monotonic_ms()); stats(&a);
end:
    /* Erase session state before waiting for potentially slow middleware. */
    peer_destroy(&a.peer);
    if(a.test_channels) channel_test_close(&a.test);
    for(unsigned i=0;i<3;i++) if(a.local[i]>=0) close(a.local[i]);
    if(a.tunnel>=0) close(a.tunnel);
    if(ep>=0) close(ep);
    if(timer>=0) close(timer);
    if(signals>=0) close(signals);
    hsm_close(&a.hsm); return result;
}
