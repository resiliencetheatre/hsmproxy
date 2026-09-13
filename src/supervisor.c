#include "supervisor.h"
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

bool supervisor_init(struct supervisor *s,int fd,uint64_t now) {
    *s=(struct supervisor){.fd=fd,.locks={-1,-1,-1},.seen=now};
    if(fd<0) return true;
    int type=0; socklen_t n=sizeof(type);
    struct sockaddr_un addr; socklen_t len=sizeof(addr);
    return getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&n)==0 && type==SOCK_SEQPACKET &&
           getsockname(fd,(struct sockaddr *)&addr,&len)==0 && addr.sun_family==AF_UNIX &&
           getpeername(fd,(struct sockaddr *)&addr,&len)==0;
}
/* Abstract Unix sockets reserve managed ports before any PIN is requested.
 * No receiver or command listener is installed; kernel lifetime is the lock. */
bool supervisor_claim(struct supervisor *s,const struct config *c) {
    if(s->fd<0) return true;
    for(unsigned i=0;i<3;i++) {
        struct sockaddr_un addr={.sun_family=AF_UNIX};
        int n=snprintf(addr.sun_path+1,sizeof(addr.sun_path)-1,"hsmproxy-ui-%lu-%u",
                       (unsigned long)getuid(),c->ports[i]);
        s->locks[i]=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
        if(s->locks[i]<0 || bind(s->locks[i],(struct sockaddr *)&addr,
           (socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+n))) {
            for(unsigned j=0;j<=i;j++) if(s->locks[j]>=0) { close(s->locks[j]); s->locks[j]=-1; }
            return false;
        }
    }
    return true;
}
bool supervisor_healthy(const struct supervisor *s,uint64_t now) {
    if(s->fd<0) return true;
    struct pollfd p={.fd=s->fd,.events=POLLIN};
    return !s->stop && now-s->seen<4000 && poll(&p,1,0)>=0 &&
           !(p.revents&(POLLHUP|POLLERR|POLLNVAL));
}
bool supervisor_poll(struct supervisor *s,uint64_t now) {
    if(s->fd<0) return true;
    for(unsigned i=0;i<16;i++) {
        char b[16]; ssize_t n=recv(s->fd,b,sizeof(b),MSG_DONTWAIT|MSG_TRUNC);
        if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break;
        if(n<0 && errno==EINTR) continue;
        if(n==4 && !memcmp(b,"PING",4)) s->seen=now;
        else if(n==5 && !memcmp(b,"REKEY",5)) s->rekey=true;
        else { s->stop=true; break; } /* STOP, EOF, malformed or failed IPC */
    }
    return supervisor_healthy(s,now);
}
void supervisor_status(struct supervisor *s,const struct config *c,const struct peer *p,
                       enum ui_state state,enum ui_reason reason,uint64_t now,bool force,uint64_t mtu) {
    if(s->fd<0 || (!force && now-s->sent<500)) return;
    char b[512];
    int n=snprintf(b,sizeof(b),"HSPUI1 %u %u %u %u %u %u %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu",
        (unsigned)state,(unsigned)reason,c->ports[0],c->ports[1],c->ports[2],
        state==UI_ESTABLISHED?p->traffic.max_payload:c->max_payload,
        (unsigned long long)p->generation,
        (unsigned long long)p->tx[0],(unsigned long long)p->tx[1],(unsigned long long)p->tx[2],
        (unsigned long long)p->rx[0],(unsigned long long)p->rx[1],(unsigned long long)p->rx[2],
        (unsigned long long)p->rejected,(unsigned long long)p->oversize,(unsigned long long)mtu);
    if(n>0 && (size_t)n<sizeof(b)) {
        ssize_t sent=send(s->fd,b,(size_t)n,MSG_DONTWAIT|MSG_NOSIGNAL);
        if(sent<0 && errno!=EAGAIN && errno!=EWOULDBLOCK && errno!=EINTR) s->stop=true;
    }
    s->sent=now;
}
