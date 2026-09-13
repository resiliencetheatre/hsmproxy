#include "supervisor.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(void) {
    int pair[2]; struct supervisor s;
    assert(socketpair(AF_UNIX,SOCK_SEQPACKET,0,pair)==0);
    assert(supervisor_init(&s,pair[0],100));
    assert(supervisor_healthy(&s,4099));
    assert(!supervisor_healthy(&s,4100));
    assert(send(pair[1],"PING",4,0)==4);
    assert(supervisor_poll(&s,4100));
    assert(send(pair[1],"REKEY",5,0)==5);
    assert(supervisor_poll(&s,4101) && s.rekey);
    struct config c={.ports={5000,5002,5004},.max_payload=1100};
    struct peer p={.generation=8,.traffic={.max_payload=1000},.tx={1,2,3}};
    supervisor_status(&s,&c,&p,UI_ESTABLISHED,UI_OK,4200,true,9);
    char b[512]={0}; ssize_t n=recv(pair[1],b,sizeof(b)-1,0);
    assert(n>0 && !strcmp(b,"HSPUI1 5 0 5000 5002 5004 1000 8 1 2 3 0 0 0 0 0 9"));
    /* Backpressure must not block the event loop. */
    for(unsigned i=0;i<10000;i++) supervisor_status(&s,&c,&p,UI_WAIT_PEER,UI_OK,4201+i,true,0);
    assert(!s.stop);
    assert(send(pair[1],"PIN secret",10,0)==10);
    assert(!supervisor_poll(&s,4300));
    close(pair[0]); close(pair[1]);
    assert(socketpair(AF_UNIX,SOCK_SEQPACKET,0,pair)==0);
    assert(supervisor_init(&s,pair[0],100)); close(pair[1]);
    assert(!supervisor_healthy(&s,101)); close(pair[0]);
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,pair)==0);
    assert(!supervisor_init(&s,pair[0],100)); close(pair[0]); close(pair[1]);
    assert(supervisor_init(&s,-1,100)); assert(supervisor_healthy(&s,999999));
    puts("supervisor: versioned snapshots, timeout, EOF, commands, socket type and backpressure passed");
}
