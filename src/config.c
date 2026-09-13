#include "config.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int digit(char c) {
    if(c>='0' && c<='9') return c-'0';
    if(c>='a' && c<='f') return c-'a'+10;
    if(c>='A' && c<='F') return c-'A'+10;
    return -1;
}
bool parse_hex(const char *s,uint8_t *out,size_t *n) {
    size_t len=strlen(s); if(!len || len%2 || len/2>*n) return false;
    for(size_t i=0;i<len/2;i++) {
        int a=digit(s[2*i]), b=digit(s[2*i+1]); if(a<0 || b<0) return false;
        out[i]=(uint8_t)((a<<4)|b);
    }
    *n=len/2; return true;
}
static char *trim(char *s) {
    while(isspace((unsigned char)*s)) s++;
    size_t n=strlen(s); while(n && isspace((unsigned char)s[n-1])) s[--n]=0;
    return s;
}
struct field { const char *name; size_t offset,size; bool number; };
#define STR(k,m) {k,offsetof(struct config,m),sizeof(((struct config *)0)->m),false}
#define NUM(k,m) {k,offsetof(struct config,m),sizeof(uint16_t),true}
static const struct field fields[]={
    STR("identity.name",name), STR("identity.pkcs11_module",module), STR("identity.token_serial",serial),
    STR("identity.reader",reader), STR("identity.key_id_hex",key_id), STR("identity.certificate",certificate),
    STR("peer.name",peer_name), STR("peer.public_key",public_key), STR("peer.spki_sha256",pin_hex),
    STR("local.listen_address",listen), STR("local.target_address",target),
    NUM("local.video_port",ports[0]), NUM("local.audio_port",ports[1]), NUM("local.text_port",ports[2]),
    STR("tunnel.role",role), STR("tunnel.bind",bind), STR("tunnel.peer",peer), NUM("tunnel.max_payload",max_payload)
};
static bool number(const char *s,uint16_t *out) {
    if(!*s) return false;
    for(const char *p=s;*p;p++) if(!isdigit((unsigned char)*p)) return false;
    errno=0; char *end; unsigned long n=strtoul(s,&end,10);
    if(errno || *end || !n || n>65535) return false;
    *out=(uint16_t)n; return true;
}
static bool endpoint(const char *s,struct sockaddr_in *a) {
    char buf[40]; if(strlen(s)>=sizeof(buf)) return false; strcpy(buf,s);
    char *colon=strchr(buf,':'); if(!colon) return false; *colon++=0;
    uint16_t port; memset(a,0,sizeof(*a)); a->sin_family=AF_INET;
    if(!number(colon,&port) || inet_pton(AF_INET,buf,&a->sin_addr)!=1) return false;
    a->sin_port=htons(port); return true;
}
bool config_load(const char *path,struct config *c,char *error,size_t cap) {
    FILE *f=fopen(path,"r"); if(!f) { snprintf(error,cap,"cannot open config: %s",strerror(errno)); return false; }
    memset(c,0,sizeof(*c)); bool seen[sizeof(fields)/sizeof(fields[0])]={0};
    char line[1200],section[32]=""; unsigned lineno=0; const char *why="invalid line";
    while(fgets(line,sizeof(line),f)) {
        lineno++; size_t len=strlen(line);
        if(!len || (len==sizeof(line)-1 && line[len-1]!='\n')) { why="line too long"; goto bad; }
        char *s=trim(line); if(!*s || *s=='#' || *s==';') continue;
        if(*s=='[') {
            char *end=strchr(s,']'); if(!end || end[1]) goto bad; *end=0; s++;
            if(strcmp(s,"identity") && strcmp(s,"peer") && strcmp(s,"local") && strcmp(s,"tunnel")) {
                why="unknown section"; goto bad;
            }
            strcpy(section,s); continue;
        }
        char *equal=strchr(s,'='); if(!equal) goto bad; *equal++=0;
        char *key=trim(s), *value=trim(equal), full[100];
        if(!*value || snprintf(full,sizeof(full),"%s.%s",section,key)>=(int)sizeof(full)) goto bad;
        size_t i; for(i=0;i<sizeof(fields)/sizeof(fields[0]);i++) if(!strcmp(full,fields[i].name)) break;
        if(i==sizeof(fields)/sizeof(fields[0])) { why="unknown setting"; goto bad; }
        if(seen[i]) { why="duplicate setting"; goto bad; } seen[i]=true;
        void *out=(char *)c+fields[i].offset;
        if(fields[i].number) { if(!number(value,out)) { why="invalid number"; goto bad; } }
        else { if(strlen(value)>=fields[i].size) { why="value too long"; goto bad; } strcpy(out,value); }
    }
    if(ferror(f)) { why="config read failed"; goto bad; }
    for(size_t i=0;i<sizeof(fields)/sizeof(fields[0]);i++) if(!seen[i]) { why="required setting missing"; goto bad; }
    uint8_t hex[64]; size_t n=sizeof(hex);
    if(strlen(c->pin_hex)!=64 || !parse_hex(c->pin_hex,hex,&n)) { why="invalid SPKI pin"; goto bad; }
    n=sizeof(hex); if(!parse_hex(c->key_id,hex,&n)) { why="invalid key ID"; goto bad; }
    if(c->module[0]!='/' || (strcmp(c->role,"initiator") && strcmp(c->role,"responder")) ||
       c->max_payload<64 || c->max_payload>HSP_MAX_PAYLOAD) { why="invalid identity or tunnel policy"; goto bad; }
    if(strcmp(c->listen,"127.0.0.2") || strcmp(c->target,"127.0.0.1")) {
        why="v1 local addresses must be 127.0.0.2 and 127.0.0.1"; goto bad;
    }
    for(unsigned i=0;i<3;i++) {
        for(unsigned j=0;j<i;j++) if(c->ports[i]==c->ports[j]) { why="channel port collision"; goto bad; }
        c->local[i].sin_family=c->delivery[i].sin_family=AF_INET;
        c->local[i].sin_port=c->delivery[i].sin_port=htons(c->ports[i]);
        if(inet_pton(AF_INET,c->listen,&c->local[i].sin_addr)!=1 ||
           inet_pton(AF_INET,c->target,&c->delivery[i].sin_addr)!=1) goto bad;
    }
    if(!endpoint(c->bind,&c->tunnel_bind) || !endpoint(c->peer,&c->tunnel_peer)) {
        why="invalid numeric IPv4 tunnel endpoint"; goto bad;
    }
    uint32_t peer=ntohl(c->tunnel_peer.sin_addr.s_addr);
    if(!peer || peer==UINT32_MAX || (peer>>28)>=14 ||
       (c->tunnel_bind.sin_addr.s_addr==c->tunnel_peer.sin_addr.s_addr &&
        c->tunnel_bind.sin_port==c->tunnel_peer.sin_port)) { why="invalid peer address"; goto bad; }
    fclose(f); return true;
bad:
    snprintf(error,cap,"config line %u: %s",lineno,why); fclose(f); return false;
}
