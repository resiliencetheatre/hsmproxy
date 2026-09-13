#include "core.h"
#include <stdio.h>
#include <string.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

void put16(uint8_t *p, uint16_t n) { p[0]=(uint8_t)(n>>8); p[1]=(uint8_t)n; }
uint16_t get16(const uint8_t *p) { return (uint16_t)((unsigned)p[0]<<8 | p[1]); }
void put64(uint8_t *p, uint64_t n) { for (int i=7;i>=0;i--) { p[i]=(uint8_t)n; n>>=8; } }
uint64_t get64(const uint8_t *p) { uint64_t n=0; for(int i=0;i<8;i++) n=(n<<8)|p[i]; return n; }
bool hash256(const void *p, size_t n, uint8_t out[32]) {
    unsigned len=0; return EVP_Digest(p,n,out,&len,EVP_sha256(),NULL)==1 && len==32;
}
bool p256_key(EVP_PKEY *p) {
    char group[80]; size_t n;
    return p && EVP_PKEY_is_a(p,"EC") &&
        EVP_PKEY_get_utf8_string_param(p,OSSL_PKEY_PARAM_GROUP_NAME,group,sizeof(group),&n)==1 &&
        !strcmp(group,"prime256v1");
}
EVP_PKEY *load_public(const char *path) {
    FILE *f=fopen(path,"r"); if(!f) return NULL;
    EVP_PKEY *p=PEM_read_PUBKEY(f,NULL,NULL,NULL);
    if(!p) { rewind(f); X509 *x=PEM_read_X509(f,NULL,NULL,NULL);
        if(x) { p=X509_get_pubkey(x); X509_free(x); } }
    fclose(f);
    if(!p256_key(p)) { EVP_PKEY_free(p); return NULL; }
    return p;
}
bool public_pin(EVP_PKEY *p, uint8_t out[32]) {
    unsigned char *der=NULL; int n=i2d_PUBKEY(p,&der);
    bool ok=n>0 && hash256(der,(size_t)n,out); OPENSSL_free(der); return ok;
}
bool verify_digest(EVP_PKEY *key, const uint8_t digest[32], const uint8_t raw[64]) {
    ECDSA_SIG *s=ECDSA_SIG_new(); BIGNUM *r=BN_bin2bn(raw,32,NULL), *b=BN_bin2bn(raw+32,32,NULL);
    if(!s || !r || !b || !ECDSA_SIG_set0(s,r,b)) {
        BN_free(r); BN_free(b); ECDSA_SIG_free(s); return false;
    }
    unsigned char *der=NULL; int n=i2d_ECDSA_SIG(s,&der);
    EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new(key,NULL);
    bool ok=n>0 && ctx && EVP_PKEY_verify_init(ctx)>0 &&
        EVP_PKEY_CTX_set_signature_md(ctx,EVP_sha256())>0 &&
        EVP_PKEY_verify(ctx,der,(size_t)n,digest,32)==1;
    EVP_PKEY_CTX_free(ctx); OPENSSL_free(der); ECDSA_SIG_free(s); return ok;
}
EVP_PKEY *ephemeral(uint8_t pub[32]) {
    EVP_PKEY *p=EVP_PKEY_Q_keygen(NULL,NULL,"X25519"); size_t n=32;
    if(!p || EVP_PKEY_get_raw_public_key(p,pub,&n)!=1 || n!=32) { EVP_PKEY_free(p); return NULL; }
    return p;
}
static bool expand(const uint8_t prk[32], const uint8_t h[32], const char *label, uint8_t *out, size_t len) {
    uint8_t info[128]; size_t n=strlen(label); if(n+34>sizeof(info)) return false;
    put16(info,(uint16_t)n); memcpy(info+2,label,n); memcpy(info+2+n,h,32);
    EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF,NULL);
    bool ok=c && EVP_PKEY_derive_init(c)>0 &&
        EVP_PKEY_CTX_hkdf_mode(c,EVP_PKEY_HKDEF_MODE_EXPAND_ONLY)>0 &&
        EVP_PKEY_CTX_set_hkdf_md(c,EVP_sha256())>0 &&
        EVP_PKEY_CTX_set1_hkdf_key(c,prk,32)>0 &&
        EVP_PKEY_CTX_add1_hkdf_info(c,info,(int)(n+34))>0 && EVP_PKEY_derive(c,out,&len)>0;
    EVP_PKEY_CTX_free(c); return ok;
}
bool derive_traffic(EVP_PKEY *eph, const uint8_t pub[32], const uint8_t h[32],
                    bool initiator, uint16_t max, struct traffic *t, uint8_t finish[2][32]) {
    uint8_t shared[32]={0}, prk[32]={0}; size_t n=32; bool ok=false;
    EVP_PKEY *remote=EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519,NULL,pub,32);
    EVP_PKEY_CTX *c=EVP_PKEY_CTX_new(eph,NULL), *k=NULL;
    memset(t,0,sizeof(*t));
    if(!remote || !c || EVP_PKEY_derive_init(c)<=0 || EVP_PKEY_derive_set_peer(c,remote)<=0 ||
       EVP_PKEY_derive(c,shared,&n)<=0 || n!=32) goto end;
    uint8_t any=0; for(unsigned i=0;i<32;i++) any|=shared[i]; if(!any) goto end;
    k=EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF,NULL); n=32;
    if(!k || EVP_PKEY_derive_init(k)<=0 ||
       EVP_PKEY_CTX_hkdf_mode(k,EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY)<=0 ||
       EVP_PKEY_CTX_set_hkdf_md(k,EVP_sha256())<=0 ||
       EVP_PKEY_CTX_set1_hkdf_salt(k,h,32)<=0 || EVP_PKEY_CTX_set1_hkdf_key(k,shared,32)<=0 ||
       EVP_PKEY_derive(k,prk,&n)<=0 || n!=32) goto end;
    if(!expand(prk,h,"hsp1/finish/I",finish[0],32) || !expand(prk,h,"hsp1/finish/R",finish[1],32) ||
       !expand(prk,h,"hsp1/session-id",t->id,16)) goto end;
    for(unsigned ch=0;ch<4;ch++) {
        char label[40]; snprintf(label,sizeof(label),"hsp1/data/I-to-R/%u",ch);
        if(!expand(prk,h,label,initiator?t->tx[ch]:t->rx[ch],32)) goto end;
        snprintf(label,sizeof(label),"hsp1/data/R-to-I/%u",ch);
        if(!expand(prk,h,label,initiator?t->rx[ch]:t->tx[ch],32)) goto end;
    }
    t->max_payload=max; ok=true;
end:
    EVP_PKEY_free(remote); EVP_PKEY_CTX_free(c); EVP_PKEY_CTX_free(k);
    OPENSSL_cleanse(shared,sizeof(shared)); OPENSSL_cleanse(prk,sizeof(prk));
    if(!ok) { OPENSSL_cleanse(t,sizeof(*t)); OPENSSL_cleanse(finish,64); }
    return ok;
}
static size_t lp(uint8_t *out, const void *p, size_t n) {
    put16(out,(uint16_t)n); memcpy(out+2,p,n); return n+2;
}
bool transcript(const uint8_t init[HSP_INIT_LEN], const uint8_t r0[66], uint8_t h[32]) {
    uint8_t b[320]; const char *label="gtk-pipe-hsm-proxy/transcript/v1";
    size_t n=lp(b,label,strlen(label)); n+=lp(b+n,init,HSP_INIT_LEN); n+=lp(b+n,r0,66);
    return hash256(b,n,h);
}
bool signature_digest(const uint8_t h[32], bool initiator, uint8_t out[32]) {
    uint8_t b[80]; const char *s=initiator?"hsp1/initiator":"hsp1/responder";
    size_t n=lp(b,s,strlen(s)); memcpy(b+n,h,32); return hash256(b,n+32,out);
}
bool confirmation(const uint8_t key[32], const uint8_t h[32], bool initiator, uint8_t out[32]) {
    uint8_t b[80]; const char *s=initiator?"hsp1/confirmed/I":"hsp1/confirmed/R";
    size_t n=lp(b,s,strlen(s)), len=32; memcpy(b+n,h,32);
    return EVP_Q_mac(NULL,"HMAC",NULL,"SHA256",NULL,key,32,b,n+32,out,32,&len)!=NULL && len==32;
}
