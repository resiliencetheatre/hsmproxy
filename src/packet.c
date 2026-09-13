#include "core.h"
#include <string.h>

bool replay_allowed(const struct replay *r, uint64_t n) {
    if(!r->initialized || n>r->top) return true;
    uint64_t d=r->top-n;
    return d<HSP_WINDOW && !(r->bits[d/64] & (UINT64_C(1)<<(d%64)));
}
void replay_commit(struct replay *r, uint64_t n) {
    if(!r->initialized) { memset(r,0,sizeof(*r)); r->initialized=true; r->top=n; }
    if(n>r->top) {
        uint64_t d=n-r->top, next[16]={0};
        if(d<HSP_WINDOW) for(unsigned i=0;i<HSP_WINDOW;i++)
            if(i+d<HSP_WINDOW && (r->bits[i/64] & (UINT64_C(1)<<(i%64))))
                next[(i+d)/64]|=UINT64_C(1)<<((i+d)%64);
        memcpy(r->bits,next,sizeof(next)); r->top=n;
    }
    uint64_t d=r->top-n;
    if(d<HSP_WINDOW) r->bits[d/64]|=UINT64_C(1)<<(d%64);
}
size_t seal_packet(struct traffic *t, unsigned ch, const void *data, size_t n, uint8_t *out) {
    if(ch>3 || n>t->max_payload || t->seq[ch]>=HSP_LIMIT) return 0;
    uint64_t seq=t->seq[ch]++; uint8_t nonce[12]={0}; put64(nonce+4,seq);
    memcpy(out,"HSP1",4); out[4]=1; out[5]=16; out[6]=(uint8_t)ch; out[7]=0;
    memcpy(out+8,t->id,16); put64(out+24,seq);
    EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new(); int len=0, tail=0;
    bool ok=c && EVP_EncryptInit_ex(c,EVP_chacha20_poly1305(),NULL,t->tx[ch],nonce)==1 &&
        EVP_EncryptUpdate(c,NULL,&len,out,32)==1 &&
        EVP_EncryptUpdate(c,out+32,&len,data,(int)n)==1 && (size_t)len==n &&
        EVP_EncryptFinal_ex(c,out+32+n,&tail)==1 && tail==0 &&
        EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_GET_TAG,16,out+32+n)==1;
    EVP_CIPHER_CTX_free(c); return ok?n+48:0;
}
bool open_packet(struct traffic *t, const uint8_t *in, size_t n, unsigned *ch, uint8_t *out, size_t *len) {
    if(n<48 || n>(size_t)t->max_payload+48 || memcmp(in,"HSP1",4) || in[4]!=1 ||
       in[5]!=16 || in[6]>3 || in[7] || CRYPTO_memcmp(in+8,t->id,16)) return false;
    unsigned channel=in[6]; uint64_t seq=get64(in+24);
    if(seq>=HSP_LIMIT || !replay_allowed(&t->replay[channel],seq)) return false;
    uint8_t nonce[12]={0}; put64(nonce+4,seq); int got=0, tail=0; n-=48;
    EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new();
    bool ok=c && EVP_DecryptInit_ex(c,EVP_chacha20_poly1305(),NULL,t->rx[channel],nonce)==1 &&
        EVP_DecryptUpdate(c,NULL,&got,in,32)==1 &&
        EVP_DecryptUpdate(c,out,&got,in+32,(int)n)==1 && (size_t)got==n &&
        EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_AEAD_SET_TAG,16,(void *)(in+32+n))==1 &&
        EVP_DecryptFinal_ex(c,out+n,&tail)==1 && tail==0;
    EVP_CIPHER_CTX_free(c);
    if(!ok) { OPENSSL_cleanse(out,n); return false; }
    replay_commit(&t->replay[channel],seq); *ch=channel; *len=n; return true;
}
