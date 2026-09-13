/* Test-only PKCS#11 module. Never install or use with real identities. */
#include <p11-kit/pkcs11.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <string.h>
#include <stdatomic.h>
static EVP_PKEY *key;
static atomic_int mode;
void mock_configure(EVP_PKEY *k,int m) { key=k; atomic_store(&mode,m); }
static CK_RV initialize(CK_VOID_PTR args) { (void)args; return CKR_OK; }
static CK_RV finalize(CK_VOID_PTR args) { (void)args; return CKR_OK; }
static CK_RV slots(CK_BBOOL present,CK_SLOT_ID_PTR out,CK_ULONG_PTR n) {
    (void)present; if(atomic_load(&mode)==1) { *n=0; return CKR_OK; }
    if(*n<1) return CKR_BUFFER_TOO_SMALL;
    out[0]=42; *n=1; return CKR_OK;
}
static CK_RV token(CK_SLOT_ID slot,CK_TOKEN_INFO_PTR info) {
    (void)slot; memset(info,0,sizeof(*info)); memset(info->serialNumber,' ',sizeof(info->serialNumber));
    memcpy(info->serialNumber,"TEST123",7);
    int m=atomic_load(&mode);
    if(m==5) info->flags=CKF_USER_PIN_LOCKED;
    if(m==6) info->flags=CKF_USER_PIN_COUNT_LOW;
    if(m==7) info->flags=CKF_USER_PIN_FINAL_TRY;
    return CKR_OK;
}
static CK_RV slot_info(CK_SLOT_ID slot,CK_SLOT_INFO_PTR info) {
    (void)slot; memset(info,0,sizeof(*info)); info->flags=CKF_HW_SLOT;
    memset(info->slotDescription,' ',sizeof(info->slotDescription)); memcpy(info->slotDescription,"Test Reader",11); return CKR_OK;
}
static CK_RV mechanism(CK_SLOT_ID slot,CK_MECHANISM_TYPE type,CK_MECHANISM_INFO_PTR info) {
    (void)slot; if(type!=CKM_ECDSA) return CKR_MECHANISM_INVALID;
    info->flags=CKF_SIGN; info->ulMinKeySize=256; info->ulMaxKeySize=256; return CKR_OK;
}
static CK_RV session(CK_SLOT_ID slot,CK_FLAGS flags,CK_VOID_PTR app,CK_NOTIFY notify,CK_SESSION_HANDLE_PTR out) {
    (void)slot; (void)flags; (void)app; (void)notify; *out=7; return CKR_OK;
}
static CK_RV close_session(CK_SESSION_HANDLE s) { (void)s; return CKR_OK; }
static CK_RV session_info(CK_SESSION_HANDLE s,CK_SESSION_INFO_PTR info) {
    (void)s; memset(info,0,sizeof(*info));
    info->state=atomic_load(&mode)==4?CKS_RO_PUBLIC_SESSION:CKS_RO_USER_FUNCTIONS;
    return CKR_OK;
}
static CK_RV login(CK_SESSION_HANDLE s,CK_USER_TYPE user,CK_UTF8CHAR_PTR pin,CK_ULONG n) {
    (void)s; (void)user; return n==4 && !memcmp(pin,"1234",4)?CKR_OK:CKR_PIN_INCORRECT;
}
static CK_RV find_init(CK_SESSION_HANDLE s,CK_ATTRIBUTE_PTR attrs,CK_ULONG n) { (void)s; (void)attrs; (void)n; return CKR_OK; }
static CK_RV find(CK_SESSION_HANDLE s,CK_OBJECT_HANDLE_PTR objects,CK_ULONG max,CK_ULONG_PTR n) {
    (void)s; (void)max; objects[0]=9; *n=1; return CKR_OK;
}
static CK_RV attributes(CK_SESSION_HANDLE s,CK_OBJECT_HANDLE object,CK_ATTRIBUTE_PTR attrs,CK_ULONG n) {
    (void)s; (void)object;
    for(CK_ULONG i=0;i<n;i++) {
        CK_ATTRIBUTE *a=&attrs[i];
        if(a->type==CKA_EC_PARAMS) {
            const unsigned char oid[]={6,8,42,134,72,206,61,3,1,7};
            if(a->ulValueLen<sizeof(oid)) return CKR_BUFFER_TOO_SMALL;
            memcpy(a->pValue,oid,sizeof(oid)); a->ulValueLen=sizeof(oid);
        } else {
            if(a->ulValueLen<sizeof(CK_BBOOL)) return CKR_BUFFER_TOO_SMALL;
            CK_BBOOL b=a->type==CKA_EXTRACTABLE || a->type==CKA_ALWAYS_AUTHENTICATE?CK_FALSE:CK_TRUE;
            if(atomic_load(&mode)==2 && a->type==CKA_EXTRACTABLE) b=CK_TRUE;
            memcpy(a->pValue,&b,sizeof(b)); a->ulValueLen=sizeof(b);
        }
    }
    return CKR_OK;
}
static CK_RV sign_init(CK_SESSION_HANDLE s,CK_MECHANISM_PTR m,CK_OBJECT_HANDLE object) {
    (void)s; (void)object; return m->mechanism==CKM_ECDSA?CKR_OK:CKR_MECHANISM_INVALID;
}
static CK_RV sign_data(CK_SESSION_HANDLE s,CK_BYTE_PTR data,CK_ULONG n,CK_BYTE_PTR sig,CK_ULONG_PTR len) {
    (void)s; if(atomic_load(&mode)==3) return CKR_DEVICE_REMOVED;
    if(!key || n!=32 || *len<64) return CKR_ARGUMENTS_BAD;
    EVP_PKEY_CTX *c=EVP_PKEY_CTX_new(key,NULL); unsigned char der[80]; size_t size=sizeof(der);
    int ok=c && EVP_PKEY_sign_init(c)>0 && EVP_PKEY_CTX_set_signature_md(c,EVP_sha256())>0 &&
        EVP_PKEY_sign(c,der,&size,data,32)>0;
    EVP_PKEY_CTX_free(c); if(!ok) return CKR_FUNCTION_FAILED;
    const unsigned char *p=der; ECDSA_SIG *ecdsa=d2i_ECDSA_SIG(NULL,&p,(long)size);
    if(!ecdsa) return CKR_FUNCTION_FAILED;
    const BIGNUM *r,*b; ECDSA_SIG_get0(ecdsa,&r,&b);
    ok=BN_bn2binpad(r,sig,32)==32 && BN_bn2binpad(b,sig+32,32)==32;
    ECDSA_SIG_free(ecdsa); *len=64; return ok?CKR_OK:CKR_FUNCTION_FAILED;
}
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR out) {
    static CK_FUNCTION_LIST list={.version={2,40},.C_Initialize=initialize,.C_Finalize=finalize,
        .C_GetSlotList=slots,.C_GetSlotInfo=slot_info,.C_GetTokenInfo=token,.C_GetMechanismInfo=mechanism,
        .C_OpenSession=session,.C_CloseSession=close_session,.C_GetSessionInfo=session_info,.C_Login=login,.C_Logout=close_session,
        .C_FindObjectsInit=find_init,.C_FindObjects=find,.C_FindObjectsFinal=close_session,
        .C_GetAttributeValue=attributes,.C_SignInit=sign_init,.C_Sign=sign_data};
    *out=&list; return CKR_OK;
}
