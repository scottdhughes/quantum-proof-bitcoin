// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#include "backup.h"
#include "../ml-dsa-key-lifecycle/key_lifecycle.c"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#ifdef PQBTC_MLDSA44_TESTING
#include "backup_test.h"
static int backup_stage, backup_clean;
static size_t backup_derivations;
#define FAIL_STAGE(x) (backup_stage==(x))
#else
#define FAIL_STAGE(x) 0
#endif

/* Independent state in this artifact. Caller serializes key use/destruction;
 * module entropy guard uses the inherited lifecycle/atfork coordinated lock. */
static uint8_t last_backup_random[28];
static int has_backup_random;
static const uint8_t pilot_domain[32]={
    0x4b,0x30,0xe0,0x76,0xb2,0xe2,0x90,0x06,0x42,0x9f,0x04,0xf7,0x74,0x8a,0xce,0x31,
    0x1a,0xdc,0x8f,0x39,0x1c,0x1a,0xcd,0x27,0x11,0x32,0x05,0x39,0xbc,0xf4,0x0c,0x79};
static const uint8_t pilot_context[]="PQBTC-ZERO-VALUE-INTENT-v1";
struct BackupScratch { uint8_t plaintext[64], derived[32], package[176]; };

static void ClearBackup(struct BackupScratch* scratch)
{
    pqbtc_mldsa44_zeroize(scratch,sizeof(*scratch));
#ifdef PQBTC_MLDSA44_TESTING
    backup_clean=ConstantTimeAllZero((const uint8_t*)scratch,sizeof(*scratch));
#endif
}
static int Hash(const uint8_t* input,size_t size,uint8_t out[32])
{ return EVP_Digest(input,size,out,NULL,EVP_sha256(),NULL)==1; }
static void Header(uint8_t h[96])
{
    memset(h,0,96); memcpy(h,"PQBWLT1\0",8);
    h[9]=1; h[11]=96; h[13]=1; memcpy(h+16,pilot_domain,32);
    h[79]=64; h[81]=2; h[87]=8; h[91]=1;
}
static int ValidHeader(const uint8_t* h)
{
    uint8_t expected[96]; Header(expected);
    /* Only salt/nonce are variable; all size/cost fields are fixed constants. */
    return ConstantTimeEqual(h,expected,48) && ConstantTimeEqual(h+76,expected+76,20);
}
static int Password(const uint8_t* p,size_t n) { return p!=NULL && n>=16 && n<=1024; }
static int Derive(const uint8_t* password,size_t n,const uint8_t salt[16],uint8_t key[32])
{
#ifdef PQBTC_MLDSA44_TESTING
    ++backup_derivations;
#endif
    return !FAIL_STAGE(TEST_KDF_FAIL) && EVP_PBE_scrypt((const char*)password,n,
        salt,16,131072,8,1,160ULL*1024*1024,key,32)==1;
}
static int RandomHeader(uint8_t* header)
{
    uint8_t random[28]={0}; int good=0;
    if(!SigningForkLifecycleReady()) return 0;
    LockSigningModule();
    if(FAIL_STAGE(TEST_RANDOM_FAIL)) goto done;
#ifdef PQBTC_MLDSA44_TESTING
    if(backup_stage==TEST_RANDOM_FIXED) {
        for(size_t i=0;i<28;++i) random[i]=(uint8_t)(i+1);
    } else if(backup_stage!=TEST_RANDOM_ZERO)
#endif
    { if(RAND_bytes(random,sizeof(random))!=1) goto done; }
    if(ConstantTimeAllZero(random,sizeof(random)) ||
       (has_backup_random && ConstantTimeEqual(random,last_backup_random,sizeof(random)))) goto done;
    memcpy(last_backup_random,random,sizeof(random)); has_backup_random=1;
    memcpy(header+48,random,sizeof(random)); good=1;
done:
    UnlockSigningModule(); pqbtc_mldsa44_zeroize(random,sizeof(random)); return good;
}

int pqbtc_backup_create(const struct pqbtc_mldsa44_key* key,
    const uint8_t* password,size_t password_size,uint8_t* package,size_t size)
{
    struct BackupScratch scratch={0}; EVP_CIPHER_CTX* ctx=NULL;
    int n=0,tail=0,result=PQBTC_BACKUP_CRYPTO;
    if(package==NULL || size!=176 ||
       RangesOverlap(package,size,password,password_size) ||
       (key!=NULL && RangesOverlap(package,size,(const uint8_t*)key,sizeof(*key)))) return -1;
    memset(package,0,size);
    if(key==NULL || !Password(password,password_size) ||
       RangesOverlap(password,password_size,(const uint8_t*)key,sizeof(*key))) return -1;
    Header(scratch.package);
    if(pqbtc_mldsa44_key_export_seed(key,scratch.plaintext,32)!=0 ||
       !Hash(key->public_key,1312,scratch.plaintext+32)) goto done;
    if(FAIL_STAGE(TEST_BAD_COMMITMENT)) scratch.plaintext[32]^=1;
    if(!RandomHeader(scratch.package)) { result=PQBTC_BACKUP_ENTROPY; goto done; }
    if(!Derive(password,password_size,scratch.package+48,scratch.derived)) goto done;
    if(FAIL_STAGE(TEST_CONTEXT_FAIL) || (ctx=EVP_CIPHER_CTX_new())==NULL) goto done;
    if(FAIL_STAGE(TEST_ENCRYPT_FAIL) ||
       EVP_EncryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,scratch.derived,scratch.package+64)!=1 ||
       EVP_EncryptUpdate(ctx,NULL,&n,scratch.package,96)!=1 ||
       EVP_EncryptUpdate(ctx,scratch.package+96,&n,scratch.plaintext,64)!=1 || n!=64 ||
       EVP_EncryptFinal_ex(ctx,scratch.package+96+n,&tail)!=1 || tail!=0 ||
       EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_GET_TAG,16,scratch.package+160)!=1) goto done;
    memcpy(package,scratch.package,176); result=0;
done:
    EVP_CIPHER_CTX_free(ctx); ClearBackup(&scratch); return result;
}

int pqbtc_backup_restore(struct pqbtc_mldsa44_key** owner,
    const uint8_t* password,size_t password_size,const uint8_t* package,size_t size)
{
    struct BackupScratch scratch={0}; EVP_CIPHER_CTX* ctx=NULL;
    struct pqbtc_mldsa44_key* candidate=NULL; uint8_t public_hash[32]={0};
    int n=0,tail=0,result=PQBTC_BACKUP_CRYPTO;
    if(owner==NULL || package==NULL || size!=176 || !Password(password,password_size) ||
       RangesOverlap((const uint8_t*)owner,sizeof(*owner),package,size) ||
       RangesOverlap((const uint8_t*)owner,sizeof(*owner),password,password_size)) return -1;
    if(*owner!=NULL) return -1;
    if(!ValidHeader(package)) return PQBTC_BACKUP_AUTH;
    /* Snapshot validated bytes; concurrent hostile mutation is outside contract. */
    memcpy(scratch.package,package,size);
    if(!Derive(password,password_size,scratch.package+48,scratch.derived)) goto done;
    if(FAIL_STAGE(TEST_CONTEXT_FAIL) || (ctx=EVP_CIPHER_CTX_new())==NULL) goto done;
    if(FAIL_STAGE(TEST_DECRYPT_FAIL) ||
       EVP_DecryptInit_ex(ctx,EVP_aes_256_gcm(),NULL,scratch.derived,scratch.package+64)!=1 ||
       EVP_DecryptUpdate(ctx,NULL,&n,scratch.package,96)!=1 ||
       EVP_DecryptUpdate(ctx,scratch.plaintext,&n,scratch.package+96,64)!=1 || n!=64 ||
       EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_SET_TAG,16,scratch.package+160)!=1) goto done;
    result=PQBTC_BACKUP_AUTH;
    if(EVP_DecryptFinal_ex(ctx,scratch.plaintext+n,&tail)!=1 || tail!=0) goto done;
    /* NEVER import provisional GCM plaintext before successful finalization. */
    result=PQBTC_BACKUP_CRYPTO;
    if(FAIL_STAGE(TEST_IMPORT_FAIL) || pqbtc_mldsa44_key_import_seed(&candidate,scratch.plaintext,32)!=0) goto done;
    if(FAIL_STAGE(TEST_AFTER_IMPORT_FAIL) || !Hash(candidate->public_key,1312,public_hash)) goto done;
    result=PQBTC_BACKUP_AUTH;
    if(!ConstantTimeEqual(public_hash,scratch.plaintext+32,32)) goto done;
    *owner=candidate; candidate=NULL; result=0;
done:
    pqbtc_mldsa44_key_destroy(&candidate); EVP_CIPHER_CTX_free(ctx);
    pqbtc_mldsa44_zeroize(public_hash,sizeof(public_hash)); ClearBackup(&scratch); return result;
}

int pqbtc_pilot_intent(uint8_t* out,size_t size,const uint8_t* pk,size_t pk_size,const uint8_t challenge[32])
{
    uint8_t intent[112]={0};
    if(out==NULL || pk==NULL || challenge==NULL || size!=112 || pk_size!=1312 ||
       RangesOverlap(out,size,pk,pk_size) || RangesOverlap(out,size,challenge,32)) return -1;
    memcpy(intent,"PQINTN1\0",8); memcpy(intent+8,pilot_domain,32);
    if(!Hash(pk,1312,intent+40)) return PQBTC_BACKUP_CRYPTO;
    memcpy(intent+72,challenge,32); memcpy(out,intent,size); return 0;
}
static int ValidIntent(const uint8_t* intent,size_t size,const uint8_t* pk,const uint8_t* challenge)
{
    uint8_t expected[112];
    return intent!=NULL && size==112 &&
        pqbtc_pilot_intent(expected,sizeof(expected),pk,1312,challenge)==0 &&
        ConstantTimeEqual(intent,expected,sizeof(expected));
}
int pqbtc_pilot_sign(const struct pqbtc_mldsa44_key* key,uint8_t* sig,size_t sig_size,
    const uint8_t* intent,size_t size,const uint8_t challenge[32])
{
    uint8_t digest[32];
    if(key==NULL || sig==NULL || sig_size!=2420 ||
       RangesOverlap(sig,sig_size,(const uint8_t*)key,sizeof(*key)) ||
       RangesOverlap(sig,sig_size,intent,size) || RangesOverlap(sig,sig_size,challenge,32)) return -1;
    memset(sig,0,sig_size);
    if(!ValidIntent(intent,size,key->public_key,challenge)) return PQBTC_BACKUP_AUTH;
    if(!Hash(intent,size,digest)) return PQBTC_BACKUP_CRYPTO;
    return pqbtc_mldsa44_key_sign_hedged(key,sig,sig_size,digest,32,pilot_context,sizeof(pilot_context)-1);
}
int pqbtc_pilot_verify(const uint8_t* sig,size_t sig_size,const uint8_t* pk,size_t pk_size,
    const uint8_t* intent,size_t size,const uint8_t challenge[32])
{
    uint8_t digest[32];
    if(pk==NULL || pk_size!=1312 || !ValidIntent(intent,size,pk,challenge)) return PQBTC_BACKUP_AUTH;
    if(!Hash(intent,size,digest)) return PQBTC_BACKUP_CRYPTO;
    return pqbtc_mldsa44_key_verify_strict(sig,sig_size,pk,pk_size,digest,32,pilot_context,sizeof(pilot_context)-1);
}
#ifdef PQBTC_MLDSA44_TESTING
void pqbtc_backup_test_reset(void)
{
    pqbtc_mldsa44_key_test_reset(); backup_stage=0; backup_clean=1; backup_derivations=0;
    LockSigningModule(); memset(last_backup_random,0,sizeof(last_backup_random)); has_backup_random=0; UnlockSigningModule();
}
void pqbtc_backup_test_stage(int stage) { backup_stage=stage; }
int pqbtc_backup_test_clean(void) { return backup_clean; }
size_t pqbtc_backup_test_derivations(void) { return backup_derivations; }
#endif
