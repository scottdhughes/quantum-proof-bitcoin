// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#include "backup.h"
#include "backup_test.h"
#include "../ml-dsa-key-lifecycle/key_lifecycle_test.h"
#include "../ml-dsa-engineering/pqbtc_mldsa44_test.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL: %s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); } } while (0)
static const uint8_t password[] = "public synthetic backup password";
static const uint8_t seed[32] = {
    0xd7,0x13,0x61,0xc0,0x00,0xf9,0xa7,0xbc,0x99,0xdf,0xb4,0x25,0xbc,0xb6,0xbb,0x27,
    0xc3,0x2c,0x36,0xab,0x44,0x4f,0xf3,0x70,0x8b,0x2d,0x93,0xb4,0xe6,0x6d,0x5b,0x5b};
static int zero(const uint8_t* p,size_t n) { uint8_t b=0; while(n--) b|=*p++; return b==0; }
static int create(const struct pqbtc_mldsa44_key* k,uint8_t* p)
{ return pqbtc_backup_create(k,password,sizeof(password)-1,p,176); }
static int restore(struct pqbtc_mldsa44_key** k,const uint8_t* p)
{ return pqbtc_backup_restore(k,password,sizeof(password)-1,p,176); }

int main(int argc,char** argv)
{
    struct pqbtc_mldsa44_key *key=NULL,*restored=NULL,*other=NULL;
    uint8_t package[177], original[176], public_key[1312], recovered_pk[1312];
    uint8_t intent[113], challenge[32]={1}, signature[2420], hash[32], exported[32], entropy[32];
    static const uint8_t want_hash[32]={0x45,0x1a,0x80,0x8c,0x52,0x22,0x18,0xfa,0xdb,0xda,0xb1,0x46,0xfc,0x12,0x00,0x4b,0x07,0x41,0xc7,0xd0,0x69,0xf2,0x38,0xf4,0x3a,0xd7,0x72,0x16,0x15,0x9f,0x6a,0x34};
    pqbtc_backup_test_reset();
    CHECK(pqbtc_mldsa44_key_import_seed(&key,seed,32)==0);
    CHECK(pqbtc_mldsa44_key_public(key,public_key,1312)==0);
    CHECK(EVP_Digest(public_key,1312,hash,NULL,EVP_sha256(),NULL)==1);
    CHECK(memcmp(hash,want_hash,32)==0);
    pqbtc_backup_test_stage(TEST_RANDOM_FIXED);
    CHECK(create(key,package)==0);
    CHECK(pqbtc_backup_test_clean()==1); /* cleanup observation calibrated by mutant */
    static const uint8_t want_package_hash[32]={0x91,0x92,0x74,0x34,0x9f,0xaf,0x69,0x8e,0x32,0x05,0x2f,0x75,0xe0,0x7e,0x4f,0x7e,0x6f,0xbb,0x99,0x7f,0x45,0xca,0x98,0x95,0x90,0x26,0x23,0xfe,0x40,0xb4,0x65,0x06};
    CHECK(EVP_Digest(package,176,hash,NULL,EVP_sha256(),NULL)==1);
    CHECK(memcmp(hash,want_package_hash,32)==0); /* independent fixture/AAD binding */
    CHECK(memcmp(package,"PQBWLT1\0",8)==0 && package[9]==1 && package[11]==96);
    memcpy(original,package,176);
    if (argc==2 && strcmp(argv[1],"--fixture")==0) {
        for(size_t i=0;i<176;++i) printf("%02x",package[i]);
        puts(""); pqbtc_mldsa44_key_destroy(&key); return 0;
    }
    CHECK(create(key,package)==PQBTC_BACKUP_ENTROPY); /* fixed sample repeat */
    CHECK(zero(package,176));
    pqbtc_backup_test_stage(0);
    CHECK(create(key,package)==0);
    CHECK(memcmp(original,package,176)!=0);
    CHECK(restore(&restored,original)==0);
    CHECK(pqbtc_mldsa44_key_export_seed(restored,exported,32)==0 && memcmp(exported,seed,32)==0);
    memset(exported,0,sizeof(exported));
    CHECK(pqbtc_mldsa44_key_public(restored,recovered_pk,1312)==0 && memcmp(public_key,recovered_pk,1312)==0);
    CHECK(restore(&restored,original)==PQBTC_BACKUP_INVALID);
    pqbtc_mldsa44_key_destroy(&restored);
    /* The normal password is a counted byte string, never strlen-normalized. */
    uint8_t nulpass[18]={1,2,3,[17]=4};
    CHECK(pqbtc_backup_create(key,nulpass,18,package,176)==0);
    CHECK(pqbtc_backup_restore(&restored,nulpass,18,package,176)==0);
    pqbtc_mldsa44_key_destroy(&restored);
    CHECK(pqbtc_backup_restore(&restored,nulpass,17,package,176)==PQBTC_BACKUP_AUTH && restored==NULL);
    CHECK(pqbtc_backup_restore(&restored,(const uint8_t*)"wrong public password",21,original,176)==PQBTC_BACKUP_AUTH && restored==NULL);
    /* All header edits except random salt/nonce fail before invoking scrypt. */
    for(size_t i=0;i<96;++i) {
        memcpy(package,original,176); package[i]^=1;
        size_t before=pqbtc_backup_test_derivations();
        CHECK(restore(&restored,package)==PQBTC_BACKUP_AUTH && restored==NULL);
        if(i<48 || i>=76) CHECK(pqbtc_backup_test_derivations()==before);
    }
    for(size_t i=96;i<176;++i) {
        memcpy(package,original,176); package[i]^=1;
        CHECK(restore(&restored,package)==PQBTC_BACKUP_AUTH && restored==NULL); /* authentication required */
        CHECK(pqbtc_backup_test_clean()==1);
    }
    for(size_t n=0;n<176;++n) CHECK(pqbtc_backup_restore(&restored,password,sizeof(password)-1,original,n)==-1 && restored==NULL);
    CHECK(pqbtc_backup_restore(&restored,password,sizeof(password)-1,package,177)==-1);
    CHECK(pqbtc_backup_create(key,password,15,package,176)==-1);
    CHECK(pqbtc_backup_create(key,password,1025,package,176)==-1);
    CHECK(pqbtc_backup_create(key,NULL,32,package,176)==-1);
    CHECK(pqbtc_backup_create(key,password,sizeof(password)-1,package,175)==-1);
    CHECK(pqbtc_backup_restore(NULL,password,sizeof(password)-1,original,176)==-1);
    union { struct pqbtc_mldsa44_key* owner; uint8_t bytes[176]; } alias;
    memcpy(alias.bytes,original,176);
    CHECK(pqbtc_backup_restore(&alias.owner,password,sizeof(password)-1,alias.bytes,176)==-1);
    memcpy(package,original,176);
    CHECK(pqbtc_backup_create(key,package,32,package,176)==-1 && memcmp(package,original,176)==0);
    size_t extent=pqbtc_mldsa44_key_test_allocation_size();
    uint8_t* snapshot=malloc(extent); CHECK(snapshot!=NULL); memcpy(snapshot,key,extent);
    size_t offsets[]={0,32,100,extent-176};
    for(size_t i=0;i<sizeof(offsets)/sizeof(offsets[0]);++i) {
        CHECK(pqbtc_backup_create(key,password,sizeof(password)-1,(uint8_t*)key+offsets[i],176)==-1);
        CHECK(memcmp(snapshot,key,extent)==0);
    }
    free(snapshot);
    pqbtc_mldsa44_key_test_fail_allocation(1);
    CHECK(restore(&restored,original)==PQBTC_BACKUP_CRYPTO && restored==NULL);
    CHECK(pqbtc_backup_test_clean()==1);
    pqbtc_mldsa44_key_test_fail_allocation(0);
    pqbtc_mldsa44_key_test_fail_keygen(1);
    CHECK(restore(&restored,original)==PQBTC_BACKUP_CRYPTO && restored==NULL);
    CHECK(pqbtc_mldsa44_key_test_release_zero()==1 && pqbtc_backup_test_clean()==1);
    pqbtc_mldsa44_key_test_fail_keygen(0);
    for(int stage=TEST_RANDOM_FAIL;stage<=TEST_AFTER_IMPORT_FAIL;++stage) {
        pqbtc_backup_test_reset(); pqbtc_backup_test_stage(stage);
        if(stage==TEST_DECRYPT_FAIL || stage==TEST_IMPORT_FAIL || stage==TEST_AFTER_IMPORT_FAIL) {
            CHECK(restore(&restored,original)!=0 && restored==NULL);
        } else if(stage==TEST_BAD_COMMITMENT) {
            CHECK(create(key,package)==0);
            pqbtc_backup_test_stage(0);
            CHECK(restore(&restored,package)==PQBTC_BACKUP_AUTH && restored==NULL);
        } else {
            memset(package,0x5a,176); CHECK(create(key,package)!=0); CHECK(zero(package,176));
        }
        CHECK(pqbtc_backup_test_clean()==1);
        if(stage==TEST_BAD_COMMITMENT || stage==TEST_AFTER_IMPORT_FAIL)
            CHECK(pqbtc_mldsa44_key_test_releases()==1 && pqbtc_mldsa44_key_test_release_zero()==1);
    }
    pqbtc_backup_test_reset();
    memset(entropy,0x31,sizeof(entropy));
    CHECK(pqbtc_mldsa44_test_set_entropy(1,entropy,32)==0);
    CHECK(pqbtc_pilot_intent(intent,112,public_key,1312,challenge)==0);
    CHECK(pqbtc_pilot_sign(key,signature,2420,intent,112,challenge)==0);
    CHECK(pqbtc_pilot_verify(signature,2420,public_key,1312,intent,112,challenge)==0);
    memset(entropy,0x42,sizeof(entropy));
    CHECK(pqbtc_mldsa44_test_set_entropy(1,entropy,32)==0);
    CHECK(pqbtc_mldsa44_key_generate(&other)==0);
    CHECK(pqbtc_mldsa44_key_public(other,recovered_pk,1312)==0);
    CHECK(pqbtc_pilot_verify(signature,2420,recovered_pk,1312,intent,112,challenge)!=0);
    for(size_t i=0;i<112;++i) {
        intent[i]^=1;
        CHECK(pqbtc_pilot_sign(key,signature,2420,intent,112,challenge)!=0);
        CHECK(pqbtc_pilot_verify(signature,2420,public_key,1312,intent,112,challenge)!=0);
        intent[i]^=1;
    }
    memset(entropy,0x43,sizeof(entropy));
    CHECK(pqbtc_mldsa44_test_set_entropy(1,entropy,32)==0);
    CHECK(pqbtc_pilot_sign(key,signature,2420,intent,112,challenge)==0);
    signature[17]^=1;
    CHECK(pqbtc_pilot_verify(signature,2420,public_key,1312,intent,112,challenge)!=0);
    CHECK(pqbtc_pilot_sign(key,signature,2420,intent,111,challenge)!=0);
    CHECK(pqbtc_pilot_sign(key,signature,2420,intent,113,challenge)!=0);
    CHECK(pqbtc_pilot_intent(intent,112,public_key,1311,challenge)!=0);
    CHECK(pqbtc_pilot_intent(intent,111,public_key,1312,challenge)!=0);
    pqbtc_mldsa44_key_destroy(&other); pqbtc_mldsa44_key_destroy(&key);
    CHECK(key==NULL && other==NULL);
    printf("backup crypto runtime: %s\n",OpenSSL_version(OPENSSL_VERSION));
    printf("backup smoke: PASS (%u checks)\n",checks);
    return 0;
}
