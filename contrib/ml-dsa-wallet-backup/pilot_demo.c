// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#define _GNU_SOURCE
#include "backup_file.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Public fixture demo ONLY, not a user-key import/export CLI. The verifier
 * build excludes even the public fixture password and recovery modes. */
static int PublicRead(int dir,const char* name,uint8_t* data,size_t size)
{
    struct stat st; int ok=0;
    int fd=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if(fd<0) return 0;
    if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() || st.st_size!=(off_t)size) goto done;
    size_t offset=0;
    while(offset<size) {
        ssize_t n=read(fd,data+offset,size-offset);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) goto done;
        offset+=(size_t)n;
    }
    uint8_t extra; ssize_t n;
    do {n=read(fd,&extra,1);} while(n<0 && errno==EINTR);
    ok=n==0;
done:
    if(close(fd)!=0) ok=0;
    return ok;
}
static int PublicWrite(int dir,const char* name,const uint8_t* data,size_t size)
{
    int ok=0;
    int fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0) return 0;
    size_t offset=0;
    while(offset<size) {
        ssize_t n=write(fd,data+offset,size-offset);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) goto done;
        offset+=(size_t)n;
    }
    ok=1;
done:
    if(close(fd)!=0) ok=0;
    return ok;
}
static int Verify(int dir)
{
    uint8_t public_key[1312],intent[112],signature[2420],challenge[32];
    return PublicRead(dir,"public.bin",public_key,sizeof(public_key)) &&
        PublicRead(dir,"intent.bin",intent,sizeof(intent)) &&
        PublicRead(dir,"signature.bin",signature,sizeof(signature)) &&
        PublicRead(dir,"challenge.bin",challenge,sizeof(challenge)) &&
        pqbtc_pilot_verify(signature,sizeof(signature),public_key,sizeof(public_key),intent,sizeof(intent),challenge)==0;
}
#ifndef PQBTC_PILOT_VERIFY_ONLY
static int Produce(int dir)
{
    uint8_t password[]="public synthetic backup password";
    uint8_t package[176],public_key[1312]; int ok=0;
    struct pqbtc_mldsa44_key* key=NULL;
    if(pqbtc_mldsa44_key_runtime_init()!=0) goto done;
    if(pqbtc_mldsa44_key_generate(&key)!=0 || pqbtc_mldsa44_key_public(key,public_key,sizeof(public_key))!=0 ||
       pqbtc_backup_create(key,password,sizeof(password)-1,package,sizeof(package))!=0) goto done;
    if(pqbtc_backup_store_at(dir,"wallet.bak",package)!=0 || !PublicWrite(dir,"public.bin",public_key,sizeof(public_key))) goto done;
    ok=1;
done:
    pqbtc_mldsa44_key_destroy(&key); OPENSSL_cleanse(password,sizeof(password)); return ok;
}
static int RestoreSign(int dir)
{
    uint8_t password[]="public synthetic backup password";
    uint8_t package[176],original[1312],recovered[1312],intent[112],signature[2420],challenge[32];
    int ok=0; struct pqbtc_mldsa44_key* key=NULL;
    if(pqbtc_mldsa44_key_runtime_init()!=0) goto done;
    if(pqbtc_backup_load_at(dir,"wallet.bak",package)!=0 ||
       pqbtc_backup_restore(&key,password,sizeof(password)-1,package,sizeof(package))!=0 ||
       pqbtc_mldsa44_key_public(key,recovered,sizeof(recovered))!=0 ||
       !PublicRead(dir,"public.bin",original,sizeof(original)) || CRYPTO_memcmp(original,recovered,sizeof(original))!=0 ||
       !PublicRead(dir,"challenge.bin",challenge,sizeof(challenge)) ||
       pqbtc_pilot_intent(intent,sizeof(intent),original,sizeof(original),challenge)!=0 ||
       pqbtc_pilot_sign(key,signature,sizeof(signature),intent,sizeof(intent),challenge)!=0) goto done;
    if(!PublicWrite(dir,"intent.bin",intent,sizeof(intent)) || !PublicWrite(dir,"signature.bin",signature,sizeof(signature))) goto done;
    ok=1;
done:
    pqbtc_mldsa44_key_destroy(&key); OPENSSL_cleanse(password,sizeof(password)); return ok;
}
#endif
int main(int argc,char** argv)
{
    struct stat st; int ok=0;
    if(argc!=3) goto failed;
    int dir=open(argv[2],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(dir<0) goto failed;
    if(fstat(dir,&st)!=0 || st.st_uid!=geteuid() || (st.st_mode&07777)!=0700) {close(dir);goto failed;}
    if(strcmp(argv[1],"challenge")==0) {
        uint8_t challenge[32];
        ok=RAND_bytes(challenge,sizeof(challenge))==1 && PublicWrite(dir,"challenge.bin",challenge,sizeof(challenge));
    } else if(strcmp(argv[1],"verify")==0) ok=Verify(dir);
#ifndef PQBTC_PILOT_VERIFY_ONLY
    else if(strcmp(argv[1],"produce")==0) ok=Produce(dir);
    else if(strcmp(argv[1],"restore-sign")==0) ok=RestoreSign(dir);
#endif
    if(close(dir)!=0) ok=0;
    if(!ok) goto failed;
    printf("{\"phase\":\"%s\",\"pid\":%ld,\"zero_value_only\":true}\n",argv[1],(long)getpid());
    return 0;
failed:
    fputs("zero-value pilot phase rejected\n",stderr); return 1;
}
