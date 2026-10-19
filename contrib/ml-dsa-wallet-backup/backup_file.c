// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#define _GNU_SOURCE
#include "backup_file.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef PQBTC_BACKUP_FILE_TESTING
static int file_stage;
static unsigned calls;
void pqbtc_backup_file_test_stage(int stage) { file_stage=stage; calls=0; }
#define FILE_FAULT(x) (file_stage==(x))
#else
#define FILE_FAULT(x) 0
#endif
static int Name(const char* name)
{
    if(name==NULL) return 0;
    size_t len=strnlen(name,65);
    if(len==0 || len>64 || name[0]=='.') return 0;
    for(size_t i=0;i<len;++i) {
        unsigned char c=(unsigned char)name[i];
        if(!((c>='a'&&c<='z') || (c>='A'&&c<='Z') || (c>='0'&&c<='9') || c=='_' || c=='-' || c=='.')) return 0;
    }
    return 1;
}
static int Directory(int dir)
{
    struct stat st;
    return fstat(dir,&st)==0 && S_ISDIR(st.st_mode) && st.st_uid==geteuid() && (st.st_mode&07777)==0700;
}
static ssize_t Write(int fd,const uint8_t* data,size_t size)
{
#ifdef PQBTC_BACKUP_FILE_TESTING
    if(FILE_FAULT(FILE_INTERRUPT_WRITE)) {
        if(calls++==0) {errno=EINTR;return -1;}
        if(size>7) size=7;
    }
    if(FILE_FAULT(FILE_NOSPC)) {errno=ENOSPC;return -1;}
#endif
    return write(fd,data,size);
}
static ssize_t Read(int fd,uint8_t* data,size_t size)
{
#ifdef PQBTC_BACKUP_FILE_TESTING
    if(FILE_FAULT(FILE_INTERRUPT_READ)) {
        if(calls++==0) {errno=EINTR;return -1;}
        if(size>7) size=7;
    }
    if(FILE_FAULT(FILE_READ_FAIL)) {errno=EIO;return -1;}
#endif
    return read(fd,data,size);
}
int pqbtc_backup_store_at(int dir,const char* name,const uint8_t package[176])
{
    char temporary[64]={0}; uint8_t random[16];
    int fd=-1,owned=0,published=0,result=PQBTC_BACKUP_IO;
    if(package==NULL || !Name(name) || !Directory(dir)) return -1;
    for(unsigned attempt=0;attempt<4;++attempt) {
        if(RAND_bytes(random,sizeof(random))!=1) goto done;
        memcpy(temporary,".pqbtc-backup-",14);
        for(size_t i=0;i<16;++i) snprintf(temporary+14+2*i,3,"%02x",random[i]);
        fd=openat(dir,temporary,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(fd>=0) {owned=1;break;}
        if(errno!=EEXIST) goto done;
    }
    if(fd<0 || fchmod(fd,0600)!=0) goto done;
    size_t offset=0;
    while(offset<176) {
        ssize_t n=Write(fd,package+offset,176-offset);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) goto done;
        offset+=(size_t)n;
    }
    if(FILE_FAULT(FILE_SYNC) || fsync(fd)!=0) goto done;
    int closed=close(fd); fd=-1;
    if(closed!=0 || FILE_FAULT(FILE_CLOSE)) goto done;
    if(FILE_FAULT(FILE_LINK) || linkat(dir,temporary,dir,name,0)!=0) goto done;
    published=1;
    if(FILE_FAULT(FILE_UNLINK) || unlinkat(dir,temporary,0)!=0) goto done;
    owned=0;
    if(FILE_FAULT(FILE_SYNC_DIR) || fsync(dir)!=0) goto done;
    result=0;
done:
    if(fd>=0) (void)close(fd);
    /* Only our successfully-created temporary inode name may be removed.
     * Never remove name: publication is a fact even if later sync fails. */
    if(owned) (void)unlinkat(dir,temporary,0);
    if(result!=0 && published) result=PQBTC_BACKUP_INDETERMINATE;
    return result;
}
int pqbtc_backup_load_at(int dir,const char* name,uint8_t package[176])
{
    struct stat st; int fd=-1,result=PQBTC_BACKUP_IO;
    if(package==NULL || !Name(name) || !Directory(dir)) return -1;
    uintptr_t a=(uintptr_t)package,b=(uintptr_t)name;
    size_t len=strlen(name)+1;
    if(a>UINTPTR_MAX-176 || b>UINTPTR_MAX-len || (a<b+len && b<a+176)) return -1;
    memset(package,0,176);
    fd=openat(dir,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if(fd<0 || fstat(fd,&st)!=0) goto done;
#ifdef PQBTC_BACKUP_FILE_TESTING
    if(FILE_FAULT(FILE_WRONG_OWNER)) st.st_uid=geteuid()+1;
#endif
    if(!S_ISREG(st.st_mode) || st.st_uid!=geteuid() || (st.st_mode&07777)!=0600 || st.st_nlink!=1 || st.st_size!=176) goto done;
    size_t offset=0;
    while(offset<176) {
        ssize_t n=Read(fd,package+offset,176-offset);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) goto done;
        offset+=(size_t)n;
    }
    uint8_t extra; ssize_t n;
    do {n=Read(fd,&extra,1);} while(n<0 && errno==EINTR);
    if(n!=0) goto done;
    result=0;
done:
    if(fd>=0 && close(fd)!=0) result=PQBTC_BACKUP_IO;
    if(result!=0) memset(package,0,176);
    return result;
}
