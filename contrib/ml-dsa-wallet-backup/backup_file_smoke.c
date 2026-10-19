// Copyright (c) 2026 The PQBTC Core developers
// Distributed under the MIT software license, see the accompanying COPYING.
#define _GNU_SOURCE
#include "backup_file.h"
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static unsigned checks;
#define CHECK(x) do { ++checks; if(!(x)) {fprintf(stderr,"FAIL: %s:%d: %s\n",__FILE__,__LINE__,#x);exit(1);} } while(0)
static void NoTemps(int dirfd)
{
    int copy=openat(dirfd,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC); CHECK(copy>=0);
    DIR* dir=fdopendir(copy); CHECK(dir!=NULL);
    struct dirent* e;
    while((e=readdir(dir))) CHECK(strncmp(e->d_name,".pqbtc-backup-",14)!=0);
    closedir(dir);
}
int main(void)
{
    char path[]="/tmp/pqbtc-backup-files.XXXXXX"; CHECK(mkdtemp(path)!=NULL);
    int dir=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); CHECK(dir>=0);
    uint8_t input[176],out[176]; for(size_t i=0;i<176;++i) input[i]=(uint8_t)i;
    CHECK(pqbtc_backup_store_at(dir,"wallet.bak",input)==0);
    CHECK(pqbtc_backup_load_at(dir,"wallet.bak",out)==0 && memcmp(out,input,176)==0);
    struct stat st; CHECK(fstatat(dir,"wallet.bak",&st,AT_SYMLINK_NOFOLLOW)==0 && (st.st_mode&07777)==0600 && st.st_nlink==1);
    uint8_t other[176]={42};
    CHECK(pqbtc_backup_store_at(dir,"wallet.bak",other)==PQBTC_BACKUP_IO);
    CHECK(pqbtc_backup_load_at(dir,"wallet.bak",out)==0 && memcmp(out,input,176)==0);
    const char* bad[]={"",".","..","../escape","/absolute","a/b",".pqbtc-backup-any","space name"};
    for(size_t i=0;i<sizeof(bad)/sizeof(bad[0]);++i) {
        CHECK(pqbtc_backup_store_at(dir,bad[i],input)==-1);
        CHECK(pqbtc_backup_load_at(dir,bad[i],out)==-1);
    }
    CHECK(symlinkat("wallet.bak",dir,"link.bak")==0);
    CHECK(pqbtc_backup_store_at(dir,"link.bak",input)==PQBTC_BACKUP_IO);
    CHECK(pqbtc_backup_load_at(dir,"link.bak",out)==PQBTC_BACKUP_IO);
    CHECK(mkdirat(dir,"directory",0700)==0);
    CHECK(pqbtc_backup_store_at(dir,"directory",input)==PQBTC_BACKUP_IO);
    CHECK(pqbtc_backup_load_at(dir,"directory",out)==PQBTC_BACKUP_IO);
    CHECK(fchmodat(dir,"wallet.bak",0640,0)==0);
    CHECK(pqbtc_backup_load_at(dir,"wallet.bak",out)==PQBTC_BACKUP_IO);
    CHECK(fchmodat(dir,"wallet.bak",0600,0)==0);
    CHECK(linkat(dir,"wallet.bak",dir,"hard.bak",0)==0);
    CHECK(pqbtc_backup_load_at(dir,"wallet.bak",out)==PQBTC_BACKUP_IO);
    CHECK(unlinkat(dir,"hard.bak",0)==0);
    CHECK(fchmod(dir,0750)==0);
    CHECK(pqbtc_backup_load_at(dir,"wallet.bak",out)==-1);
    CHECK(pqbtc_backup_store_at(dir,"no.bak",input)==-1);
    CHECK(fchmod(dir,0700)==0);
    for(int stage=FILE_INTERRUPT_WRITE;stage<=FILE_WRONG_OWNER;++stage) {
        char name[32]; snprintf(name,sizeof(name),"fault-%d.bak",stage);
        pqbtc_backup_file_test_stage(stage);
        if(stage==FILE_INTERRUPT_READ || stage==FILE_READ_FAIL || stage==FILE_WRONG_OWNER) {
            int result=pqbtc_backup_load_at(dir,"wallet.bak",out);
            CHECK(result==(stage==FILE_INTERRUPT_READ ? 0 : PQBTC_BACKUP_IO));
            if(result==0) CHECK(memcmp(out,input,176)==0);
        } else {
            int result=pqbtc_backup_store_at(dir,name,input);
            int want=stage==FILE_INTERRUPT_WRITE ? 0 :
                ((stage==FILE_UNLINK || stage==FILE_SYNC_DIR) ? PQBTC_BACKUP_INDETERMINATE : PQBTC_BACKUP_IO);
            CHECK(result==want);
            pqbtc_backup_file_test_stage(0);
            if(result==0 || result==PQBTC_BACKUP_INDETERMINATE)
                CHECK(pqbtc_backup_load_at(dir,name,out)==0 && memcmp(out,input,176)==0);
            else CHECK(faccessat(dir,name,F_OK,0)!=0);
        }
        pqbtc_backup_file_test_stage(0); NoTemps(dir);
    }
    for(size_t length=0;length<=177;++length) {
        if(length==176) continue;
        int fd=openat(dir,"bad-size.bak",O_CREAT|O_TRUNC|O_WRONLY|O_NOFOLLOW,0600); CHECK(fd>=0);
        uint8_t bytes[177]={0}; CHECK(write(fd,bytes,length)==(ssize_t)length); CHECK(close(fd)==0);
        memset(out,0x5a,sizeof(out)); CHECK(pqbtc_backup_load_at(dir,"bad-size.bak",out)==PQBTC_BACKUP_IO);
        uint8_t zeros[176]={0}; CHECK(memcmp(out,zeros,176)==0);
    }
    CHECK(close(dir)==0);
    printf("backup file smoke: PASS (%u checks)\n",checks); return 0;
}
