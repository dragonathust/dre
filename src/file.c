#include <unistd.h>
#include <stdio.h>
#include <memory.h>
#include <sys/mman.h>
#include <pthread.h>
#include <linux/kvm.h>
#include <fcntl.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>


#include "dre.h"
#include "file.h"


void handle_open(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_open_param_t *open_args = (linux_open_param_t *)(mem+arg);
	char *path = open_args->args.path ? (char*)(mem+open_args->args.path) : NULL;
	int fd;

	DBGPRINTF("%s [path %s, flag 0x%x, mode 0x%x]\n",__FUNCTION__,
		path,open_args->args.flag,open_args->args.mode);
	
	fd = open((char*)path,open_args->args.flag);
	DBGPRINTF("%s fd=%d\n",__FUNCTION__,fd);
	
	open_args->rets.ret = fd;
	open_args->rets._errno = errno;
}

void handle_close(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_close_param_t *close_args = (linux_close_param_t *)(mem+arg);
	int ret;

	ret = close(close_args->args.fd);
	close_args->rets.ret = ret;
	close_args->rets._errno = errno;	
}

void handle_read(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_read_write_param__t *read_args = (linux_read_write_param__t *)(mem+arg);
	char *buf = read_args->args.buf ? (char*)(mem+read_args->args.buf) : NULL;
	int len;

	DBGPRINTF("%s [fd=%d,count=%d]\n",__FUNCTION__,read_args->args.fd,read_args->args.count);
	
	len = read(read_args->args.fd,buf,read_args->args.count);
	
	read_args->rets.ret = len;
	read_args->rets._errno = errno;
}

void handle_write(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_read_write_param__t *write_args = (linux_read_write_param__t *)(mem+arg);
	char *buf = write_args->args.buf ? (char*)(mem+write_args->args.buf) : NULL;
	int len;

	len = write(write_args->args.fd,buf,write_args->args.count);

	write_args->rets.ret = len;
	write_args->rets._errno = errno;	
}


void handle_access(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_access_param_t *access_args = (linux_access_param_t *)(mem+arg);
	char *path = access_args->args.path ? (char*)(mem+access_args->args.path) : NULL;
	int ret;
	
	DBGPRINTF("%s [path=%s,flags=%d]\n",__FUNCTION__,path,access_args->rgs.flags );
	ret =  access(path, access_args->args.flags);
	DBGPRINTF("%s ret=%d\n",__FUNCTION__,ret);
	access_args->rets.ret = ret;
	access_args->rets._errno = errno;
}



void handle_mkfifo(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
   linux_mkfifo_param_t *mkfifo_args = (linux_mkfifo_param_t *)(mem+arg);
	char *path = mkfifo_args->args.path ? (char*)(mem+mkfifo_args->args.path) : NULL;
	int ret;
	
	DBGPRINTF("%s [path=%s,mode=%d]\n",__FUNCTION__,path,mkfifo_args->args.mode );
	ret =  mkfifo(path, mkfifo_args->args.mode);
	DBGPRINTF("%s ret=%d\n",__FUNCTION__,ret);
	
	mkfifo_args->rets.ret = ret;
	mkfifo_args->rets._errno = errno;
}
