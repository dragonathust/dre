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

#include "dre.h"
#include "net.h"


#ifdef DEBUG_DRE
static void hex_dump_r(unsigned char *tempc, int dump_size)
{
	int j;

	printf("{");
	for(j = 0; j < dump_size; j++) {
		if ((j % 16) == 0) printf("\n");
			printf("%02x ", tempc[j]);
		}
	printf("}\n");
}
#endif

void handle_select(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_select_param_t *select_args = (linux_select_param_t *)(mem+arg);
	
	fd_set *readfds = select_args->args.in ? (fd_set *)(mem+select_args->args.in) : NULL;
	fd_set *writefds = select_args->args.out ? (fd_set *)(mem+select_args->args.out) : NULL;
	fd_set *exceptfds = select_args->args.ex ? (fd_set *)(mem+select_args->args.ex) : NULL;
	struct timeval *timeout = select_args->args.time ? (struct timeval *)(mem+select_args->args.time) : NULL;
	int ret;
		
	DBGPRINTF("%s [fd=%d,sizeof(fd_set)=%ld]\n",__FUNCTION__,select_args->args.nd,sizeof(fd_set));	
 	ret = select(select_args->args.nd, readfds, writefds, exceptfds, timeout);
#ifdef DEBUG_DRE
	if(select_args->args.in) {
		hex_dump_r((unsigned char *)readfds,sizeof(fd_set));
	}
#endif
	
	select_args->rets.ret = ret;
	select_args->rets._errno = errno;	
	
	DBGPRINTF("%s [ret=%d,errno=%d]\n",__FUNCTION__,ret,errno );	

}

void handle_socket(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_socket_param__t *socket_args = (linux_socket_param__t *)(mem+arg);
	int ret;
	
	DBGPRINTF("%s [socket_family=0x%x,socket_type=0x%x,protocol=0x%x]\n",__FUNCTION__,socket_args->args.socket_family,
		socket_args->args.socket_type, socket_args->args.protocol);
	
	ret = socket(socket_args->args.socket_family, socket_args->args.socket_type, socket_args->args.protocol);
	socket_args->rets.ret = ret;
	socket_args->rets._errno = errno;
}

void handle_bind(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_bind_param_t *bind_args = (linux_bind_param_t *)(mem+arg);
	struct sockaddr *addr = bind_args->args.buf ? (struct sockaddr *)(mem+bind_args->args.buf) : NULL;
	int ret;
		
	DBGPRINTF("%s [fd=%d, addlen=%d]\n",__FUNCTION__, bind_args->args.fd,bind_args->args.len);
#ifdef DEBUG_DRE
	hex_dump_r((unsigned char *)addr,bind_args->args.len);
#endif
	
	ret = bind(bind_args->args.fd, addr, bind_args->args.len);
	bind_args->rets.ret = ret;
	bind_args->rets._errno = errno;
}

void handle_connect(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_connect_param_t *connect_args = (linux_connect_param_t *)(mem+arg);
	struct sockaddr *addr = connect_args->args.name ? (struct sockaddr *)(mem+connect_args->args.name) : NULL;
	int ret;
	
	DBGPRINTF("%s [fd=%d, addlen=%d]\n",__FUNCTION__, connect_args->args.fd,connect_args->args.namelen);
#ifdef DEBUG_DRE
	hex_dump_r((unsigned char *)addr,connect_args->args.namelen);
#endif
	
	ret = connect(connect_args->args.fd, addr, connect_args->args.namelen);
	
	connect_args->rets.ret = ret;
	connect_args->rets._errno = errno;
}

void handle_listen(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_listen_param_t *listen_args = (linux_listen_param_t *)(mem+arg);
	int ret;
	
	DBGPRINTF("%s [fd=%d, backlog=0x%x]\n",__FUNCTION__, listen_args->args.fd,listen_args->args.backlog);
	
	ret = listen(listen_args->args.fd, listen_args->args.backlog);
	listen_args->rets.ret = ret;
	listen_args->rets._errno = errno;

}

void handle_accept(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_accept_param_t *accept_args = (linux_accept_param_t *)(mem+arg);
	struct sockaddr *addr = accept_args->args.buf_sock ? (struct sockaddr *)(mem+accept_args->args.buf_sock) : NULL;
	socklen_t *addrlen = accept_args->args.buf_len ? (socklen_t *)(mem+accept_args->args.buf_len) : NULL;
	int ret;
		
	DBGPRINTF("%s [fd=%d, addlen=%d]\n",__FUNCTION__, accept_args->args.fd,(int)*addrlen);
#ifdef DEBUG_DRE
	hex_dump_r((unsigned char*)addr,(int)*addrlen);
#endif
	
	ret = accept(accept_args->args.fd, addr, addrlen);
	accept_args->rets.ret = ret;
	accept_args->rets._errno = errno;

}

void handle_sendto(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_sendto_param_t *sendto_args = (linux_sendto_param_t *)(mem+arg);
	struct sockaddr *addr = sendto_args->args.to ? (struct sockaddr *)(mem+sendto_args->args.to) : NULL;
	char *buf = sendto_args->args.buf ? (char*)(mem+sendto_args->args.buf) : NULL;	
	int len;
	
	DBGPRINTF("%s [fd=%d, addlen=%d, len =%d]\n",__FUNCTION__, sendto_args->args.fd,
		sendto_args->args.tolen, sendto_args->args.len);
	
	len = sendto(sendto_args->args.fd, buf, sendto_args->args.len,
		sendto_args->args.flags, addr, sendto_args->args.tolen);
	
	sendto_args->rets.ret = len;
	sendto_args->rets._errno = errno;
		
	DBGPRINTF("%s [len=%d,errno=%d]\n",__FUNCTION__,len,errno );

}

void handle_sendmsg(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{

}

void handle_recvfrom(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_recvfrm_param_t *recvfrom_args = (linux_recvfrm_param_t *)(mem+arg);
	struct sockaddr *addr = recvfrom_args->args.from_addr ? (struct sockaddr *)(mem+recvfrom_args->args.from_addr) : NULL;
	socklen_t *addrlen = recvfrom_args->args.from_len ? (socklen_t *)(mem+recvfrom_args->args.from_len) : NULL;
	char *buf = recvfrom_args->args.buf ? (char*)(mem+recvfrom_args->args.buf) : NULL;	
	int len;

	DBGPRINTF("%s [fd=%d, addlen=%d]\n",__FUNCTION__, recvfrom_args->args.fd, (int)*addrlen);

	len = recvfrom(recvfrom_args->args.fd, buf, recvfrom_args->args.len,
		recvfrom_args->args.flags, addr, addrlen);

	recvfrom_args->rets.ret = len;
	recvfrom_args->rets._errno = errno;

	DBGPRINTF("%s [len=%d,errno=%d]\n",__FUNCTION__,len,errno );	
}

void handle_recvmsg(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{

}

void handle_setsockopt(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_setsockopt_param_t *setsockopt_args = (linux_setsockopt_param_t *)(mem+arg);
	int *optval = setsockopt_args->args.val ? (int *)(mem+setsockopt_args->args.val) : NULL;
	int ret;

	ret = setsockopt(setsockopt_args->args.fd, setsockopt_args->args.level, setsockopt_args->args.name,
		optval, setsockopt_args->args.valsize);
	
	setsockopt_args->rets.ret = ret;
	setsockopt_args->rets._errno = errno;

}

void handle_getsockopt(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_getsockopt_param_t *getsockopt_args = (linux_getsockopt_param_t *)(mem+arg);
	int *optval = getsockopt_args->args.val ? (int *)(mem+getsockopt_args->args.val) : NULL;
	socklen_t *optlen = getsockopt_args->args.avalsize ? (socklen_t *)(mem+getsockopt_args->args.avalsize) : NULL;
	int ret;
	
	ret = getsockopt(getsockopt_args->args.fd, getsockopt_args->args.level, getsockopt_args->args.name,
		optval, optlen);

	getsockopt_args->rets.ret = ret;
	getsockopt_args->rets._errno = errno;

}
