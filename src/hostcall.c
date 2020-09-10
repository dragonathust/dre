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

//#define DEBUG_DRE

#include "dre.h"
#include "kvm.h"
#include "vcpu.h"
#include "family.h"
#include "process.h"
#include "file.h"
#include "net.h"
#include "misc.h"


static void (*const hostcall_handlers[])(struct vcpu *vcpu, char *mem,hwaddr32 arg) = {
#ifdef TEST
	[1]                  = handle_create_family,
	[2] 				 = handle_create_process,
#endif	
	[SYS_create_family]                  = handle_create_family,
	[SYS_create_process] 				 = handle_create_process,
	[SYS_open]                  = handle_open,
	[SYS_close]                  = handle_close,
	[SYS_read]                  = handle_read,
	[SYS_write]                  = handle_write,
	[SYS_select]                  = handle_select,
	[SYS_socket]                  = handle_socket,
	[SYS_bind]                  = handle_bind,
	[SYS_connect]                  = handle_connect,
	[SYS_listen]                  = handle_listen,
	[SYS_accept]                  = handle_accept,
	[SYS_sendto]                  = handle_sendto,
	[SYS_sendmsg]                  = handle_sendmsg,
	[SYS_recvfrom]                  = handle_recvfrom,
	[SYS_recvmsg]                  = handle_recvmsg,
	[SYS_setsockopt]                  = handle_setsockopt,
	[SYS_getsockopt]                  = handle_getsockopt,
	[SYS_dre_halt]              = handle_dre_halt,
	[SYS_log]                   = handle_syslog,
	[SYS_access]                = handle_access,
	[SYS_mkfifo]                = handle_mkfifo,
	[SYS_delay]                 = handle_delay,
	[SYS_clock_ratio]           = handle_clock_ratio,
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static const int hostcall_handlers_max_num =
	ARRAY_SIZE(hostcall_handlers);

int kvm_handle_hostcall(struct vcpu *vcpu)
{
	char *mem;
	hwaddr32 arg_address;
	unsigned int call_number;
	
	kvm_arch_get_registers(vcpu);
	mem = (char *)vcpu->kvm->ram_start;
	call_number = vcpu->regs.rax;
	arg_address = vcpu->regs.rbx;
	
	DBGPRINTF("%s call num 0x%llx, para 0x%llx \n", __FUNCTION__, vcpu->regs.rax, vcpu->regs.rbx);

	if (call_number < hostcall_handlers_max_num
	    && hostcall_handlers[call_number]) {
		hostcall_handlers[call_number](vcpu, mem, arg_address);
		return 0;
	} else {
		printf("%s Unknow hostcall num[0x%x]\n", __FUNCTION__, call_number);
		return -1;
	}

}

