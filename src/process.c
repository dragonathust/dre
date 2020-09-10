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
#include "kvm.h"
#include "vcpu.h"
#include "family.h"
#include "process.h"

void handle_create_process(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_dmx_create_process_t *create_process_args = (linux_dmx_create_process_t *)(mem+arg);
	int ret;
	vcpu_env_t env;

	kvm_arch_get_sregisters(vcpu);	
	//ADD by JHJ
	kvm_arch_get_registers(vcpu);
	env.regs = vcpu->regs;
	env.sregs = vcpu->sregs;	
	env.vcpu_type = DMX_PROCESS;
	env.dmx_env = create_process_args->args;	
	ret = create_process(vcpu, &env);
	
#ifndef TEST	
	create_process_args->rets.ret = ret;
#endif
}

int create_process(struct vcpu *vcpu, vcpu_env_t *env)
{
	int ret;
	struct kvm *kvm = vcpu->kvm;
	int vcpu_id = kvm->vcpu_number;

	kvm->vcpus[vcpu_id] = kvm_init_vcpu(kvm, vcpu_id, kvm_cpu_thread, env);
	if( !kvm->vcpus[vcpu_id] ) {
		printf("create vcpu[%d] failed!\n",vcpu_id);
		return -1;
	}
	
	ret = kvm_run_vcpu(kvm->vcpus[vcpu_id]);
	if( ret ) {
		kvm_clean_vcpu(kvm->vcpus[vcpu_id]);
		return -1;
	}

	kvm->vcpu_number++;
	
	return 0;
}
