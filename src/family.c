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

void handle_create_family(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
	linux_dmx_create_family_t *create_family_args = (linux_dmx_create_family_t *)(mem+arg);
	int ret;
	vcpu_env_t env;

	kvm_arch_get_sregisters(vcpu);	
	//ADD by JHJ
	kvm_arch_get_registers(vcpu);
	env.regs = vcpu->regs;
	env.sregs = vcpu->sregs;
	env.vcpu_type = DMX_FAMILY;
	env.dmx_env = create_family_args->args;
	ret = create_family(&env);
	
#ifndef TEST		
	create_family_args->rets.ret = ret;
#endif
}

int create_family(vcpu_env_t *env)
{
	pid_t       fam_pid;
	struct kvm *kvm = NULL;

	kvm = get_kvm_instance();
	DBGPRINTF("%s parent kvm is %p\n",__FUNCTION__, kvm);
	if( !kvm ) {
		DBGPRINTF("%s parent is NULL\n",__FUNCTION__);
		return -1;
	}
	
	fam_pid = fork();
	if( fam_pid == (pid_t) -1 ) {
	DBGPRINTF("%s fork error:%s\n",__FUNCTION__,strerror(errno));
	return -1;
	}
	else if( fam_pid == 0 ) {
	/* CHILD's thread of execution */
/*	
	    if (pthread_kill(kvm->vcpus[0]->vcpu_thread, 0) != ESRCH){
			pthread_kill(kvm->vcpus[0]->vcpu_thread, SIGQUIT);
			pthread_join(kvm->vcpus[0]->vcpu_thread, NULL);
			DBGPRINTF("%s kvm in forked context %p\n",__FUNCTION__, kvm);
		}
*/
	kvm->env->vcpu_type = DMX_FAMILY;
	kvm_clean_all(kvm);
	DBGPRINTF("%s kvm clean all %p\n",__FUNCTION__, kvm);
	kvm_main(env);
	DBGPRINTF("%s family exit\n",__FUNCTION__);
	exit(0);
	}
	
	/* PARENT's thread of execution. */
	return 0;
}

