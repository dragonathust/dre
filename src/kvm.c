#include <unistd.h>
#include <stdio.h>
#include <memory.h>
#include <sys/mman.h>
#include <pthread.h>
#include <linux/kvm.h>
#include <fcntl.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>

#include "dre.h"
#include "kvm.h"

#define VM_SHARE_MEM "/vm_share_mem"

static struct kvm *kvm_instance = NULL;

struct kvm *get_kvm_instance(void)
{
	return kvm_instance;
}

int kvm_arch_get_registers(struct vcpu *vcpu) {
	return ioctl(vcpu->vcpu_fd, KVM_GET_REGS, &vcpu->regs);
}

int kvm_arch_set_registers(struct vcpu *vcpu) {
	return ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &vcpu->regs);
}

int kvm_arch_get_sregisters(struct vcpu *vcpu) {
	return ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &vcpu->sregs);
}

int kvm_arch_set_sregisters(struct vcpu *vcpu) {
	return ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &vcpu->sregs);
}

int kvm_check_extension(struct kvm *kvm, unsigned int extension)
{
    int ret;

    ret = ioctl(kvm->dev_fd, KVM_CHECK_EXTENSION, extension);
    if (ret < 0) {
        ret = 0;
    }

    return ret;
}

int kvm_recommended_vcpus(struct kvm *kvm)
{
    int ret = kvm_check_extension(kvm, KVM_CAP_NR_VCPUS);
    return (ret) ? ret : 4;
}

int kvm_max_vcpus(struct kvm *kvm)
{
    int ret = kvm_check_extension(kvm, KVM_CAP_MAX_VCPUS);
    return (ret) ? ret : kvm_recommended_vcpus(kvm);
}

int kvm_max_vcpu_id(struct kvm *kvm)
{
    int ret = kvm_check_extension(kvm, KVM_CAP_MAX_VCPU_ID);
    return (ret) ? ret : kvm_max_vcpus(kvm);
}

struct kvm *kvm_init(void) {
		struct kvm *kvm = malloc(sizeof(struct kvm));
		if( !kvm ) return NULL;
		
		memset(kvm,0,sizeof(struct kvm));		
		kvm->dev_fd = open(KVM_DEVICE, O_RDWR);

		if (kvm->dev_fd < 0) {
				perror("open kvm device fault: ");
				return NULL;
		}

		kvm->kvm_version = ioctl(kvm->dev_fd, KVM_GET_API_VERSION, 0);
		kvm->event_fd = eventfd(0,EFD_SEMAPHORE);
		
		return kvm;
}

void kvm_clean(struct kvm *kvm) {
		assert (kvm != NULL);
		close(kvm->event_fd);
		close(kvm->dev_fd);
		free(kvm);
		kvm_instance = NULL;
}

int kvm_create_vm(struct kvm *kvm, __u64 ram_size, vcpu_env_t *env) {
		int ret = 0;
		size_t share_mem_length = 0;
		
		kvm->vm_fd = ioctl(kvm->dev_fd, KVM_CREATE_VM, 0);

		if (kvm->vm_fd < 0) {
				perror("can not create vm");
				return -1;
		}

		kvm->ram_size = ram_size;
#ifndef VM_SHARE_MEM
		kvm->ram_start =  (__u64)mmap(NULL, kvm->ram_size, 
								PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, 
								-1, 0);

		if ((void *)kvm->ram_start == MAP_FAILED) {
				perror("can not mmap ram");
				return -1;
		}
#else
		if( env->vcpu_type == DMX_NONE) {
		ret = util_shm_create_r(VM_SHARE_MEM,kvm->ram_size);
		if(ret) {
			if( ret != FILE_ALREADY_EXIST_EC ) {
				perror("can not create share ram");
				return -1;
			}
			
			if( ret == FILE_ALREADY_EXIST_EC ) {
			printf("share mem already exist!\n");
				if( env->vcpu_type == DMX_NONE) {
				util_shm_remove_r(VM_SHARE_MEM);
				printf("remove share mem!\n");
				ret = util_shm_create_r(VM_SHARE_MEM,kvm->ram_size);
					if( ret ) {
						perror("can not create share ram");
						return -1;
					}
					}
				}
			}			
		}
		
		ret = util_shm_open_r(&kvm->share_mem_handle, VM_SHARE_MEM, O_RDWR,
                       (void **)&kvm->ram_start, &share_mem_length);
		if(ret) {
				perror("can not open share ram");
				return -1;
		}
#endif
		
		kvm->mem.slot = 0;
		kvm->mem.flags = 0;
		kvm->mem.guest_phys_addr = 0;
		kvm->mem.memory_size = kvm->ram_size;
		kvm->mem.userspace_addr = kvm->ram_start;

		ret = ioctl(kvm->vm_fd, KVM_SET_USER_MEMORY_REGION, &(kvm->mem));

		if (ret < 0) {
				perror("can not set user memory region");
				return ret;
		}

		return ret;
}

void kvm_clean_vm(struct kvm *kvm) {
		close(kvm->vm_fd);
#ifndef VM_SHARE_MEM	
		munmap((void *)kvm->ram_start, kvm->ram_size);
#else
		util_shm_close_r(&kvm->share_mem_handle);
		if( kvm->env->vcpu_type == DMX_NONE) {	
		   printf("remove share mem %s!\n", __FUNCTION__);
		   util_shm_remove_r(VM_SHARE_MEM);
		}
#endif
}

struct vcpu *kvm_init_vcpu(struct kvm *kvm, int vcpu_id, void *(*fn)(void *), vcpu_env_t *env) {
		struct vcpu *vcpu;

		vcpu = malloc(sizeof(struct vcpu));
		if( !vcpu ) return NULL;

		memset(vcpu,0,sizeof(struct vcpu));
		vcpu->kvm = kvm;
		vcpu->vcpu_id = vcpu_id;
		vcpu->vcpu_fd = ioctl(kvm->vm_fd, KVM_CREATE_VCPU, vcpu->vcpu_id);

		if (vcpu->vcpu_fd < 0) {
			free(vcpu);
			perror("can not create vcpu");
			return NULL;
		}

		vcpu->kvm_run_mmap_size = ioctl(kvm->dev_fd, KVM_GET_VCPU_MMAP_SIZE, 0);

		if (vcpu->kvm_run_mmap_size < 0) {
				free(vcpu);
				perror("can not get vcpu mmsize");
				return NULL;
		}

		printf("kvm_run_mmap_size: %d\n", vcpu->kvm_run_mmap_size);
		vcpu->kvm_run = mmap(NULL, vcpu->kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu->vcpu_fd, 0);

		if (vcpu->kvm_run == MAP_FAILED) {
				free(vcpu);
				perror("can not mmap kvm_run");
				return NULL;
		}

		vcpu->vcpu_thread_func = fn;
		if(env) {
		vcpu->vcpu_env = *env;
		}
		
		return vcpu;
}

void kvm_clean_vcpu(struct vcpu *vcpu) {
		munmap(vcpu->kvm_run, vcpu->kvm_run_mmap_size);
		close(vcpu->vcpu_fd);
		free(vcpu);
}

void kvm_run_vm(struct kvm *kvm) {
	int i = 0;

	for (i = 0; i < kvm->vcpu_number; i++) {
		if (pthread_create(&(kvm->vcpus[i]->vcpu_thread), (const pthread_attr_t *)NULL, kvm->vcpus[i]->vcpu_thread_func, kvm->vcpus[i]) != 0) {
			perror("can not create kvm thread");
			return;
		}
	}

}

int kvm_run_vcpu(struct vcpu *vcpu) {
	int ret;
	
	ret = pthread_create(&(vcpu->vcpu_thread), (const pthread_attr_t *)NULL, vcpu->vcpu_thread_func, vcpu);
	if (ret) {
		perror("can not create vcpu thread");
	}
	
	return ret;
}

void kvm_wait(struct kvm *kvm) {
#if 0
	int i = 0;
	int ret;
	
	for (i = 0; i < kvm->vcpu_number; i++) {
		ret = pthread_join(kvm->vcpus[i]->vcpu_thread, NULL);
		if(ret) {
			printf("can not join kvm thread, ret=%d\n",ret);
		}
	}
#else
	int i = 0;
	__u64 u = 1;

	for (i = 0; i < kvm->vcpu_number; i++) {	
	read(kvm->event_fd, &u, sizeof(__u64));
	}	
#endif
}

void kvm_cancel(struct kvm *kvm) {
	int i = 0;
	int ret;
	
	for (i = 0; i < kvm->vcpu_number; i++) {
		ret = pthread_cancel(kvm->vcpus[i]->vcpu_thread);
		if(ret) {
			printf("can not cancel kvm thread, ret=%d\n",ret);
		}
	}

}

int kvm_wait_vcpu(struct vcpu *vcpu) {
	int ret;
	
	ret = pthread_join(vcpu->vcpu_thread, NULL);
	if (ret) {
		printf("can not join vcpu thread, ret=%d\n",ret);
	}
	
	return ret;	
}

int kvm_cancel_vcpu(struct vcpu *vcpu) {
	int ret;
	
	ret = pthread_cancel(vcpu->vcpu_thread);
	if (ret) {
		printf("can not cancel vcpu thread, ret=%d\n",ret);
	}
	
	return ret;	
}

void kvm_clean_all(struct kvm *kvm)
{
	int i;
	
	for(i=0;i<kvm->vcpu_number;i++ ) {
		if( kvm->vcpus[i] ) {
			kvm_clean_vcpu(kvm->vcpus[i]);
			}
	}

	kvm_clean_vm(kvm);
	kvm_clean(kvm);	
}

int kvm_main(vcpu_env_t *env) {
		struct kvm *kvm;
		int recommended_vcpus;
		int max_vcpus;
		int max_vcpu_id;
	
		kvm = kvm_init();
		if (kvm == NULL) {
				fprintf(stderr, "kvm init fault\n");
				return -1;
		}

		kvm_instance = kvm;
		kvm->env=env;
		recommended_vcpus = kvm_recommended_vcpus(kvm);
		max_vcpus = kvm_max_vcpus(kvm);
		max_vcpu_id = kvm_max_vcpu_id(kvm);
		
		printf("kvm_version=0x%x\n", kvm->kvm_version);
		printf("recommended_vcpus=%d, max_vcpus=%d, max_vcpu_id=%d\n",
			 recommended_vcpus, max_vcpus, max_vcpu_id);
		
		if (kvm_create_vm(kvm, RAM_SIZE, env) < 0) {
				fprintf(stderr, "create vm fault\n");
				return -1;
		}
		
		if( env->vcpu_type == DMX_NONE) {
		kvm_memory_init(kvm);
		}
		
		kvm->vcpu_number = 1;
		kvm->vcpus[0] = kvm_init_vcpu(kvm, 0, kvm_cpu_thread, env);
		if( !kvm->vcpus[0] ) {
				printf("create vcpu[0] failed!\n"); 
				goto cleanup;
			}
	
		kvm_run_vcpu(kvm->vcpus[0]);

		printf("wait vcpu threads ...\n");

		kvm_wait(kvm);
		
cleanup:		
		printf("kvm_clean_all\n");
		kvm_clean_all(kvm);

		return 0;
	
}
