#ifndef __DRE_H__
#define __DRE_H__

typedef unsigned int hwaddr32;
typedef struct kvm_segment dmx_kvm_segment;
#define near

#include "shm.h"
#pragma pack(1)
#include "sys_dre.h"
#include "hostcall.h"
#pragma pack()

#define VCPU_MAX_NUMBER 1024

typedef enum tag_vcpu_t{
  DMX_NONE =0,
  DMX_FAMILY,
  DMX_PROCESS,
}vcpu_t;
typedef enum tag_vcpu_run_state_t{
  VCPU_RUN =0,
  VCPU_USR_STOP,
  VCPU_INTERNAL_STOP,
}vcpu_run_state_t;

typedef struct tag_ {
    struct kvm_regs regs;
    struct kvm_sregs sregs;
	vcpu_t vcpu_type;
	linux_dmx_env_t dmx_env;
}vcpu_env_t;

struct vcpu {
	struct kvm *kvm;
    int vcpu_id;
    int vcpu_fd;
    pthread_t vcpu_thread;
    struct kvm_run *kvm_run;
    int kvm_run_mmap_size;
    struct kvm_regs regs;
    struct kvm_sregs sregs;
    void *(*vcpu_thread_func)(void *);
	vcpu_env_t vcpu_env;
    vcpu_run_state_t vcpu_state;
};

struct kvm {
   int dev_fd;
   int vm_fd;
   __u64 ram_size;
   __u64 ram_start;
   int kvm_version;
   struct kvm_userspace_memory_region mem;

   struct vcpu *vcpus[VCPU_MAX_NUMBER];
   int vcpu_number;
   int event_fd;
   util_shm_ptr_t   share_mem_handle;
   vcpu_env_t *env;
};

#define KVM_DEVICE "/dev/kvm"
//#define RAM_SIZE (0x100000000ULL)
#define RAM_SIZE (0xF0000000ULL)

#ifdef DEBUG_DRE
#define DBGPRINTF(fmt, ...)                                       \
    do { printf(fmt , ## __VA_ARGS__); } while (0)
#else
#define DBGPRINTF(fmt, ...) do {} while (0)
#endif

#endif //__DRE_H__
