#ifndef __KVM_H__
#define __KVM_H__

int kvm_arch_get_registers(struct vcpu *vcpu);
int kvm_arch_set_registers(struct vcpu *vcpu);
int kvm_arch_get_sregisters(struct vcpu *vcpu);
int kvm_arch_set_sregisters(struct vcpu *vcpu);
int kvm_check_extension(struct kvm *kvm, unsigned int extension);
int kvm_recommended_vcpus(struct kvm *kvm);
int kvm_max_vcpus(struct kvm *kvm);
int kvm_max_vcpu_id(struct kvm *kvm);
struct kvm *kvm_init(void);
void kvm_clean(struct kvm *kvm);
int kvm_create_vm(struct kvm *kvm, __u64 ram_size, vcpu_env_t *env);
void kvm_clean_vm(struct kvm *kvm);
struct vcpu *kvm_init_vcpu(struct kvm *kvm, int vcpu_id, void *(*fn)(void *), vcpu_env_t *env);
void kvm_clean_vcpu(struct vcpu *vcpu);
void kvm_run_vm(struct kvm *kvm);
int kvm_run_vcpu(struct vcpu *vcpu);
void kvm_wait(struct kvm *kvm);
void kvm_cancel(struct kvm *kvm);
int kvm_wait_vcpu(struct vcpu *vcpu);
int kvm_cancel_vcpu(struct vcpu *vcpu);
void kvm_clean_all(struct kvm *kvm);

int kvm_reset_vcpu (struct vcpu *vcpu);
void *kvm_cpu_thread(void *data);

int kvm_memory_init(struct kvm *kvm);

int kvm_handle_hostcall(struct vcpu *vcpu);
int kvm_main(vcpu_env_t *env);
struct kvm *get_kvm_instance(void);

#endif
