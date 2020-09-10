#ifndef __PROCESS_H__
#define __PROCESS_H__

void handle_create_process(struct vcpu *vcpu, char *mem,hwaddr32 arg);
int create_process(struct vcpu *vcpu, vcpu_env_t *env);

#endif
