#ifndef __FAMILY_H__
#define __FAMILY_H__

void handle_create_family(struct vcpu *vcpu, char *mem,hwaddr32 arg);
int create_family(vcpu_env_t *env);

#endif
