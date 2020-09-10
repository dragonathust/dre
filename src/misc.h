#ifndef __MISC_H__
#define __MISC_H__

void handle_syslog(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_dre_halt(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_delay(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_clock_ratio(struct vcpu *vcpu, char *mem,hwaddr32 arg);

#endif
