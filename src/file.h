#ifndef __FILE_H__
#define __FILE_H__

void handle_open(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_close(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_read(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_write(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_access(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_mkfifo(struct vcpu *vcpu, char *mem,hwaddr32 arg);

#endif
