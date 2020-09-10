#ifndef __NET_H__
#define __NET_H__

void handle_select(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_socket(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_bind(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_connect(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_listen(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_accept(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_sendto(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_sendmsg(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_recvfrom(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_recvmsg(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_setsockopt(struct vcpu *vcpu, char *mem,hwaddr32 arg);
void handle_getsockopt(struct vcpu *vcpu, char *mem,hwaddr32 arg);

#endif
