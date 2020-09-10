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
#include <sys/prctl.h>

//#define DEBUG_DRE

#include "dre.h"
#include "kvm.h"
#include "vcpu.h"

#define DEBUG_DRE
extern int do_exit;

static void hex_dump_r(unsigned char *tempc, int dump_size)
{
	int j;

	DBGPRINTF("{");
	for(j = 0; j < dump_size; j++) {
		if ((j % 16) == 0) DBGPRINTF("\n");
			DBGPRINTF("%02x ", tempc[j]);
		}
	DBGPRINTF("}\n");
}

#ifndef TEST

#define CR0_PE 1
#define DMX_STACK     0x40107DC
#define BOL_IDT_BASE_OFFSET                  0x04008806
#define BOL_IDT_LIMIT_OFFSET                  0x04008804

__u64 gdt_base = 0;
unsigned int gdt_limit = 0;

static void print_dtable(const char *name, struct kvm_dtable *dtable)
{
	DBGPRINTF( " %s                 %016llx  %08hx\n",
		name, (__u64) dtable->base, (__u16) dtable->limit);
}

static void print_segment(const char *name, struct kvm_segment *seg)
{
	DBGPRINTF( " %s       %04hx      %016llx  %08x  %02hhx    %x %x   %x  %x %x %x %x\n",
		name, (__u16) seg->selector, (__u64) seg->base, (__u32) seg->limit,
		(__u8) seg->type, seg->present, seg->dpl, seg->db, seg->s, seg->l, seg->g, seg->avl);
}

void kvm_cpu__show_registers(struct vcpu *vcpu)
{
	unsigned long cr0, cr2, cr3;
	unsigned long cr4, cr8;
	unsigned long rax, rbx, rcx;
	unsigned long rdx, rsi, rdi;
	unsigned long rbp,  r8,  r9;
	unsigned long r10, r11, r12;
	unsigned long r13, r14, r15;
	unsigned long rip, rsp;
	struct kvm_sregs sregs;
	unsigned long rflags;
	struct kvm_regs regs;
	int i;

	if (ioctl(vcpu->vcpu_fd, KVM_GET_REGS, &regs) < 0)
	{
	   perror("KVM_GET_REGS");
		return;
   }

	rflags = regs.rflags;

	rip = regs.rip; rsp = regs.rsp;
	rax = regs.rax; rbx = regs.rbx; rcx = regs.rcx;
	rdx = regs.rdx; rsi = regs.rsi; rdi = regs.rdi;
	rbp = regs.rbp; r8  = regs.r8;  r9  = regs.r9;
	r10 = regs.r10; r11 = regs.r11; r12 = regs.r12;
	r13 = regs.r13; r14 = regs.r14; r15 = regs.r15;

	DBGPRINTF( "\n Registers:\n");
	DBGPRINTF(   " ----------\n");
	DBGPRINTF( " rip: %016lx   rsp: %016lx flags: %016lx\n", rip, rsp, rflags);
	DBGPRINTF( " rax: %016lx   rbx: %016lx   rcx: %016lx\n", rax, rbx, rcx);
	DBGPRINTF( " rdx: %016lx   rsi: %016lx   rdi: %016lx\n", rdx, rsi, rdi);
	DBGPRINTF( " rbp: %016lx    r8: %016lx    r9: %016lx\n", rbp, r8,  r9);
	DBGPRINTF( " r10: %016lx   r11: %016lx   r12: %016lx\n", r10, r11, r12);
	DBGPRINTF( " r13: %016lx   r14: %016lx   r15: %016lx\n", r13, r14, r15);

	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &sregs) < 0)
	{
	   perror("KVM_GET_SREGS");
		return;
   }
	cr0 = sregs.cr0; cr2 = sregs.cr2; cr3 = sregs.cr3;
	cr4 = sregs.cr4; cr8 = sregs.cr8;

	DBGPRINTF( " cr0: %016lx   cr2: %016lx   cr3: %016lx\n", cr0, cr2, cr3);
	DBGPRINTF( " cr4: %016lx   cr8: %016lx\n", cr4, cr8);
	DBGPRINTF( "\n Segment registers:\n");
	DBGPRINTF(   " ------------------\n");
	DBGPRINTF( " register  selector  base              limit     type  p dpl db s l g avl\n");
	print_segment("cs ", &sregs.cs);
	print_segment("ss ", &sregs.ss);
	print_segment("ds ", &sregs.ds);
	print_segment("es ", &sregs.es);
	print_segment("fs ", &sregs.fs);
	print_segment("gs ", &sregs.gs);
	print_segment("tr ", &sregs.tr);
	print_segment("ldt", &sregs.ldt);
	print_dtable("gdt", &sregs.gdt);
	print_dtable("idt", &sregs.idt);

	DBGPRINTF( "\n APIC:\n");
	DBGPRINTF(   " -----\n");
	DBGPRINTF( " efer: %016llx  apic base: %016llx  \n",
		(__u64) sregs.efer, (__u64) sregs.apic_base );

	DBGPRINTF( "\n Interrupt bitmap:\n");
	DBGPRINTF(   " -----------------\n");
	for (i = 0; i < (KVM_NR_INTERRUPTS + 63) / 64; i++)
		DBGPRINTF( " %016llx", (__u64) sregs.interrupt_bitmap[i]);
	DBGPRINTF( "\n");
}

void fill_segment_descriptor(__u64 *dt, struct kvm_segment *seg)
{
    descriptor_t *dec;
    __u16 index = seg->selector >> 3;
    dec =(descriptor_t *) (dt + index);
    seg->limit = dec->limit_lo|(dec->limit_hi<<16);
    seg->type = dec->type;
    seg->s    = dec->s;
    seg->dpl  = dec->privilege;
    seg->present = dec->present;
    seg->avl = dec->available;
    seg->l  = dec->zero;
    seg->db = dec->bits_32;
    seg->g = dec->granularity;
    seg->base =  dec->base_lo | ((__u64)(dec->base_hi)<<24);
    
}

static void setup_protected_mode(struct vcpu *vcpu, struct kvm_sregs *sregs)
{
	struct kvm_segment seg;
	descriptor_t *gdt;
	__u64 memspace_start = vcpu->kvm->ram_start;
	
	sregs->cr0 |= CR0_PE; /* enter protected mode */
	sregs->gdt.base = gdt_base;
	sregs->gdt.limit = gdt_limit;
	sregs->idt.base = *(__u32 *)( BOL_IDT_BASE_OFFSET + memspace_start);
	sregs->idt.limit = *(__u16 *)( BOL_IDT_LIMIT_OFFSET + memspace_start);
	
	gdt = (descriptor_t *)(gdt_base +memspace_start);
	/* gdt[0] is the null segment */
	
	memset(&seg,0,sizeof(seg));

	seg.selector = 12 << 3;
	fill_segment_descriptor((__u64 *)(gdt), &seg);
	sregs->cs = seg;
    
    
    memset(&seg,0,sizeof(seg));
	seg.selector = 1 << 3;
	fill_segment_descriptor((__u64 *)(gdt), &seg);
	sregs->ds = sregs->es = sregs->fs = sregs->gs
		= sregs->ss = seg;
}

int kvm_reset_vcpu (struct vcpu *vcpu)
{

	switch(vcpu->vcpu_env.vcpu_type)
	{
	case DMX_FAMILY:
		vcpu->sregs = vcpu->vcpu_env.sregs;
		vcpu->sregs.ss = vcpu->vcpu_env.dmx_env.dmx_env_family.ss_reg;
		vcpu->sregs.cs = vcpu->vcpu_env.dmx_env.dmx_env_family.cs_create_first_r;
		break;
		
	case DMX_PROCESS:
		vcpu->sregs = vcpu->vcpu_env.sregs;	
		//vcpu->sregs.ss = vcpu->vcpu_env.dmx_env.dmx_env_process.init_ss_reg;
		//vcpu->sregs.cs = vcpu->vcpu_env.dmx_env.dmx_env_process.init_cs_reg;
		//vcpu->sregs.ds = vcpu->vcpu_env.dmx_env.dmx_env_process.init_ds_reg;
		//vcpu->sregs.es = vcpu->vcpu_env.dmx_env.dmx_env_process.init_es_reg;
		vcpu->sregs.ldt = vcpu->vcpu_env.dmx_env.dmx_env_process.init_ldt_reg;
		vcpu->sregs.ldt.present = 1;
		vcpu->sregs.ldt.type = 2;
		DBGPRINTF( " register  selector  base              limit     type  p dpl db s l g avl\n");
	   print_segment("ldt", &vcpu->sregs.ldt);
		break;
		
	default:
		if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &vcpu->sregs) < 0) {
			perror("KVM_GET_SREGS");
			return -1;
		}
		setup_protected_mode(vcpu, &vcpu->sregs);
		break;
	}
	
	if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &vcpu->sregs) < 0) {
		perror("can not set sregs");
		return -1;
	}
   kvm_cpu__show_registers( vcpu );
   if( vcpu->vcpu_env.vcpu_type == DMX_FAMILY ||
       vcpu->vcpu_env.vcpu_type == DMX_PROCESS )
	   vcpu->regs = vcpu->vcpu_env.regs;
	else
	   memset(&vcpu->regs, 0, sizeof(vcpu->regs));
		
	switch(vcpu->vcpu_env.vcpu_type)
	{
	case DMX_FAMILY:
		vcpu->regs.rsp = vcpu->vcpu_env.dmx_env.dmx_env_family.esp_reg;
		vcpu->regs.rip = vcpu->vcpu_env.dmx_env.dmx_env_family.eip_create_first_r;
		*(__u32*)((char *)vcpu->kvm->ram_start+vcpu->sregs.ss.base+vcpu->regs.rsp+8) = 
		vcpu->vcpu_env.dmx_env.dmx_env_family.family_id; 
		DBGPRINTF( "create first cs %x, eip %llx, base %llx, ss.esp %x %llx, base %llx, fam id %x\n", 
		         vcpu->sregs.cs.selector, 
		         vcpu->regs.rip,
		         vcpu->sregs.cs.base,
		         vcpu->sregs.ss.selector,
		         vcpu->regs.rsp,
		         vcpu->sregs.ss.base,
		         vcpu->vcpu_env.dmx_env.dmx_env_family.family_id );
	   
	   hex_dump_r( (char *)vcpu->kvm->ram_start+vcpu->sregs.cs.base+vcpu->regs.rip, 32);
	   
	   
		break;
		
	case DMX_PROCESS:
	   //TODO: DRE, add process pcb_t in EBX, and wrapper "0xa18" in parameter;
	   // also stack uses process own stack (or signle init_stack? this may cause
	   //cocurrency porblem!! ) 
	   vcpu->regs.rax = vcpu->sregs.ldt.selector;
		vcpu->regs.rsp = vcpu->regs.rsp + 200;
		vcpu->regs.rbp = vcpu->regs.rsp;
		vcpu->regs.rip = 0xa18;//vcpu->vcpu_env.dmx_env.dmx_env_process.init_eip_reg;
		vcpu->regs.rflags = 2;
		DBGPRINTF( "create process cs %x, eip %llx, base %llx, ss.esp %x %llx, base %llx, LDTR sel %x, CR0 %llx, TR %x\n", 
		         vcpu->sregs.cs.selector, 
		         vcpu->regs.rip,
		         vcpu->sregs.cs.base,
		         vcpu->sregs.ss.selector,
		         vcpu->regs.rsp,
		         vcpu->sregs.ss.base,
		         vcpu->sregs.ldt.selector,
		         vcpu->sregs.cr0,
		         vcpu->sregs.tr.selector );

		#if 0
		{
		   /*
		    00000094 0e                                 71         PUSH   cs
          00000095 68 4d 01 00 00                     72         PUSH   0x14d
          0000009a 0f b4 34 24                        73         LFS    ESI,PWORD PTR [ESP]
		   */
	      unsigned char l_tmp_insn[] = { 0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x78,
	         0xBA, 0xF8, 0x03, 0x0, 0x0, 0xB8, 0x30, 0x0, 0x0, 0x0, 0xEE, 0x40, 0xEB,  0xFC};
	      memcpy( (char *)vcpu->kvm->ram_start+vcpu->sregs.cs.base+vcpu->regs.rip, l_tmp_insn, sizeof(l_tmp_insn));
	   }
	   #endif
	   
		hex_dump_r( (char *)vcpu->kvm->ram_start+vcpu->sregs.cs.base+vcpu->regs.rip, 32);    
		break;
		
	default:
		/* Clear all FLAGS bits, except bit 1 which is always set. */
		vcpu->regs.rflags = 2;
		vcpu->regs.rip = 0x28;
		vcpu->regs.rsp = 0x07BFF;
		vcpu->regs.rbp= 0x00500;
		break;
	}	
    
	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &vcpu->regs) < 0) {
		perror("KVM_SET_REGS");
		return -1;
	}
	return 0;
}

#else

#define CR0_PE 1

void fill_segment_descriptor(__u64 *dt, struct kvm_segment *seg)
{
	__u16 index = seg->selector >> 3;
	__u32 limit = seg->g ? seg->limit >> 12 : seg->limit;
	dt[index] = (limit & 0xffff) /* Limit bits 0:15 */
		| (seg->base & 0xffffff) << 16 /* Base bits 0:23 */
		| (__u64)seg->type << 40
		| (__u64)seg->s << 44 /* system or code/data */
		| (__u64)seg->dpl << 45 /* Privilege level */
		| (__u64)seg->present << 47
		| (limit & 0xf0000ULL) << 48 /* Limit bits 16:19 */
		| (__u64)seg->avl << 52 /* Available for system software */
		| (__u64)seg->l << 53 /* 64-bit code segment */
		| (__u64)seg->db << 54 /* 16/32-bit segment */
		| (__u64)seg->g << 55 /* 4KB granularity */
		| (seg->base & 0xff000000ULL) << 56; /* Base bits 24:31 */
}

static void setup_protected_mode(struct vcpu *vcpu, struct kvm_sregs *sregs)
{
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.present = 1,
		.dpl = 0,
		.db = 1,
		.s = 1, /* Code/data */
		.l = 0,
		.g = 1, /* 4KB granularity */
	};
	__u64 *gdt;

	sregs->cr0 |= CR0_PE; /* enter protected mode */
	sregs->gdt.base = 0x1000;
	sregs->gdt.limit = 3 * 8 - 1;

	gdt = (void *)(vcpu->kvm->ram_start + sregs->gdt.base);
	/* gdt[0] is the null segment */

	seg.type = 11; /* Code: execute, read, accessed */
	seg.selector = 1 << 3;
	fill_segment_descriptor(gdt, &seg);
	sregs->cs = seg;

	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;
	fill_segment_descriptor(gdt, &seg);
	sregs->ds = sregs->es = sregs->fs = sregs->gs
		= sregs->ss = seg;
}

int kvm_reset_vcpu (struct vcpu *vcpu) {
	if (ioctl(vcpu->vcpu_fd, KVM_GET_SREGS, &(vcpu->sregs)) < 0) {
		perror("can not get sregs\n");
		return -1;
	}

	setup_protected_mode(vcpu, &vcpu->sregs);

	if (ioctl(vcpu->vcpu_fd, KVM_SET_SREGS, &vcpu->sregs) < 0) {
		perror("can not set sregs");
		return -1;
	}
	
	memset(&vcpu->regs, 0, sizeof(vcpu->regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	vcpu->regs.rflags = 2;
	vcpu->regs.rip = 0;

	if (ioctl(vcpu->vcpu_fd, KVM_SET_REGS, &(vcpu->regs)) < 0) {
		perror("KVM SET REGS\n");
		return -1;
	}
	
	return 0;
}
#endif

static void sigquitproc(int signum, siginfo_t *info, void *__ctx)
{
    signum = signum;
    do_exit = 1;	
}

void *kvm_cpu_thread(void *data) {
    struct sigaction sact;
	struct vcpu *vcpu = (struct vcpu *)data;
	int ret = 0;
    __u64 u = 1;
	char name[16];
	
    sact.sa_sigaction = sigquitproc;
    sact.sa_flags     = SA_SIGINFO;
    sigaction(SIGQUIT, &sact, NULL);

	sprintf(name, "vcpu-%d", vcpu->vcpu_id);
	prctl(PR_SET_NAME, name);
	
	kvm_reset_vcpu(vcpu);

	printf("vcpu[%d] start run\n",vcpu->vcpu_id);	
	vcpu->vcpu_state = VCPU_RUN;
	hex_dump_r( (char *)vcpu->kvm->ram_start+vcpu->sregs.cs.base+vcpu->regs.rip, 32);
	kvm_cpu__show_registers( vcpu );
	while (!do_exit&& vcpu->vcpu_state == VCPU_RUN) {

		ret = ioctl(vcpu->vcpu_fd, KVM_RUN, 0);
	
		if (ret < 0) {
			fprintf(stderr, "KVM_RUN failed\n");
			return NULL;
		}

		switch (vcpu->kvm_run->exit_reason) {
		case KVM_EXIT_UNKNOWN:
			printf("KVM_EXIT_UNKNOWN\n");
			break;
		case KVM_EXIT_DEBUG:
			printf("KVM_EXIT_DEBUG\n");
			break;
			
		case KVM_EXIT_HLT:
			printf("KVM_EXIT_HLT\n");
			break;
			
		case KVM_EXIT_IO:
		
         if( vcpu->kvm_run->io.direction == KVM_EXIT_IO_OUT && 
             vcpu->kvm_run->io.size == 1 && 
             vcpu->kvm_run->io.port == 0x3f8 && 
             vcpu->kvm_run->io.count == 1 )
            putchar(*((char *)(vcpu->kvm_run) + vcpu->kvm_run->io.data_offset));

			if((vcpu->kvm_run->io.port == 0xFFFF)) {
			   kvm_handle_hostcall(vcpu);
			}
			
#ifdef TEST

			if((vcpu->kvm_run->io.port == 0xFF)&&(*(int *)((char *)(vcpu->kvm_run) + vcpu->kvm_run->io.data_offset)==1)) {
			kvm_handle_hostcall(vcpu);
			}
		
			if((vcpu->kvm_run->io.port == 0xFF)&&(*(int *)((char *)(vcpu->kvm_run) + vcpu->kvm_run->io.data_offset)==2)) {
			//kvm_handle_hostcall(vcpu);
			}

			printf("vcpu[%d] out port: %d, data: %d\n", vcpu->vcpu_id,
				vcpu->kvm_run->io.port,  
				*(int *)((char *)(vcpu->kvm_run) + vcpu->kvm_run->io.data_offset)
				);
			sleep(1);
#endif			
			break;

		case KVM_EXIT_MMIO:
			printf("KVM_EXIT_MMIO\n");
			break;
		case KVM_EXIT_INTR:
			printf("KVM_EXIT_INTR\n");
			break;
		case KVM_EXIT_SHUTDOWN:
			printf("KVM_EXIT_SHUTDOWN\n");
			goto exit_kvm;
			break;
		default:
			printf("KVM PANIC\n");
			goto exit_kvm;
		}
	}

exit_kvm:
   
	printf("vcpu[%d] exit\n", vcpu->vcpu_id);
	
   write(vcpu->kvm->event_fd, &u, sizeof(__u64));
	
	return NULL;
}

