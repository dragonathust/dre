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
#include <syslog.h>

#include "dre.h"
#include "file.h"

static __inline__ unsigned long long rdtsc(void)
{
  unsigned hi, lo;
  __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
  return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

void handle_syslog(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
   linux_syslog_t *syslog_args = (linux_syslog_t *)(mem+arg);
   char *log_buf = syslog_args->args.log_buf ? (char*)(mem+syslog_args->args.log_buf) : NULL;
  
   
   DBGPRINTF("%s [log buf %s log_buf addr 0x%x]\n",__FUNCTION__,
             log_buf, syslog_args->args.log_buf);
   
   DBGPRINTF( "%s\n", __FUNCTION__ );
   DBGPRINTF( "%s\n", log_buf );
   syslog(LOG_DEBUG,"%s\n", log_buf );
   
   syslog_args->rets.ret = 0;
}

void handle_dre_halt(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
   linux_halt_t *halt_args = (linux_halt_t *)(mem+arg);
   
   //TODO: add global vars setting here
   DBGPRINTF("%s [halt reason 0x%x]\n",__FUNCTION__,
             halt_args->args.halt_reason);
   vcpu->vcpu_state = VCPU_USR_STOP;
   halt_args->rets.ret = 0;  
}


void handle_delay(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
   struct timeval delay;
   linux_delay_param_t *delay_args = (linux_delay_param_t *)(mem+arg);
   
   delay.tv_sec = delay_args->args.time_limit / 100;
   delay.tv_usec = ( delay_args->args.time_limit%100 ) * 10 * 1000;
   
   select(0, NULL, NULL, NULL, &delay);

   DBGPRINTF("%s [delay %d ms]\n",__FUNCTION__,
             delay_args->args.time_limit*10 );
   
   delay_args->rets.ret = 0;  
}

#define   CLOCK_RATIO_TOT_SECONDS    8 // 8s

void handle_clock_ratio(struct vcpu *vcpu, char *mem,hwaddr32 arg)
{
   struct timeval delay;
   unsigned long long start_ticks, end_ticks;
   linux_clock_ratio_t *clock_ratio_args = (linux_clock_ratio_t *)(mem+arg);
   
   delay.tv_sec = CLOCK_RATIO_TOT_SECONDS;    //8 seconds
   delay.tv_usec = 0;
   
   do
   {
      start_ticks = rdtsc();
      select(0, NULL, NULL, NULL, &delay);
      end_ticks = rdtsc();
   }while( start_ticks >= end_ticks );
   //0.8us * 1000 * 1000 * 10 = 8 seconds
   clock_ratio_args->rets.clock_ratio = (end_ticks-start_ticks)/(1000*1000*10); 
   DBGPRINTF( "%s [clock ratio %d ]\n",__FUNCTION__,
              clock_ratio_args->rets.clock_ratio );
}

