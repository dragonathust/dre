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

#include "dre.h"
#include "kvm.h"

int do_exit = 0;

/* ctrl-c signal handler */
void sigintproc(int signum)
{
signum = signum;
do_exit = 1;
}

/* TERM signal handler */
void sigtermproc(int signum)
{
signum = signum;
do_exit = 1;
}

int daemon_main(void) {
	vcpu_env_t vcpu_env;
	
	/* setup signal handlers */
	signal(SIGINT, sigintproc);
	signal(SIGTERM, sigtermproc);
	
	vcpu_env.vcpu_type = DMX_NONE;
	return kvm_main(&vcpu_env);	

}


int main(int argc, char *argv[])
{
	daemon_main();

	return 0;
}
