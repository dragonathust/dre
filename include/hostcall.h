#ifndef  __HOSTCALL_H__
#define __HOSTCALL_H__

#ifdef  __GNUC__
typedef hwaddr32 DMX_POINTER;
#else
typedef unsigned int DMX_POINTER;

#ifdef  __IN_POSIX
typedef  unsigned int      dword;
typedef  unsigned short    word;
typedef  unsigned char     byte;
typedef  unsigned long long qword;
#endif

typedef struct  __tagkvm_segment{
   qword base;
   dword limit;
   word  selector;
   byte  type;
   byte  present, dpl, db, s, l, g, avl;
   byte  unusable;
   byte  padding;
} dmx_kvm_segment;
#endif

#define T                   1
#define F                   0



typedef union __taglinux_socket_param__t
{
   struct {
      int  socket_family;
      int  socket_type;
      int  protocol;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_socket_param__t;

typedef union __taglinux_read_write_param__t
{
   struct {
      int fd;
      DMX_POINTER buf;
      unsigned int count;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_read_write_param__t;

typedef union _taglinux_listen_param_t
{
   struct {
      int fd;
      int backlog;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_listen_param_t;

/*TODO: struct sockaddr size is same with linux*/
typedef union _taglinux_bind_param_t
{
   struct {
      int fd;
      DMX_POINTER buf;
      int len;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_bind_param_t;

/* int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);, socklen_t is 4 bytes in Linux*/
typedef union _taglinux_accept_param_t
{
   struct {
      int fd;
      DMX_POINTER buf_sock;
      DMX_POINTER buf_len;
   }args;
   struct {
      int ret;
   int _errno;
  }rets;
}linux_accept_param_t;

typedef union _taglinux_open_param_t
{
   struct {
      DMX_POINTER path;
      int flag;
      int mode;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_open_param_t;

typedef union _taglinux_close_param_t
{
   struct{
      int fd;
      int ret;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_close_param_t;


/*int select(int nfds, fd_set *readfds, fd_set *writefds,
                  fd_set *exceptfds, struct timeval *timeout);*/
typedef union _taglinux_select_param_t
{
   struct {
      int nd;
      DMX_POINTER in;
      DMX_POINTER out;
      DMX_POINTER ex;
      DMX_POINTER time;
   }args;
   
   struct {
      int ret;
   int _errno;
   }rets;
}linux_select_param_t;

typedef union _taglinux_connect_param_t
{
   struct{
      int fd;
      DMX_POINTER name;
      int namelen;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_connect_param_t;


typedef union _taglinux_recv_param_t
{
   struct{
      int fd;
      DMX_POINTER buf;
      int len;
      int flags;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_recv_param_t;


typedef union _taglinux_recvfrm_param_t
{
   struct{
      int fd;
      DMX_POINTER buf;
      int len;
      int flags;
      DMX_POINTER from_addr;
      DMX_POINTER from_len;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_recvfrm_param_t;

typedef union _taglinux_recvmsg_param_t
{
   struct{
      int fd;
      DMX_POINTER msghdr;
      int flags;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_recvmsg_param_t;
typedef union _taglinux_send_param_t
{
   struct{
      int fd;
      DMX_POINTER buf;
      int len;
      int flags;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_send_param_t;




typedef union _taglinux_sendto_param_t
{
   struct{
      int fd;
      DMX_POINTER buf;
      int len;
      int flags;
      DMX_POINTER to;
      int tolen;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_sendto_param_t;


typedef union _taglinux_sendmsg_param_t
{
   struct{
      int fd;
      DMX_POINTER buf;
      int flags;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_sendmsg_param_t;


typedef union _taglinux_setsockopt_param_t
{
   struct{
      int fd;
      int level;
      int name;
      DMX_POINTER val;
      int valsize;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_setsockopt_param_t;


typedef union _taglinux_getsockopt_param_t
{
   struct{
      int fd;
      int level;
      int name;
      DMX_POINTER val;
      DMX_POINTER avalsize;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_getsockopt_param_t;

typedef union _taglinux_dmx_env_t
{
   struct{
      int    gdt_base;     //not used
      int    gdt_limit;    //not used
      dmx_kvm_segment    ss_reg;
      int    esp_reg;
      dmx_kvm_segment    cs_create_first_r;
      int    eip_create_first_r;
      int    family_id;
   }dmx_env_family;

   struct{
      dmx_kvm_segment  init_ss_reg;
      int              init_esp_reg;
      dmx_kvm_segment  init_cs_reg;
      int              init_eip_reg;
      dmx_kvm_segment  init_ds_reg;
      dmx_kvm_segment  init_es_reg;
      dmx_kvm_segment  init_ldt_reg;
   }dmx_env_process;

}linux_dmx_env_t;

typedef union _taglinux_dmx_create_family
{
   linux_dmx_env_t args;
   struct {
      int ret;
   }rets;
}linux_dmx_create_family_t;

typedef union _taglinux_dmx_create_process
{
   linux_dmx_env_t args;
   struct {
      int ret;
   }rets;
}linux_dmx_create_process_t;

typedef union _taglinux_halt
{
   struct{
      int    halt_reason;
   }args;
   struct {
      int ret;
   }rets;
}linux_halt_t;

typedef union _taglinux_syslog
{
   struct{
      DMX_POINTER   log_buf;
   }args;
   struct {
      int ret;
   }rets;
}linux_syslog_t;

typedef union _taglinux_access_param_t
{
   struct{
      DMX_POINTER path;
      int  flags;
   }args;
   struct {
      int ret;
   int _errno;
   }rets;
}linux_access_param_t;

typedef union _taglinux_mkfifo_param_t
{
    struct{
      DMX_POINTER path;
      int  mode;
    }args;
   struct {
    int ret;
    int _errno;
   }rets;

}linux_mkfifo_param_t;

typedef union _taglinux_delay_param_t
{
    struct{
      unsigned int  time_limit;
    }args;
   struct {
    int ret;
   }rets;

}linux_delay_param_t;

typedef union _taglinux_clock_ratio_t
{
    struct{
      unsigned int  ticks;    //0.8us default, not used yet.
    }args;
   struct {
    unsigned int clock_ratio;
   }rets;

}linux_clock_ratio_t;


int near linux_read__r( int fd, char * buf, unsigned int count );
int near linux_socket__r( int socket_family, int socket_type, int protocol );
int near linux_open__r(void *path, int uflag, int umode);
int near linux_close__r(int ufd);
int near linux_listen__r(int ufd, int ubacklog);
int near linux_bind__r(int ufd, void *sock_buf, int ulen);
int near linux_accept__r(int ufd, void *sock_buf, void *sock_len );
int near linux_select__r(int und, void *uin, void *uout, void *uex, void *utime);
int near linux_connect__r(int ufd, void *uname, int unamelen);
int near linux_recv__r(int ufd, void *ubf, size_t ulen, int uflags);
int near linux_recvfrom__r(int ufd, void *ubuf, size_t ulen, int uflags, void *ufrom_addr, void *ufrom_len);
int near linux_recvmsg__r(int ufd, void *umsghdr, int uflags);
int near linux_send__r(int ufd, void *buf, int ulen, int uflags);
int near linux_sendto__r(int ufd, void *buf, int ulen, int uflags, void *to, int utolen);
int near linux_sendmsg__r(int ufd, void *buf, int uflags);
int near linux_setsockopt__r(int ufd, int ulevel, int uname, void *uval, int uvalsize);
int near linux_getsockopt__r(int ufd, int ulevel, int uname, void *uval, void *uavalsize);
int near linux_write__r(int ufd, void *buf, size_t ucount);

int near linux_dmx_create_family__r( unsigned short  family_id );
int near linux_dmx_create_process__r( void *own_pcb );
int near linux_halt__r( int reason );
int near linux_syslog__r( void * log_buf );
int near linux_log__r( char * fmt, ... );
int near linux_delay__r( unsigned int time_limit );

int near linux_access__r(void *path, int flags);
int near linux_mkfifo__r(void *path, int mode);
void * near linux_malloc__r(unsigned int size);
void near linux_free__r(void *ptr);
unsigned int near linux_clock_ratio__r( unsigned int ticks );



void near test_read_host_file( void );
#endif
