#include <unistd.h>
#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <linux/kvm.h>
#include <fcntl.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>

#include "dre.h"
#include "memory.h"

#ifndef TEST

#define MEM_BOLERO_AREA_OFFSET               0x4000000
#define BOL_VARIABLE_AREA_LEN                0xFB000
#define BOL_SMALLEST_ALLOCATED_ADDR_OFFSET   0x04008884
#define BOL_MEMMORY_TOP_OFFSET               0x0400888C
#define BOL_GDT_BASE_OFFSET                  0x0400880E
#define BOL_GDT_LIMIT_OFFSET                  0x0400880C


#define get_page(x) ((unsigned long)(x) & ~(page_mask))
#define get_offs(x) ((unsigned long)(x) & (page_mask))
#define map_length(offs, sz) get_page(get_offs(offs) + (sz) + page_size - 1)

unsigned long page_size = 0, page_mask;
#define MEM_FILE "/dev/mem"

extern __u64 gdt_base;
extern unsigned int gdt_limit;


int open_mem_file(void)
{
    int mem_fd = -1;
    mem_fd = open(MEM_FILE, O_RDONLY);
    
    if(mem_fd < 0) {
      printf( "cannot open %s errno = %d", MEM_FILE,errno);
    }
    return mem_fd;     
}

int close_mem_file(int mem_fd)
{ 
    int fd = -1;
    
    fd = close(mem_fd);  
    if(fd != 0)
        printf(" close file failed errno=%d", errno);
    return fd;
}

void* do_mmap(unsigned long addr, unsigned long len, int mem_fd)
{
  void *p;
  unsigned long real_addr;
  
  if(page_size == 0) {
    page_size = getpagesize();
    page_mask = page_size - 1;

    printf("Page size = %08lx, page mask = %08lx\n",
      page_size, page_mask);
  }
  
  real_addr = get_page(addr);
  len += get_offs(addr);
  
  p = mmap(0, len, PROT_READ, MAP_SHARED, mem_fd, real_addr);
  
  if(p == MAP_FAILED) {
      printf("mmap failed: errno=%d", errno);
      return NULL;
  }

  p += get_offs(addr);
  
  return p;
}

void do_munmap(void* p, unsigned long len)
{
  void* real_p = (void*)get_page(p);
  int r;
  
  r = munmap(real_p, len + get_offs(p));

  if(r < 0) {
      printf("munmap failed: errno=%d", errno);
  }

  page_size = 0;
}


/*****************************************************************************
 *  FUNCTION: bolvar_get_bolero_variable_r
 *****************************************************************************
 *  Get a BOLERO variable from memory.
 *
 *  EXTERNAL VARIABLE REFERENCES:
 *    IN:       addr        address of variable
 *    IN:       size        size of variable
 *    OUT:      value       value of variable
 *
 *  RETURN VALUE:int        status of operation
 *
 *****************************************************************************/
int bolvar_get_bolero_variable_r(unsigned int addr, unsigned int size, unsigned int *value)
{
	int fd;
	unsigned int page_size, page_mask;
	unsigned int real_page, real_offset;
	void * p;

	/* calculate mmap address */
	page_size = getpagesize();
	page_mask = page_size - 1;
	real_offset = addr & page_mask;
	real_page = addr - real_offset;

	/* open memory and mmap */

	fd = open("/dev/mem", O_RDWR);

	if(fd < 0) {
		return 1;
	}

	/* get two pages, in case the address overlaps with a page boundary */
	p = mmap(0, 2*page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		fd, real_page);

	if(p == MAP_FAILED) {
		close(fd);
		return 1;
	}

	switch(size) {
	case 1:
		*value = *(unsigned char*)&((char*)p)[real_offset];
		break;
	case 2:
		*value = *(unsigned short*)&((char*)p)[real_offset];
		break;
	case 4:
		*value = *(unsigned int*)&((char*)p)[real_offset];
		break;
	default:
    	munmap(p, page_size);
	    close(fd);
		return 1;
	}

	/* cleanup */
	munmap(p, page_size);
	close(fd);

	return 0;
}

int preload_memory(struct kvm *kvm)
{
    void *p;
    int mem_fd = -1;
    __u64 length = 0;
    char *ram= NULL;
    unsigned int value = 0;
    __u64 smallest_allocated_addr = 0;
    __u64 memmory_top = 0;    

   if( bolvar_get_bolero_variable_r(0x4000810,4,&value)){
            printf("read gdt base error: %s\n", strerror(errno));
        return errno;
    }
  
    printf("read gdt base value: %x\n", value);

    if( bolvar_get_bolero_variable_r(BOL_GDT_BASE_OFFSET,4,&value)){
        return errno;
    }
    gdt_base = value;
    printf("read gdt base: %llx\n", gdt_base);
        
    if( bolvar_get_bolero_variable_r(BOL_GDT_LIMIT_OFFSET,2,&value)){
        return errno;
    }
    gdt_limit = value;
    printf("read gdt limit: %4x\n", gdt_limit);
       
    if( bolvar_get_bolero_variable_r(BOL_SMALLEST_ALLOCATED_ADDR_OFFSET,4,&value)){
        return errno;
    }
    smallest_allocated_addr = value;
    printf("read smallest_allocated_addr: %llx\n", smallest_allocated_addr);
    if(bolvar_get_bolero_variable_r(BOL_MEMMORY_TOP_OFFSET,4,&value))
       return errno;   
    memmory_top = value;   
    printf("read memmory_top: %llx\n", memmory_top);
    length = memmory_top - smallest_allocated_addr;
   
    if(memmory_top > kvm->ram_size )
    {
      printf( "small KVM memmory");  
      return -1;
    }
    mem_fd = open_mem_file();
    if( mem_fd < 0){
       printf( "open memmory file failed %d",mem_fd);   
       return mem_fd;
    }     
    /* read next module address */
    p = do_mmap(smallest_allocated_addr, length,mem_fd);
    if(!p) {
      printf( "preload_memory failed, invalid mmap (1)");
      return errno;
    }    
    ram = (char *)(kvm->ram_start + smallest_allocated_addr);
    memcpy(ram, p, length);
    do_munmap(p, length);


    p = do_mmap(MEM_BOLERO_AREA_OFFSET, BOL_VARIABLE_AREA_LEN,mem_fd);
    if(!p) {
      printf( "preload_memory failed, invalid mmap (1)");
      return errno;
    }    
    ram = (char *)(kvm->ram_start + MEM_BOLERO_AREA_OFFSET);
    memcpy(ram, p, BOL_VARIABLE_AREA_LEN);
    do_munmap(p, BOL_VARIABLE_AREA_LEN);     
    
    printf( "MEM_BOLERO_AREA GDT  %llx\n",*((__u64 *)(kvm->ram_start + gdt_base)));
    printf( "MEM_BOLERO_AREA gdt %llx\n",*((__u64 *)(kvm->ram_start + gdt_base + 8)));
    
    
    if(close_mem_file(mem_fd) != 0)
    {
       printf( "close memmory file failed %d",mem_fd);   
       return errno;
    }
    
    return 0;
}

#else
#define BINARY_FILE "test.bin"

int preload_memory(struct kvm *kvm) {
    int fd = open(BINARY_FILE, O_RDONLY);

    if (fd < 0) {
        fprintf(stderr, "can not open binary file\n");
        return -1;
    }

    int ret = 0;
    char *p = (char *)kvm->ram_start;

    while(1) {
        ret = read(fd, p, 4096);
        if (ret <= 0) {
            break;
        }
        printf("read size: %d\n", ret);
        p += ret;
    }
	return 0;
}
#endif


int kvm_memory_init(struct kvm *kvm) {
    
    int status;
    
    status= preload_memory(kvm);
    if( status != 0){
        printf("prepare memory failed status: %d",status);
        return status;
    }
    return status;
}
