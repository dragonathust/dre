#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "shm.h"

#define UTIL_SHM_FILE_MODE__C (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH)

typedef struct _Sutil_shm_t {
  int fd;
  int size;
  void *mem_ptr;
} util_shm_t;

#define REAL_SIZE(size) (size)

#define MALLOC(a) (a *)malloc(sizeof (a))
#define FREE(a)   { void *p = (*a); free(p); *a = NULL; }


static void make_shm_handle(util_shm_t *real_shm, char *mem, int size, int fd)
{
  real_shm->size = size;
  real_shm->mem_ptr = mem;
  real_shm->fd = fd;
}

dmx_error_t
util_shm_create_r
(
  char *name,
  size_t size
)
{
  int fd;
  char *mem;
  util_shm_t real_shm;
  //dmx_error_t rc;
  
  if(name == NULL) {
    return NULL_POINTER_TO_PARAM_EC;
  }

  /* allow write access for root group */
  umask(002);

  fd = shm_open(name, O_RDWR, UTIL_SHM_FILE_MODE__C );
  if (fd < 0) {
    /* create */
    close(fd);
    fd = shm_open(name, O_RDWR | O_CREAT | O_EXCL, UTIL_SHM_FILE_MODE__C);
    if (fd < 0){
      return FILE_CREATE_FAILED_EC;
    }
  } else {
      close(fd);
      return FILE_ALREADY_EXIST_EC;
  }

  if (ftruncate(fd, REAL_SIZE(size)) < 0) {
    close(fd);
    return FILE_RESIZE_PREVENTED_EC;
  }

  mem = mmap(NULL, REAL_SIZE(size), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mem < 0) {
    close(fd);
    return MEMORY_ALLOC_ERROR_EC;
  }
  
  make_shm_handle(&real_shm, mem, size, fd);
/*
  rc = util_shm_mem_clear_r(&real_shm);
  if (rc) {
    munmap(mem, REAL_SIZE(size));
    close(fd);
    return rc;
  }
*/
  if (munmap(mem, REAL_SIZE(size)) < 0) {
    return MEMORY_ALLOC_ERROR_EC;
  }
  
  close(fd);

  return SUCCESS_EC;
}



dmx_error_t
util_shm_remove_r
(
  char *name
)
{
  if(name == NULL) {
    return NULL_POINTER_TO_PARAM_EC;
  }

  if (shm_unlink(name) < 0) {
    return -1;
  }

  return SUCCESS_EC;
}



dmx_error_t
util_shm_open_r
(
  util_shm_ptr_t *handle,
  char *name,
  int mode,
  void **mem,
  size_t *size
)
{
  int fd;
  char *tmp_ptr;
  util_shm_t *real_shm;
  int mmap_mode = 0;
  struct stat sbuf;

  if (handle == NULL) {
    return POINTER_TO_NULL_EC;
  }

  /* need read-write access for the read-write locking! */
  //mode = O_RDWR;
  //mmap_mode = PROT_READ | PROT_WRITE;

  if(mode == O_RDONLY) {
    mmap_mode = PROT_READ;
  }
  else if(mode == O_RDWR) {
    mmap_mode = PROT_READ | PROT_WRITE;
  }
  else {
    return INCORRECT_ACCESS_MODE_EC;
  }

  if (name == NULL) {
    return POINTER_TO_NULL_EC;
  }

  if (mem == NULL) {
    return POINTER_TO_NULL_EC;
  }

  if (size == NULL) {
    return POINTER_TO_NULL_EC;
  }

  fd = shm_open(name, mode, UTIL_SHM_FILE_MODE__C);
  if (fd < 0) {
    if (errno == EACCES) {
      return POSIX_EACCES_EC;
    }

    /* shm doesn't exist */
    return NO_SUCH_FILE_EC;
  }
  
  if(fstat(fd, &sbuf) < 0) {
    /* stat failed */
    close(fd);
    return NO_SUCH_FILE_EC;
  }

  tmp_ptr = mmap(NULL, sbuf.st_size, mmap_mode, MAP_SHARED, fd, 0);
  if (tmp_ptr < 0) {
    close(fd);
    return MEMORY_ALLOC_ERROR_EC;
  }

  real_shm = MALLOC(util_shm_t);
  if (!real_shm) {
    close(fd);
    munmap(tmp_ptr, sbuf.st_size);
    return MEMORY_ALLOC_ERROR_EC;
  }

  make_shm_handle(real_shm, tmp_ptr, sbuf.st_size, fd);

  *handle = real_shm;
  *mem = tmp_ptr;
  *size = sbuf.st_size;

  return SUCCESS_EC;
}



dmx_error_t
util_shm_close_r
(
  util_shm_ptr_t *handle
)
{
  util_shm_t *real_shm;
  char *tmp_ptr;
  size_t tmp_size;

  if (handle == NULL) {
    return POINTER_TO_NULL_EC;
  }

  real_shm = *handle;
  if (real_shm == NULL) {
    return INCORRECT_FILE_HANDLE_EC;
  }

  tmp_ptr = (char *)real_shm->mem_ptr;
  tmp_size = REAL_SIZE(real_shm->size);

  if (munmap(tmp_ptr, tmp_size) < 0) {
    /* if we end up here, the handle contained invalid data (and is invalid) */
    return INCORRECT_FILE_HANDLE_EC;
  }
  
  close(real_shm->fd);

  FREE(&real_shm);

  *handle = NULL;

  return SUCCESS_EC;
}

/*
dmx_error_t
util_shm_mem_clear_r
(
  util_shm_ptr_t handle
)
{
  util_shm_t *real_shm;
  sigset_t old_mask;
  dmx_error_t rc;

  if (!handle) {
    return INCORRECT_FILE_HANDLE_EC;
  }

  real_shm = (util_shm_t *)handle;
  if (!(char *)real_shm->mem_ptr) {
    return POINTER_TO_NULL_EC;
  }

  rc = util_signals_block_r(NULL, &old_mask);
  if (rc != SUCCESS_EC) {
    return rc;
  }

  rc = util_shm_write_lock_r(handle);
  if (rc != SUCCESS_EC) {
    util_signals_unblock_r(&old_mask);
    return rc;
  }

  memset((char *)real_shm->mem_ptr, 0, real_shm->size);

  rc = util_shm_write_unlock_r(handle);
  if (rc != SUCCESS_EC) {
    util_signals_unblock_r(&old_mask);
    return rc;
  }

  rc = util_signals_unblock_r(&old_mask);
  if (rc != SUCCESS_EC) {
    return rc;
  }

  return SUCCESS_EC;
}
*/


dmx_error_t
util_shm_read_lock_r
(
  util_shm_ptr_t handle
)
{
  if (!handle) {
    return INCORRECT_FILE_HANDLE_EC;
  }

  if(flock(handle->fd, LOCK_SH) < 0) {
    return -1;
  }
  
  return SUCCESS_EC;
}



dmx_error_t
util_shm_read_unlock_r
(
  util_shm_ptr_t handle
)
{
  if (!handle) {
    return INCORRECT_FILE_HANDLE_EC;
  }

  if(flock(handle->fd, LOCK_UN) < 0) {
    return -1;
  }
  
  return SUCCESS_EC;
}



dmx_error_t
util_shm_write_lock_r
(
  util_shm_ptr_t handle
)
{
  if (!handle) {
    return INCORRECT_FILE_HANDLE_EC;
  }

  if(flock(handle->fd, LOCK_EX) < 0) {
    return -1;
  }
  
  return SUCCESS_EC;
}



dmx_error_t
util_shm_write_unlock_r
(
  util_shm_ptr_t handle
)
{
  if (!handle) {
    return INCORRECT_FILE_HANDLE_EC;
  }

  if(flock(handle->fd, LOCK_UN) < 0) {
    return -1;
  }
  
  return SUCCESS_EC;
}



/* EOF */
