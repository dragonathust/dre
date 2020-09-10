#ifndef __SHM_H__
#define __SHM_H__

typedef int dmx_error_t;

enum {
SUCCESS_EC = 0,
NULL_POINTER_TO_PARAM_EC,
FILE_CREATE_FAILED_EC,
FILE_ALREADY_EXIST_EC,
FILE_RESIZE_PREVENTED_EC,
MEMORY_ALLOC_ERROR_EC,
POINTER_TO_NULL_EC,
INCORRECT_ACCESS_MODE_EC,
POSIX_EACCES_EC,
NO_SUCH_FILE_EC,
INCORRECT_FILE_HANDLE_EC,
};

/** Shared memory handle */
typedef struct _Sutil_shm_t * util_shm_ptr_t;


/**
 * Create a shared memory.
 *
 * @param[in] name  Name of the shared memory.
 * @param[in] size  Size of the shared memory.
 *
 * @return  SUCCESS_EC
 * @return  FILE_ALREADY_EXIST_EC
 * @return  FILE_CREATE_FAILED_EC
 * @return  FILE_RESIZE_PREVENTED_EC
 * @return  MEMORY_ALLOC_ERROR_EC, mmap() or munmap() failed.
 * @return  NULL_POINTER_TO_PARAM_EC, if name was NULL.
 */
dmx_error_t
util_shm_create_r
(
    char   *name,
    size_t  size
);


/**
 * Remove a shared memory.
 *
 * @param[in] name  Name of shared memory.
 *
 * @return  SUCCESS_EC
 * @return  POSIX_*_EC, matching POSIX errno.
 * @return  LINUX_*_EC, matching Linux errno.
 * @return  NULL_POINTER_TO_PARAM_EC, if name was NULL.
 */
dmx_error_t
util_shm_remove_r
(
    char *name
);


/**
 * Open a shared memory.
 *
 * @param[out] handle  Shared memory handle.
 * @param[in]  name    Name of shared memory.
 * @param[in]  mode    Open file mode (O_RDONLY or O_RDWR).
 * @param[out] ptr     Pointer to shared memory.
 * @param[out] size    Size of shared memory.
 *
 * @return  SUCCESS_EC
 * @return  POINTER_TO_NULL_EC, illegal null pointer argument.
 * @return  INCORRECT_ACCESS_MODE_EC, mode argument was invalid.
 * @return  POSIX_EACCES_EC, requested access mode not allowed.
 * @return  NO_SUCH_FILE_EC
 * @return  MEMORY_ALLOC_ERROR_EC
 * @return  POSIX_*_EC, matching POSIX errno.
 * @return  LINUX_*_EC, matching Linux errno.
 */
dmx_error_t
util_shm_open_r
(
    util_shm_ptr_t  *handle,
    char            *name,
    int              mode,
    void           **ptr,
    size_t          *size
);


/**
 * Close a shared memory.
 *
 * @param[in,out] handle  Shared memory handle.
 *
 * @return  POINTER_TO_NULL_EC
 * @return  INCORRECT_FILE_HANDLE_EC
 * @return  POSIX_*_EC, matching POSIX errno.
 * @return  LINUX_*_EC, matching Linux errno.
 *
 * @note  Handle is zeroed on success.
 */

dmx_error_t
util_shm_close_r
(
    util_shm_ptr_t *handle
);


/**
 *  Initialize shared memory to zero.
 *
 * @param[in] handle  Shared memory handle.
 *
 * @return  INCORRECT_FILE_HANDLE_EC
 * @return  POINTER_TO_NULL_EC
 */
dmx_error_t
util_shm_mem_clear_r
(
    util_shm_ptr_t handle
);


/**
 * Wait for read access in a semaphore.
 *
 * @param[in] handle  Shared memory handle.
 *
 * @return  SUCCESS_EC
 * @return  INCORRECT_FILE_HANDLE_EC
 * @return  POSIX_*_EC, matching POSIX errno.
 * @return  LINUX_*_EC, matching Linux errno.
 *
 * @note  It may be a good idea to block signals first with
 *        util_signals_block_r().
 */
dmx_error_t
util_shm_read_lock_r
(
    util_shm_ptr_t handle
);


/**
 * Release the read lock.
 *
 * @param[in] handle  Shared memory handle.
 *
 * @return  SUCCESS_EC
 * @return  INCORRECT_FILE_HANDLE_EC
 * @return  POSIX_*_EC, matching POSIX errno.
 * @return  LINUX_*_EC, matching Linux errno.
 *
 * @note  If you have blocked signals, remember to unblock them with
 *        util_signals_unblock_r().
 */
dmx_error_t
util_shm_read_unlock_r
(
    util_shm_ptr_t handle
);


/**
 * Wait for write access in a semaphore.
 *
 * @param[in] handle  Shared memory handle
 *
 * @return  SUCCESS_EC
 * @return  INCORRECT_FILE_HANDLE_EC
 * @return  POSIX_*_EC, matching POSIX errno
 * @return  LINUX_*_EC, matching Linux errno
 *
 * @note  It may be a good idea to block signals first with
 *        util_signals_block_r().
 */
dmx_error_t
util_shm_write_lock_r
(
    util_shm_ptr_t handle
);


/**
 * Release the write lock.
 *
 * @param[in] handle  Shared memory handle.
 *
 * @return  SUCCESS_EC
 * @return  INCORRECT_FILE_HANDLE_EC
 * @return  POSIX_*_EC, matching POSIX errno.
 * @return  LINUX_*_EC, matching Linux errno.
 *
 * @note If you have blocked signals, remember to unblock them with
 *       util_signals_unblock_r().
 */
dmx_error_t
util_shm_write_unlock_r
(
    util_shm_ptr_t handle
);

#endif

