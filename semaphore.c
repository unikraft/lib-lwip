#include <uk/semaphore.h>
#include <uk/arch/time.h>
#include <lwip/sys.h>

#include <uk/essentials.h>

/* Initializes a new semaphore. The "count" argument specifies
 * the initial state of the semaphore. */
err_t sys_sem_new(sys_sem_t *sem, u8_t count)
{
	uk_semaphore_init(&sem->sem, (long) count);
	sem->valid = 1;
	return ERR_OK;
}

int sys_sem_valid(sys_sem_t *sem)
{
	return (sem->valid == 1);
}

void sys_sem_set_invalid(sys_sem_t *sem)
{
	sem->valid = 0;
}

void sys_sem_free(sys_sem_t *sem)
{
	sys_sem_set_invalid(sem);
}

/* Signals a semaphore. */
void sys_sem_signal(sys_sem_t *sem)
{
	uk_semaphore_up(&sem->sem);
}

/* Blocks the thread while waiting for the semaphore to be
 * signaled. If the "timeout" argument is non-zero, the thread should
 * only be blocked for the specified time (measured in
 * milliseconds).
 *
 * If the timeout argument is non-zero, the return value is the number of
 * milliseconds spent waiting for the semaphore to be signaled. If the
 * semaphore wasn't signaled within the specified time, the return value is
 * SYS_ARCH_TIMEOUT. If the thread didn't have to wait for the semaphore
 * (i.e., it was already signaled), the function may return zero. */
u32_t sys_arch_sem_wait(sys_sem_t *sem, u32_t timeout)
{
    __nsec nsret;

    nsret = uk_semaphore_down_to(&sem->sem,
                                    ukarch_time_msec_to_nsec((__nsec) timeout));
    if (unlikely(nsret == __NSEC_MAX))
        return SYS_ARCH_TIMEOUT;
    return (u32_t) ukarch_time_nsec_to_msec(nsret);
}
