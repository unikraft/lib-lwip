#include <uk/mutex.h>
#include <uk/arch/time.h>
#include <lwip/sys.h>

#include <uk/essentials.h>

/* Initializes a new semaphore. The "count" argument specifies
 * the initial state of the semaphore. */
err_t sys_mutex_new(sys_mutex_t *mtx)
{
	uk_mutex_init(&mtx->mtx);
	mtx->valid = 1;
	return ERR_OK;
}

int sys_mutex_valid(sys_mutex_t *mtx)
{
	return (mtx->valid == 1);
}

void sys_mutex_set_invalid(sys_mutex_t *mtx)
{
	mtx->valid = 0;
}

void sys_mutex_free(sys_mutex_t *mtx)
{
	sys_mutex_set_invalid(mtx);
}

/* Signals a mtxaphore. */
void sys_mutex_lock(sys_mutex_t *mtx)
{
	uk_mutex_hold(&mtx->mtx);
}

void sys_mutex_unlock(sys_mutex_t *mtx)
{
	uk_mutex_release(&mtx->mtx);
}
