#include <uk/mbox.h>
#include <uk/arch/time.h>
#include <lwip/sys.h>

#include <uk/essentials.h>

/* Creates an empty mailbox. */
err_t sys_mbox_new(sys_mbox_t *mbox, int size)
{
    if (size <= 0)
        size = 32;

    UK_ASSERT(mbox);
    mbox->a = uk_alloc_get_default();
    UK_ASSERT(mbox->a);
    mbox->mbox = uk_mbox_create(mbox->a, size);
    if (!mbox->mbox)
        return ERR_MEM;
    mbox->valid = 1;
    return ERR_OK;
}

int sys_mbox_valid(sys_mbox_t *mbox)
{
    if (!mbox)
        return 0;
    return (mbox->valid == 1);
}

void sys_mbox_set_invalid(sys_mbox_t *mbox)
{
    UK_ASSERT(mbox);
    mbox->valid = 0;
}

/* Deallocates a mailbox. If there are messages still present in the
 * mailbox when the mailbox is deallocated, it is an indication of a
 * programming error in lwIP and the developer should be notified. */
void sys_mbox_free(sys_mbox_t *mbox)
{
    UK_ASSERT(sys_mbox_valid(mbox));

    uk_mbox_free(mbox->a, mbox->mbox);
    sys_mbox_set_invalid(mbox);
}

/* Posts the "msg" to the mailbox. */
void sys_mbox_post(sys_mbox_t *mbox, void *msg)
{
    UK_ASSERT(sys_mbox_valid(mbox));

    if (!msg) { /* FIXME? */
        uk_printd(DLVL_WARN, "Ignore posting NULL message");
	return;
    }

    uk_mbox_post(mbox->mbox, msg);
}

/* Try to post the "msg" to the mailbox. */
err_t sys_mbox_trypost(sys_mbox_t *mbox, void *msg)
{
    UK_ASSERT(sys_mbox_valid(mbox));

    if (uk_mbox_post_try(mbox->mbox, msg) < 0)
        return ERR_MEM;
    return ERR_OK;
}

/* Blocks the thread until a message arrives in the mailbox, but does
 * not block the thread longer than "timeout" milliseconds (similar to
 * the sys_arch_sem_wait() function). The "msg" argument is a result
 * parameter that is set by the function (i.e., by doing "*msg =
 * ptr"). The "msg" parameter maybe NULL to indicate that the message
 * should be dropped.
 *
 * The return values are the same as for the sys_arch_sem_wait() function:
 * Number of milliseconds spent waiting or SYS_ARCH_TIMEOUT if there was a
 * timeout. */
u32_t sys_arch_mbox_fetch(sys_mbox_t *mbox, void **msg, u32_t timeout)
{
    __nsec nsret;

    UK_ASSERT(sys_mbox_valid(mbox));

    nsret = uk_mbox_recv_to(mbox->mbox, msg,
                               ukarch_time_msec_to_nsec((__nsec) timeout));
    if (unlikely(nsret == __NSEC_MAX))
        return SYS_ARCH_TIMEOUT;
    return (u32_t) ukarch_time_nsec_to_msec(nsret);
}

/* This is similar to sys_arch_mbox_fetch, however if a message is not
 * present in the mailbox, it immediately returns with the code
 * SYS_MBOX_EMPTY. On success 0 is returned.
 *
 * To allow for efficient implementations, this can be defined as a
 * function-like macro in sys_arch.h instead of a normal function. For
 * example, a naive implementation could be:
 *   #define sys_arch_mbox_tryfetch(mbox,msg) \
 *     sys_arch_mbox_fetch(mbox,msg,1)
 * although this would introduce unnecessary delays. */

u32_t sys_arch_mbox_tryfetch(sys_mbox_t *mbox, void **msg) {
    void *rmsg;

    UK_ASSERT(sys_mbox_valid(mbox));

    if (uk_mbox_recv_try(mbox->mbox, &rmsg) < 0)
	return SYS_MBOX_EMPTY;

    if (msg)
        *msg = rmsg;
    return 0;
}
