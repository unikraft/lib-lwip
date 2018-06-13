#include <uk/arch/limits.h>
#include <uk/sched.h>
#include <uk/thread.h>
#include <uk/print.h>
#include <uk/assert.h>
#include <lwip/sys.h>

/* Starts a new thread with priority "prio" that will begin its execution in the
 * function "thread()". The "arg" argument will be passed as an argument to the
 * thread() function. The id of the new thread is returned. Both the id and
 * the priority are system dependent. */
sys_thread_t sys_thread_new(const char *name, lwip_thread_fn thread, void *arg,
				int stacksize, int prio)
{
	struct uk_thread *t;
	if (stacksize > __STACK_SIZE) {
		uk_printd(DLVL_CRIT, "Can't create lwIP thread: stack size %u is too large (> %u)\n",
					stacksize, __STACK_SIZE);
		UK_CRASH("Dying\n");
	}
	t = uk_thread_create((char *) name, thread, arg);
	return t;
}
