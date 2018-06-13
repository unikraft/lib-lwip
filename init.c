#include <uk/config.h>
#include <lwip/tcpip.h>
#include <lwip/init.h>
#include <uk/plat/ctors.h>

/* This function is called before the any other sys_arch-function is
 * called and is meant to be used to initialize anything that has to
 * be up and running for the rest of the functions to work. for
 * example to set up a pool of semaphores. */
void sys_init(void)
{
    return;
}

/*
 * This function initializing the lwip network stack
 *
 */
int liblwip_init(void)
{
#if LIBUKSCHED
        tcpip_init(NULL, NULL);
#else
        lwip_init();
#endif /* LIBUKSCHED */
	return 0;
}
