/*
 * lwip/arch/sys_arch.h
 *
 * Arch-specific semaphores and mailboxes for lwIP running on mini-os
 *
 * Tim Deegan <Tim.Deegan@eu.citrix.net>, July 2007
 * Simon Kuenzer <Simon.Kuenzer@neclab.eu>, October 2014
 */

#ifndef __LWIP_ARCH_SYS_ARCH_H__
#define __LWIP_ARCH_SYS_ARCH_H__

#include <uk/config.h>

#include <stdlib.h>
#include <uk/mutex.h>
#include <uk/semaphore.h>
#include <uk/mbox.h>
#if LIBUKSCHED
#include <uk/thread.h>
#endif

#if LWIP_SOCKET && HAVE_LIBC
#include <fcntl.h>
#endif

#define SYS_SEM_NULL   NULL
#define SYS_MUTEX_NULL NULL
#define SYS_MBOX_NULL  NULL

typedef struct {
	struct uk_mutex mtx;
	int valid;
} sys_mutex_t;

typedef struct {
	struct uk_semaphore sem;
	int valid;
} sys_sem_t;

typedef struct {
	struct uk_alloc *a;
	struct uk_mbox *mbox;
	int valid;
} sys_mbox_t;

#if LIBUKSCHED
typedef struct uk_thread *sys_thread_t;
#endif

typedef unsigned long sys_prot_t;

#endif /*__LWIP_ARCH_SYS_ARCH_H__ */
