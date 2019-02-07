/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Simon Kuenzer <simon.kuenzer@neclab.eu>
 *
 * Copyright (c) 2019, NEC Laboratories Europe GmbH, NEC Corporation.
 *                     All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
 */

#include <uk/config.h>
#include "lwip/opt.h"
#include "lwip/tcpip.h"
#include "lwip/init.h"
#include "lwip/dhcp.h"
#if CONFIG_LWIP_NOTHREADS
#include "lwip/timeouts.h"
#else /* CONFIG_LWIP_NOTHREADS */
#include <uk/semaphore.h>
#endif /* CONFIG_LWIP_NOTHREADS */

void sys_init(void)
{
	/*
	 * This function is called before the any other sys_arch-function is
	 * called and is meant to be used to initialize anything that has to
	 * be up and running for the rest of the functions to work. for
	 * example to set up a pool of semaphores.
	 */
}

#if !CONFIG_LWIP_NOTHREADS
static struct uk_semaphore _lwip_init_sem;

static void _lwip_init_done(void *arg __unused)
{
	uk_semaphore_up(&_lwip_init_sem);
}
#endif /* !CONFIG_LWIP_NOTHREADS */

/*
 * This function initializing the lwip network stack
 */
int liblwip_init(void)
{

#if !CONFIG_LWIP_NOTHREADS
	uk_semaphore_init(&_lwip_init_sem, 0);
#endif /* !CONFIG_LWIP_NOTHREADS */

#if CONFIG_LWIP_NOTHREADS
	lwip_init();
#else /* CONFIG_LWIP_NOTHREADS */
	tcpip_init(_lwip_init_done, NULL);

	/* Wait until stack is booted */
	uk_semaphore_down(&_lwip_init_sem);
#endif /* CONFIG_LWIP_NOTHREADS */

	return 0;
}
