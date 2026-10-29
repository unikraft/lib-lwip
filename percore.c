/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Per-core state storage and initialization for lwIP in NO_SYS mode.
 */

#include <uk/config.h>
#include <string.h>
#include "lwip_percore.h"

struct lwip_core_state uk_lwip_core_states[LWIP_CORE_MAX];

#if !defined(__Unikraft__)
__thread unsigned int lwip_test_core_id = 0;
#endif

void lwip_core_state_init(unsigned int core_id)
{
	struct lwip_core_state *cs;

	if (core_id >= LWIP_CORE_MAX)
		return;

	cs = &uk_lwip_core_states[core_id];
	memset(cs, 0, sizeof(*cs));

	cs->tcp_pcb_lists[0] = &cs->tcp_listen_pcbs.pcbs;
	cs->tcp_pcb_lists[1] = &cs->tcp_bound_pcbs;
	cs->tcp_pcb_lists[2] = &cs->tcp_active_pcbs;
	cs->tcp_pcb_lists[3] = &cs->tcp_tw_pcbs;
}

void lwip_core_state_init_all(void)
{
	unsigned int i;

	for (i = 0; i < LWIP_CORE_MAX; i++)
		lwip_core_state_init(i);
}
