/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Per-core stack state for lwIP in NO_SYS mode.
 */

#ifndef __LWIP_PERCORE_H__
#define __LWIP_PERCORE_H__

#include <uk/config.h>
#include <uk/essentials.h>
#include "lwip/opt.h"
#include "lwip/ip_addr.h"
#include "lwip/netif.h"
#include "lwip/prot/ethernet.h"
#include "lwip/timeouts.h"

#if LWIP_SOCKET
#include "lwip/priv/sockets_priv.h"
#endif

#if defined(CONFIG_LIBUKPCPUVAR) && CONFIG_LIBUKPCPUVAR
#include <uk/pcpuvar.h>
#endif

#ifndef LWIP_CORE_MAX
#if defined(CONFIG_UKPLAT_CPU_MAXCOUNT)
#define LWIP_CORE_MAX CONFIG_UKPLAT_CPU_MAXCOUNT
#else
#define LWIP_CORE_MAX 4
#endif
#endif

#ifndef NUM_TCP_PCB_LISTS
#define NUM_TCP_PCB_LISTS 4
#endif

#ifndef ARP_TABLE_SIZE
#define ARP_TABLE_SIZE 10
#endif

#ifndef NUM_SOCKETS
#ifdef MEMP_NUM_NETCONN
#define NUM_SOCKETS MEMP_NUM_NETCONN
#else
#define NUM_SOCKETS 64
#endif
#endif

#ifndef LWIP_MEMP_MAX
#define LWIP_MEMP_MAX 32
#endif

struct tcp_pcb;
struct tcp_pcb_listen;
struct memp;
struct lwip_select_cb;
struct etharp_q_entry;

#ifndef TCP_LISTEN_PCBS_T_DEFINED
#define TCP_LISTEN_PCBS_T_DEFINED
union tcp_listen_pcbs_t {
	struct tcp_pcb_listen *listen_pcbs;
	struct tcp_pcb *pcbs;
};
#endif

#ifndef ETHARP_ENTRY_DEFINED
#define ETHARP_ENTRY_DEFINED
struct etharp_entry {
#if ARP_QUEUEING
	struct etharp_q_entry *q;
#else
	struct pbuf *q;
#endif
	ip4_addr_t ipaddr;
	struct netif *netif;
	struct eth_addr ethaddr;
	u16_t ctime;
	u8_t state;
};
#endif

/* Per-core lwIP state structure */
struct lwip_core_state {
	/* TCP Protocol Control Block lists */
	struct tcp_pcb *tcp_bound_pcbs;
	union tcp_listen_pcbs_t tcp_listen_pcbs;
	struct tcp_pcb *tcp_active_pcbs;
	struct tcp_pcb *tcp_tw_pcbs;
	struct tcp_pcb **tcp_pcb_lists[NUM_TCP_PCB_LISTS];
	u8_t tcp_active_pcbs_changed;
	struct tcp_pcb *tcp_input_pcb;
	u8_t tcp_timer;
	u8_t tcp_timer_ctr;

	/* TCP Clock and Timers */
	u32_t tcp_ticks;
	struct sys_timeo *next_timeout;
	u32_t current_timeout_due_time;
	int tcpip_tcp_timer_active;

	/* Memory pool free list heads */
	struct memp *memp_tabs[LWIP_MEMP_MAX];

	/* ARP Cache */
	struct etharp_entry arp_table[ARP_TABLE_SIZE];
#if !LWIP_NETIF_HWADDRHINT
	netif_addr_idx_t etharp_cached_entry;
#endif

	/* Socket table */
#if LWIP_SOCKET
	struct lwip_sock sockets[NUM_SOCKETS];
	struct lwip_select_cb *select_cb_list;
	volatile int select_cb_ctr;
#endif
} __align(64);

extern struct lwip_core_state uk_lwip_core_states[LWIP_CORE_MAX];

#if !defined(__Unikraft__)
extern __thread unsigned int lwip_test_core_id;
static inline void lwip_set_current_core_id(unsigned int id)
{
	lwip_test_core_id = id;
}
#endif

static inline unsigned int lwip_current_core_id(void)
{
#if defined(__Unikraft__)
#if defined(CONFIG_LIBUKPCPUVAR) && CONFIG_LIBUKPCPUVAR
	unsigned int id = (unsigned int)uk_pcpuvar_current_get(uk_pcpuvar_cpu_idx);
	if (unlikely(id >= LWIP_CORE_MAX))
		return 0;
	return id;
#else
	return 0;
#endif
#else
	if (lwip_test_core_id >= LWIP_CORE_MAX)
		return 0;
	return lwip_test_core_id;
#endif
}

static inline struct lwip_core_state *lwip_get_core_state(void)
{
	return &uk_lwip_core_states[lwip_current_core_id()];
}

static inline struct lwip_core_state *lwip_get_core_state_by_id(unsigned int core_id)
{
	if (unlikely(core_id >= LWIP_CORE_MAX))
		return &uk_lwip_core_states[0];
	return &uk_lwip_core_states[core_id];
}

void lwip_core_state_init(unsigned int core_id);
void lwip_core_state_init_all(void);

/* Inline access macros for active PCB lists and timer heads */
#define LWIP_CORE_ACTIVE_PCBS(cs)   ((cs)->tcp_active_pcbs)
#define LWIP_CORE_TW_PCBS(cs)       ((cs)->tcp_tw_pcbs)
#define LWIP_CORE_LISTEN_PCBS(cs)   ((cs)->tcp_listen_pcbs)
#define LWIP_CORE_BOUND_PCBS(cs)    ((cs)->tcp_bound_pcbs)
#define LWIP_CORE_TIMEOUTS(cs)      ((cs)->next_timeout)
#define LWIP_CORE_TCP_TICKS(cs)     ((cs)->tcp_ticks)

#endif /* __LWIP_PERCORE_H__ */
