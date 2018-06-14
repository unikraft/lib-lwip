/*
 * lwipopts.h
 *
 * Configuration for lwIP running on mini-os
 *
 * Tim Deegan <Tim.Deegan@eu.citrix.net>, July 2007
 * Simon Kuenzer <simon.kuenzer@neclab.eu>, October 2013
 */
#ifndef __LWIP_LWIPOPTS_H__
#define __LWIP_LWIPOPTS_H__

#include <inttypes.h>
#include <uk/config.h>

#define SO_REUSE 1

/*
 * General options/System settings
 */
/* lightweight protection */
#define SYS_LIGHTWEIGHT_PROT 1

/* provide malloc/free by Unikraft */
#if CONFIG_LWIP_HEAP /* default */
  /* Only use malloc/free for lwIP.
   * Every allocation is done by the heap.
   * Note: This setting results in the smallest binary
   *       size but leads to heavy malloc/free usage during
   *       network processing.
   */
  #define MEM_LIBC_MALLOC 1 /* enable heap */
  #define MEMP_MEM_MALLOC 1 /* pool allocations via malloc (thus not from pool in data segment) */
#elif CONFIG_LWIP_POOLS
  /* This is the default configuration (mixed).
   * Pools are used for pool allocations and the heap
   * is used for all the rest of allocations.
   * Note: Per design, lwIP allocates outgoing packet buffers
   *       from heap (via PBUF_RAM) and incoming from pools (via PBUF_POOL)
   *       CONFIG_LWIP_PBUF_POOL_SIZE defines the pool size for PBUF_POOL
   *       allocations
   * Note: lwIP allocate pools on the data segment
   */
  #define MEM_LIBC_MALLOC 1 /* enable heap */
  #define MEMP_MEM_MALLOC 0 /* pool allocations still via pool */
#else
 #error Configuration error!
#endif /* CONFIG_LWIP_HEAP_ONLY / CONFIG_LWIP_POOLS_ONLY */

#define MEMP_SEPARATE_POOLS 1 /* for each pool use a separate array in data segment */

//#ifdef CONFIG_LWIP_POOLS_ON_HEAP /* not supported yet */
//#define MEMP_POOLS_ON_HEAP 1 /* allocate pools on system's heap */
//#endif

#define MEM_ALIGNMENT 4

#if MEM_LIBC_MALLOC
#include <stddef.h> /* size_t */
void *sys_malloc(size_t size);
void *sys_calloc(int num, size_t size);
void sys_free(void *ptr);

#define mem_clib_malloc   sys_malloc
#define mem_clib_calloc   sys_calloc
#define mem_clib_free     sys_free
#endif /* MEM_LIBC_MALLOC */

#if MEM_USE_POOLS
/* requires lwippools.h */
#define MEMP_USE_CUSTOM_POOLS 0
#endif /* MEM_USE_POOLS */

/*
 * Most features are selected by uk/config.h
 */
#define LWIP_NETIF_REMOVE_CALLBACK 1
#define LWIP_TIMEVAL_PRIVATE 0

/* disable BSD-style socket - layer is provided by libc */
#define LWIP_COMPAT_SOCKETS 0

/*
 * Thread options
 */
#ifndef CONFIG_LWIP_NOTHREADS
#define TCPIP_THREAD_NAME "lwip"
#define TCPIP_MBOX_SIZE 256
#define MEMP_NUM_TCPIP_MSG_INPKT 256
#endif /* CONFIG_LWIP_NOTHREADS */

/*
 * ARP options
 */
#define MEMP_NUM_ARP_QUEUE 256
#define ETHARP_SUPPORT_STATIC_ENTRIES 1

/*
 * UDP options
 */
//#define MEMP_NUM_UDP_PCB 16

/*
 * TCP options
 */
#define TCP_MSS CONFIG_LWIP_TCP_MSS


#define TCP_CALCULATE_EFF_SEND_MSS 1
#define IP_FRAG 0



#if CONFIG_LWIP_WND_SCALE
/*
 * Maximum window and scaling factor
 * Optimal settings for RX performance are:
 * 	TCP_WND		262143
 * 	TCP_RCV_SCALE	5
 */
#define LWIP_WND_SCALE  1
#if defined CONFIG_LWIP_WND_SCALE_FACTOR && CONFIG_LWIP_WND_SCALE_FACTOR >= 1
#define TCP_RCV_SCALE CONFIG_LWIP_WND_SCALE_FACTOR /* scaling factor 0..14 */
#else
#define TCP_RCV_SCALE 4
#endif /* defined CONFIG_LWIP_WND_SCALE_FACTOR && CONFIG_LWIP_WND_SCALE_FACTOR >= 1 */
#define TCP_WND 262142
#define TCP_SND_BUF ( 1024 * 1024 )

#else /* CONFIG_LWIP_WND_SCALE */
/*
 * Options when no window scaling  is enabled
 */
#define TCP_WND 32766 /* Ideally, TCP_WND should be link bandwidth multiplied by rtt */
#define TCP_SND_BUF (TCP_WND + (2 * TCP_MSS))
#endif /* LWIP_WND_SCALE */

#define TCP_SNDLOWAT (4 * TCP_MSS)
#define TCP_SND_QUEUELEN (2 * (TCP_SND_BUF) / (TCP_MSS))
#define TCP_QUEUE_OOSEQ 4
#define MEMP_NUM_TCP_SEG (MEMP_NUM_TCP_PCB * ((TCP_SND_QUEUELEN) / 5))
#define MEMP_NUM_FRAG_PBUF 32

#define MEMP_NUM_TCP_PCB CONFIG_LWIP_NUM_TCPCON /* max num of sim. TCP connections */
#define MEMP_NUM_TCP_PCB_LISTEN 32 /* max num of sim. TCP listeners */

/*
 * DNS options
 */
#define DNS_MAX_SERVERS CONFIG_LWIP_DNS_MAX_SERVERS
#define DNS_TABLE_SIZE CONFIG_LWIP_DNS_TABLE_SIZE
#define DNS_LOCAL_HOST_LIST 1
#define DNS_LOCAL_HOSTLIST_IS_DYNAMIC 1

/*
 * Pool options
 */
/* PBUF pools */
#ifndef PBUF_POOL_SIZE
#define PBUF_POOL_SIZE ((TCP_WND + TCP_MSS - 1) / TCP_MSS)
#endif
#ifndef CONFIG_NETFRONT_PERSISTENT_GRANTS
#define LWIP_SUPPORT_CUSTOM_PBUF 1
#endif
#ifndef MEMP_NUM_PBUF
#define MEMP_NUM_PBUF ((MEMP_NUM_TCP_PCB * (TCP_SND_QUEUELEN)) / 2)
#endif

/*
 * Checksum options
 */
#define CHECKSUM_GEN_IP CONFIG_LWIP_TXCHECKSUM
#define CHECKSUM_GEN_IP6 CONFIG_LWIP_TXCHECKSUM
#define CHECKSUM_GEN_ICMP CONFIG_LWIP_TXCHECKSUM
#define CHECKSUM_GEN_ICMP6 CONFIG_LWIP_TXCHECKSUM
#define CHECKSUM_GEN_UDP CONFIG_LWIP_TXCHECKSUM
#define CHECKSUM_GEN_TCP CONFIG_LWIP_TXCHECKSUM
#define LWIP_CHECKSUM_ON_COPY 1

/* Checksum checking is offloaded to the host (lwip-net is a virtual interface)
 * TODO: better solution is when netfront forwards checksum flags to lwIP */
#define CHECKSUM_CHECK_IP CONFIG_LWIP_RXCHECKSUM
#define CHECKSUM_CHECK_UDP CONFIG_LWIP_RXCHECKSUM
#define CHECKSUM_CHECK_TCP CONFIG_LWIP_RXCHECKSUM
#define CHECKSUM_CHECK_ICMP CONFIG_LWIP_RXCHECKSUM
#define CHECKSUM_CHECK_ICMP6 CONFIG_LWIP_RXCHECKSUM
#define CHECKSUM_CHECK_TCP CONFIG_LWIP_RXCHECKSUM

#ifdef CONFIG_LWIP_MAINLOOP_DEBUG
#define IP_DEBUG         LWIP_DBG_ON
#define TCPIP_DEBUG      LWIP_DBG_ON
#define TIMERS_DEBUG     LWIP_DBG_ON
#endif /* CONFIG_LWIP_MAINLOOP_DEBUG */

#ifdef CONFIG_LWIP_IF_DEBUG
#define NETIF_DEBUG      LWIP_DBG_ON
#endif /* CONFIG_LWIP_IF_DEBUG */

#ifdef CONFIG_LWIP_IP_DEBUG
#define IP_DEBUG         LWIP_DBG_ON
#define IP6_DEBUG        LWIP_DBG_ON
#define IP_REASS_DEBUG   LWIP_DBG_ON
#endif /* CONFIG_LWIP_IP_DEBUG */

#ifdef CONFIG_LWIP_UDP_DEBUG
#define UDP_DEBUG        LWIP_DBG_ON
#endif /* CONFIG_LWIP_UDP_DEBUG */

#ifdef CONFIG_LWIP_TCP_DEBUG
#define TCP_DEBUG        LWIP_DBG_ON
#define TCP_FR_DEBUG     LWIP_DBG_ON
#define TCP_RTO_DEBUG    LWIP_DBG_ON
#define TCP_CWND_DEBUG   LWIP_DBG_ON
#define TCP_WND_DEBUG    LWIP_DBG_ON
#define TCP_RST_DEBUG    LWIP_DBG_ON
#define TCP_QLEN_DEBUG   LWIP_DBG_ON
//#define TCP_OUTPUT_DEBUG LWIP_DBG_ON
//#define TCP_INPUT_DEBUG LWIP_DBG_ON
#if LWIP_CHECKSUM_ON_COPY
#define TCP_CHECKSUM_ON_COPY_SANITY_CHECK 1
#endif
#endif /* CONFIG_LWIP_TCP_DEBUG */

#ifdef CONFIG_LWIP_SYS_DEBUG
#define SYS_DEBUG        LWIP_DBG_ON
#define PBUF_DEBUG       LWIP_DBG_ON
#define MEM_DEBUG        LWIP_DBG_ON
#define MEMP_DEBUG       LWIP_DBG_ON
#endif /* LWIP_SYS_DEBUG */

#ifdef LWIP_API_DEBUG
#define SOCKETS_DEBUG    LWIP_DBG_ON
#define RAW_DEBUG        LWIP_DBG_ON
#define API_MSG_DEBUG    LWIP_DBG_ON
#define API_LIB_DEBUG    LWIP_DBG_ON
#endif /* LWIP_API_DEBUG */

#ifdef LWIP_SERVICE_DEBUG
#define ETHARP_DEBUG     LWIP_DBG_ON
#define DNS_DEBUG        LWIP_DBG_ON
#define AUTOIP_DEBUG     LWIP_DBG_ON
#define DHCP_DEBUG       LWIP_DBG_ON
#define ICMP_DEBUG       LWIP_DBG_ON
#define SNMP_DEBUG       LWIP_DBG_ON
#define SNMP_MSG_DEBUG   LWIP_DBG_ON
#define SNMP_MIB_DEBUG   LWIP_DBG_ON
#define PPP_DEBUG        LWIP_DBG_ON
#define SLIP_DEBUG       LWIP_DBG_ON
#endif /* LWIP_SERVICE_DEBUG */

#endif /* __LWIP_LWIPOPTS_H__ */
