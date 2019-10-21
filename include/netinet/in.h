#ifndef _NETINET_IN_H_
#define _NETINET_IN_H_

#include <uk/config.h>

#ifdef CONFIG_LWIP_SOCKET
#include <lwip/sockets.h>
/* Taken from musl's netinet/in.h */
#ifdef CONFIG_LWIP_IPV6
#define IN6_IS_ADDR_MULTICAST(a) (((uint8_t *) (a))[0] == 0xff)
#define IN6_IS_ADDR_LINKLOCAL(a) \
  ((((uint8_t *) (a))[0]) == 0xfe && (((uint8_t *) (a))[1] & 0xc0) == 0x80)
#define IN6_IS_ADDR_MC_LINKLOCAL(a) \
  (IN6_IS_ADDR_MULTICAST(a) && ((((uint8_t *) (a))[1] & 0xf) == 0x2))
#endif /* LWIP_IPV6 */
#else /* CONFIG_LWIP_SOCKET */
#include_next <netinet/in.h>
#endif

#endif /* _NETINET_IN_H_ */
