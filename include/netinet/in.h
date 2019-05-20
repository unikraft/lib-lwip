#ifndef _NETINET_IN_H_
#define _NETINET_IN_H_

#include <uk/config.h>

#ifdef CONFIG_LWIP_SOCKET
#include <lwip/sockets.h>
#else /* CONFIG_LWIP_SOCKET */
#include_next <netinet/in.h>
#endif

#endif /* _NETINET_IN_H_ */
