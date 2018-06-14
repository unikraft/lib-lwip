#ifndef UK_LWIP_SOCKET_H
#include <uk/config.h>

#ifndef CONFIG_HAVE_LIBC

#if CONFIG_LIBLWIP
#include <lwip/inet.h>
#include <lwip/sockets.h>
#endif /* CONFIG_LIBLWIP */

#define SOCK_CLOEXEC    0x10000000
#define SOCK_NONBLOCK   0x20000000

#endif /* CONFIG_HAVELIBC */
#endif /* UK_LWIP_SOCKET_H */
