#include <compat/posix/netdb.h>

#if LWIP_DNS && LWIP_SOCKET && !(LWIP_COMPAT_SOCKETS)

#define gethostbyname(name) lwip_gethostbyname(name)
#define gethostbyname_r(name, ret, buf, buflen, result, h_errnop) \
		lwip_gethostbyname_r(name, ret, buf, buflen, result, h_errnop)

#define freeaddrinfo(addrinfo) lwip_freeaddrinfo(addrinfo)
#define getaddrinfo(nodname, servname, hints, res) \
		lwip_getaddrinfo(nodname, servname, hints, res)

#endif /* LWIP_DNS && LWIP_SOCKET && !(LWIP_COMPAT_SOCKETS) */

struct servent {
	char    *s_name;        /* official service name */
	char    **s_aliases;    /* alias list */
	int     s_port;         /* port # */
	char    *s_proto;       /* protocol to use */
};

struct protoent {
	char    *p_name;        /* official protocol name */
	char    **p_aliases;    /* alias list */
	int     p_proto;        /* protocol # */
};

const char *gai_strerror(int errcode);
