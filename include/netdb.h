#include <compat/posix/netdb.h>

#if LWIP_DNS && LWIP_SOCKET

#if !(LWIP_COMPAT_SOCKETS)
struct hostent *gethostbyname(const char *name);
int gethostbyname_r(const char *name,
		struct hostent *ret, char *buf, size_t buflen,
		struct hostent **result, int *h_errnop);
#endif

struct hostent *gethostbyaddr(const void *addr __unused,
		socklen_t len __unused, int type __unused);

int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints,
		struct addrinfo **res);
void freeaddrinfo(struct addrinfo *res);

#endif /* LWIP_DNS && LWIP_SOCKET && !(LWIP_COMPAT_SOCKETS) */

const char *gai_strerror(int errcode);


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

struct protoent *getprotoent(void);
struct protoent *getprotobyname(const char *name);
struct protoent *getprotobynumber(int num);
void endprotoent(void);
void setprotoent(int stayopen);

/*
 * Constants for getnameinfo()
 */
#define NI_MAXHOST      1025
#define NI_MAXSERV      32

/*
 * Flag values for getnameinfo()
 */
#define NI_NUMERICHOST  0x01
#define NI_NUMERICSERV  0x02
#define NI_NOFQDN       0x04
#define NI_NAMEREQD     0x08
#define NI_DGRAM        0x10
#define NI_NUMERICSCOPE 0x20

/* Error values for getaddrinfo() not defined by lwip/netdb.h */
#define EAI_OVERFLOW    205      /* Argument buffer overflow.  */

int getnameinfo(const struct sockaddr *addr, socklen_t addrlen,
		char *host, socklen_t hostlen,
		char *serv, socklen_t servlen, int flags);

struct servent *getservbyname(const char *name, const char *proto);
struct servent *getservbyport(int port, const char *proto);
