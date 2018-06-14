/* network stub calls */
#include <sys/time.h>
#include <vfscore/file.h>
#include <uk/alloc.h>
#include <uk/essentials.h>
#include <uk/print.h>
#include <stdio.h>
#include <errno.h>
#include <lwip/sockets.h>

#define  NET_LIB_NAME          "lwip-socket"


struct sock_net_file {
	struct vfscore_file vfscore_file;
	int sock_fd;
};

static int sock_net_close(struct vfscore_file *vfscore_file)
{
	int    ret = 0;
	return ret;
}

static ssize_t sock_net_write(struct vfscore_file *vfscore_file, const void *buf,
			     size_t count)
{
	int ret = 0;
	return ret;
}

static ssize_t sock_net_read(struct vfscore_file *vfscore_file, void *buf,
			    size_t count)
{
	int ret = 0;
	return ret;
}

static struct vfscore_fops sock_net_fops = {
	.close = sock_net_close,
	.write = sock_net_write,
	.read  = sock_net_read,
};

int socket(int domain, int type, int protocol)
{
	int ret = 0;
	return ret;
}

int accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	int ret = 0;
	return ret;
}

int bind(int s, const struct sockaddr *name, socklen_t namelen)
{
	int ret = 0;
	return ret;
}

int shutdown(int s, int how)
{
	int ret = 0;
	return ret;
}

int getpeername(int s, struct sockaddr *name, socklen_t *namelen)
{
	int ret = 0;
	return ret;
}

int getsockname(int s, struct sockaddr *name, socklen_t *namelen)
{
	int ret = 0;
	return ret;
}

int getsockopt(int s, int level, int optname, void *optval, socklen_t
		*optlen)
{
	int ret = 0;
	return ret;
}

int setsockopt (int s, int level, int optname, const void *optval,
		socklen_t optlen)
{
	int ret = 0;
	return ret;
}

int connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	int ret = 0;
	return ret;
}

int listen(int s, int backlog)
{
	int ret = 0;
	return ret;
}

int recv(int s, void *mem, size_t len, int flags)
{
	int ret = 0;
	return ret;
}

int recvfrom(int s, void *mem, size_t len, int flags,
		      struct sockaddr *from, socklen_t *fromlen)
{
	int ret = 0;
	return ret;
}

int send(int s, const void *dataptr, size_t size, int flags)
{
	int ret = 0;
	return ret;
}

int sendmsg(int s, const struct msghdr *message, int flags)
{
	int ret = 0;
	return ret;
}

int sendto(int s, const void *dataptr, size_t size, int flags,
		    const struct sockaddr *to, socklen_t tolen)
{
	int ret = 0;
	return ret;
}

int select(int maxfdp1, fd_set *readset, fd_set *writeset, fd_set
		*exceptset, struct timeval *timeout)
{
	int ret = -ENOTSUP;
	return ret;
}
