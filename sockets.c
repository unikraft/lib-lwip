/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Alexander Jung <alexander.jung@neclab.eu>
 *          Marc Rittinghaus <marc.rittinghaus@kit.edu>
 *
 * Copyright (c) 2020, NEC Laboratories Europe GmbH, NEC Corporation.
 *                     All rights reserved.
 * Copyright (c) 2021, Karlsruhe Institute of Technology (KIT).
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
 */

#include <uk/config.h>
#include <uk/assert.h>
#include <uk/print.h>
#include <uk/essentials.h>
#include <uk/socket_driver.h>
#include <vfscore/eventpoll.h>

#include <lwip/sockets.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <lwip/priv/sockets_priv.h>
#include <lwip/api.h>
#include <lwip/sys.h>

struct lwip_socket_data {
	/* fd of the corresponding lwip socket */
	int lwip_fd;

	/* List of registered eventpolls. The list is synchronized with
	 * lwip SYS_ARCH_PROTECT, as this lock is held anyways during the event
	 * callback and needed during poll to receive a current event state
	 * from the lwip socket.
	 */
	struct uk_list_head evp_list;
};

static struct lwip_socket_data *
lwip_socket_data_alloc(struct uk_alloc *a)
{
	struct lwip_socket_data *sock_data;

	sock_data = uk_malloc(a, sizeof(struct lwip_socket_data));
	if (unlikely(!sock_data))
		return NULL;

	sock_data->lwip_fd = -1;

	UK_INIT_LIST_HEAD(&sock_data->evp_list);

	return sock_data;
}

static void
lwip_socket_data_free(struct uk_alloc *a, struct lwip_socket_data *sock_data)
{
	UK_ASSERT(sock_data);

	uk_free(a, sock_data);
}

static int
lwip_socket_apply_flags(struct lwip_socket_data *sock_data, int flags)
{
	int val;

	if (flags & SOCK_NONBLOCK) {
		val = 1;

		val = lwip_ioctl(sock_data->lwip_fd, FIONBIO, &val);
		if (unlikely(val < 0)) {
			return -errno;
		}
	}

	/* Ignore SOCK_CLOEXEC */

	return 0;
}

#define SOCK_FLAGS	(SOCK_NONBLOCK | SOCK_CLOEXEC)

static void *
lwip_posix_socket_create(struct posix_socket_driver *d, int family, int type,
			 int protocol)
{
	struct lwip_socket_data *sock_data;
	void *ret = NULL;
	int flags, rc;

	sock_data = lwip_socket_data_alloc(d->allocator);
	if (unlikely(!sock_data)) {
		ret = ERR2PTR(-ENOMEM);
		goto EXIT;
	}

	flags = type & SOCK_FLAGS;
	type = type & ~SOCK_FLAGS;

	sock_data->lwip_fd = lwip_socket(family, type, protocol);
	if (unlikely(sock_data->lwip_fd < 0)) {
		ret = ERR2PTR(-errno);
		goto LWIP_SOCKET_CLEANUP;
	}

	rc = lwip_socket_apply_flags(sock_data, flags);
	if (unlikely(rc)) {
		ret = ERR2PTR(rc);
		goto LWIP_SOCKET_CLEANUP;
	}

	ret = sock_data;

EXIT:
	return ret;

LWIP_SOCKET_CLEANUP:
	lwip_socket_data_free(d->allocator, sock_data);
	return ret;
}

static void *
lwip_posix_socket_accept4(struct posix_socket_file *file,
			  struct sockaddr *restrict addr,
			  socklen_t *restrict addr_len, int flags)
{
	struct lwip_socket_data *sock_data, *new_sock_data;
	void *ret = NULL;
	int rc;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	/* We allocate the socket data prior to accepting the connection so
	 * that we do not have to
	 */
	new_sock_data = lwip_socket_data_alloc(file->driver->allocator);
	if (unlikely(!new_sock_data)) {
		ret = ERR2PTR(-ENOMEM);
		goto EXIT;
	}

	new_sock_data->lwip_fd = lwip_accept(sock_data->lwip_fd,
					     addr, addr_len);
	if (unlikely(new_sock_data->lwip_fd < 0)) {
		ret = ERR2PTR(-errno);
		goto LWIP_SOCKET_CLEANUP;
	}

	rc = lwip_socket_apply_flags(new_sock_data, flags);
	if (unlikely(rc)) {
		ret = ERR2PTR(rc);
		goto LWIP_SOCKET_CLOSE;
	}

	ret = new_sock_data;

EXIT:
	return ret;
LWIP_SOCKET_CLOSE:
	lwip_close(new_sock_data->lwip_fd);
LWIP_SOCKET_CLEANUP:
	lwip_socket_data_free(file->driver->allocator, new_sock_data);
	goto EXIT;
}

static int
lwip_posix_socket_bind(struct posix_socket_file *file,
		       const struct sockaddr *addr,
		       socklen_t addr_len)
{
	struct lwip_socket_data *sock_data;
	int ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_bind(sock_data->lwip_fd, addr, addr_len);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

static int
lwip_posix_socket_shutdown(struct posix_socket_file *file, int how)
{
	struct lwip_socket_data *sock_data;
	int ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_shutdown(sock_data->lwip_fd, how);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

static int
lwip_posix_socket_getpeername(struct posix_socket_file *file,
			      struct sockaddr *restrict addr,
			      socklen_t *restrict addr_len)
{
	struct lwip_socket_data *sock_data;
	int ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_getpeername(sock_data->lwip_fd, addr, addr_len);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

static int
lwip_posix_socket_getsockname(struct posix_socket_file *file,
			      struct sockaddr *restrict addr,
			      socklen_t *restrict addr_len)
{
	struct lwip_socket_data *sock_data;
	int ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_getsockname(sock_data->lwip_fd, addr, addr_len);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

static int
lwip_posix_socket_getsockopt(struct posix_socket_file *file, int level,
			     int optname, void *restrict optval,
			     socklen_t *restrict optlen)
{
	struct lwip_socket_data *sock_data;
	int ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_getsockopt(sock_data->lwip_fd, level, optname,
			      optval, optlen);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

static int
lwip_posix_socket_setsockopt(struct posix_socket_file *file, int level,
			     int optname, const void *optval, socklen_t optlen)
{
	struct lwip_socket_data *sock_data;
	int ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_setsockopt(sock_data->lwip_fd, level, optname,
			      optval, optlen);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

static int
lwip_posix_socket_connect(struct posix_socket_file *file,
			  const struct sockaddr *addr, socklen_t addr_len)
{
	struct lwip_socket_data *sock_data;
	int ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_connect(sock_data->lwip_fd, addr, addr_len);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

static int
lwip_posix_socket_listen(struct posix_socket_file *file, int backlog)
{
	struct lwip_socket_data *sock_data;
	int ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_listen(sock_data->lwip_fd, backlog);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

static ssize_t
lwip_posix_socket_recvfrom(struct posix_socket_file *file, void *restrict buf,
			   size_t len, int flags, struct sockaddr *from,
			   socklen_t *restrict fromlen)
{
	struct lwip_socket_data *sock_data;
	ssize_t ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_recvfrom(sock_data->lwip_fd, buf, len, flags, from, fromlen);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

static ssize_t
lwip_posix_socket_recvmsg(struct posix_socket_file *file, struct msghdr *msg,
			  int flags)
{
	struct lwip_socket_data *sock_data;
	ssize_t ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_recvmsg(sock_data->lwip_fd, msg, flags);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

static ssize_t
lwip_posix_socket_sendmsg(struct posix_socket_file *file,
			  const struct msghdr *msg, int flags)
{
	struct lwip_socket_data *sock_data;
	ssize_t ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_sendmsg(sock_data->lwip_fd, msg, flags);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

static ssize_t
lwip_posix_socket_sendto(struct posix_socket_file *file, const void *buf,
			 size_t len, int flags,
			 const struct sockaddr *dest_addr,
			 socklen_t addrlen)
{
	struct lwip_socket_data *sock_data;
	ssize_t ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_sendto(sock_data->lwip_fd, buf, len, flags,
			  dest_addr, addrlen);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

static ssize_t
lwip_posix_socket_read(struct posix_socket_file *file, const struct iovec *iov,
		       int iovcnt)
{
	struct lwip_socket_data *sock_data;
	ssize_t ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_readv(sock_data->lwip_fd, iov, iovcnt);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

static ssize_t
lwip_posix_socket_write(struct posix_socket_file *file, const struct iovec *iov,
		       int iovcnt)
{
	struct lwip_socket_data *sock_data;
	ssize_t ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_writev(sock_data->lwip_fd, iov, iovcnt);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

static int
lwip_posix_socket_close(struct posix_socket_file *file)
{
	struct lwip_socket_data *sock_data;
	int ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_close(sock_data->lwip_fd);
	if (unlikely(ret < 0))
		ret = -errno;

	lwip_socket_data_free(file->driver->allocator, sock_data);

	return ret;
}

static int
lwip_posix_socket_ioctl(struct posix_socket_file *file, int request, void *argp)
{
	struct lwip_socket_data *sock_data;
	int ret;

	UK_ASSERT(file->sock_data);

	sock_data = (struct lwip_socket_data *)file->sock_data;
	UK_ASSERT(sock_data->lwip_fd >= 0);

	ret = lwip_ioctl(sock_data->lwip_fd, request, argp);
	if (unlikely(ret < 0))
		ret = -errno;

	return ret;
}

#if LWIP_NETCONN_FULLDUPLEX
#define NETCONN_RECVMBOX_WAITABLE(conn)					\
	(sys_mbox_valid(&(conn)->recvmbox) &&				\
	 (((conn)->flags & NETCONN_FLAG_MBOXINVALID) == 0))
#else /* LWIP_NETCONN_FULLDUPLEX */
#define NETCONN_RECVMBOX_WAITABLE(conn)					\
	sys_mbox_valid(&(conn)->recvmbox)
#endif /* LWIP_NETCONN_FULLDUPLEX */

static unsigned int
get_lwip_socket_events(struct lwip_sock *sock)
{
	unsigned int events = 0;

	UK_ASSERT(sock);

	/* A TCP connection may be in not-connected state. Don't report it as
	 * readable or writeable.
	 */
	if ((NETCONNTYPE_GROUP(sock->conn->type) == NETCONN_TCP) &&
	    (sock->conn->state == NETCONN_NONE) &&
	    (!NETCONN_RECVMBOX_WAITABLE(sock->conn))) {
		if (sock->errevent != 0)
			events |= EPOLLERR;

		return events;
	}

	if (sock->lastdata.pbuf || sock->rcvevent > 0)
		events |= EPOLLIN | EPOLLRDNORM;
	if (sock->sendevent != 0)
		events |= EPOLLOUT | EPOLLWRNORM;
	if (sock->errevent != 0)
		events |= EPOLLERR;

	return events;
}

void
lwip_posix_socket_event_callback(struct lwip_sock *sock,
				 enum netconn_evt evt __unused,
				 u16_t len __unused)
{
	struct lwip_socket_data *sock_data;
	struct eventpoll_cb *ecb;
	struct uk_list_head *itr;
	unsigned int events;

	UK_ASSERT(sock);

	if (unlikely(!sock->sock_data))
		return;

	sock_data = (struct lwip_socket_data *)sock->sock_data;
	UK_ASSERT(sock_data->lwip_fd == sock->conn->socket);

	events = get_lwip_socket_events(sock);
	if (!events)
		return;

	uk_list_for_each(itr, &sock_data->evp_list) {
		ecb = uk_list_entry(itr, struct eventpoll_cb, cb_link);

		UK_ASSERT(ecb->unregister);

		eventpoll_signal(ecb, events);
	}
}

static void
lwip_socket_unregister_eventpoll(struct eventpoll_cb *ecb)
{
	SYS_ARCH_DECL_PROTECT(lev);

	UK_ASSERT(ecb);

	SYS_ARCH_PROTECT(lev);
	UK_ASSERT(!uk_list_empty(&ecb->cb_link));
	uk_list_del(&ecb->cb_link);

	ecb->data = NULL;
	ecb->unregister = NULL;
	SYS_ARCH_UNPROTECT(lev);
}

static int
lwip_posix_socket_poll(struct posix_socket_file *file, unsigned int *revents,
		       struct eventpoll_cb *ecb)
{
	struct lwip_socket_data *sock_data;
	struct lwip_sock *sock;
	SYS_ARCH_DECL_PROTECT(lev);

	UK_ASSERT(file->sock_data);
	UK_ASSERT(revents);

	sock_data = (struct lwip_socket_data *)file->sock_data;

	SYS_ARCH_PROTECT(lev);
	/* This is a bit hacky but lwip does not provide a different public
	 * interface to get a reference to the socket. Furthermore, this
	 * function does not increase the reference count which is good
	 * as we do not hold the reference longer than the lock anyways. Since
	 * we need to hold the lock for evaluating the socket state this fits
	 * in well.
	 */
	sock = lwip_socket_dbg_get_socket(sock_data->lwip_fd);
	*revents = get_lwip_socket_events(sock);

	if (!ecb->unregister) {
		UK_ASSERT(uk_list_empty(&ecb->cb_link));
		UK_ASSERT(!ecb->data);

		/* This is the first time we see this cb. Add it to the
		 * eventpoll list and set the unregister callback so
		 * we remove it when the eventpoll is freed.
		 */
		uk_list_add_tail(&ecb->cb_link, &sock_data->evp_list);

		ecb->data = sock_data;
		ecb->unregister = lwip_socket_unregister_eventpoll;

		sock->sock_data = sock_data;
	}
	SYS_ARCH_UNPROTECT(lev);

	return 0;
}

static struct posix_socket_ops lwip_posix_socket_ops = {
	/* POSIX interfaces */
	.create		= lwip_posix_socket_create,
	.accept4	= lwip_posix_socket_accept4,
	.bind		= lwip_posix_socket_bind,
	.shutdown	= lwip_posix_socket_shutdown,
	.getpeername	= lwip_posix_socket_getpeername,
	.getsockname	= lwip_posix_socket_getsockname,
	.getsockopt	= lwip_posix_socket_getsockopt,
	.setsockopt	= lwip_posix_socket_setsockopt,
	.connect	= lwip_posix_socket_connect,
	.listen		= lwip_posix_socket_listen,
	.recvfrom	= lwip_posix_socket_recvfrom,
	.recvmsg	= lwip_posix_socket_recvmsg,
	.sendmsg	= lwip_posix_socket_sendmsg,
	.sendto		= lwip_posix_socket_sendto,
	/* vfscore ops */
	.read		= lwip_posix_socket_read,
	.write		= lwip_posix_socket_write,
	.close		= lwip_posix_socket_close,
	.ioctl		= lwip_posix_socket_ioctl,
	.poll		= lwip_posix_socket_poll,
};

POSIX_SOCKET_FAMILY_REGISTER(AF_INET, &lwip_posix_socket_ops);

#ifdef CONFIG_LWIP_IPV6
POSIX_SOCKET_FAMILY_REGISTER(AF_INET6, &lwip_posix_socket_ops);
#endif /* CONFIG_LWIP_IPV6 */
