/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Authors: Sharan Santhanam <sharan.santhanam@neclab.eu>
 *
 * Copyright (c) 2019, NEC Laboratories Europe GmbH, NEC Corporation.
 *                     All rights reserved.
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
 *
 * THIS HEADER MAY NOT BE EXTRACTED OR MODIFIED IN ANY WAY.
 */

/* network stub calls */
#include <sys/time.h>
#include <vfscore/file.h>
#include <vfscore/fs.h>
#include <vfscore/vnode.h>
#include <uk/alloc.h>
#include <uk/essentials.h>
#include <uk/errptr.h>
#include <stdio.h>
#include <errno.h>
#include <lwip/sockets.h>

#define SOCK_NET_SET_ERRNO(errcode) \
	(errno = -(errcode))

struct sock_net_file {
	struct vfscore_file vfscore_file;
	int sock_fd;
};

static inline struct sock_net_file *sock_net_file_get(int fd)
{
	struct sock_net_file *file = NULL;
	struct vfscore_file *fos;

	fos  = vfscore_get_file(fd);
	if (!fos) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed with invalid descriptor\n"));
		file = ERR2PTR(-EINVAL);
		goto EXIT;
	}
	file = __containerof(fos, struct sock_net_file, vfscore_file);
EXIT:
	return file;
}

static int sock_fd_alloc(struct vnops *v_op, int sock_fd)
{
	int ret = 0;
	int vfs_fd;
	struct sock_net_file *file = NULL;
	struct dentry *s_dentry;
	struct vnode *s_vnode;

	/* Reserve file descriptor number */
	vfs_fd = vfscore_alloc_fd();
	if (vfs_fd < 0) {
		ret = -ENFILE;
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("Failed to allocate file descriptor number\n"));
		goto ERR_EXIT;
	}

	/* Allocate file, dentry, and vnode */
	file = uk_calloc(uk_alloc_get_default(), 1, sizeof(*file));
	if (!file) {
		ret = -ENOMEM;
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("Failed to allocate socket file: Out of memory\n"));
		goto ERR_MALLOC_FILE;
	}
	s_dentry = uk_calloc(uk_alloc_get_default(), 1, sizeof(*s_dentry));
	if (!s_dentry) {
		ret = -ENOMEM;
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("Failed to allocate socket dentry: Out of memory\n"));
		goto ERR_MALLOC_DENTRY;
	}
	s_vnode = uk_calloc(uk_alloc_get_default(), 1, sizeof(*s_vnode));
	if (!s_vnode) {
		ret = -ENOMEM;
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("Failed to allocate socket vnode: Out of memory\n"));
		goto ERR_MALLOC_VNODE;
	}

	/* Put things together, and fill out necessary fields */
	file->vfscore_file.fd = vfs_fd;
	file->vfscore_file.f_flags = UK_FWRITE | UK_FREAD;
	file->vfscore_file.f_count = 1;
	file->vfscore_file.f_dentry = s_dentry;

	s_dentry->d_vnode = s_vnode;

	s_vnode->v_op = v_op;
	uk_mutex_init(&s_vnode->v_lock);
	s_vnode->v_refcnt = 1;
	s_vnode->v_data = file;

	file->sock_fd = sock_fd;
	LWIP_DEBUGF(SOCKETS_DEBUG, ("Allocated socket %d (%x)\n",
				    file->vfscore_file.fd,
				    file->sock_fd));

	/* Storing the information within the vfs structure */
	ret = vfscore_install_fd(vfs_fd, &file->vfscore_file);
	if (ret) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("Failed to install socket fd\n"));
		goto ERR_VFS_INSTALL;
	}

	/* Return file descriptor of our socket */
	return vfs_fd;

ERR_VFS_INSTALL:
	uk_free(uk_alloc_get_default(), s_vnode);
ERR_MALLOC_VNODE:
	uk_free(uk_alloc_get_default(), s_dentry);
ERR_MALLOC_DENTRY:
	uk_free(uk_alloc_get_default(), file);
ERR_MALLOC_FILE:
	vfscore_put_fd(vfs_fd);
ERR_EXIT:
	UK_ASSERT(ret < 0);
	return ret;
}

static int sock_net_close(struct vnode *s_vnode,
			  struct vfscore_file *vfscore_file __maybe_unused)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = s_vnode->v_data;
	LWIP_DEBUGF(SOCKETS_DEBUG, ("%s fd:%d lwip_fd:%d\n",
				    __func__,
				    file->vfscore_file.fd,
				    file->sock_fd));

	UK_ASSERT(vfscore_file->f_dentry->d_vnode == s_vnode);
	UK_ASSERT(s_vnode->v_refcnt == 1);

	/* Close and release the lwip socket */
	ret = lwip_close(file->sock_fd);
	/* Release the file descriptor number */
	vfscore_put_fd(file->vfscore_file.fd);
	/* Free socket vnode */
	uk_free(uk_alloc_get_default(), file->vfscore_file.f_dentry->d_vnode);
	/* Free socket dentry */
	uk_free(uk_alloc_get_default(), file->vfscore_file.f_dentry);
	/* Free socket file */
	uk_free(uk_alloc_get_default(), file);
	return ret;
}

static ssize_t sock_net_write(struct vnode *s_vnode,
			      struct uio *buf, int ioflag __unused)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = s_vnode->v_data;
	LWIP_DEBUGF(SOCKETS_DEBUG, ("%s fd:%d lwip_fd:%d\n",
				    __func__,
				    file->vfscore_file.fd,
				    file->sock_fd));
	ret = lwip_writev(file->sock_fd, buf->uio_iov, buf->uio_iovcnt);
	return ret;
}

static ssize_t sock_net_read(struct vnode *s_vnode,
			     struct vfscore_file *vfscore_file __unused,
			     struct uio *buf, int ioflag __unused)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = s_vnode->v_data;
	LWIP_DEBUGF(SOCKETS_DEBUG, ("%s fd:%d lwip_fd:%d\n",
				    __func__,
				    file->vfscore_file.fd,
				    file->sock_fd));
	ret = lwip_readv(file->sock_fd, buf->uio_iov, buf->uio_iovcnt);
	return ret;
}

static struct vnops sock_net_fops = {
	.vop_close = sock_net_close,
	.vop_write = sock_net_write,
	.vop_read  = sock_net_read,
};

int socket(int domain, int type, int protocol)
{
	int ret = 0;
	int vfs_fd = 0xff;
	int sock_fd = 0;

	/* Create lwip_socket */
	sock_fd = lwip_socket(domain, type, protocol);
	if (sock_fd < 0) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("failed to create socket %d\n",
					    errno));
		ret = -1;
		goto EXIT;
	}

	/* Allocate the file descriptor */
	vfs_fd = sock_fd_alloc(&sock_net_fops, sock_fd);
	if (vfs_fd < 0) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to allocate descriptor %d\n",
			     errno));
		ret = -1;
		/* Setting the errno */
		SOCK_NET_SET_ERRNO(vfs_fd);
		goto LWIP_SOCKET_CLEANUP;
	}

	/* Returning the file descriptor to the user */
	ret = vfs_fd;
EXIT:
	return ret;
LWIP_SOCKET_CLEANUP:
	/* Cleanup the lwip socket */
	lwip_close(sock_fd);
	goto EXIT;
}

int accept(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	int ret = 0;
	struct sock_net_file *file;
	int sock_fd, vfs_fd;

	file = sock_net_file_get(s);
	if (PTRISERR(file)) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to accept incoming connection\n"));
		ret = -1;
		/* Setting the errno */
		SOCK_NET_SET_ERRNO(PTR2ERR(file));
		goto EXIT;
	}

	/* Accept an incoming connection */
	sock_fd = lwip_accept(file->sock_fd, addr, addrlen);
	if (sock_fd < 0) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to accept incoming connection\n"));
		ret = -1;
		goto EXIT_FDROP;
	}

	/* Allocate the file descriptor for the accepted connection */
	vfs_fd = sock_fd_alloc(&sock_net_fops, sock_fd);
	if (vfs_fd < 0) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to allocate descriptor for accepted connection\n"));
		ret = -1;
		/* Setting the errno */
		SOCK_NET_SET_ERRNO(vfs_fd);
		goto LWIP_SOCKET_CLEANUP;
	}
	ret = vfs_fd;
EXIT_FDROP:
	vfscore_put_file(&file->vfscore_file); /* release refcount */
EXIT:
	return ret;

LWIP_SOCKET_CLEANUP:
	lwip_close(sock_fd);
	goto EXIT_FDROP;
}

int bind(int s, const struct sockaddr *name, socklen_t namelen)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = sock_net_file_get(s);
	if (PTRISERR(file)) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to identify socket descriptor\n"));
		ret = -1;
		/* Setting the errno */
		SOCK_NET_SET_ERRNO(PTR2ERR(file));
		goto EXIT;
	}
	/* Bind an incoming connection */
	ret = lwip_bind(file->sock_fd, name, namelen);
	if (ret < 0) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to bind with socket\n"));
		ret = -1;
		goto EXIT_FDROP;
	}
EXIT_FDROP:
	vfscore_put_file(&file->vfscore_file); /* release refcount */
EXIT:
	return ret;
}

int shutdown(int s, int how)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = sock_net_file_get(s);
	if (PTRISERR(file)) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to identify socket descriptor\n"));
		ret = -1;
		/* Setting the errno */
		SOCK_NET_SET_ERRNO(PTR2ERR(file));
		goto EXIT;
	}
	/* Shutdown of the descriptor */
	ret = lwip_shutdown(file->sock_fd, how);
	vfscore_put_file(&file->vfscore_file); /* release refcount */
EXIT:
	return ret;
}

int getpeername(int s, struct sockaddr *name, socklen_t *namelen)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = sock_net_file_get(s);
	if (PTRISERR(file)) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("failed to identify socket\n"));
		ret = -1;
		SOCK_NET_SET_ERRNO(PTR2ERR(file));
		goto EXIT;
	}
	ret = lwip_getpeername(file->sock_fd, name, namelen);
	vfscore_put_file(&file->vfscore_file); /* release refcount */
EXIT:
	return ret;
}

int getsockname(int s, struct sockaddr *name, socklen_t *namelen)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = sock_net_file_get(s);
	if (PTRISERR(file)) {
		LWIP_DEBUGF(SOCKETS_DEBUG, ("failed to identify socket\n"));
		ret = -1;
		SOCK_NET_SET_ERRNO(PTR2ERR(file));
		goto EXIT;
	}
	ret = lwip_getsockname(file->sock_fd, name, namelen);
	vfscore_put_file(&file->vfscore_file); /* release refcount */
EXIT:
	return ret;
}

int getsockopt(int s, int level, int optname, void *optval, socklen_t *optlen)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = sock_net_file_get(s);
	if (PTRISERR(file)) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to identify socket descriptor\n"));
		ret = -1;
		SOCK_NET_SET_ERRNO(PTR2ERR(file));
		goto EXIT;
	}
	ret = lwip_getsockopt(file->sock_fd, level, optname, optval, optlen);
	vfscore_put_file(&file->vfscore_file); /* release refcount */
EXIT:
	return ret;
}

int setsockopt(int s, int level, int optname, const void *optval,
	       socklen_t optlen)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = sock_net_file_get(s);
	if (PTRISERR(file)) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to identify socket descriptor\n"));
		ret = -1;
		SOCK_NET_SET_ERRNO(PTR2ERR(file));
		goto EXIT;
	}
	ret = lwip_setsockopt(file->sock_fd, level, optname, optval, optlen);
	vfscore_put_file(&file->vfscore_file); /* release refcount */
EXIT:
	return ret;
}

int connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = sock_net_file_get(s);
	if (PTRISERR(file)) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to identify socket descriptor\n"));
		ret = -1;
		SOCK_NET_SET_ERRNO(PTR2ERR(file));
		goto EXIT;
	}
	ret = lwip_connect(file->sock_fd, name, namelen);
	vfscore_put_file(&file->vfscore_file); /* release refcount */
EXIT:
	return ret;
}

int listen(int s, int backlog)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = sock_net_file_get(s);
	if (PTRISERR(file)) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to identify socket descriptor\n"));
		ret = -1;
		SOCK_NET_SET_ERRNO(PTR2ERR(file));
		goto EXIT;
	}
	ret = lwip_listen(file->sock_fd, backlog);
	vfscore_put_file(&file->vfscore_file); /* release refcount */
EXIT:
	return ret;
}

int recv(int s, void *mem, size_t len, int flags)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = sock_net_file_get(s);
	if (PTRISERR(file)) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to identify socket descriptor\n"));
		ret = -1;
		SOCK_NET_SET_ERRNO(PTR2ERR(file));
		goto EXIT;
	}
	ret = lwip_recv(file->sock_fd, mem, len, flags);
	vfscore_put_file(&file->vfscore_file); /* release refcount */
EXIT:
	return ret;
}

int recvfrom(int s, void *mem, size_t len, int flags,
		      struct sockaddr *from, socklen_t *fromlen)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = sock_net_file_get(s);
	if (PTRISERR(file)) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to identify socket descriptor\n"));
		ret = -1;
		SOCK_NET_SET_ERRNO(PTR2ERR(file));
		goto EXIT;
	}
	ret = lwip_recvfrom(file->sock_fd, mem, len, flags, from, fromlen);
	vfscore_put_file(&file->vfscore_file); /* release refcount */
EXIT:
	return ret;
}

int send(int s, const void *dataptr, size_t size, int flags)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = sock_net_file_get(s);
	if (PTRISERR(file)) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to identify socket descriptor\n"));
		ret = -1;
		SOCK_NET_SET_ERRNO(PTR2ERR(file));
		goto EXIT;
	}
	ret = lwip_send(file->sock_fd, dataptr, size, flags);
	vfscore_put_file(&file->vfscore_file); /* release refcount */
EXIT:
	return ret;
}

int sendmsg(int s, const struct msghdr *message, int flags)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = sock_net_file_get(s);
	if (PTRISERR(file)) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to identify socket descriptor\n"));
		ret = -1;
		SOCK_NET_SET_ERRNO(PTR2ERR(file));
		goto EXIT;
	}
	ret = lwip_sendmsg(file->sock_fd, message, flags);
	vfscore_put_file(&file->vfscore_file); /* release refcount */
EXIT:
	return ret;
}

int sendto(int s, const void *dataptr, size_t size, int flags,
		    const struct sockaddr *to, socklen_t tolen)
{
	int ret = 0;
	struct sock_net_file *file = NULL;

	file = sock_net_file_get(s);
	if (PTRISERR(file)) {
		LWIP_DEBUGF(SOCKETS_DEBUG,
			    ("failed to identify socket descriptor\n"));
		ret = -1;
		SOCK_NET_SET_ERRNO(PTR2ERR(file));
		goto EXIT;
	}
	ret = lwip_sendto(file->sock_fd, dataptr, size, flags, to, tolen);
	vfscore_put_file(&file->vfscore_file); /* release refcount */
EXIT:
	return ret;
}
