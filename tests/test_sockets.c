/* SPDX-License-Identifier: BSD-3-Clause */
/* Copyright (c) 2026, Unikraft GmbH and The Unikraft Authors.
 * Licensed under the BSD-3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 */

#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <uk/test.h>

#define TEST_PORT	7350

static int test_connect(int port, int *cli, int *srv)
{
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_port = htons(port),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int lfd;

	*cli = -1;
	*srv = -1;
	lfd = socket(AF_INET, SOCK_STREAM, 0);
	if (lfd < 0)
		return -1;
	if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) ||
	    listen(lfd, 1))
		goto out;
	*cli = socket(AF_INET, SOCK_STREAM, 0);
	if (*cli < 0 || connect(*cli, (struct sockaddr *)&sa, sizeof(sa)))
		goto out;
	*srv = accept(lfd, NULL, NULL);
out:
	close(lfd);
	return *srv < 0 ? -1 : 0;
}

static ssize_t test_read_eof(int cli, int srv)
{
	char c;

	close(cli);
	return read(srv, &c, 1);
}

UK_TESTCASE(lwip_sockets, read_at_eof_keeps_errno)
{
	int cli, srv;
	ssize_t n;
	char c;

	UK_TEST_ASSERT(test_connect(TEST_PORT, &cli, &srv) == 0);
	close(cli);

	errno = EDOM;
	n = read(srv, &c, 1);

	UK_TEST_EXPECT_SNUM_EQ(n, 0);
	UK_TEST_EXPECT_SNUM_EQ(errno, EDOM);

	close(srv);
}

UK_TESTCASE(lwip_sockets, socket_at_eof_is_readable)
{
	struct pollfd p;
	int cli, srv;

	UK_TEST_ASSERT(test_connect(TEST_PORT + 1, &cli, &srv) == 0);
	UK_TEST_EXPECT_SNUM_EQ(test_read_eof(cli, srv), 0);

	p = (struct pollfd){ .fd = srv, .events = POLLIN | POLLRDHUP };
	UK_TEST_EXPECT_SNUM_EQ(poll(&p, 1, 0), 1);
	UK_TEST_EXPECT(p.revents & POLLIN);
	UK_TEST_EXPECT(p.revents & POLLRDHUP);

	close(srv);
}

UK_TESTCASE(lwip_sockets, reset_socket_reports_err_and_hup)
{
	struct pollfd p;
	int cli, srv;

	UK_TEST_ASSERT(test_connect(TEST_PORT + 2, &cli, &srv) == 0);
	UK_TEST_EXPECT_SNUM_EQ(test_read_eof(cli, srv), 0);

	UK_TEST_EXPECT_SNUM_EQ(write(srv, "x", 1), 1);
	p = (struct pollfd){ .fd = srv, .events = 0 };
	UK_TEST_EXPECT_SNUM_EQ(poll(&p, 1, 1000), 1);

	p = (struct pollfd){ .fd = srv, .events = POLLIN | POLLOUT };
	UK_TEST_EXPECT_SNUM_EQ(poll(&p, 1, 0), 1);
	UK_TEST_EXPECT(p.revents & POLLERR);
	UK_TEST_EXPECT(p.revents & POLLHUP);
	UK_TEST_EXPECT(p.revents & POLLIN);

	close(srv);
}

uk_testsuite_register(lwip_sockets, NULL);
