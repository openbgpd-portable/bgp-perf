/*	$OpenBSD: config.c,v 1.113 2024/12/13 19:21:03 claudio Exp $ */

/*
 * Copyright (c) 2003, 2004, 2005 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bgpd.h"
#include "session.h"
#include "log.h"

int		host_ip(const char *, struct bgpd_addr *, uint8_t *);
void		free_networks(struct network_head *);

struct bgpd_config *
new_config(void)
{
	struct bgpd_config	*conf;

	if ((conf = calloc(1, sizeof(struct bgpd_config))) == NULL)
		fatal(NULL);

	if ((conf->listen_addrs = calloc(1, sizeof(struct listen_addrs))) ==
	    NULL)
		fatal(NULL);

	/* init the various list for later */
	RB_INIT(&conf->peers);
	TAILQ_INIT(&conf->networks);
	TAILQ_INIT(conf->listen_addrs);

	return (conf);
}

void
copy_config(struct bgpd_config *to, struct bgpd_config *from)
{
	to->flags = from->flags;
	to->log = from->log;
	to->default_tableid = from->default_tableid;
	to->bgpid = from->bgpid;
	to->as = from->as;
	to->short_as = from->short_as;
	to->holdtime = from->holdtime;
	to->min_holdtime = from->min_holdtime;
	to->staletime = from->staletime;
	to->connectretry = from->connectretry;
	free(to->ometric_path);
	if ((to->ometric_path = strdup(from->ometric_path)) == NULL)
		fatal(NULL);
}

static void
filterset_free(struct filter_set_head *sh)
{
	struct filter_set *s;

	if (sh == NULL)
		return;

	while ((s = TAILQ_FIRST(sh)) != NULL) {
		TAILQ_REMOVE(sh, s, entry);
		free(s);
	}
}

const char *
filterset_name(enum action_types type)
{
	switch (type) {
	case ACTION_SET_LOCALPREF:
	case ACTION_SET_RELATIVE_LOCALPREF:
		return ("localpref");
	case ACTION_SET_MED:
	case ACTION_SET_RELATIVE_MED:
		return ("metric");
	case ACTION_SET_WEIGHT:
	case ACTION_SET_RELATIVE_WEIGHT:
		return ("weight");
	case ACTION_SET_PREPEND_SELF:
		return ("prepend-self");
	case ACTION_SET_PREPEND_PEER:
		return ("prepend-peer");
	case ACTION_SET_COMMUNITY:
		return ("community");
	case ACTION_DEL_COMMUNITY:
		return ("community delete");
	case ACTION_SET_ORIGIN:
		return ("origin");
	}

	fatalx("filterset_name: got lost");
}

/*
 * this function is a bit more complicated than a memcmp() because there are
 * types that need to be considered equal e.g. ACTION_SET_MED and
 * ACTION_SET_RELATIVE_MED. Also ACTION_SET_COMMUNITY and ACTION_SET_NEXTHOP
 * need some special care. It only checks the types and not the values so
 * it does not do a real compare.
 */
int
filterset_cmp(struct filter_set *a, struct filter_set *b)
{
	if (strcmp(filterset_name(a->type), filterset_name(b->type)))
		return (a->type - b->type);

	if (a->type == ACTION_SET_COMMUNITY ||
	    a->type == ACTION_DEL_COMMUNITY) {	/* a->type == b->type */
		return (memcmp(&a->action.community, &b->action.community,
		    sizeof(a->action.community)));
	}

	/* equal */
	return (0);
}

/*
 * move filterset from source to dest. dest will be initialized first.
 * After the move source is an empty list.
 */
void
filterset_move(struct filter_set_head *source, struct filter_set_head *dest)
{
	TAILQ_INIT(dest);
	if (source == NULL)
		return;
	TAILQ_CONCAT(dest, source, entry);
}


void
network_free(struct network *n)
{
	filterset_free(&n->net.attrset);
	free(n);
}

void
free_networks(struct network_head *networks)
{
	struct network		*n;

	while ((n = TAILQ_FIRST(networks)) != NULL) {
		TAILQ_REMOVE(networks, n, entry);
		network_free(n);
	}
}

void
free_config(struct bgpd_config *conf)
{
	struct peer		*p, *next;
	struct listen_addr	*la;

	free_networks(&conf->networks);

	while ((la = TAILQ_FIRST(conf->listen_addrs)) != NULL) {
		TAILQ_REMOVE(conf->listen_addrs, la, entry);
		free(la);
	}
	free(conf->listen_addrs);

	RB_FOREACH_SAFE(p, peer_head, &conf->peers, next) {
		RB_REMOVE(peer_head, &conf->peers, p);
		free(p);
	}

	free(conf->ometric_path);
	free(conf);
}

uint32_t
get_bgpid(void)
{
	struct ifaddrs		*ifap, *ifa;
	uint32_t		 ip = 0, cur, localnet;

	localnet = INADDR_LOOPBACK & IN_CLASSA_NET;

	if (getifaddrs(&ifap) == -1)
		fatal("getifaddrs");

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL ||
		    ifa->ifa_addr->sa_family != AF_INET)
			continue;
		cur = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr;
		cur = ntohl(cur);
		if ((cur & localnet) == localnet)	/* skip 127/8 */
			continue;
		if (cur > ip)
			ip = cur;
	}
	freeifaddrs(ifap);

	return (ip);
}

int
host(const char *s, struct bgpd_addr *h, uint8_t *len)
{
	int			 mask = 128;
	char			*p, *ps;
	const char		*errstr;

	if ((ps = strdup(s)) == NULL)
		fatal("%s: strdup", __func__);

	if ((p = strrchr(ps, '/')) != NULL) {
		mask = strtonum(p+1, 0, 128, &errstr);
		if (errstr) {
			log_warnx("prefixlen is %s: %s", errstr, p);
			free(ps);
			return (0);
		}
		p[0] = '\0';
	}

	memset(h, 0, sizeof(*h));

	if (host_ip(ps, h, len) == 0) {
		free(ps);
		return (0);
	}

	if (p != NULL)
		*len = mask;

	free(ps);
	return (1);
}

int
host_ip(const char *s, struct bgpd_addr *h, uint8_t *len)
{
	struct addrinfo		 hints, *res;
	int			 bits;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM; /*dummy*/
	hints.ai_flags = AI_NUMERICHOST;
	if (getaddrinfo(s, NULL, &hints, &res) == 0) {
		*len = res->ai_family == AF_INET6 ? 128 : 32;
		sa2addr(res->ai_addr, h, NULL);
		freeaddrinfo(res);
	} else {	/* ie. for 10/8 parsing */
		if ((bits = inet_net_pton(AF_INET, s, &h->v4,
		    sizeof(h->v4))) == -1)
			return (0);
		*len = bits;
		h->aid = AID_INET;
	}

	return (1);
}

int
prepare_listeners(struct bgpd_config *conf)
{
	struct listen_addr	*la, *next;
	int			 opt = 1;
	int			 r = 0;

	for (la = TAILQ_FIRST(conf->listen_addrs); la != NULL; la = next) {
		next = TAILQ_NEXT(la, entry);
		if ((la->fd = socket(la->sa.ss_family,
		    SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    IPPROTO_TCP)) == -1) {
			if (la->flags & DEFAULT_LISTENER && (errno ==
			    EAFNOSUPPORT || errno == EPROTONOSUPPORT)) {
				TAILQ_REMOVE(conf->listen_addrs, la, entry);
				free(la);
				continue;
			} else
				fatal("socket");
		}

		opt = 1;
		if (setsockopt(la->fd, SOL_SOCKET, SO_REUSEADDR,
		    &opt, sizeof(opt)) == -1)
			fatal("setsockopt SO_REUSEADDR");

		if (bind(la->fd, (struct sockaddr *)&la->sa, la->sa_len) ==
		    -1) {
			switch (la->sa.ss_family) {
			case AF_INET:
				log_warn("cannot bind to %s:%u",
				    log_sockaddr((struct sockaddr *)&la->sa,
				    la->sa_len), ntohs(((struct sockaddr_in *)
				    &la->sa)->sin_port));
				break;
			case AF_INET6:
				log_warn("cannot bind to [%s]:%u",
				    log_sockaddr((struct sockaddr *)&la->sa,
				    la->sa_len), ntohs(((struct sockaddr_in6 *)
				    &la->sa)->sin6_port));
				break;
			default:
				log_warn("cannot bind to %s",
				    log_sockaddr((struct sockaddr *)&la->sa,
				    la->sa_len));
				break;
			}
			close(la->fd);
			TAILQ_REMOVE(conf->listen_addrs, la, entry);
			free(la);
			r = -1;
			continue;
		}
	}

	return (r);
}
