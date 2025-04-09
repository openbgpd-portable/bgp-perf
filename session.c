/*	$OpenBSD: session.c,v 1.518 2025/02/20 19:47:31 claudio Exp $ */

/*
 * Copyright (c) 2003, 2004, 2005 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2017 Peter van Dijk <peter.van.dijk@powerdns.com>
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

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <limits.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "bgpd.h"
#include "session.h"
#include "log.h"

#define PFD_LISTENERS_START	0

#define MAX_TIMEOUT		240

void	session_sighdlr(int);
void	init_peer(struct peer *, struct bgpd_config *);
int	session_setup_socket(struct peer *);
void	session_accept(struct bgpd_config *, int);
void	session_graceful_stop(struct peer *);

struct bgpd_sysdep	 sysdep;
u_int			 peer_cnt;

extern volatile sig_atomic_t	 quit;

static inline int
peer_compare(const struct peer *a, const struct peer *b)
{
	return a->conf.id - b->conf.id;
}

RB_GENERATE(peer_head, peer, entry, peer_compare);

static void
setup_listeners(struct bgpd_config *conf, u_int *la_cnt)
{
	int			 ttl = 255;
	struct listen_addr	*la;
	u_int			 cnt = 0;

	TAILQ_FOREACH(la, conf->listen_addrs, entry) {
		cnt++;

		if (la->flags & LISTENER_LISTENING)
			continue;

		if (la->fd == -1) {
			log_warn("cannot establish listener on %s: invalid fd",
			    log_sockaddr((struct sockaddr *)&la->sa,
			    la->sa_len));
			continue;
		}

		if (tcp_md5_prep_listener(la, &conf->peers) == -1)
			fatal("tcp_md5_prep_listener");

		/* set ttl to 255 so that ttl-security works */
		if (la->sa.ss_family == AF_INET && setsockopt(la->fd,
		    IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1) {
			log_warn("setup_listeners setsockopt TTL");
			continue;
		}
		if (la->sa.ss_family == AF_INET6 && setsockopt(la->fd,
		    IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)) == -1) {
			log_warn("setup_listeners setsockopt hoplimit");
			continue;
		}

		if (listen(la->fd, MAX_BACKLOG)) {
			close(la->fd);
			fatal("listen");
		}

		la->flags |= LISTENER_LISTENING;

		log_info("listening on %s",
		    log_sockaddr((struct sockaddr *)&la->sa, la->sa_len));
	}

	*la_cnt = cnt;
}

void
session_main(struct bgpd_config *conf)
{
	unsigned int		 i, j, idx_peers, idx_listeners;
	u_int			 pfd_elms = 0, peer_l_elms = 0;
	u_int			 listener_cnt;
	u_int			 new_cnt;
	struct passwd		*pw;
	struct peer		*p, **peer_l = NULL, *next;
	struct pollfd		*pfd = NULL;
	struct listen_addr	*la;
	void			*newp;
	monotime_t		 now, timeout;
	short			 events;

	if ((pw = getpwnam(BGPD_USER)) == NULL)
		fatal(NULL);

	setproctitle("session engine");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("can't drop privileges");

	if (pledge("stdio inet rpath wpath cpath fattr", NULL) == -1)
		fatal("pledge");

	listener_cnt = 0;
	peer_cnt = 0;
	setup_listeners(conf, &listener_cnt);

	log_info("session engine ready");

	while (quit == 0) {
		/* check for peers to be initialized or deleted */
		RB_FOREACH_SAFE(p, peer_head, &conf->peers, next) {
			/* new peer that needs init? */
			if (p->state == STATE_NONE)
				init_peer(p, conf);
		}

		if (peer_cnt > peer_l_elms) {
			if ((newp = reallocarray(peer_l, peer_cnt,
			    sizeof(struct peer *))) == NULL) {
				/* panic for now */
				log_warn("could not resize peer_l from %u -> %u"
				    " entries", peer_l_elms, peer_cnt);
				fatalx("exiting");
			}
			peer_l = newp;
			peer_l_elms = peer_cnt;
		}

		new_cnt = PFD_LISTENERS_START + listener_cnt + peer_cnt;
		if (new_cnt > pfd_elms) {
			if ((newp = reallocarray(pfd, new_cnt,
			    sizeof(struct pollfd))) == NULL) {
				/* panic for now */
				log_warn("could not resize pfd from %u -> %u"
				    " entries", pfd_elms, new_cnt);
				fatalx("exiting");
			}
			pfd = newp;
			pfd_elms = new_cnt;
		}

		memset(pfd, 0, sizeof(struct pollfd) * pfd_elms);

		i = PFD_LISTENERS_START;
		TAILQ_FOREACH(la, conf->listen_addrs, entry) {
			pfd[i].fd = la->fd;
			pfd[i].events = POLLIN;
			i++;
		}
		idx_listeners = i;
		now = getmonotime();
		timeout = monotime_add(now, monotime_from_sec(MAX_TIMEOUT));

		/* check and set gloabl timers */
		global_timer_handle(conf, now);
		timeout = global_timer_next(timeout);

		RB_FOREACH(p, peer_head, &conf->peers) {
			monotime_t nextaction;
			struct timer *pt;

			/* check timers */
			if ((pt = timer_nextisdue(&p->timers, now)) != NULL) {
				switch (pt->type) {
				case Timer_Hold:
					bgp_fsm(p, EVNT_TIMER_HOLDTIME, NULL);
					break;
				case Timer_SendHold:
					bgp_fsm(p, EVNT_TIMER_SENDHOLD, NULL);
					break;
				case Timer_ConnectRetry:
					bgp_fsm(p, EVNT_TIMER_CONNRETRY, NULL);
					break;
				case Timer_Keepalive:
					bgp_fsm(p, EVNT_TIMER_KEEPALIVE, NULL);
					break;
				case Timer_IdleHold:
					bgp_fsm(p, EVNT_START, NULL);
					break;
				case Timer_IdleHoldReset:
					p->IdleHoldTime =
					    INTERVAL_IDLE_HOLD_INITIAL;
					p->errcnt = 0;
					timer_stop(&p->timers,
					    Timer_IdleHoldReset);
					break;
				case Timer_CarpUndemote:
					timer_stop(&p->timers,
					    Timer_CarpUndemote);
					break;
				case Timer_RestartTimeout:
					timer_stop(&p->timers,
					    Timer_RestartTimeout);
					session_graceful_stop(p);
					break;
				case Timer_SessionDown:
					timer_stop(&p->timers,
					    Timer_SessionDown);
					break;
				default:
					fatalx("King Bula lost in time");
				}
			}
			nextaction = timer_nextduein(&p->timers);
			if (monotime_valid(nextaction) &&
			    monotime_cmp(nextaction, timeout) < 0)
				timeout = nextaction;

			/* are we waiting for a write? */
			events = POLLIN;
			if (msgbuf_queuelen(p->wbuf) > 0 ||
			    p->state == STATE_CONNECT)
				events |= POLLOUT;
			/* is there still work to do? */
			if (p->rpending)
				timeout = monotime_clear();

			/* poll events */
			if (p->fd != -1 && events != 0) {
				pfd[i].fd = p->fd;
				pfd[i].events = events;
				peer_l[i - idx_listeners] = p;
				i++;
			}
		}

		idx_peers = i;

		if (i > pfd_elms)
			fatalx("poll pfd overflow");

		timeout = monotime_sub(timeout, getmonotime());
		if (!monotime_valid(timeout))
			timeout = monotime_clear();

		if (poll(pfd, i, monotime_to_msec(timeout)) == -1) {
			if (errno == EINTR)
				continue;
			fatal("poll error");
		}

		for (j = PFD_LISTENERS_START; j < idx_listeners; j++)
			if (pfd[j].revents & POLLIN)
				session_accept(conf, pfd[j].fd);

		for (; j < idx_peers; j++)
			session_dispatch_msg(&pfd[j],
			    peer_l[j - idx_listeners]);

		RB_FOREACH(p, peer_head, &conf->peers)
			session_process_msg(p);
	}

	RB_FOREACH_SAFE(p, peer_head, &conf->peers, next) {
		session_stop(p, ERR_CEASE_ADMIN_DOWN, "bgpd shutting down");
		timer_remove_all(&p->timers);
		tcp_md5_del_listener(conf, p);
		RB_REMOVE(peer_head, &conf->peers, p);
		free(p);
	}

	free_config(conf);
	free(peer_l);
	free(pfd);

	log_info("session engine exiting");
	exit(0);
}

void
init_peer(struct peer *p, struct bgpd_config *c)
{
	TAILQ_INIT(&p->timers);
	p->fd = -1;
	if (p->wbuf != NULL)
		fatalx("%s: msgbuf already set", __func__);
	if ((p->wbuf = msgbuf_new_reader(MSGSIZE_HEADER, parse_header, p)) ==
	    NULL)
		fatal(NULL);

	p->depend_ok = 1;

	/* apply holdtime and min_holdtime settings */
	if (p->conf.holdtime == 0)
		p->conf.holdtime = c->holdtime;
	if (p->conf.min_holdtime == 0)
		p->conf.min_holdtime = c->min_holdtime;
	if (p->conf.connectretry == 0)
		p->conf.connectretry = c->connectretry;
	p->local_bgpid = p->conf.bgpid;

	peer_cnt++;

	change_state(p, STATE_IDLE, EVNT_NONE);
	if (p->conf.down)
		timer_stop(&p->timers, Timer_IdleHold); /* no autostart */
	else
		timer_set(&p->timers, Timer_IdleHold, SESSION_CLEAR_DELAY);

	p->stats.last_updown = getmonotime();
}

int
session_dispatch_msg(struct pollfd *pfd, struct peer *p)
{
	socklen_t	len;
	int		error;

	if (p->state == STATE_CONNECT) {
		if (pfd->revents & POLLOUT) {
			if (pfd->revents & POLLIN) {
				/* error occurred */
				len = sizeof(error);
				if (getsockopt(pfd->fd, SOL_SOCKET, SO_ERROR,
				    &error, &len) == -1 || error) {
					if (error)
						errno = error;
					if (errno != p->lasterr) {
						log_peer_warn(&p->conf,
						    "socket error");
						p->lasterr = errno;
					}
					bgp_fsm(p, EVNT_CON_OPENFAIL, NULL);
					return (1);
				}
			}
			bgp_fsm(p, EVNT_CON_OPEN, NULL);
			return (1);
		}
		if (pfd->revents & POLLHUP) {
			bgp_fsm(p, EVNT_CON_OPENFAIL, NULL);
			return (1);
		}
		if (pfd->revents & (POLLERR|POLLNVAL)) {
			bgp_fsm(p, EVNT_CON_FATAL, NULL);
			return (1);
		}
		return (0);
	}

	if (pfd->revents & POLLHUP) {
		bgp_fsm(p, EVNT_CON_CLOSED, NULL);
		return (1);
	}
	if (pfd->revents & (POLLERR|POLLNVAL)) {
		bgp_fsm(p, EVNT_CON_FATAL, NULL);
		return (1);
	}

	if (pfd->revents & POLLOUT && msgbuf_queuelen(p->wbuf) > 0) {
		if (ibuf_write(p->fd, p->wbuf) == -1) {
			if (errno == EPIPE)
				log_peer_warnx(&p->conf, "Connection closed");
			else
				log_peer_warn(&p->conf, "write error");
			bgp_fsm(p, EVNT_CON_FATAL, NULL);
			return (1);
		}
		p->stats.last_write = getmonotime();
		start_timer_sendholdtime(p);
		if (!(pfd->revents & POLLIN))
			return (1);
	}

	if (p->fd != -1 && pfd->revents & POLLIN) {
		switch (ibuf_read(p->fd, p->wbuf)) {
		case -1:
			if (p->state == STATE_IDLE)
				/* error already handled before */
				return (1);
			log_peer_warn(&p->conf, "read error");
			bgp_fsm(p, EVNT_CON_FATAL, NULL);
			return (1);
		case 0:
			bgp_fsm(p, EVNT_CON_CLOSED, NULL);
			return (1);
		}
		p->stats.last_read = getmonotime();
		return (1);
	}
	return (0);
}

void
session_accept(struct bgpd_config *conf, int listenfd)
{
	int			 connfd;
	socklen_t		 len;
	struct sockaddr_storage	 cliaddr, myaddr;
	struct peer		*p = NULL;

	len = sizeof(cliaddr);
	if ((connfd = accept4(listenfd,
	    (struct sockaddr *)&cliaddr, &len,
	    SOCK_CLOEXEC | SOCK_NONBLOCK)) == -1) {
		if (errno != EWOULDBLOCK && errno != EINTR &&
		    errno != ECONNABORTED)
			log_warn("accept");
		return;
	}

	len = sizeof(myaddr);
	if (getsockname(connfd, (struct sockaddr *)&myaddr, &len) == -1) {
		close(connfd);
		return;
	}
	p = getpeerbyip(conf, (struct sockaddr *)&cliaddr,
	    (struct sockaddr *)&myaddr);

	if (p != NULL && p->state == STATE_IDLE && p->errcnt < 2) {
		if (timer_running(&p->timers, Timer_IdleHold, NULL)) {
			/* fast reconnect after clear */
			p->passive = 1;
			bgp_fsm(p, EVNT_START, NULL);
		}
	}

	if (p != NULL &&
	    (p->state == STATE_CONNECT || p->state == STATE_ACTIVE)) {
		if (p->fd != -1) {
			if (p->state == STATE_CONNECT)
				session_close(p);
			else {
				close(connfd);
				return;
			}
		}

open:
		if (p->auth_conf.method != AUTH_NONE && sysdep.no_pfkey) {
			log_peer_warnx(&p->conf,
			    "ipsec or md5sig configured but not available");
			close(connfd);
			return;
		}

		if (tcp_md5_check(connfd, &p->auth_conf) == -1) {
			log_peer_warn(&p->conf, "check md5sig");
			close(connfd);
			return;
		}
		p->fd = connfd;
		if (session_setup_socket(p)) {
			close(connfd);
			return;
		}
		bgp_fsm(p, EVNT_CON_OPEN, NULL);
		return;
	} else if (p != NULL && p->state == STATE_ESTABLISHED &&
	    p->capa.neg.grestart.restart == 2) {
		/* first do the graceful restart dance */
		change_state(p, STATE_CONNECT, EVNT_CON_CLOSED);
		/* then do part of the open dance */
		goto open;
	} else {
		log_conn_attempt(p, (struct sockaddr *)&cliaddr, len);
		close(connfd);
	}
}

int
session_connect(struct peer *peer)
{
	struct sockaddr		*sa;
	struct bgpd_addr	*bind_addr;
	socklen_t		 sa_len;

	/*
	 * we do not need the overcomplicated collision detection RFC 1771
	 * describes; we simply make sure there is only ever one concurrent
	 * tcp connection per peer.
	 */
	if (peer->fd != -1)
		return (-1);

	if ((peer->fd = socket(aid2af(peer->conf.remote_addr.aid),
	    SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP)) == -1) {
		log_peer_warn(&peer->conf, "session_connect socket");
		bgp_fsm(peer, EVNT_CON_OPENFAIL, NULL);
		return (-1);
	}

	if (peer->auth_conf.method != AUTH_NONE && sysdep.no_pfkey) {
		log_peer_warnx(&peer->conf,
		    "ipsec or md5sig configured but not available");
		bgp_fsm(peer, EVNT_CON_OPENFAIL, NULL);
		return (-1);
	}

	if (tcp_md5_set(peer->fd, &peer->auth_conf,
	    &peer->conf.remote_addr) == -1)
		log_peer_warn(&peer->conf, "setting md5sig");

	/* if local-address is set we need to bind() */
	bind_addr = session_localaddr(peer);
	if ((sa = addr2sa(bind_addr, 0, &sa_len)) != NULL) {
		if (bind(peer->fd, sa, sa_len) == -1) {
			log_peer_warn(&peer->conf, "session_connect bind");
			bgp_fsm(peer, EVNT_CON_OPENFAIL, NULL);
			return (-1);
		}
	}

	if (session_setup_socket(peer)) {
		bgp_fsm(peer, EVNT_CON_OPENFAIL, NULL);
		return (-1);
	}

	sa = addr2sa(&peer->conf.remote_addr, peer->conf.remote_port, &sa_len);
	if (connect(peer->fd, sa, sa_len) == -1) {
		if (errno == EINPROGRESS)
			return (0);

		if (errno != peer->lasterr)
			log_peer_warn(&peer->conf, "connect");
		peer->lasterr = errno;
		bgp_fsm(peer, EVNT_CON_OPENFAIL, NULL);
		return (-1);
	}

	bgp_fsm(peer, EVNT_CON_OPEN, NULL);

	return (0);
}

int
session_setup_socket(struct peer *p)
{
	int	ttl = p->conf.distance;
	int	pre = IPTOS_PREC_INTERNETCONTROL;
	int	nodelay = 1;
	int	bsize;

	switch (p->conf.remote_addr.aid) {
	case AID_INET:
		/* set precedence, see RFC 1771 appendix 5 */
		if (setsockopt(p->fd, IPPROTO_IP, IP_TOS, &pre, sizeof(pre)) ==
		    -1) {
			log_peer_warn(&p->conf,
			    "session_setup_socket setsockopt TOS");
			return (-1);
		}

		if (p->conf.ebgp) {
			/*
			 * set TTL to foreign router's distance
			 * 1=direct n=multihop with ttlsec, we always use 255
			 */
			if (p->conf.ttlsec) {
				ttl = 256 - p->conf.distance;
				if (setsockopt(p->fd, IPPROTO_IP, IP_MINTTL,
				    &ttl, sizeof(ttl)) == -1) {
					log_peer_warn(&p->conf,
					    "session_setup_socket: "
					    "setsockopt MINTTL");
					return (-1);
				}
				ttl = 255;
			}

			if (setsockopt(p->fd, IPPROTO_IP, IP_TTL, &ttl,
			    sizeof(ttl)) == -1) {
				log_peer_warn(&p->conf,
				    "session_setup_socket setsockopt TTL");
				return (-1);
			}
		}
		break;
	case AID_INET6:
		if (setsockopt(p->fd, IPPROTO_IPV6, IPV6_TCLASS, &pre,
		    sizeof(pre)) == -1) {
			log_peer_warn(&p->conf, "session_setup_socket "
			    "setsockopt TCLASS");
			return (-1);
		}

		if (p->conf.ebgp) {
			/*
			 * set hoplimit to foreign router's distance
			 * 1=direct n=multihop with ttlsec, we always use 255
			 */
			if (p->conf.ttlsec) {
				ttl = 256 - p->conf.distance;
				if (setsockopt(p->fd, IPPROTO_IPV6,
				    IPV6_MINHOPCOUNT, &ttl, sizeof(ttl))
				    == -1) {
					log_peer_warn(&p->conf,
					    "session_setup_socket: "
					    "setsockopt MINHOPCOUNT");
					return (-1);
				}
				ttl = 255;
			}
			if (setsockopt(p->fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
			    &ttl, sizeof(ttl)) == -1) {
				log_peer_warn(&p->conf,
				    "session_setup_socket setsockopt hoplimit");
				return (-1);
			}
		}
		break;
	}

	/* set TCP_NODELAY */
	if (setsockopt(p->fd, IPPROTO_TCP, TCP_NODELAY, &nodelay,
	    sizeof(nodelay)) == -1) {
		log_peer_warn(&p->conf,
		    "session_setup_socket setsockopt TCP_NODELAY");
		return (-1);
	}

	/* limit bufsize. no biggie if it fails */
	bsize = 65535;
	setsockopt(p->fd, SOL_SOCKET, SO_RCVBUF, &bsize, sizeof(bsize));
	setsockopt(p->fd, SOL_SOCKET, SO_SNDBUF, &bsize, sizeof(bsize));

	return (0);
}

void
session_close(struct peer *peer)
{
	if (peer->fd != -1)
		close(peer->fd);

	peer->fd = -1;
}

#if 0
/*
 * compare the bgpd_addr with the sockaddr by converting the latter into
 * a bgpd_addr. Return true if the two are equal, including any scope
 */
static int
sa_equal(struct bgpd_addr *ba, struct sockaddr *b)
{
	struct bgpd_addr bb;

	sa2addr(b, &bb, NULL);
	return (memcmp(ba, &bb, sizeof(*ba)) == 0);
}
#endif

void
get_alternate_addr(struct bgpd_addr *local, struct bgpd_addr *remote,
    struct bgpd_addr *alt, unsigned int *scope)
{
#if 0
	struct ifaddrs	*ifap, *ifa, *match;
	int connected = 0;
	u_int8_t plen;

	if (getifaddrs(&ifap) == -1)
		fatal("getifaddrs");

	for (match = ifap; match != NULL; match = match->ifa_next) {
		if (match->ifa_addr == NULL)
			continue;
		if (match->ifa_addr->sa_family != AF_INET &&
		    match->ifa_addr->sa_family != AF_INET6)
			continue;
		if (sa_equal(local, match->ifa_addr)) {
			if (remote->aid == AID_INET6 &&
			    IN6_IS_ADDR_LINKLOCAL(&remote->v6)) {
				/* IPv6 LLA are by definition connected */
				connected = 1;
			} else if (match->ifa_flags & IFF_POINTOPOINT &&
			    match->ifa_dstaddr != NULL) {
				if (sa_equal(remote, match->ifa_dstaddr))
					connected = 1;
			} else if (match->ifa_netmask != NULL) {
				plen = mask2prefixlen(
				    match->ifa_addr->sa_family,
				    match->ifa_netmask);
				if (prefix_compare(local, remote, plen) == 0)
					connected = 1;
			}
			break;
		}
	}

	if (match == NULL) {
		log_warnx("%s: local address not found", __func__);
		return;
	}
	if (connected)
		*scope = if_nametoindex(match->ifa_name);
	else
		*scope = 0;

	switch (local->aid) {
	case AID_INET6:
		for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr != NULL &&
			    ifa->ifa_addr->sa_family == AF_INET &&
			    strcmp(ifa->ifa_name, match->ifa_name) == 0) {
				sa2addr(ifa->ifa_addr, alt, NULL);
				break;
			}
		}
		break;
	case AID_INET:
		for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
			if (ifa->ifa_addr != NULL &&
			    ifa->ifa_addr->sa_family == AF_INET6 &&
			    strcmp(ifa->ifa_name, match->ifa_name) == 0) {
				struct sockaddr_in6 *s =
				    (struct sockaddr_in6 *)ifa->ifa_addr;

				/* only accept global scope addresses */
				if (IN6_IS_ADDR_LINKLOCAL(&s->sin6_addr) ||
				    IN6_IS_ADDR_SITELOCAL(&s->sin6_addr))
					continue;
				sa2addr(ifa->ifa_addr, alt, NULL);
				break;
			}
		}
		break;
	default:
		log_warnx("%s: unsupported address family %s", __func__,
		    aid2str(local->aid));
		break;
	}

	freeifaddrs(ifap);
#endif
}

void
session_handle_update(struct peer *peer, struct ibuf *msg)
{
	global_parse_update(peer, msg);
}

void
session_handle_rrefresh(struct peer *peer, struct route_refresh *rr)
{
	/* XXX */
}

void
session_graceful_restart(struct peer *p)
{
	/* dummy */
}

void
session_graceful_stop(struct peer *p)
{
	/* dummy */
}

void
session_graceful_flush(struct peer *p, uint8_t aid, const char *why)
{
	/* dummy */
}	

void
session_mrt_dump_state(struct peer *p, enum session_state oldstate,
    enum session_state newstate)
{
}

void
session_mrt_dump_bgp_msg(struct peer *p, struct ibuf *msg,
     enum msg_type msgtype, enum directions dir)
{
}

struct peer *
getpeerbydesc(struct bgpd_config *c, const char *descr)
{
	struct peer	*p, *res = NULL;
	int		 match = 0;

	RB_FOREACH(p, peer_head, &c->peers)
		if (!strcmp(p->conf.descr, descr)) {
			res = p;
			match++;
		}

	if (match > 1)
		log_info("neighbor description \"%s\" not unique, request "
		    "aborted", descr);

	if (match == 1)
		return (res);
	else
		return (NULL);
}

struct peer *
getpeerbyip(struct bgpd_config *c, struct sockaddr *rip, struct sockaddr *lip)
{
	struct bgpd_addr laddr, raddr;
	struct peer	*p;

	sa2addr(rip, &raddr, NULL);
	sa2addr(lip, &laddr, NULL);

	/* we might want a more effective way to find peers by IP */
	RB_FOREACH(p, peer_head, &c->peers)
		if (memcmp(&raddr, &p->conf.remote_addr, sizeof(raddr)) == 0 &&
		    memcmp(&laddr, &p->conf.local_addr, sizeof(laddr)) == 0)
			return (p);

	return (NULL);
}

struct peer *
getpeerbyid(struct bgpd_config *c, uint32_t peerid)
{
	static struct peer lookup;

	lookup.conf.id = peerid;

	return RB_FIND(peer_head, &c->peers, &lookup);
}

void
session_down(struct peer *p)
{
	memset(&p->capa.neg, 0, sizeof(p->capa.neg));
	p->stats.last_updown = getmonotime();

	timer_set(&p->timers, Timer_SessionDown, INTERVAL_SESSION_DOWN);

	global_peer_down(p);
}

void
session_up(struct peer *p)
{
	/* clear last errors, now that the session is up */
	p->stats.last_sent_errcode = 0;
	p->stats.last_sent_suberr = 0;
	p->stats.last_rcvd_errcode = 0;
	p->stats.last_rcvd_suberr = 0;
	memset(p->stats.last_reason, 0, sizeof(p->stats.last_reason));
	p->stats.last_updown = getmonotime();

	timer_stop(&p->timers, Timer_SessionDown);

	global_peer_up(p);
}

void
session_demote(struct peer *p, int level)
{
}

void
session_md5_reload(struct peer *p)
{
}

void
session_stop(struct peer *peer, uint8_t subcode, const char *reason)
{
	struct ibuf *ibuf;

	if (reason != NULL)
		strlcpy(peer->conf.reason, reason, sizeof(peer->conf.reason));

	ibuf = ibuf_dynamic(0, REASON_LEN);

	if ((subcode == ERR_CEASE_ADMIN_DOWN ||
	    subcode == ERR_CEASE_ADMIN_RESET) &&
	    reason != NULL && *reason != '\0' &&
	    ibuf != NULL) {
		if (ibuf_add_n8(ibuf, strlen(reason)) == -1 ||
		    ibuf_add(ibuf, reason, strlen(reason))) {
			log_peer_warnx(&peer->conf,
			    "trying to send overly long shutdown reason");
			ibuf_free(ibuf);
			ibuf = NULL;
		}
	}
	switch (peer->state) {
	case STATE_OPENSENT:
	case STATE_OPENCONFIRM:
	case STATE_ESTABLISHED:
		session_notification(peer, ERR_CEASE, subcode, ibuf);
		break;
	default:
		/* session not open, no need to send notification */
		if (subcode >= sizeof(suberr_cease_names) / sizeof(char *) ||
		    suberr_cease_names[subcode] == NULL)
			log_peer_warnx(&peer->conf, "session stop: %s, "
			    "unknown subcode %u", errnames[ERR_CEASE], subcode);
		else
			log_peer_warnx(&peer->conf, "session stop: %s, %s",
			    errnames[ERR_CEASE], suberr_cease_names[subcode]);
		break;
	}
	ibuf_free(ibuf);
	bgp_fsm(peer, EVNT_STOP, NULL);
}

struct bgpd_addr *
session_localaddr(struct peer *p)
{
	return &p->conf.local_addr;
}
