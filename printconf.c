/*	$OpenBSD: printconf.c,v 1.181 2025/01/27 15:22:11 claudio Exp $	*/

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2016 Job Snijders <job@instituut.net>
 * Copyright (c) 2016 Peter Hessler <phessler@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA, PROFITS OR MIND, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bgpd.h"
#include "bgp.h"
#include "session.h"
#include "log.h"

const char	*community_type(struct community *c);
void		 print_community(struct community *c);
void		 print_origin(uint8_t);
void		 print_set(struct filter_set_head *);
void		 print_mainconf(struct bgpd_config *);
const char	*print_af(uint8_t);
void		 print_network(struct network_config *, const char *);
void		 print_peer(struct peer *, struct bgpd_config *, const char *);
const char	*print_auth_alg(enum auth_alg);
const char	*print_enc_alg(enum auth_enc_alg);
void		 print_announce(struct peer_config *, const char *);

const char *
community_type(struct community *c)
{
	switch ((uint8_t)c->flags) {
	case COMMUNITY_TYPE_BASIC:
		return "community";
	case COMMUNITY_TYPE_LARGE:
		return "large-community";
	default:
		return "???";
	}
}

void
print_community(struct community *c)
{
	switch ((uint8_t)c->flags) {
	case COMMUNITY_TYPE_BASIC:
		switch ((c->flags >> 8) & 0xff) {
		case COMMUNITY_ANY:
			printf("*:");
			break;
		case COMMUNITY_NEIGHBOR_AS:
			printf("neighbor-as:");
			break;
		case COMMUNITY_LOCAL_AS:
			printf("local-as:");
			break;
		default:
			printf("%u:", c->data1);
			break;
		}
		switch ((c->flags >> 16) & 0xff) {
		case COMMUNITY_ANY:
			printf("* ");
			break;
		case COMMUNITY_NEIGHBOR_AS:
			printf("neighbor-as ");
			break;
		case COMMUNITY_LOCAL_AS:
			printf("local-as ");
			break;
		default:
			printf("%u ", c->data2);
			break;
		}
		break;
	case COMMUNITY_TYPE_LARGE:
		switch ((c->flags >> 8) & 0xff) {
		case COMMUNITY_ANY:
			printf("*:");
			break;
		case COMMUNITY_NEIGHBOR_AS:
			printf("neighbor-as:");
			break;
		case COMMUNITY_LOCAL_AS:
			printf("local-as:");
			break;
		default:
			printf("%u:", c->data1);
			break;
		}
		switch ((c->flags >> 16) & 0xff) {
		case COMMUNITY_ANY:
			printf("*:");
			break;
		case COMMUNITY_NEIGHBOR_AS:
			printf("neighbor-as:");
			break;
		case COMMUNITY_LOCAL_AS:
			printf("local-as:");
			break;
		default:
			printf("%u:", c->data2);
			break;
		}
		switch ((c->flags >> 24) & 0xff) {
		case COMMUNITY_ANY:
			printf("* ");
			break;
		case COMMUNITY_NEIGHBOR_AS:
			printf("neighbor-as ");
			break;
		case COMMUNITY_LOCAL_AS:
			printf("local-as ");
			break;
		default:
			printf("%u ", c->data3);
			break;
		}
		break;
	}
}

void
print_origin(uint8_t o)
{
	if (o == ORIGIN_IGP)
		printf("igp ");
	else if (o == ORIGIN_EGP)
		printf("egp ");
	else if (o == ORIGIN_INCOMPLETE)
		printf("incomplete ");
	else
		printf("%u ", o);
}

void
print_set(struct filter_set_head *set)
{
	struct filter_set	*s;

	if (TAILQ_EMPTY(set))
		return;

	printf("set { ");
	TAILQ_FOREACH(s, set, entry) {
		switch (s->type) {
		case ACTION_SET_LOCALPREF:
			printf("localpref %u ", s->action.metric);
			break;
		case ACTION_SET_RELATIVE_LOCALPREF:
			printf("localpref %+d ", s->action.relative);
			break;
		case ACTION_SET_MED:
			printf("metric %u ", s->action.metric);
			break;
		case ACTION_SET_RELATIVE_MED:
			printf("metric %+d ", s->action.relative);
			break;
		case ACTION_SET_WEIGHT:
			printf("weight %u ", s->action.metric);
			break;
		case ACTION_SET_RELATIVE_WEIGHT:
			printf("weight %+d ", s->action.relative);
			break;
		case ACTION_SET_PREPEND_SELF:
			printf("prepend-self %u ", s->action.prepend);
			break;
		case ACTION_SET_PREPEND_PEER:
			printf("prepend-neighbor %u ", s->action.prepend);
			break;
		case ACTION_DEL_COMMUNITY:
			printf("%s delete ",
			    community_type(&s->action.community));
			print_community(&s->action.community);
			break;
		case ACTION_SET_COMMUNITY:
			printf("%s ", community_type(&s->action.community));
			print_community(&s->action.community);
			break;
		case ACTION_SET_ORIGIN:
			printf("origin ");
			print_origin(s->action.origin);
			break;
		}
	}
	printf("}");
}

void
print_mainconf(struct bgpd_config *conf)
{
	struct in_addr		 ina;
	struct listen_addr	*la;

	printf("AS %s", log_as(conf->as));
	if (conf->as > USHRT_MAX && conf->short_as != AS_TRANS)
		printf(" %u", conf->short_as);
	ina.s_addr = htonl(conf->bgpid);
	printf("\nrouter-id %s\n", inet_ntoa(ina));

	if (conf->holdtime != INTERVAL_HOLD)
		printf("holdtime %u\n", conf->holdtime);
	if (conf->min_holdtime != MIN_HOLDTIME)
		printf("holdtime min %u\n", conf->min_holdtime);
	if (conf->connectretry != INTERVAL_CONNECTRETRY)
		printf("connect-retry %u\n", conf->connectretry);
	if (conf->staletime != INTERVAL_STALE)
		printf("staletime %u\n", conf->staletime);

	TAILQ_FOREACH(la, conf->listen_addrs, entry) {
		struct bgpd_addr addr;
		uint16_t port;

		sa2addr((struct sockaddr *)&la->sa, &addr, &port);
		printf("listen on %s",
		    log_sockaddr((struct sockaddr *)&la->sa, la->sa_len));
		if (port != BGP_PORT)
			printf(" port %hu", port);
		printf("\n");
	}

	printf("\n");
}

const char *
print_af(uint8_t aid)
{
	/*
	 * Hack around the fact that aid2str() will return "IPv4 unicast"
	 * for AID_INET. AID_INET, AID_INET6 and the flowspec AID need
	 * special handling and the other AID should never end up here.
	 */
	if (aid == AID_INET)
		return ("inet");
	if (aid == AID_INET6)
		return ("inet6");
	return (aid2str(aid));
}

void
print_network(struct network_config *n, const char *c)
{
	printf("%snetwork %s/%u", c, log_addr(&n->prefix), n->prefixlen);
	if (!TAILQ_EMPTY(&n->attrset))
		printf(" ");
	print_set(&n->attrset);
	printf("\n");
}

static void
print_auth(struct auth_config *auth, const char *c)
{
	char *method;

	if (auth->method == AUTH_MD5SIG)
		printf("%s\ttcp md5sig\n", c);
	else if (auth->method == AUTH_IPSEC_MANUAL_ESP ||
	    auth->method == AUTH_IPSEC_MANUAL_AH) {
		if (auth->method == AUTH_IPSEC_MANUAL_ESP)
			method = "esp";
		else
			method = "ah";

		printf("%s\tipsec %s in spi %u %s XXXXXX", c, method,
		    auth->spi_in, print_auth_alg(auth->auth_alg_in));
		if (auth->enc_alg_in)
			printf(" %s XXXXXX", print_enc_alg(auth->enc_alg_in));
		printf("\n");

		printf("%s\tipsec %s out spi %u %s XXXXXX", c, method,
		    auth->spi_out, print_auth_alg(auth->auth_alg_out));
		if (auth->enc_alg_out)
			printf(" %s XXXXXX",
			    print_enc_alg(auth->enc_alg_out));
		printf("\n");
	} else if (auth->method == AUTH_IPSEC_IKE_AH)
		printf("%s\tipsec ah ike\n", c);
	else if (auth->method == AUTH_IPSEC_IKE_ESP)
		printf("%s\tipsec esp ike\n", c);

}

void
print_peer(struct peer *peer, struct bgpd_config *conf, const char *c)
{
	struct peer_config	*p = &peer->conf;

	printf("%sneighbor %s {\n", c, log_addr(&p->remote_addr));
	if (p->descr[0])
		printf("%s\tdescr \"%s\"\n", c, p->descr);
	if (p->remote_as)
		printf("%s\tremote-as %s\n", c, log_as(p->remote_as));
	if (p->local_as != conf->as) {
		printf("%s\tlocal-as %s", c, log_as(p->local_as));
		if (p->local_as > USHRT_MAX && p->local_short_as != AS_TRANS)
			printf(" %u", p->local_short_as);
		printf("\n");
	}
	if (p->down)
		printf("%s\tdown\n", c);
	if (p->distance > 1)
		printf("%s\tmultihop %u\n", c, p->distance);
	if (p->passive)
		printf("%s\tpassive\n", c);
	if (p->local_addr.aid)
		printf("%s\tlocal-address %s\n", c, log_addr(&p->local_addr));
	if (p->remote_port != BGP_PORT)
		printf("%s\tport %hu\n", c, p->remote_port);
	if (p->role != ROLE_NONE)
		printf("%s\trole %s\n", c, log_policy(p->role));
	if (p->max_prefix) {
		printf("%s\tmax-prefix %u", c, p->max_prefix);
		if (p->max_prefix_restart)
			printf(" restart %u", p->max_prefix_restart);
		printf("\n");
	}
	if (p->holdtime)
		printf("%s\tholdtime %u\n", c, p->holdtime);
	if (p->min_holdtime)
		printf("%s\tholdtime min %u\n", c, p->min_holdtime);
	if (p->staletime)
		printf("%s\tstaletime %u\n", c, p->staletime);

	print_auth(&peer->auth_conf, c);

	if (p->ttlsec)
		printf("%s\tttl-security yes\n", c);

	print_announce(p, c);

	printf("%s}\n", c);
}

const char *
print_auth_alg(enum auth_alg alg)
{
	switch (alg) {
	case AUTH_AALG_SHA1HMAC:
		return ("sha1");
	case AUTH_AALG_MD5HMAC:
		return ("md5");
	default:
		return ("???");
	}
}

const char *
print_enc_alg(enum auth_enc_alg alg)
{
	switch (alg) {
	case AUTH_EALG_3DESCBC:
		return ("3des");
	case AUTH_EALG_AES:
		return ("aes");
	default:
		return ("???");
	}
}

void
print_announce(struct peer_config *p, const char *c)
{
	uint8_t	aid;
	int match = 0;

	for (aid = AID_MIN; aid < AID_MAX; aid++)
		if (p->capabilities.mp[aid] == 2) {
			printf("%s\tannounce %s enforce\n", c, aid2str(aid));
			match = 1;
		} else if (p->capabilities.mp[aid]) {
			printf("%s\tannounce %s\n", c, aid2str(aid));
			match = 1;
		}
	if (!match) {
		printf("%s\tannounce IPv4 none\n", c);
		printf("%s\tannounce IPv6 none\n", c);
	}

	if (p->capabilities.refresh == 2)
		printf("%s\tannounce refresh enforce\n", c);
	else if (p->capabilities.refresh == 0)
		printf("%s\tannounce refresh no\n", c);

	if (p->capabilities.enhanced_rr == 2)
		printf("%s\tannounce enhanced refresh enforce\n", c);
	else if (p->capabilities.enhanced_rr == 1)
		printf("%s\tannounce enhanced refresh yes\n", c);

	if (p->capabilities.as4byte == 2)
		printf("%s\tannounce as4byte enforce\n", c);
	else if (p->capabilities.as4byte == 0)
		printf("%s\tannounce as4byte no\n", c);

	if (p->capabilities.ext_msg == 2)
		printf("%s\tannounce extended message enforce\n", c);
	else if (p->capabilities.ext_msg == 1)
		printf("%s\tannounce extended message yes\n", c);

	if (p->capabilities.ext_nh[AID_INET] == 2)
		printf("%s\tannounce extended nexthop enforce\n", c);
	else if (p->capabilities.ext_nh[AID_INET] == 1)
		printf("%s\tannounce extended nexthop yes\n", c);

	if (p->capabilities.policy == 2)
		printf("%s\tannounce policy enforce\n", c);
	else if (p->capabilities.policy == 1)
		printf("%s\tannounce policy yes\n", c);
	else
		printf("%s\tannounce policy no\n", c);
}

void
print_config(struct bgpd_config *conf)
{
	struct network		*n;
	struct peer		*p;

	print_mainconf(conf);
	TAILQ_FOREACH(n, &conf->networks, entry)
		print_network(&n->net, "");
	printf("\n");
	RB_FOREACH(p, peer_head, &conf->peers)
		print_peer(p, conf, "");
}
