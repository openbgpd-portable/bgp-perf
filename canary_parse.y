/*	$OpenBSD: parse.y,v 1.479 2025/02/04 18:16:56 denis Exp $ */

/*
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2004-2025 Claudio Jeker <claudio@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
 * Copyright (c) 2016, 2017 Job Snijders <job@openbsd.org>
 * Copyright (c) 2016 Peter Hessler <phessler@openbsd.org>
 * Copyright (c) 2017, 2018 Sebastian Benoit <benno@openbsd.org>
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

%{
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_ipsp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <endian.h>
#include <err.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "bgpd.h"
#include "bgp.h"
#include "session.h"
#include "log.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#define MACRO_NAME_LEN		128

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	size_t			 ungetpos;
	size_t			 ungetsize;
	u_char			*ungetbuf;
	int			 eof_reached;
	int			 lineno;
	int			 errors;
} *file, *topfile;
struct file	*pushfile(const char *, int);
int		 popfile(void);
int		 check_file_secrecy(int, const char *);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 igetc(void);
int		 lgetc(int);
void		 lungetc(int);
int		 findeol(void);
int		 expand_macro(void);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};
int		 symset(const char *, const char *, int);
char		*symget(const char *);

struct peer	*alloc_peer(void);
struct peer	*new_peer(void);
int		 get_id(struct peer *);
int		 str2key(char *, char *, size_t);
int		 neighbor_consistent(struct peer *);
int		 merge_filterset(struct filter_set_head *, struct filter_set *);

int		 parsecommunity(struct community *, int, char *);
static int	 merge_auth_conf(struct auth_config *, struct auth_config *);

static struct bgpd_config	*conf;
static struct network_head	*netconf;
static struct peer_head		*new_peers, *cur_peers;
static struct peer		*curpeer;

typedef struct {
	union {
		long long		 number;
		char			*string;
		struct bgpd_addr	 addr;
		uint8_t			 u8;
		struct filter_set	*filter_set;
		struct filter_set_head	*filter_set_head;
		struct {
			struct bgpd_addr	prefix;
			uint8_t			len;
		}			prefix;
		struct auth_config	authconf;
		struct {
			enum auth_enc_alg	enc_alg;
			uint8_t			enc_key_len;
			char			enc_key[IPSEC_ENC_KEY_LEN];
		}			encspec;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	AS ROUTERID HOLDTIME YMIN LISTEN ON FIBUPDATE FIBPRIORITY RTABLE
%token	NONE UNICAST VPN RD EXPORT EXPORTTRGT IMPORTTRGT DEFAULTROUTE
%token	RDE RIB EVALUATE IGNORE COMPARE PORT MINVERSION STALETIME
%token	GROUP NEIGHBOR NETWORK
%token	EBGP IBGP
%token	FLOWSPEC PROTO FLAGS FRAGMENT TOS LENGTH ICMPTYPE CODE
%token	LOCALAS REMOTEAS DESCR LOCALADDR MULTIHOP PASSIVE MAXPREFIX RESTART
%token	ANNOUNCE REFRESH AS4BYTE CONNECTRETRY ENHANCED ADDPATH EXTENDED
%token	SEND RECV PLUS POLICY ROLE GRACEFUL NOTIFICATION MESSAGE
%token	DEMOTE ENFORCE NEIGHBORAS ASOVERRIDE REFLECTOR DEPEND DOWN
%token	DUMP IN OUT SOCKET RESTRICTED
%token	LOG TRANSPARENT FILTERED
%token	TCP MD5SIG PASSWORD KEY TTLSECURITY
%token	ALLOW DENY MATCH
%token	QUICK
%token	FROM TO ANY
%token	CONNECTED STATIC
%token	COMMUNITY EXTCOMMUNITY LARGECOMMUNITY DELETE
%token	MAXCOMMUNITIES MAXEXTCOMMUNITIES MAXLARGECOMMUNITIES
%token	PREFIX PREFIXLEN PREFIXSET
%token	ASPASET ROASET ORIGINSET OVS AVS EXPIRES
%token	ASSET SOURCEAS TRANSITAS PEERAS PROVIDERAS CUSTOMERAS MAXASLEN MAXASSEQ
%token	SET LOCALPREF MED METRIC NEXTHOP REJECT BLACKHOLE NOMODIFY SELF
%token	PREPEND_SELF PREPEND_PEER PFTABLE WEIGHT RTLABEL ORIGIN PRIORITY
%token	ERROR INCLUDE
%token	IPSEC ESP AH SPI IKE
%token	IPV4 IPV6 EVPN
%token	QUALIFY VIA
%token	NE LE GE XRANGE LONGER MAXLEN MAX
%token	<v.string>		STRING
%token	<v.number>		NUMBER
%type	<v.number>		asnumber as4number
%type	<v.number>		espah af safi restart origincode
%type	<v.number>		yesno yesnoenforce enforce inout
%type	<v.number>		port
%type	<v.string>		string
%type	<v.addr>		address
%type	<v.prefix>		prefix
%type	<v.u8>			delete community
%type	<v.filter_set>		filter_set_opt
%type	<v.filter_set_head>	filter_set filter_set_l
%type	<v.authconf>		authconf
%type	<v.encspec>		encspec
%%

grammar		: /* empty */
		| grammar '\n'
		| grammar varset '\n'
		| grammar include '\n'
		| grammar network '\n'
		| grammar conf_main '\n'
		| grammar neighbor '\n'
		| grammar error '\n'		{ file->errors++; }
		;

asnumber	: NUMBER			{
			/*
			 * According to iana 65535 and 4294967295 are reserved
			 * but enforcing this is not duty of the parser.
			 */
			if ($1 < 0 || $1 > UINT_MAX) {
				yyerror("AS too big: max %u", UINT_MAX);
				YYERROR;
			}
		}

as4number	: STRING			{
			const char	*errstr;
			char		*dot;
			uint32_t	 uvalh = 0, uval;

			if ((dot = strchr($1,'.')) != NULL) {
				*dot++ = '\0';
				uvalh = strtonum($1, 0, USHRT_MAX, &errstr);
				if (errstr) {
					yyerror("number %s is %s", $1, errstr);
					free($1);
					YYERROR;
				}
				uval = strtonum(dot, 0, USHRT_MAX, &errstr);
				if (errstr) {
					yyerror("number %s is %s", dot, errstr);
					free($1);
					YYERROR;
				}
				free($1);
			} else {
				yyerror("AS %s is bad", $1);
				free($1);
				YYERROR;
			}
			if (uvalh == 0 && (uval == AS_TRANS || uval == 0)) {
				yyerror("AS %u is reserved and may not be used",
				    uval);
				YYERROR;
			}
			$$ = uval | (uvalh << 16);
		}
		| asnumber {
			if ($1 == AS_TRANS || $1 == 0) {
				yyerror("AS %u is reserved and may not be used",
				    (uint32_t)$1);
				YYERROR;
			}
			$$ = $1;
		}
		;

string		: string STRING			{
			if (asprintf(&$$, "%s %s", $1, $2) == -1)
				fatal("string: asprintf");
			free($1);
			free($2);
		}
		| STRING
		;

yesno		: STRING			{
			if (!strcmp($1, "yes"))
				$$ = 1;
			else if (!strcmp($1, "no"))
				$$ = 0;
			else {
				yyerror("syntax error, "
				    "either yes or no expected");
				free($1);
				YYERROR;
			}
			free($1);
		}
		;

varset		: STRING '=' string		{
			char *s = $1;
			if (strlen($1) >= MACRO_NAME_LEN) {
				yyerror("macro name to long, max %d characters",
				    MACRO_NAME_LEN - 1);
				free($1);
				free($3);
				YYERROR;
			}
			do {
				if (isalnum((unsigned char)*s) || *s == '_')
					continue;
				yyerror("macro name can only contain "
					    "alphanumerics and '_'");
				free($1);
				free($3);
				YYERROR;
			} while (*++s);

			if (cmd_opts & BGPD_OPT_VERBOSE)
				printf("%s = \"%s\"\n", $1, $3);
			if (symset($1, $3, 0) == -1)
				fatal("cannot store variable");
			free($1);
			free($3);
		}
		;

include		: INCLUDE STRING		{
			struct file	*nfile;

			if ((nfile = pushfile($2, 1)) == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);

			file = nfile;
			lungetc('\n');
		}
		;

conf_main	: HOLDTIME NUMBER	{
			if ($2 < MIN_HOLDTIME || $2 > USHRT_MAX) {
				yyerror("holdtime must be between %u and %u",
				    MIN_HOLDTIME, USHRT_MAX);
				YYERROR;
			}
			conf->holdtime = $2;
		}
		| HOLDTIME YMIN NUMBER	{
			if ($3 < MIN_HOLDTIME || $3 > USHRT_MAX) {
				yyerror("holdtime must be between %u and %u",
				    MIN_HOLDTIME, USHRT_MAX);
				YYERROR;
			}
			conf->min_holdtime = $3;
		}
		| STALETIME NUMBER	{
			if ($2 < MIN_HOLDTIME || $2 > USHRT_MAX) {
				yyerror("staletime must be between %u and %u",
				    MIN_HOLDTIME, USHRT_MAX);
				YYERROR;
			}
			conf->staletime = $2;
		}
		| LISTEN ON address	{
			struct listen_addr	*la;
			struct sockaddr		*sa;

			if ((la = calloc(1, sizeof(struct listen_addr))) ==
			    NULL)
				fatal("parse conf_main listen on calloc");

			la->fd = -1;
			sa = addr2sa(&$3, BGP_PORT, &la->sa_len);
			memcpy(&la->sa, sa, la->sa_len);
			TAILQ_INSERT_TAIL(conf->listen_addrs, la, entry);
		}
		| LISTEN ON address PORT port	{
			struct listen_addr	*la;
			struct sockaddr		*sa;

			if ((la = calloc(1, sizeof(struct listen_addr))) ==
			    NULL)
				fatal("parse conf_main listen on calloc");

			la->fd = -1;
			sa = addr2sa(&$3, $5, &la->sa_len);
			memcpy(&la->sa, sa, la->sa_len);
			TAILQ_INSERT_TAIL(conf->listen_addrs, la, entry);
		}
		| CONNECTRETRY NUMBER {
			if ($2 > USHRT_MAX || $2 < 1) {
				yyerror("invalid connect-retry");
				YYERROR;
			}
			conf->connectretry = $2;
		}
		| DUMP METRIC STRING {
			conf->ometric_path = $3;
		}
		;

network		: NETWORK prefix filter_set	{
			struct network	*n, *m;

			if ((n = calloc(1, sizeof(struct network))) == NULL)
				fatal("new_network");
			memcpy(&n->net.prefix, &$2.prefix,
			    sizeof(n->net.prefix));
			n->net.prefixlen = $2.len;
			filterset_move($3, &n->net.attrset);
			free($3);
			TAILQ_FOREACH(m, netconf, entry) {
				if (n->net.prefixlen == m->net.prefixlen &&
				    prefix_compare(&n->net.prefix,
				    &m->net.prefix, n->net.prefixlen) == 0)
					yyerror("duplicate prefix "
					    "in network statement");
			}

			TAILQ_INSERT_TAIL(netconf, n, entry);
		}
		;

inout		: IN			{ $$ = 1; }
		| OUT			{ $$ = 0; }
		;

address		: STRING		{
			uint8_t	len;

			if (!host($1, &$$, &len)) {
				yyerror("could not parse address spec \"%s\"",
				    $1);
				free($1);
				YYERROR;
			}
			free($1);

			if (($$.aid == AID_INET && len != 32) ||
			    ($$.aid == AID_INET6 && len != 128)) {
				/* unreachable */
				yyerror("got prefixlen %u, expected %u",
				    len, $$.aid == AID_INET ? 32 : 128);
				YYERROR;
			}
		}
		;

prefix		: STRING '/' NUMBER	{
			char	*s;
			if ($3 < 0 || $3 > 128) {
				yyerror("bad prefixlen %lld", $3);
				free($1);
				YYERROR;
			}
			if (asprintf(&s, "%s/%lld", $1, $3) == -1)
				fatal(NULL);
			free($1);

			if (!host(s, &$$.prefix, &$$.len)) {
				yyerror("could not parse address \"%s\"", s);
				free(s);
				YYERROR;
			}
			free(s);
		}
		| NUMBER '/' NUMBER	{
			char	*s;

			/* does not match IPv6 */
			if ($1 < 0 || $1 > 255 || $3 < 0 || $3 > 32) {
				yyerror("bad prefix %lld/%lld", $1, $3);
				YYERROR;
			}
			if (asprintf(&s, "%lld/%lld", $1, $3) == -1)
				fatal(NULL);

			if (!host(s, &$$.prefix, &$$.len)) {
				yyerror("could not parse address \"%s\"", s);
				free(s);
				YYERROR;
			}
			free(s);
		}
		;

port		: NUMBER		{
			if ($1 < 1 || $1 > USHRT_MAX) {
				yyerror("port must be between %u and %u",
				    1, USHRT_MAX);
				YYERROR;
			}
			$$ = $1;
		}
		| STRING		{
			if (($$ = getservice($1)) == -1) {
				yyerror("unknown port '%s'", $1);
				free($1);
				YYERROR;
			}
			free($1);
		}
		;

neighbor	: { curpeer = new_peer(); }
		    NEIGHBOR address {
			memcpy(&curpeer->conf.remote_addr, &$3,
			    sizeof(curpeer->conf.remote_addr));
			if (get_id(curpeer)) {
				yyerror("get_id failed");
				YYERROR;
			}
		}
		    peeropts_h {
			uint8_t		aid;

			/*
			 * Check if any MP capa is set, if none is set and
			 * and the default AID was not disabled via none then
			 * enable it. Finally fixup the disabled AID.
			 */
			for (aid = AID_MIN; aid < AID_MAX; aid++) {
				if (curpeer->conf.capabilities.mp[aid] > 0)
					break;
			}
			if (aid == AID_MAX &&
			    curpeer->conf.capabilities.mp[
			    curpeer->conf.remote_addr.aid] != -1)
				curpeer->conf.capabilities.mp[
				    curpeer->conf.remote_addr.aid] = 1;
			for (aid = AID_MIN; aid < AID_MAX; aid++) {
				if (curpeer->conf.capabilities.mp[aid] == -1)
					curpeer->conf.capabilities.mp[aid] = 0;
			}

			if (neighbor_consistent(curpeer) == -1) {
				free(curpeer);
				YYERROR;
			}
			if (RB_INSERT(peer_head, new_peers, curpeer) != NULL)
				fatalx("%s: peer tree is corrupt", __func__);
			curpeer = NULL;
		}
		;

peeropts_h	: '{' '\n' peeropts_l '}'
		| '{' peeropts '}'
		| /* empty */
		;

peeropts_l	: /* empty */
		| peeropts_l '\n'
		| peeropts_l peeropts '\n'
		| peeropts_l error '\n'
		;

peeropts	: REMOTEAS as4number	{
			curpeer->conf.remote_as = $2;
		}
		| LOCALAS as4number	{
			curpeer->conf.local_as = $2;
			if ($2 > USHRT_MAX)
				curpeer->conf.local_short_as = AS_TRANS;
			else
				curpeer->conf.local_short_as = $2;
		}
		| LOCALAS as4number asnumber {
			curpeer->conf.local_as = $2;
			curpeer->conf.local_short_as = $3;
		}
		| ROUTERID address		{
			if ($2.aid != AID_INET) {
				yyerror("router-id must be an IPv4 address");
				YYERROR;
			}
			curpeer->conf.bgpid = ntohl($2.v4.s_addr);
		}
		| DESCR string		{
			if (strlcpy(curpeer->conf.descr, $2,
			    sizeof(curpeer->conf.descr)) >=
			    sizeof(curpeer->conf.descr)) {
				yyerror("descr \"%s\" too long: max %zu",
				    $2, sizeof(curpeer->conf.descr) - 1);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| LOCALADDR address	{
			if ($2.aid == curpeer->conf.remote_addr.aid) {
				memcpy(&curpeer->conf.local_addr, &$2,
				    sizeof(curpeer->conf.local_addr));
			} else {
				yyerror("Address family %s for local-addr "
				    "does not match remote-addr",
				    aid2str($2.aid));
				YYERROR;
			}
		}
		| MULTIHOP NUMBER	{
			if ($2 < 2 || $2 > 255) {
				yyerror("invalid multihop distance %lld", $2);
				YYERROR;
			}
			curpeer->conf.distance = $2;
		}
		| PASSIVE		{
			curpeer->conf.passive = 1;
		}
		| DOWN			{
			curpeer->conf.down = 1;
		}
		| DOWN STRING		{
			curpeer->conf.down = 1;
			if (strlcpy(curpeer->conf.reason, $2,
				sizeof(curpeer->conf.reason)) >=
				sizeof(curpeer->conf.reason)) {
				    yyerror("shutdown reason too long");
				    free($2);
				    YYERROR;
			}
			free($2);
		}
		| HOLDTIME NUMBER	{
			if ($2 < MIN_HOLDTIME || $2 > USHRT_MAX) {
				yyerror("holdtime must be between %u and %u",
				    MIN_HOLDTIME, USHRT_MAX);
				YYERROR;
			}
			curpeer->conf.holdtime = $2;
		}
		| HOLDTIME YMIN NUMBER	{
			if ($3 < MIN_HOLDTIME || $3 > USHRT_MAX) {
				yyerror("holdtime must be between %u and %u",
				    MIN_HOLDTIME, USHRT_MAX);
				YYERROR;
			}
			curpeer->conf.min_holdtime = $3;
		}
		| STALETIME NUMBER	{
			if ($2 < MIN_HOLDTIME || $2 > USHRT_MAX) {
				yyerror("staletime must be between %u and %u",
				    MIN_HOLDTIME, USHRT_MAX);
				YYERROR;
			}
			curpeer->conf.staletime = $2;
		}
		| ANNOUNCE af safi enforce {
			uint8_t		aid, safi;
			uint16_t	afi;

			if ($3 == SAFI_NONE) {
				for (aid = AID_MIN; aid < AID_MAX; aid++) {
					if (aid2afi(aid, &afi, &safi) == -1 ||
					    afi != $2)
						continue;
					curpeer->conf.capabilities.mp[aid] = -1;
				}
			} else {
				if (afi2aid($2, $3, &aid) == -1) {
					yyerror("unknown AFI/SAFI pair");
					YYERROR;
				}
				if ($4)
					curpeer->conf.capabilities.mp[aid] = 2;
				else
					curpeer->conf.capabilities.mp[aid] = 1;
			}
		}
		| ANNOUNCE REFRESH yesnoenforce {
			curpeer->conf.capabilities.refresh = $3;
		}
		| ANNOUNCE ENHANCED REFRESH yesnoenforce {
			curpeer->conf.capabilities.enhanced_rr = $4;
		}
		| ANNOUNCE AS4BYTE yesnoenforce {
			curpeer->conf.capabilities.as4byte = $3;
		}
		| ANNOUNCE POLICY yesnoenforce {
			curpeer->conf.capabilities.policy = $3;
		}
		| ANNOUNCE EXTENDED MESSAGE yesnoenforce {
			curpeer->conf.capabilities.ext_msg = $4;
		}
		| ANNOUNCE EXTENDED NEXTHOP yesnoenforce {
			curpeer->conf.capabilities.ext_nh[AID_VPN_IPv4] =
			    curpeer->conf.capabilities.ext_nh[AID_INET] = $4;
		}
		| ROLE STRING {
			if (strcmp($2, "provider") == 0) {
				curpeer->conf.role = ROLE_PROVIDER;
			} else if (strcmp($2, "rs") == 0) {
				curpeer->conf.role = ROLE_RS;
			} else if (strcmp($2, "rs-client") == 0) {
				curpeer->conf.role = ROLE_RS_CLIENT;
			} else if (strcmp($2, "customer") == 0) {
				curpeer->conf.role = ROLE_CUSTOMER;
			} else if (strcmp($2, "peer") == 0) {
				curpeer->conf.role = ROLE_PEER;
			} else {
				yyerror("syntax error, one of none, provider, "
				    "rs, rs-client, customer, peer expected");
				free($2);
				YYERROR;
			}
			free($2);
		}
		| ROLE NONE {
			curpeer->conf.role = ROLE_NONE;
		}
		| MAXPREFIX NUMBER restart {
			if ($2 < 0 || $2 > UINT_MAX) {
				yyerror("bad maximum number of prefixes");
				YYERROR;
			}
			curpeer->conf.max_prefix = $2;
			curpeer->conf.max_prefix_restart = $3;
		}
		| authconf {
			if (merge_auth_conf(&curpeer->auth_conf, &$1) == 0)
				YYERROR;
		}
		| TTLSECURITY yesno	{
			curpeer->conf.ttlsec = $2;
		}
		| SET filter_set_opt	{
#if 0
			struct filter_rule	*r;

			r = get_rule($2->type);
			if (merge_filterset(&r->set, $2) == -1)
				YYERROR;
#endif
		}
		| SET '{' optnl filter_set_l optnl '}'	{
#if 0
			struct filter_rule	*r;
			struct filter_set	*s;

			while ((s = TAILQ_FIRST($4)) != NULL) {
				TAILQ_REMOVE($4, s, entry);
				r = get_rule(s->type);
				if (merge_filterset(&r->set, s) == -1)
					YYERROR;
			}
			free($4);
#endif
		}
		| PORT port {
			curpeer->conf.remote_port = $2;
		}
		;

restart		: /* nada */		{ $$ = 0; }
		| RESTART NUMBER	{
			if ($2 < 1 || $2 > USHRT_MAX) {
				yyerror("restart out of range. 1 to %u minutes",
				    USHRT_MAX);
				YYERROR;
			}
			$$ = $2;
		}
		;

af		: IPV4	{ $$ = AFI_IPv4; }
		| IPV6	{ $$ = AFI_IPv6; }
		;

safi		: NONE		{ $$ = SAFI_NONE; }
		| UNICAST	{ $$ = SAFI_UNICAST; }
		| VPN		{ $$ = SAFI_MPLSVPN; }
		;

authconf	: TCP MD5SIG PASSWORD string {
			memset(&$$, 0, sizeof($$));
			if (strlcpy($$.md5key, $4, sizeof($$.md5key)) >=
			    sizeof($$.md5key)) {
				yyerror("tcp md5sig password too long: max %zu",
				    sizeof($$.md5key) - 1);
				free($4);
				YYERROR;
			}
			$$.method = AUTH_MD5SIG;
			$$.md5key_len = strlen($4);
			free($4);
		}
		| TCP MD5SIG KEY string {
			memset(&$$, 0, sizeof($$));
			if (str2key($4, $$.md5key, sizeof($$.md5key)) == -1) {
				free($4);
				YYERROR;
			}
			$$.method = AUTH_MD5SIG;
			$$.md5key_len = strlen($4) / 2;
			free($4);
		}
		| IPSEC espah IKE {
			memset(&$$, 0, sizeof($$));
			if ($2)
				$$.method = AUTH_IPSEC_IKE_ESP;
			else
				$$.method = AUTH_IPSEC_IKE_AH;
		}
		| IPSEC espah inout SPI NUMBER STRING STRING encspec {
			enum auth_alg	auth_alg;
			uint8_t		keylen;

			memset(&$$, 0, sizeof($$));
			if (!strcmp($6, "sha1")) {
				auth_alg = AUTH_AALG_SHA1HMAC;
				keylen = 20;
			} else if (!strcmp($6, "md5")) {
				auth_alg = AUTH_AALG_MD5HMAC;
				keylen = 16;
			} else {
				yyerror("unknown auth algorithm \"%s\"", $6);
				free($6);
				free($7);
				YYERROR;
			}
			free($6);

			if (strlen($7) / 2 != keylen) {
				yyerror("auth key len: must be %u bytes, "
				    "is %zu bytes", keylen, strlen($7) / 2);
				free($7);
				YYERROR;
			}

			if ($2)
				$$.method = AUTH_IPSEC_MANUAL_ESP;
			else {
				if ($8.enc_alg) {
					yyerror("\"ipsec ah\" doesn't take "
					    "encryption keys");
					free($7);
					YYERROR;
				}
				$$.method = AUTH_IPSEC_MANUAL_AH;
			}

			if ($5 <= SPI_RESERVED_MAX || $5 > UINT_MAX) {
				yyerror("bad spi number %lld", $5);
				free($7);
				YYERROR;
			}

			if ($3 == 1) {
				if (str2key($7, $$.auth_key_in,
				    sizeof($$.auth_key_in)) == -1) {
					free($7);
					YYERROR;
				}
				$$.spi_in = $5;
				$$.auth_alg_in = auth_alg;
				$$.enc_alg_in = $8.enc_alg;
				memcpy(&$$.enc_key_in, &$8.enc_key,
				    sizeof($$.enc_key_in));
				$$.enc_keylen_in = $8.enc_key_len;
				$$.auth_keylen_in = keylen;
			} else {
				if (str2key($7, $$.auth_key_out,
				    sizeof($$.auth_key_out)) == -1) {
					free($7);
					YYERROR;
				}
				$$.spi_out = $5;
				$$.auth_alg_out = auth_alg;
				$$.enc_alg_out = $8.enc_alg;
				memcpy(&$$.enc_key_out, &$8.enc_key,
				    sizeof($$.enc_key_out));
				$$.enc_keylen_out = $8.enc_key_len;
				$$.auth_keylen_out = keylen;
			}
			free($7);
		}
		;

espah		: ESP		{ $$ = 1; }
		| AH		{ $$ = 0; }
		;

encspec		: /* nada */	{
			memset(&$$, 0, sizeof($$));
		}
		| STRING STRING {
			memset(&$$, 0, sizeof($$));
			if (!strcmp($1, "3des") || !strcmp($1, "3des-cbc")) {
				$$.enc_alg = AUTH_EALG_3DESCBC;
				$$.enc_key_len = 21; /* XXX verify */
			} else if (!strcmp($1, "aes") ||
			    !strcmp($1, "aes-128-cbc")) {
				$$.enc_alg = AUTH_EALG_AES;
				$$.enc_key_len = 16;
			} else {
				yyerror("unknown enc algorithm \"%s\"", $1);
				free($1);
				free($2);
				YYERROR;
			}
			free($1);

			if (strlen($2) / 2 != $$.enc_key_len) {
				yyerror("enc key length wrong: should be %u "
				    "bytes, is %zu bytes",
				    $$.enc_key_len * 2, strlen($2));
				free($2);
				YYERROR;
			}

			if (str2key($2, $$.enc_key, sizeof($$.enc_key)) == -1) {
				free($2);
				YYERROR;
			}
			free($2);
		}
		;

filter_set	: /* empty */	{ $$ = NULL; }
		| SET filter_set_opt	{
			if (($$ = calloc(1, sizeof(struct filter_set_head))) ==
			    NULL)
				fatal(NULL);
			TAILQ_INIT($$);
			TAILQ_INSERT_TAIL($$, $2, entry);
		}
		| SET '{' optnl filter_set_l optnl '}'	{ $$ = $4; }
		;

filter_set_l	: filter_set_l comma filter_set_opt	{
			$$ = $1;
			if (merge_filterset($$, $3) == 1)
				YYERROR;
		}
		| filter_set_opt {
			if (($$ = calloc(1, sizeof(struct filter_set_head))) ==
			    NULL)
				fatal(NULL);
			TAILQ_INIT($$);
			TAILQ_INSERT_TAIL($$, $1, entry);
		}
		;

community	: COMMUNITY		{ $$ = COMMUNITY_TYPE_BASIC; }
		| LARGECOMMUNITY	{ $$ = COMMUNITY_TYPE_LARGE; }
		;

delete		: /* empty */	{ $$ = 0; }
		| DELETE	{ $$ = 1; }
		;

enforce		: /* empty */	{ $$ = 0; }
		| ENFORCE	{ $$ = 2; }
		;

yesnoenforce	: yesno		{ $$ = $1; }
		| ENFORCE	{ $$ = 2; }
		;

filter_set_opt	: LOCALPREF NUMBER		{
			if ($2 < -INT_MAX || $2 > UINT_MAX) {
				yyerror("bad localpref %lld", $2);
				YYERROR;
			}
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if ($2 >= 0) {
				$$->type = ACTION_SET_LOCALPREF;
				$$->action.metric = $2;
			} else {
				$$->type = ACTION_SET_RELATIVE_LOCALPREF;
				$$->action.relative = $2;
			}
		}
		| LOCALPREF '+' NUMBER		{
			if ($3 < 0 || $3 > INT_MAX) {
				yyerror("bad localpref +%lld", $3);
				YYERROR;
			}
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			$$->type = ACTION_SET_RELATIVE_LOCALPREF;
			$$->action.relative = $3;
		}
		| LOCALPREF '-' NUMBER		{
			if ($3 < 0 || $3 > INT_MAX) {
				yyerror("bad localpref -%lld", $3);
				YYERROR;
			}
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			$$->type = ACTION_SET_RELATIVE_LOCALPREF;
			$$->action.relative = -$3;
		}
		| MED NUMBER			{
			if ($2 < -INT_MAX || $2 > UINT_MAX) {
				yyerror("bad metric %lld", $2);
				YYERROR;
			}
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if ($2 >= 0) {
				$$->type = ACTION_SET_MED;
				$$->action.metric = $2;
			} else {
				$$->type = ACTION_SET_RELATIVE_MED;
				$$->action.relative = $2;
			}
		}
		| MED '+' NUMBER		{
			if ($3 < 0 || $3 > INT_MAX) {
				yyerror("bad metric +%lld", $3);
				YYERROR;
			}
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			$$->type = ACTION_SET_RELATIVE_MED;
			$$->action.relative = $3;
		}
		| MED '-' NUMBER		{
			if ($3 < 0 || $3 > INT_MAX) {
				yyerror("bad metric -%lld", $3);
				YYERROR;
			}
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			$$->type = ACTION_SET_RELATIVE_MED;
			$$->action.relative = -$3;
		}
		| METRIC NUMBER			{	/* alias for MED */
			if ($2 < -INT_MAX || $2 > UINT_MAX) {
				yyerror("bad metric %lld", $2);
				YYERROR;
			}
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if ($2 >= 0) {
				$$->type = ACTION_SET_MED;
				$$->action.metric = $2;
			} else {
				$$->type = ACTION_SET_RELATIVE_MED;
				$$->action.relative = $2;
			}
		}
		| METRIC '+' NUMBER		{
			if ($3 < 0 || $3 > INT_MAX) {
				yyerror("bad metric +%lld", $3);
				YYERROR;
			}
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			$$->type = ACTION_SET_RELATIVE_MED;
			$$->action.metric = $3;
		}
		| METRIC '-' NUMBER		{
			if ($3 < 0 || $3 > INT_MAX) {
				yyerror("bad metric -%lld", $3);
				YYERROR;
			}
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			$$->type = ACTION_SET_RELATIVE_MED;
			$$->action.relative = -$3;
		}
		| WEIGHT NUMBER			{
			if ($2 < -INT_MAX || $2 > UINT_MAX) {
				yyerror("bad weight %lld", $2);
				YYERROR;
			}
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if ($2 > 0) {
				$$->type = ACTION_SET_WEIGHT;
				$$->action.metric = $2;
			} else {
				$$->type = ACTION_SET_RELATIVE_WEIGHT;
				$$->action.relative = $2;
			}
		}
		| WEIGHT '+' NUMBER		{
			if ($3 < 0 || $3 > INT_MAX) {
				yyerror("bad weight +%lld", $3);
				YYERROR;
			}
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			$$->type = ACTION_SET_RELATIVE_WEIGHT;
			$$->action.relative = $3;
		}
		| WEIGHT '-' NUMBER		{
			if ($3 < 0 || $3 > INT_MAX) {
				yyerror("bad weight -%lld", $3);
				YYERROR;
			}
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			$$->type = ACTION_SET_RELATIVE_WEIGHT;
			$$->action.relative = -$3;
		}
		| PREPEND_SELF NUMBER		{
			if ($2 < 0 || $2 > 128) {
				yyerror("bad number of prepends");
				YYERROR;
			}
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			$$->type = ACTION_SET_PREPEND_SELF;
			$$->action.prepend = $2;
		}
		| PREPEND_PEER NUMBER		{
			if ($2 < 0 || $2 > 128) {
				yyerror("bad number of prepends");
				YYERROR;
			}
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			$$->type = ACTION_SET_PREPEND_PEER;
			$$->action.prepend = $2;
		}
		| community delete STRING	{
			uint8_t f1, f2, f3;

			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			if ($2)
				$$->type = ACTION_DEL_COMMUNITY;
			else
				$$->type = ACTION_SET_COMMUNITY;

			if (parsecommunity(&$$->action.community, $1, $3) ==
			    -1) {
				free($3);
				free($$);
				YYERROR;
			}
			free($3);
			/* Don't allow setting of any match */
			f1 = $$->action.community.flags >> 8;
			f2 = $$->action.community.flags >> 16;
			f3 = $$->action.community.flags >> 24;
			if (!$2 && (f1 == COMMUNITY_ANY ||
			    f2 == COMMUNITY_ANY || f3 == COMMUNITY_ANY)) {
				yyerror("'*' is not allowed in set community");
				free($$);
				YYERROR;
			}
		}
		| ORIGIN origincode {
			if (($$ = calloc(1, sizeof(struct filter_set))) == NULL)
				fatal(NULL);
			$$->type = ACTION_SET_ORIGIN;
			$$->action.origin = $2;
		}
		;

origincode	: STRING	{
			if (!strcmp($1, "egp"))
				$$ = ORIGIN_EGP;
			else if (!strcmp($1, "igp"))
				$$ = ORIGIN_IGP;
			else if (!strcmp($1, "incomplete"))
				$$ = ORIGIN_INCOMPLETE;
			else {
				yyerror("unknown origin \"%s\"", $1);
				free($1);
				YYERROR;
			}
			free($1);
		};

optnl		: /* empty */
		| '\n' optnl
		;

comma		: /* empty */
		| ','
		| '\n' optnl
		| ',' '\n' optnl
		;

%%

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*msg;

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		fatalx("yyerror vasprintf");
	va_end(ap);
	logit(LOG_CRIT, "%s:%d: %s", file->name, yylval.lineno, msg);
	free(msg);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* this has to be sorted always */
	static const struct keywords keywords[] = {
		{ "AS",			AS },
		{ "EVPN",		EVPN },
		{ "IPv4",		IPV4 },
		{ "IPv6",		IPV6 },
		{ "add-path",		ADDPATH },
		{ "ah",			AH },
		{ "allow",		ALLOW },
		{ "announce",		ANNOUNCE },
		{ "any",		ANY },
		{ "as-4byte",		AS4BYTE },
		{ "as-override",	ASOVERRIDE },
		{ "as-set",		ASSET },
		{ "aspa-set",		ASPASET },
		{ "avs",		AVS },
		{ "blackhole",		BLACKHOLE },
		{ "community",		COMMUNITY },
		{ "compare",		COMPARE },
		{ "connect-retry",	CONNECTRETRY },
		{ "connected",		CONNECTED },
		{ "customer-as",	CUSTOMERAS },
		{ "default-route",	DEFAULTROUTE },
		{ "delete",		DELETE },
		{ "demote",		DEMOTE },
		{ "deny",		DENY },
		{ "depend",		DEPEND },
		{ "descr",		DESCR },
		{ "down",		DOWN },
		{ "dump",		DUMP },
		{ "ebgp",		EBGP },
		{ "enforce",		ENFORCE },
		{ "enhanced",		ENHANCED },
		{ "esp",		ESP },
		{ "evaluate",		EVALUATE },
		{ "expires",		EXPIRES },
		{ "export",		EXPORT },
		{ "export-target",	EXPORTTRGT },
		{ "ext-community",	EXTCOMMUNITY },
		{ "extended",		EXTENDED },
		{ "fib-priority",	FIBPRIORITY },
		{ "fib-update",		FIBUPDATE },
		{ "filtered",		FILTERED },
		{ "flags",		FLAGS },
		{ "flowspec",		FLOWSPEC },
		{ "fragment",		FRAGMENT },
		{ "from",		FROM },
		{ "graceful",		GRACEFUL },
		{ "holdtime",		HOLDTIME },
		{ "ibgp",		IBGP },
		{ "ignore",		IGNORE },
		{ "ike",		IKE },
		{ "import-target",	IMPORTTRGT },
		{ "in",			IN },
		{ "include",		INCLUDE },
		{ "inet",		IPV4 },
		{ "inet6",		IPV6 },
		{ "ipsec",		IPSEC },
		{ "key",		KEY },
		{ "large-community",	LARGECOMMUNITY },
		{ "listen",		LISTEN },
		{ "local-address",	LOCALADDR },
		{ "local-as",		LOCALAS },
		{ "localpref",		LOCALPREF },
		{ "log",		LOG },
		{ "match",		MATCH },
		{ "max",		MAX },
		{ "max-as-len",		MAXASLEN },
		{ "max-as-seq",		MAXASSEQ },
		{ "max-communities",	MAXCOMMUNITIES },
		{ "max-ext-communities",	MAXEXTCOMMUNITIES },
		{ "max-large-communities",	MAXLARGECOMMUNITIES },
		{ "max-prefix",		MAXPREFIX },
		{ "maxlen",		MAXLEN },
		{ "md5sig",		MD5SIG },
		{ "med",		MED },
		{ "message",		MESSAGE },
		{ "metric",		METRIC },
		{ "min",		YMIN },
		{ "min-version",	MINVERSION },
		{ "multihop",		MULTIHOP },
		{ "neighbor",		NEIGHBOR },
		{ "neighbor-as",	NEIGHBORAS },
		{ "network",		NETWORK },
		{ "nexthop",		NEXTHOP },
		{ "no-modify",		NOMODIFY },
		{ "none",		NONE },
		{ "notification",	NOTIFICATION },
		{ "on",			ON },
		{ "or-longer",		LONGER },
		{ "origin",		ORIGIN },
		{ "origin-set",		ORIGINSET },
		{ "out",		OUT },
		{ "ovs",		OVS },
		{ "passive",		PASSIVE },
		{ "password",		PASSWORD },
		{ "peer-as",		PEERAS },
		{ "pftable",		PFTABLE },
		{ "plus",		PLUS },
		{ "policy",		POLICY },
		{ "port",		PORT },
		{ "prefix",		PREFIX },
		{ "prefix-set",		PREFIXSET },
		{ "prefixlen",		PREFIXLEN },
		{ "prepend-neighbor",	PREPEND_PEER },
		{ "prepend-self",	PREPEND_SELF },
		{ "priority",		PRIORITY },
		{ "proto",		PROTO },
		{ "provider-as",	PROVIDERAS },
		{ "qualify",		QUALIFY },
		{ "quick",		QUICK },
		{ "rd",			RD },
		{ "rde",		RDE },
		{ "recv",		RECV },
		{ "refresh",		REFRESH },
		{ "reject",		REJECT },
		{ "remote-as",		REMOTEAS },
		{ "restart",		RESTART },
		{ "rib",		RIB },
		{ "roa-set",		ROASET },
		{ "role",		ROLE },
		{ "route-reflector",	REFLECTOR },
		{ "router-id",		ROUTERID },
		{ "rtable",		RTABLE },
		{ "rtlabel",		RTLABEL },
		{ "self",		SELF },
		{ "send",		SEND },
		{ "set",		SET },
		{ "socket",		SOCKET },
		{ "source-as",		SOURCEAS },
		{ "spi",		SPI },
		{ "staletime",		STALETIME },
		{ "static",		STATIC },
		{ "tcp",		TCP },
		{ "to",			TO },
		{ "tos",		TOS },
		{ "transit-as",		TRANSITAS },
		{ "transparent-as",	TRANSPARENT },
		{ "ttl-security",	TTLSECURITY },
		{ "unicast",		UNICAST },
		{ "via",		VIA },
		{ "vpn",		VPN },
		{ "weight",		WEIGHT },
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, nitems(keywords), sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

#define START_EXPAND	1
#define DONE_EXPAND	2

static int	expanding;

int
igetc(void)
{
	int	c;

	while (1) {
		if (file->ungetpos > 0)
			c = file->ungetbuf[--file->ungetpos];
		else
			c = getc(file->stream);

		if (c == START_EXPAND)
			expanding = 1;
		else if (c == DONE_EXPAND)
			expanding = 0;
		else
			break;
	}
	return (c);
}

int
lgetc(int quotec)
{
	int		c, next;

	if (quotec) {
		if ((c = igetc()) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = igetc()) == '\\') {
		next = igetc();
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	if (c == EOF) {
		/*
		 * Fake EOL when hit EOF for the first time. This gets line
		 * count right if last line in included file is syntactically
		 * invalid and has no newline.
		 */
		if (file->eof_reached == 0) {
			file->eof_reached = 1;
			return ('\n');
		}
		while (c == EOF) {
			if (file == topfile || popfile() == EOF)
				return (EOF);
			c = igetc();
		}
	}
	return (c);
}

void
lungetc(int c)
{
	if (c == EOF)
		return;

	if (file->ungetpos >= file->ungetsize) {
		void *p = reallocarray(file->ungetbuf, file->ungetsize, 2);
		if (p == NULL)
			err(1, "lungetc");
		file->ungetbuf = p;
		file->ungetsize *= 2;
	}
	file->ungetbuf[file->ungetpos++] = c;
}

int
findeol(void)
{
	int	c;

	/* skip to either EOF or the first real EOL */
	while (1) {
		c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
expand_macro(void)
{
	char	 buf[MACRO_NAME_LEN];
	char	*p, *val;
	int	 c;

	p = buf;
	while (1) {
		if ((c = lgetc('$')) == EOF)
			return (ERROR);
		if (p + 1 >= buf + sizeof(buf) - 1) {
			yyerror("macro name too long");
			return (ERROR);
		}
		if (isalnum(c) || c == '_') {
			*p++ = c;
			continue;
		}
		*p = '\0';
		lungetc(c);
		break;
	}
	val = symget(buf);
	if (val == NULL) {
		yyerror("macro '%s' not defined", buf);
		return (ERROR);
	}
	p = val + strlen(val) - 1;
	lungetc(DONE_EXPAND);
	while (p >= val) {
		lungetc((unsigned char)*p);
		p--;
	}
	lungetc(START_EXPAND);
	return (0);
}

int
yylex(void)
{
	char	 buf[8096];
	char	*p;
	int	 quotec, next, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && !expanding) {
		c = expand_macro();
		if (c != 0)
			return (c);
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || next == ' ' ||
				    next == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error: unterminated quote");
				return (findeol());
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			fatal("yylex: strdup");
		return (STRING);
	case '!':
		next = lgetc(0);
		if (next == '=')
			return (NE);
		lungetc(next);
		break;
	case '<':
		next = lgetc(0);
		if (next == '=')
			return (LE);
		lungetc(next);
		break;
	case '>':
		next = lgetc(0);
		if (next == '<')
			return (XRANGE);
		else if (next == '=')
			return (GE);
		lungetc(next);
		break;
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc((unsigned char)*--p);
			c = (unsigned char)*--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '/' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_' || c == '*') {
		do {
			if (c == '$' && !expanding) {
				c = expand_macro();
				if (c != 0)
					return (c);
			} else
				*p++ = c;

			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				fatal("yylex: strdup");
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat	st;

	if (fstat(fd, &st)) {
		log_warn("cannot stat %s", fname);
		return (-1);
	}
	return (0);
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		log_warn("%s", __func__);
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		log_warn("%s", __func__);
		free(nfile);
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		log_warn("%s: %s", __func__, nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = TAILQ_EMPTY(&files) ? 1 : 0;
	nfile->ungetsize = 16;
	nfile->ungetbuf = malloc(nfile->ungetsize);
	if (nfile->ungetbuf == NULL) {
		log_warn("%s", __func__);
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file->ungetbuf);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

static void
init_config(struct bgpd_config *c)
{
	c->min_holdtime = MIN_HOLDTIME;
	c->holdtime = INTERVAL_HOLD;
	c->staletime = INTERVAL_STALE;
	c->connectretry = INTERVAL_CONNECTRETRY;
	c->bgpid = get_bgpid();
}

struct bgpd_config *
parse_config(const char *filename, struct peer_head *ph)
{
	struct sym		*sym, *next;
	int			 errors = 0;

	conf = new_config();
	init_config(conf);

	curpeer = NULL;

	cur_peers = ph;
	new_peers = &conf->peers;
	netconf = &conf->networks;

	if ((file = pushfile(filename, 1)) == NULL)
		goto errors;
	topfile = file;

	yyparse();
	errors = file->errors;
	popfile();

	/* Free macros and check which have not been used. */
	TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	/* clear the globals */
	curpeer = NULL;
	cur_peers = NULL;
	new_peers = NULL;
	netconf = NULL;

	if (errors) {
errors:
		free_config(conf);
		return (NULL);
	}

	/* Create default listeners if none where specified. */
	if (TAILQ_EMPTY(conf->listen_addrs)) {
		struct listen_addr *la;

		if ((la = calloc(1, sizeof(struct listen_addr))) == NULL)
			fatal("setup_listeners calloc");
		la->fd = -1;
		la->flags = DEFAULT_LISTENER;
		la->sa_len = sizeof(struct sockaddr_in);
		((struct sockaddr_in *)&la->sa)->sin_family = AF_INET;
		((struct sockaddr_in *)&la->sa)->sin_addr.s_addr =
		    htonl(INADDR_ANY);
		((struct sockaddr_in *)&la->sa)->sin_port = htons(BGP_PORT);
		TAILQ_INSERT_TAIL(conf->listen_addrs, la, entry);

		if ((la = calloc(1, sizeof(struct listen_addr))) == NULL)
			fatal("setup_listeners calloc");
		la->fd = -1;
		la->flags = DEFAULT_LISTENER;
		la->sa_len = sizeof(struct sockaddr_in6);
		((struct sockaddr_in6 *)&la->sa)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)&la->sa)->sin6_port = htons(BGP_PORT);
		TAILQ_INSERT_TAIL(conf->listen_addrs, la, entry);
	}

	return (conf);
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0)
			break;
	}

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	ret;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);
	sym = strndup(s, val - s);
	if (sym == NULL)
		fatal("%s: strndup", __func__);
	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	}
	return (NULL);
}

static int
cmpcommunity(struct community *a, struct community *b)
{
	if (a->flags > b->flags)
		return 1;
	if (a->flags < b->flags)
		return -1;
	if (a->data1 > b->data1)
		return 1;
	if (a->data1 < b->data1)
		return -1;
	if (a->data2 > b->data2)
		return 1;
	if (a->data2 < b->data2)
		return -1;
	if (a->data3 > b->data3)
		return 1;
	if (a->data3 < b->data3)
		return -1;
	return 0;
}

static int
getcommunity(char *s, int large, uint32_t *val, uint32_t *flag)
{
	long long	 max = USHRT_MAX;
	const char	*errstr;

	*flag = 0;
	*val = 0;
	if (strcmp(s, "*") == 0) {
		*flag = COMMUNITY_ANY;
		return 0;
	} else if (strcmp(s, "neighbor-as") == 0) {
		*flag = COMMUNITY_NEIGHBOR_AS;
		return 0;
	} else if (strcmp(s, "local-as") == 0) {
		*flag = COMMUNITY_LOCAL_AS;
		return 0;
	}
	if (large)
		max = UINT_MAX;
	*val = strtonum(s, 0, max, &errstr);
	if (errstr) {
		yyerror("Community %s is %s (max: %lld)", s, errstr, max);
		return -1;
	}
	return 0;
}

static void
setcommunity(struct community *c, uint32_t as, uint32_t data,
    uint32_t asflag, uint32_t dataflag)
{
	c->flags = COMMUNITY_TYPE_BASIC;
	c->flags |= asflag << 8;
	c->flags |= dataflag << 16;
	c->data1 = as;
	c->data2 = data;
	c->data3 = 0;
}

static int
parselargecommunity(struct community *c, char *s)
{
	char *p, *q;
	uint32_t dflag1, dflag2, dflag3;

	if ((p = strchr(s, ':')) == NULL) {
		yyerror("Bad community syntax");
		return (-1);
	}
	*p++ = 0;

	if ((q = strchr(p, ':')) == NULL) {
		yyerror("Bad community syntax");
		return (-1);
	}
	*q++ = 0;

	if (getcommunity(s, 1, &c->data1, &dflag1) == -1 ||
	    getcommunity(p, 1, &c->data2, &dflag2) == -1 ||
	    getcommunity(q, 1, &c->data3, &dflag3) == -1)
		return (-1);
	c->flags = COMMUNITY_TYPE_LARGE;
	c->flags |= dflag1 << 8;
	c->flags |= dflag2 << 16;
	c->flags |= dflag3 << 24;
	return (0);
}

int
parsecommunity(struct community *c, int type, char *s)
{
	char *p;
	uint32_t as, data, asflag, dataflag;

	if (type == COMMUNITY_TYPE_LARGE)
		return parselargecommunity(c, s);

	/* Well-known communities */
	if (strcasecmp(s, "GRACEFUL_SHUTDOWN") == 0) {
		setcommunity(c, COMMUNITY_WELLKNOWN,
		    COMMUNITY_GRACEFUL_SHUTDOWN, 0, 0);
		return (0);
	} else if (strcasecmp(s, "NO_EXPORT") == 0) {
		setcommunity(c, COMMUNITY_WELLKNOWN,
		    COMMUNITY_NO_EXPORT, 0, 0);
		return (0);
	} else if (strcasecmp(s, "NO_ADVERTISE") == 0) {
		setcommunity(c, COMMUNITY_WELLKNOWN,
		    COMMUNITY_NO_ADVERTISE, 0, 0);
		return (0);
	} else if (strcasecmp(s, "NO_EXPORT_SUBCONFED") == 0) {
		setcommunity(c, COMMUNITY_WELLKNOWN,
		    COMMUNITY_NO_EXPSUBCONFED, 0, 0);
		return (0);
	} else if (strcasecmp(s, "NO_PEER") == 0) {
		setcommunity(c, COMMUNITY_WELLKNOWN,
		    COMMUNITY_NO_PEER, 0, 0);
		return (0);
	} else if (strcasecmp(s, "BLACKHOLE") == 0) {
		setcommunity(c, COMMUNITY_WELLKNOWN,
		    COMMUNITY_BLACKHOLE, 0, 0);
		return (0);
	}

	if ((p = strchr(s, ':')) == NULL) {
		yyerror("Bad community syntax");
		return (-1);
	}
	*p++ = 0;

	if (getcommunity(s, 0, &as, &asflag) == -1 ||
	    getcommunity(p, 0, &data, &dataflag) == -1)
		return (-1);
	setcommunity(c, as, data, asflag, dataflag);
	return (0);
}

struct peer *
alloc_peer(void)
{
	struct peer	*p;

	if ((p = calloc(1, sizeof(struct peer))) == NULL)
		fatal("new_peer");

	/* some sane defaults */
	p->state = STATE_NONE;
	p->conf.distance = 1;
	p->conf.capabilities.refresh = 1;
	p->conf.capabilities.as4byte = 1;
	p->conf.capabilities.policy = 1;
	p->conf.local_as = conf->as;
	p->conf.local_short_as = conf->short_as;
	p->conf.remote_port = BGP_PORT;

	return (p);
}

struct peer *
new_peer(void)
{
	struct peer		*p;

	p = alloc_peer();

	return (p);
}

int
get_id(struct peer *newpeer)
{
	static uint32_t id = PEER_ID_STATIC_MIN;
	struct peer	*p = NULL;

	/* check if the peer already existed before */
	if (newpeer->conf.remote_addr.aid) {
		/* neighbor */
		if (cur_peers)
			RB_FOREACH(p, peer_head, cur_peers)
				if (memcmp(&p->conf.remote_addr,
				    &newpeer->conf.remote_addr,
				    sizeof(p->conf.remote_addr)) == 0)
					break;
		if (p) {
			newpeer->conf.id = p->conf.id;
			return (0);
		}
	}

	/* else new one */
	if (id < PEER_ID_STATIC_MAX) {
		newpeer->conf.id = id++;
		return (0);
	}

	return (-1);
}

static int
h2i(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else
		return -1;
}

int
str2key(char *s, char *dest, size_t max_len)
{
	size_t	i;

	if (strlen(s) / 2 > max_len) {
		yyerror("key too long");
		return (-1);
	}

	if (strlen(s) % 2) {
		yyerror("key must be of even length");
		return (-1);
	}

	for (i = 0; i < strlen(s) / 2; i++) {
		int hi, lo;

		hi = h2i(s[2 * i]);
		lo = h2i(s[2 * i + 1]);
		if (hi == -1 || lo == -1) {
			yyerror("key must be specified in hex");
			return (-1);
		}
		dest[i] = (hi << 4) | lo;
	}

	return (0);
}

int
neighbor_consistent(struct peer *p)
{
	struct bgpd_addr *local_addr;
	struct peer *xp;

	local_addr = &p->conf.local_addr;

	/* with any form of ipsec local-address is required */
	if ((p->auth_conf.method == AUTH_IPSEC_IKE_ESP ||
	    p->auth_conf.method == AUTH_IPSEC_IKE_AH ||
	    p->auth_conf.method == AUTH_IPSEC_MANUAL_ESP ||
	    p->auth_conf.method == AUTH_IPSEC_MANUAL_AH) &&
	    local_addr->aid == AID_UNSPEC) {
		yyerror("neighbors with any form of IPsec configured "
		    "need local-address to be specified");
		return (-1);
	}

	/* with static keying we need both directions */
	if ((p->auth_conf.method == AUTH_IPSEC_MANUAL_ESP ||
	    p->auth_conf.method == AUTH_IPSEC_MANUAL_AH) &&
	    (!p->auth_conf.spi_in || !p->auth_conf.spi_out)) {
		yyerror("with manual keyed IPsec, SPIs and keys "
		    "for both directions are required");
		return (-1);
	}

	/* set default values if they where undefined */
	p->conf.ebgp = (p->conf.remote_as != p->conf.local_as);

	if (p->conf.remote_as == 0) {
		yyerror("peer AS may not be zero");
		return (-1);
	}

	/* BGP role and RFC 9234 role are only valid for EBGP neighbors */
	if (!p->conf.ebgp) {
		p->conf.role = ROLE_NONE;
		p->conf.capabilities.policy = 0;
	} else if (p->conf.role == ROLE_NONE) {
		/* no role, no policy capability */
		p->conf.capabilities.policy = 0;
	}

	/* check for duplicate peer definitions */
	RB_FOREACH(xp, peer_head, new_peers)
		if (memcmp(&xp->conf.remote_addr, &p->conf.remote_addr,
		    sizeof(p->conf.remote_addr)) == 0 &&
		    memcmp(&xp->conf.local_addr, &p->conf.local_addr,
		    sizeof(p->conf.local_addr)) == 0)
			break;
	if (xp != NULL) {
		char *descr = log_fmt_peer(&p->conf);
		yyerror("duplicate %s", descr);
		free(descr);
		return (-1);
	}

	return (0);
}

static void
filterset_add(struct filter_set_head *sh, struct filter_set *s)
{
	struct filter_set	*t;

	TAILQ_FOREACH(t, sh, entry) {
		if (s->type < t->type) {
			TAILQ_INSERT_BEFORE(t, s, entry);
			return;
		}
		if (s->type == t->type) {
			switch (s->type) {
			case ACTION_SET_COMMUNITY:
			case ACTION_DEL_COMMUNITY:
				switch (cmpcommunity(&s->action.community,
				    &t->action.community)) {
				case -1:
					TAILQ_INSERT_BEFORE(t, s, entry);
					return;
				case 0:
					break;
				case 1:
					continue;
				}
				break;
			case ACTION_SET_LOCALPREF:
			case ACTION_SET_MED:
			case ACTION_SET_WEIGHT:
				/* only last set matters */
				t->action.metric = s->action.metric;
				break;
			case ACTION_SET_RELATIVE_LOCALPREF:
			case ACTION_SET_RELATIVE_MED:
			case ACTION_SET_RELATIVE_WEIGHT:
				/* sum all relative numbers */
				t->action.relative += s->action.relative;
				break;
			case ACTION_SET_ORIGIN:
				/* only last set matters */
				t->action.origin = s->action.origin;
				break;
			default:
				break;
			}
			free(s);
			return;
		}
	}

	TAILQ_INSERT_TAIL(sh, s, entry);
}

int
merge_filterset(struct filter_set_head *sh, struct filter_set *s)
{
	struct filter_set	*t;

	TAILQ_FOREACH(t, sh, entry) {
		/*
		 * need to cycle across the full list because even
		 * if types are not equal filterset_cmp() may return 0.
		 */
		if (filterset_cmp(s, t) == 0) {
			if (s->type == ACTION_SET_COMMUNITY)
				yyerror("community is already set");
			else if (s->type == ACTION_DEL_COMMUNITY)
				yyerror("community will already be deleted");
			else
				yyerror("redefining set parameter %s",
				    filterset_name(s->type));
			return (-1);
		}
	}

	filterset_add(sh, s);
	return (0);
}

static int
getservice(char *n)
{
	struct servent	*s;

	s = getservbyname(n, "tcp");
	if (s == NULL)
		s = getservbyname(n, "udp");
	if (s == NULL)
		return -1;
	return s->s_port;
}

static int
merge_auth_conf(struct auth_config *to, struct auth_config *from)
{
	if (to->method != 0) {
		/* extra magic for manual ipsec rules */
		if (to->method == from->method &&
		    (to->method == AUTH_IPSEC_MANUAL_ESP ||
		    to->method == AUTH_IPSEC_MANUAL_AH)) {
			if (to->spi_in == 0 && from->spi_in != 0) {
				to->spi_in = from->spi_in;
				to->auth_alg_in = from->auth_alg_in;
				to->enc_alg_in = from->enc_alg_in;
				memcpy(to->enc_key_in, from->enc_key_in,
				    sizeof(to->enc_key_in));
				to->enc_keylen_in = from->enc_keylen_in;
				to->auth_keylen_in = from->auth_keylen_in;
				return 1;
			} else if (to->spi_out == 0 && from->spi_out != 0) {
				to->spi_out = from->spi_out;
				to->auth_alg_out = from->auth_alg_out;
				to->enc_alg_out = from->enc_alg_out;
				memcpy(to->enc_key_out, from->enc_key_out,
				    sizeof(to->enc_key_out));
				to->enc_keylen_out = from->enc_keylen_out;
				to->auth_keylen_out = from->auth_keylen_out;
				return 1;
			}
		}
		yyerror("auth method cannot be redefined");
		return 0;
	}
	*to = *from;
	return 1;
}

