/*	$OpenBSD: bgpd.h,v 1.512 2025/02/04 18:16:56 denis Exp $ */

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
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
#ifndef __BGPD_H__
#define	__BGPD_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>

#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <imsg.h>

#include "monotime.h"

#define	BGP_VERSION			4
#define	RTR_MAX_VERSION			2
#define	RTR_DEFAULT_VERSION		1
#define	BGP_PORT			179
#define	RTR_PORT			323
#define	BGPD_USER			"_bgpd"
#define	PEER_DESCR_LEN			64
#define	REASON_LEN			256	/* includes NUL terminator */
#define	PFTABLE_LEN			32
#define	ROUTELABEL_LEN			32
#define	TCP_MD5_KEY_LEN			80
#define	IPSEC_ENC_KEY_LEN		32
#define	IPSEC_AUTH_KEY_LEN		20
#define	SET_NAME_LEN			128

#define	MAX_PKTSIZE			4096
#define	MAX_EXT_PKTSIZE			65535
#define	MAX_BGPD_IMSGSIZE		(128 * 1024)
#define	MAX_SOCK_BUF			(4 * IBUF_READ_SIZE)
#define	RT_BUF_SIZE			16384
#define	MAX_RTSOCK_BUF			(2 * 1024 * 1024)
#define	MAX_COMM_MATCH			3
#define	MAX_ASPA_SPAS_COUNT		10000
#define	MIN_HOLDTIME			3

#define	BGPD_OPT_VERBOSE		0x0001
#define	BGPD_OPT_NOACTION		0x0002

#define CTASSERT(x)	extern char  _ctassert[(x) ? 1 : -1 ] \
			    __attribute__((__unused__))

/*
 * Limit the number of messages queued in the session engine.
 * The SE will send an IMSG_XOFF messages to the RDE if the high water mark
 * is reached. The RDE should then throttle this peer or control connection.
 * Once the message queue in the SE drops below the low water mark an
 * IMSG_XON message will be sent and the RDE will produce more messages again.
 */
#define SESS_MSG_HIGH_MARK	2000
#define SESS_MSG_LOW_MARK	500

/* Address Family Numbers as per RFC 1700 */
#define	AFI_UNSPEC	0
#define	AFI_IPv4	1
#define	AFI_IPv6	2
#define	AFI_L2VPN	25

/* Subsequent Address Family Identifier as per RFC 4760 */
#define	SAFI_NONE		0
#define	SAFI_UNICAST		1
#define	SAFI_MULTICAST		2
#define	SAFI_MPLS		4
#define	SAFI_EVPN		70	/* RFC 7432 */
#define	SAFI_MPLSVPN		128
#define	SAFI_FLOWSPEC		133
#define	SAFI_VPNFLOWSPEC	134

struct aid {
	uint16_t	 afi;
	sa_family_t	 af;
	uint8_t		 safi;
	const char	*name;
};

extern const struct aid aid_vals[];

#define	AID_UNSPEC	0
#define	AID_INET	1
#define	AID_INET6	2
#define	AID_VPN_IPv4	3
#define	AID_VPN_IPv6	4
#define	AID_MAX		5
#define	AID_MIN		1	/* skip AID_UNSPEC since that is a dummy */

#define AID_VALS	{					\
	/* afi, af, safii, name */				\
	{ AFI_UNSPEC, AF_UNSPEC, SAFI_NONE, "unspec"},		\
	{ AFI_IPv4, AF_INET, SAFI_UNICAST, "IPv4 unicast" },	\
	{ AFI_IPv6, AF_INET6, SAFI_UNICAST, "IPv6 unicast" },	\
	{ AFI_IPv4, AF_INET, SAFI_MPLSVPN, "IPv4 vpn" },	\
	{ AFI_IPv6, AF_INET6, SAFI_MPLSVPN, "IPv6 vpn" },	\
}

#define BGP_MPLS_BOS	0x01

struct bgpd_addr {
	union {
		struct in_addr		v4;
		struct in6_addr		v6;
		/* maximum size for a prefix is 256 bits */
	};		    /* 128-bit address */
	uint64_t	rd;		/* route distinguisher for VPN addrs */
	uint32_t	scope_id;	/* iface scope id for v6 */
	uint8_t		aid;
	uint8_t		labellen;	/* size of the labelstack */
	uint8_t		labelstack[18];	/* max that makes sense */
};

#define	DEFAULT_LISTENER	0x01
#define	LISTENER_LISTENING	0x02

struct listen_addr {
	TAILQ_ENTRY(listen_addr)	entry;
	struct sockaddr_storage		sa;
	int				fd;
	socklen_t			sa_len;
	uint8_t				flags;
};

TAILQ_HEAD(listen_addrs, listen_addr);
TAILQ_HEAD(filter_set_head, filter_set);

struct peer;
RB_HEAD(peer_head, peer);

struct network;
TAILQ_HEAD(network_head, network);

struct bgpd_config {
	struct peer_head			 peers;
	struct network_head			 networks;
	struct listen_addrs			*listen_addrs;
	char					*ometric_path;
	char					*mrt_path;
	int					 flags;
	int					 log;
	u_int					 default_tableid;
	uint32_t				 bgpid;
	uint32_t				 as;
	uint16_t				 short_as;
	uint16_t				 holdtime;
	uint16_t				 min_holdtime;
	uint16_t				 connectretry;
	uint16_t				 staletime;
	uint8_t					 fib_priority;
};

extern int cmd_opts;

enum enforce_as {
	ENFORCE_AS_UNDEF,
	ENFORCE_AS_OFF,
	ENFORCE_AS_ON
};

enum role {
	ROLE_NONE,
	ROLE_CUSTOMER,
	ROLE_PROVIDER,
	ROLE_RS,
	ROLE_RS_CLIENT,
	ROLE_PEER,
};

enum auth_method {
	AUTH_NONE,
	AUTH_MD5SIG,
	AUTH_IPSEC_MANUAL_ESP,
	AUTH_IPSEC_MANUAL_AH,
	AUTH_IPSEC_IKE_ESP,
	AUTH_IPSEC_IKE_AH
};

enum auth_alg {
	AUTH_AALG_NONE,
	AUTH_AALG_SHA1HMAC,
	AUTH_AALG_MD5HMAC,
};

enum auth_enc_alg {
	AUTH_EALG_NONE,
	AUTH_EALG_3DESCBC,
	AUTH_EALG_AES,
};

struct auth_config {
	char			md5key[TCP_MD5_KEY_LEN];
	char			auth_key_in[IPSEC_AUTH_KEY_LEN];
	char			auth_key_out[IPSEC_AUTH_KEY_LEN];
	char			enc_key_in[IPSEC_ENC_KEY_LEN];
	char			enc_key_out[IPSEC_ENC_KEY_LEN];
	uint32_t		spi_in;
	uint32_t		spi_out;
	enum auth_method	method;
	enum auth_alg		auth_alg_in;
	enum auth_alg		auth_alg_out;
	enum auth_enc_alg	enc_alg_in;
	enum auth_enc_alg	enc_alg_out;
	uint8_t			md5key_len;
	uint8_t			auth_keylen_in;
	uint8_t			auth_keylen_out;
	uint8_t			enc_keylen_in;
	uint8_t			enc_keylen_out;
};

struct capabilities {
	struct {
		int16_t	timeout;	/* graceful restart timeout */
		int8_t	flags[AID_MAX];	/* graceful restart per AID flags */
		int8_t	restart;	/* graceful restart, RFC 4724 */
		int8_t	grnotification;	/* graceful notification, RFC 8538 */
	}	grestart;
	int8_t	mp[AID_MAX];		/* multiprotocol extensions, RFC 4760 */
	int8_t	add_path[AID_MAX];	/* ADD_PATH, RFC 7911 */
	int8_t	ext_nh[AID_MAX];	/* Ext Nexthop Encoding, RFC 8950 */
	int8_t	refresh;		/* route refresh, RFC 2918 */
	int8_t	as4byte;		/* 4-byte ASnum, RFC 4893 */
	int8_t	enhanced_rr;		/* enhanced route refresh, RFC 7313 */
	int8_t	policy;			/* Open Policy, RFC 9234, 2 = enforce */
	int8_t	ext_msg;		/* Extended Msg, RFC 8654 */
};

enum capa_codes {
	CAPA_NONE = 0,
	CAPA_MP = 1,
	CAPA_REFRESH = 2,
	CAPA_EXT_NEXTHOP = 5,
	CAPA_EXT_MSG = 6,
	CAPA_ROLE = 9,
	CAPA_RESTART = 64,
	CAPA_AS4BYTE = 65,
	CAPA_ADD_PATH = 69,
	CAPA_ENHANCED_RR = 70,
};

/* flags for RFC 4724 - graceful restart */
#define	CAPA_GR_PRESENT		0x01
#define	CAPA_GR_RESTART		0x02
#define	CAPA_GR_FORWARD		0x04
#define	CAPA_GR_RESTARTING	0x08
#define	CAPA_GR_TIMEMASK	0x0fff
#define	CAPA_GR_R_FLAG		0x8000
#define	CAPA_GR_N_FLAG		0x4000
#define	CAPA_GR_F_FLAG		0x80

/* flags for RFC 7911 - enhanced router refresh */
#define	CAPA_AP_RECV		0x01
#define	CAPA_AP_SEND		0x02
#define	CAPA_AP_BIDIR		0x03
#define	CAPA_AP_MASK		0x0f
#define	CAPA_AP_RECV_ENFORCE	0x10	/* internal only */
#define	CAPA_AP_SEND_ENFORCE	0x20	/* internal only */

/* values for RFC 9234 - BGP Open Policy */
#define CAPA_ROLE_PROVIDER	0x00
#define CAPA_ROLE_RS		0x01
#define CAPA_ROLE_RS_CLIENT	0x02
#define CAPA_ROLE_CUSTOMER	0x03
#define CAPA_ROLE_PEER		0x04

struct peer_config {
	struct bgpd_addr	 remote_addr;
	struct bgpd_addr	 local_addr;
	struct capabilities	 capabilities;
	char			 descr[PEER_DESCR_LEN];
	char			 reason[REASON_LEN];
	char			 demote_group[IFNAMSIZ];
	uint32_t		 id;
	uint32_t		 remote_as;
	uint32_t		 local_as;
	uint32_t		 bgpid;
	uint32_t		 max_prefix;
	enum enforce_as		 enforce_as;
	enum role		 role;
	uint16_t		 max_prefix_restart;
	uint16_t		 holdtime;
	uint16_t		 min_holdtime;
	uint16_t		 connectretry;
	uint16_t		 staletime;
	uint16_t		 local_short_as;
	uint16_t		 remote_port;
	uint8_t			 template;
	uint8_t			 ebgp;		/* 0 = ibgp else ebgp */
	uint8_t			 distance;	/* 1 = direct, >1 = multihop */
	uint8_t			 passive;
	uint8_t			 down;
	uint8_t			 reflector_client;
	uint8_t			 ttlsec;	/* TTL security hack */
	uint8_t			 flags;
};

#define	PEER_ID_NONE		0
#define	PEER_ID_SELF		1
#define	PEER_ID_STATIC_MIN	2	/* exclude self */
#define	PEER_ID_STATIC_MAX	(UINT_MAX / 2)
#define	PEER_ID_DYN_MAX		UINT_MAX

struct network_config {
	struct bgpd_addr	 prefix;
	struct filter_set_head	 attrset;
	uint64_t		 rd;
	uint8_t			 prefixlen;
	uint8_t			 old;	/* used for reloading */
};

struct network {
	struct network_config	net;
	TAILQ_ENTRY(network)	entry;
};

/*
 * Communities are encoded depending on their type. The low byte of flags
 * is the COMMUNITY_TYPE (BASIC, LARGE, EXT). BASIC encoding is just using
 * data1 and data2, LARGE uses all data fields and EXT is also using all
 * data fields. The 4-byte flags fields consists of up to 3 data flags
 * for e.g. COMMUNITY_ANY and the low byte is the community type.
 * If flags is 0 the community struct is unused. If the upper 24bit of
 * flags is 0 a fast compare can be used.
 * The code uses a type cast to uint8_t to access the type.
 */
struct community {
	uint32_t	flags;
	uint32_t	data1;
	uint32_t	data2;
	uint32_t	data3;
};

/* special community type, keep in sync with the attribute type */
#define	COMMUNITY_TYPE_NONE		0
#define	COMMUNITY_TYPE_BASIC		8
#define	COMMUNITY_TYPE_EXT		16
#define	COMMUNITY_TYPE_LARGE		32

#define	COMMUNITY_ANY			1
#define	COMMUNITY_NEIGHBOR_AS		2
#define	COMMUNITY_LOCAL_AS		3

/* wellknown community definitions */
#define	COMMUNITY_WELLKNOWN		0xffff
#define	COMMUNITY_GRACEFUL_SHUTDOWN	0x0000  /* RFC 8326 */
#define	COMMUNITY_BLACKHOLE		0x029A	/* RFC 7999 */
#define	COMMUNITY_NO_EXPORT		0xff01
#define	COMMUNITY_NO_ADVERTISE		0xff02
#define	COMMUNITY_NO_EXPSUBCONFED	0xff03
#define	COMMUNITY_NO_PEER		0xff04	/* RFC 3765 */

enum directions {
	DIR_IN = 1,
	DIR_OUT
};

enum action_types {
	ACTION_SET_LOCALPREF,
	ACTION_SET_RELATIVE_LOCALPREF,
	ACTION_SET_MED,
	ACTION_SET_RELATIVE_MED,
	ACTION_SET_WEIGHT,
	ACTION_SET_RELATIVE_WEIGHT,
	ACTION_SET_PREPEND_SELF,
	ACTION_SET_PREPEND_PEER,
	ACTION_DEL_COMMUNITY,
	ACTION_SET_COMMUNITY,
	ACTION_SET_ORIGIN
};

struct filter_set {
	TAILQ_ENTRY(filter_set)		entry;
	union {
		uint8_t				 prepend;
		uint16_t			 id;
		uint32_t			 metric;
		int32_t				 relative;
		struct community		 community;
		uint8_t				 origin;
	}				action;
	enum action_types		type;
};

/* error codes and subcodes needed in SE and RDE */
enum err_codes {
	ERR_HEADER = 1,
	ERR_OPEN,
	ERR_UPDATE,
	ERR_HOLDTIMEREXPIRED,
	ERR_FSM,
	ERR_CEASE,
	ERR_RREFRESH,
	ERR_SENDHOLDTIMEREXPIRED,
};

enum suberr_update {
	ERR_UPD_UNSPECIFIC,
	ERR_UPD_ATTRLIST,
	ERR_UPD_UNKNWN_WK_ATTR,
	ERR_UPD_MISSNG_WK_ATTR,
	ERR_UPD_ATTRFLAGS,
	ERR_UPD_ATTRLEN,
	ERR_UPD_ORIGIN,
	ERR_UPD_LOOP,
	ERR_UPD_NEXTHOP,
	ERR_UPD_OPTATTR,
	ERR_UPD_NETWORK,
	ERR_UPD_ASPATH
};

enum suberr_cease {
	ERR_CEASE_MAX_PREFIX = 1,
	ERR_CEASE_ADMIN_DOWN,
	ERR_CEASE_PEER_UNCONF,
	ERR_CEASE_ADMIN_RESET,
	ERR_CEASE_CONN_REJECT,
	ERR_CEASE_OTHER_CHANGE,
	ERR_CEASE_COLLISION,
	ERR_CEASE_RSRC_EXHAUST,
	ERR_CEASE_HARD_RESET,
	ERR_CEASE_MAX_SENT_PREFIX
};

enum suberr_rrefresh {
	ERR_RR_INV_LEN = 1
};

struct route_refresh {
	uint8_t			aid;
	uint8_t			subtype;
};
#define ROUTE_REFRESH_REQUEST	0
#define ROUTE_REFRESH_BEGIN_RR	1
#define ROUTE_REFRESH_END_RR	2

/* 4-byte magic AS number */
#define AS_TRANS	23456
/* AS_NONE for origin validation */
#define AS_NONE		0

/* prototypes */
/* config.c */
struct bgpd_config	*new_config(void);
void		copy_config(struct bgpd_config *, struct bgpd_config *);
void		network_free(struct network *);
void		free_config(struct bgpd_config *);
int		host(const char *, struct bgpd_addr *, uint8_t *);
uint32_t	get_bgpid(void);

int		 filterset_cmp(struct filter_set *, struct filter_set *);
void		 filterset_move(struct filter_set_head *,
		    struct filter_set_head *);
const char      *filterset_name(enum action_types);


/* log.c */
void		 log_peer_info(const struct peer_config *, const char *, ...)
			__attribute__((__format__ (printf, 2, 3)));
void		 log_peer_warn(const struct peer_config *, const char *, ...)
			__attribute__((__format__ (printf, 2, 3)));
void		 log_peer_warnx(const struct peer_config *, const char *, ...)
			__attribute__((__format__ (printf, 2, 3)));

/* parse.y */
int			cmdline_symset(char *);
struct bgpd_config	*parse_config(const char *, struct peer_head *);

/* util.c */
char		*ibuf_get_string(struct ibuf *, size_t);
const char	*log_addr(const struct bgpd_addr *);
const char	*log_in6addr(const struct in6_addr *);
const char	*log_sockaddr(struct sockaddr *, socklen_t);
const char	*log_rd(uint64_t);
const char	*log_as(uint32_t);
const char	*log_reason(const char *);
const char	*log_aspath_error(int);
const char	*log_policy(enum role);
const char	*log_capability(uint8_t);
int		 aspath_asprint(char **, struct ibuf *);
uint32_t	 aspath_extract(const void *, int);
int		 aspath_verify(struct ibuf *, int, int);
#define		 AS_ERR_LEN	-1
#define		 AS_ERR_TYPE	-2
#define		 AS_ERR_BAD	-3
#define		 AS_ERR_SOFT	-4
struct ibuf	*aspath_inflate(struct ibuf *);
int		 extract_prefix(const u_char *, int, void *, uint8_t, uint8_t);
int		 nlri_get_prefix(struct ibuf *, struct bgpd_addr *, uint8_t *);
int		 nlri_get_prefix6(struct ibuf *, struct bgpd_addr *, uint8_t *);
int		 nlri_get_vpn4(struct ibuf *, struct bgpd_addr *, uint8_t *,
		    int);
int		 nlri_get_vpn6(struct ibuf *, struct bgpd_addr *, uint8_t *,
		    int);
int		 nlri_get_evpn(struct ibuf *, struct bgpd_addr *, uint8_t *);
int		 prefix_compare(const struct bgpd_addr *,
		    const struct bgpd_addr *, int);
void		 inet4applymask(struct in_addr *, const struct in_addr *, int);
void		 inet6applymask(struct in6_addr *, const struct in6_addr *,
		    int);
void		 applymask(struct bgpd_addr *, const struct bgpd_addr *, int);
const char	*aid2str(uint8_t);
int		 aid2afi(uint8_t, uint16_t *, uint8_t *);
int		 afi2aid(uint16_t, uint8_t, uint8_t *);
sa_family_t	 aid2af(uint8_t);
int		 af2aid(sa_family_t, uint8_t, uint8_t *);
struct sockaddr	*addr2sa(const struct bgpd_addr *, uint16_t, socklen_t *);
void		 sa2addr(struct sockaddr *, struct bgpd_addr *, uint16_t *);
const char	*get_baudrate(unsigned long long, char *);

/* attr.c */
struct mrt_rib_entry;
struct bgp_prefix;
struct bgp_attr;
struct attr;
int		 attr_writebuf(struct ibuf *, uint8_t, uint8_t, void *,
		    uint16_t);
void		 attr_init(void);
int		 attr_optadd(struct bgp_attr *, uint8_t, uint8_t, void *,
		    uint16_t);
struct attr	*attr_optget(const struct bgp_attr *, uint8_t);
void		 attr_freeall(struct bgp_attr *);
uint8_t		 attr_flags(uint8_t);
int		 nlri_len(const struct bgp_prefix *);
int		 nlri_writebuf(struct ibuf *, const struct bgp_prefix *);
void		 bgp_attr_free(struct bgp_attr *);
uint64_t	 bgp_attr_calc_hash(const struct bgp_attr *);
struct bgp_attr	*mrt_to_bgp_attr(struct mrt_rib_entry *, int);

/* output_ometric.c */
void		 ometric_init(void);
void		 ometric_free(void);
void		 ometric_dump(struct bgpd_config *);

/* individual functions */
void		 global_setup(struct bgpd_config *);
void		 global_shutdown(void);
void		 global_timer_handle(struct bgpd_config *, monotime_t);
monotime_t	 global_timer_next(monotime_t);
void		 global_parse_update(struct peer *, struct ibuf *);
void		 global_ometric_stats(struct bgpd_config *);
void		 global_peer_up(struct peer *);
void		 global_peer_down(struct peer *);


static const char * const log_procnames[] = {
	"parent",
	"SE",
	"RDE",
	"RTR"
};

/* logmsg.c and needed by bgpctl */
static const char * const statenames[] = {
	"None",
	"Idle",
	"Connect",
	"Active",
	"OpenSent",
	"OpenConfirm",
	"Established"
};

static const char * const msgtypenames[] = {
	"NONE",
	"OPEN",
	"UPDATE",
	"NOTIFICATION",
	"KEEPALIVE",
	"RREFRESH"
};

static const char * const eventnames[] = {
	"None",
	"Start",
	"Stop",
	"Connection opened",
	"Connection closed",
	"Connection open failed",
	"Fatal error",
	"ConnectRetryTimer expired",
	"HoldTimer expired",
	"KeepaliveTimer expired",
	"SendHoldTimer expired",
	"OPEN message received",
	"KEEPALIVE message received",
	"UPDATE message received",
	"NOTIFICATION received",
	"graceful NOTIFICATION received",
};

static const char * const errnames[] = {
	"none",
	"Header error",
	"error in OPEN message",
	"error in UPDATE message",
	"HoldTimer expired",
	"Finite State Machine error",
	"Cease",
	"error in ROUTE-REFRESH message"
};

static const char * const suberr_header_names[] = {
	"none",
	"synchronization error",
	"wrong length",
	"unknown message type"
};

static const char * const suberr_open_names[] = {
	"none",
	"version mismatch",
	"AS unacceptable",
	"BGPID invalid",
	"optional parameter error",
	"authentication error",
	"unacceptable holdtime",
	"unsupported capability",
	NULL,
	NULL,
	NULL,
	"role mismatch",
};

static const char * const suberr_fsm_names[] = {
	"unspecified error",
	"received unexpected message in OpenSent",
	"received unexpected message in OpenConfirm",
	"received unexpected message in Established"
};

static const char * const suberr_update_names[] = {
	"none",
	"attribute list error",
	"unknown well-known attribute",
	"well-known attribute missing",
	"attribute flags error",
	"attribute length wrong",
	"origin unacceptable",
	"loop detected",
	"nexthop unacceptable",
	"optional attribute error",
	"network unacceptable",
	"AS-Path unacceptable"
};

static const char * const suberr_cease_names[] = {
	"none",
	"received max-prefix exceeded",
	"administratively down",
	"peer unconfigured",
	"administrative reset",
	"connection rejected",
	"other config change",
	"collision",
	"resource exhaustion",
	"hard reset",
	"sent max-prefix exceeded"
};

static const char * const suberr_rrefresh_names[] = {
	"none",
	"invalid message length"
};

static const char * const ctl_res_strerror[] = {
	"no error",
	"no such neighbor",
	"permission denied",
	"neighbor does not have this capability",
	"config file has errors, reload failed",
	"previous reload still running",
	"out of memory",
	"not a cloned peer",
	"peer still active, down peer first",
	"no such RIB",
	"operation not supported",
};

static const char * const timernames[] = {
	"None",
	"ConnectRetryTimer",
	"KeepaliveTimer",
	"HoldTimer",
	"SendHoldTimer",
	"IdleHoldTimer",
	"IdleHoldResetTimer",
	"CarpUndemoteTimer",
	"RestartTimer",
	"SessionDownTimer",
	"RTR RefreshTimer",
	"RTR RetryTimer",
	"RTR ExpireTimer",
	"RTR ActiveTimer",
	"Canary",
	"Metric",
	""
};

#endif /* __BGPD_H__ */
