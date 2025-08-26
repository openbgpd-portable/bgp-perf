#include <limits.h>
#include <siphash.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bgpd.h"
#include "bgp.h"
#include "log.h"
#include "mrtparser.h"
#include "session.h"
#include "chash.h"

int
attr_writebuf(struct ibuf *buf, uint8_t flags, uint8_t type, void *data,
    uint16_t data_len)
{
	u_char	hdr[4];

	flags &= ~ATTR_DEFMASK;
	if (data_len > 255) {
		flags |= ATTR_EXTLEN;
		hdr[2] = (data_len >> 8) & 0xff;
		hdr[3] = data_len & 0xff;
	} else {
		hdr[2] = data_len & 0xff;
	}

	hdr[0] = flags;
	hdr[1] = type;

	if (ibuf_add(buf, hdr, flags & ATTR_EXTLEN ? 4 : 3) == -1)
		return (-1);
	if (data != NULL && ibuf_add(buf, data, data_len) == -1)
		return (-1);
	return (0);
}

/* optional attribute specific functions */
static struct attr	*attr_alloc(uint8_t, uint8_t, void *, uint16_t);
static struct attr	*attr_lookup(uint8_t, uint8_t, void *, uint16_t);
static void		 attr_put(struct attr *);

static SIPHASH_KEY	 attrkey, bakey;

static inline uint64_t
attr_hash(const struct attr *a)
{
	return a->hash;
}

CH_HEAD(attr_tree, attr)	attrtable = CH_INITIALIZER(&attr);
CH_PROTOTYPE(attr_tree, attr, attr_hash);

void
attr_init(void)
{
	arc4random_buf(&attrkey, sizeof(attrkey));
	arc4random_buf(&bakey, sizeof(bakey));
}

int
attr_optadd(struct bgp_attr *ba, uint8_t flags, uint8_t type,
    void *data, uint16_t len)
{
	int		 l;
	struct attr	*a, *t;
	void		*p;

	/* attribute allowed only once */
	for (l = 0; l < ba->nattrs; l++) {
		if (ba->attrs[l] == NULL)
			break;
		if (type == ba->attrs[l]->type)
			return (-1);
		if (type < ba->attrs[l]->type)
			break;
	}

	if ((a = attr_lookup(flags, type, data, len)) == NULL)
		a = attr_alloc(flags, type, data, len);

	/* add attribute to the table but first bump refcnt */
	a->refcnt++;

	for (l = 0; l < ba->nattrs; l++) {
		if (ba->attrs[l] == NULL) {
			ba->attrs[l] = a;
			return (0);
		}
		/* list is sorted */
		if (a->type < ba->attrs[l]->type) {
			t = ba->attrs[l];
			ba->attrs[l] = a;
			a = t;
		}
	}

	/* no empty slot found, need to realloc */
	if (ba->nattrs == UCHAR_MAX)
		fatalx("attr_optadd: attribute overflow");

	ba->nattrs++;
	if ((p = reallocarray(ba->attrs,
	    ba->nattrs, sizeof(struct attr *))) == NULL)
		fatal("%s", __func__);
	ba->attrs = p;

	/* l stores the size of others before resize */
	ba->attrs[l] = a;
	return (0);
}

struct attr *
attr_optget(const struct bgp_attr *ba, uint8_t type)
{
	int l;

	for (l = 0; l < ba->nattrs; l++) {
		if (ba->attrs[l] == NULL)
			break;
		if (type == ba->attrs[l]->type)
			return (ba->attrs[l]);
		if (type < ba->attrs[l]->type)
			break;
	}
	return (NULL);
}

void
attr_freeall(struct bgp_attr *ba)
{
	int l;

	for (l = 0; l < ba->nattrs; l++)
		attr_put(ba->attrs[l]);

	free(ba->attrs);
	ba->attrs = NULL;
	ba->nattrs = 0;
}

uint8_t
attr_flags(uint8_t type)
{
	switch (type) {
	case ATTR_ORIGIN:
		return ATTR_WELL_KNOWN;
	case ATTR_ASPATH:
		return ATTR_WELL_KNOWN;
	case ATTR_NEXTHOP:
		return ATTR_WELL_KNOWN;
	case ATTR_MED:
		return ATTR_OPTIONAL;
	case ATTR_LOCALPREF:
		return ATTR_WELL_KNOWN;
	case ATTR_ATOMIC_AGGREGATE:
		return ATTR_WELL_KNOWN;
	case ATTR_AGGREGATOR:
		return ATTR_OPTIONAL|ATTR_TRANSITIVE;
	case ATTR_COMMUNITIES:
		return ATTR_OPTIONAL|ATTR_TRANSITIVE;
	case ATTR_ORIGINATOR_ID:
		return ATTR_OPTIONAL;
	case ATTR_CLUSTER_LIST:
		return ATTR_OPTIONAL;
	case ATTR_MP_REACH_NLRI:
		return ATTR_OPTIONAL;
	case ATTR_MP_UNREACH_NLRI:
		return ATTR_OPTIONAL;
	case ATTR_EXT_COMMUNITIES:
		return ATTR_OPTIONAL|ATTR_TRANSITIVE;
	case ATTR_AS4_PATH:
		return ATTR_OPTIONAL|ATTR_TRANSITIVE;
	case ATTR_AS4_AGGREGATOR:
		return ATTR_OPTIONAL|ATTR_TRANSITIVE;
	case ATTR_LARGE_COMMUNITIES:
		return ATTR_OPTIONAL|ATTR_TRANSITIVE;
	case ATTR_OTC:
		return ATTR_OPTIONAL|ATTR_TRANSITIVE;
	default:
		return ATTR_OPTIONAL | ATTR_TRANSITIVE | ATTR_PARTIAL;
	}

}

static uint64_t
attr_calc_hash(const struct attr *oa)
{
	SIPHASH_CTX ctx;

	SipHash24_Init(&ctx, &attrkey);
	SipHash24_Update(&ctx, &oa->type, sizeof(oa->type));
	SipHash24_Update(&ctx, oa->data, oa->len);
	return SipHash24_End(&ctx);
}

static inline int
attr_eq(const struct attr *oa, const struct attr *ob)
{
	if (oa->hash != ob->hash)
		return 0;
	if (oa->type != ob->type)
		return 0;
	if (oa->flags != ob->flags)
		return 0;
	if (oa->len != ob->len)
		return 0;
	return (oa->len == 0 || memcmp(oa->data, ob->data, oa->len) == 0);
}

static struct attr *
attr_alloc(uint8_t flags, uint8_t type, void *data, uint16_t len)
{
	struct attr *a;

	a = calloc(1, sizeof(struct attr));
	if (a == NULL)
		fatal("%s", __func__);

	flags &= ~ATTR_DEFMASK;	/* normalize mask */
	a->flags = flags;
	a->type = type;
	a->len = len;
	if (len != 0) {
		if ((a->data = malloc(len)) == NULL)
			fatal("%s", __func__);
		memcpy(a->data, data, len);
	} else
		a->data = NULL;

	a->hash = attr_calc_hash(a);

	if (CH_INSERT(attr_tree, &attrtable, a, NULL) != 1)
		fatalx("corrupted attr tree");

	return (a);
}

static struct attr *
attr_lookup(uint8_t flags, uint8_t type, void *data, uint16_t len)
{
	struct attr needle;

	flags &= ~ATTR_DEFMASK;	/* normalize mask */

	needle.flags = flags;
	needle.type = type;
	needle.len = len;
	needle.data = data;
	needle.hash = attr_calc_hash(&needle);

	return CH_FIND(attr_tree, &attrtable, &needle);
}

static void
attr_put(struct attr *a)
{
	if (a == NULL)
		return;

	if (--a->refcnt > 0)
		/* somebody still holds a reference */
		return;

	/* unlink */
	CH_REMOVE(attr_tree, &attrtable, a);

	free(a->data);
	free(a);
}

CH_GENERATE(attr_tree, attr, attr_eq, attr_hash);

/* API for bgp_attr and bgp_prefix */

int
nlri_len(const struct bgp_prefix *bp)
{
	int len;

	switch (bp->prefix.aid) {
	case AID_INET:
	case AID_INET6:
		/* XXX what about add-path */
		len = PREFIX_SIZE(bp->prefixlen);
		break;
	default:
		fatalx("%s: unknown aid %d", __func__, bp->prefix.aid);
	}

	return len;
}

int
nlri_writebuf(struct ibuf *buf, const struct bgp_prefix *bp)
{
	switch (bp->prefix.aid) {
	case AID_INET:
	case AID_INET6:
		if (ibuf_add_n8(buf, bp->prefixlen) == -1)
			return -1;
		if (ibuf_add(buf, &bp->prefix.v6,
		    PREFIX_SIZE(bp->prefixlen) - 1) == -1)
			return -1;
		return 0;
	default:
		fatalx("%s: unknown aid %d", __func__, bp->prefix.aid);
	}
}

void
bgp_attr_free(struct bgp_attr *ba)
{
	if (ba == NULL)
		return;
	attr_freeall(ba);
	free(ba);
}

uint64_t
bgp_attr_calc_hash(const struct bgp_attr *ba)
{
	SIPHASH_CTX ctx;

	SipHash24_Init(&ctx, &bakey);
	SipHash24_Update(&ctx, &ba->nexthop, sizeof(ba->nexthop));
	SipHash24_Update(&ctx, ba->attrs, ba->nattrs * sizeof(*ba->attrs));
	return SipHash24_End(&ctx);
}

static int
bgp_attr_eq(const struct bgp_attr *l, const struct bgp_attr *r)
{
	int n;

	if (l->hash != r->hash)
		return 0;
	if (l->nattrs != r->nattrs)
		return 0;
	if (memcmp(&l->nexthop, &r->nexthop, sizeof(l->nexthop)) != 0)
		return 0;

	for (n = 0; n < l->nattrs; n++)
		if (l->attrs[n] != r->attrs[n])
			return 0;
	return 1;
}

CH_GENERATE(rib, bgp_attr, bgp_attr_eq, bgp_attr_hash);

/* mrt helpers */
static int
mrt_attr_add(struct bgp_attr *ba, struct mrt_attr *attr)
{
	uint16_t attr_len;
	uint8_t flags, type;
	uint8_t *buf = attr->attr;
	size_t len = attr->attr_len;

	if (len < 3)
		return -1;
	flags = *buf++;
	type = *buf++;
	len -= 2;

	if (flags & ATTR_EXTLEN) {
		attr_len = *buf++;
		attr_len = attr_len << 8 | *buf++;
		len -= 2;
	} else {
		attr_len = *buf++;
		len--;
	}

	if (len != attr_len) {
		log_warnx("%s: len mismatch", __func__);
		return -1;
	}

	/*
	 * fixup some bad mrtdump issues I have seen:
	 *   = attribute flags are 0 apart from ATTR_EXTLEN
	 *   = ext communities attribute included with 0 len
	 */
	if ((flags & ~ATTR_DEFMASK) == 0)
		flags = attr_flags(type);
	if (type == ATTR_EXT_COMMUNITIES && len == 0)
		return 0;

	return attr_optadd(ba, flags, type, buf, attr_len);
}

struct bgp_attr *
mrt_to_bgp_attr(struct mrt_rib_entry *mre, int ibgp)
{
	struct bgp_attr *ba;
	uint32_t tmp;
	int i;

	if ((ba = calloc(1, sizeof(*ba))) == NULL)
		fatal(NULL);
	TAILQ_INIT(&ba->prefixes);
	ba->nexthop = mre->nexthop;

	if (attr_optadd(ba, ATTR_WELL_KNOWN, ATTR_ORIGIN,
	    &mre->origin, 1) == -1)
		goto fail;
	if (attr_optadd(ba, ATTR_WELL_KNOWN, ATTR_ASPATH,
	    mre->aspath, mre->aspath_len) == -1)
		goto fail;
	tmp = htonl(mre->med);
	if (attr_optadd(ba, ATTR_OPTIONAL, ATTR_MED,
	    &tmp, sizeof(tmp)) == -1)
		goto fail;
	if (ibgp) {
		tmp = htonl(mre->local_pref);
		if (attr_optadd(ba, ATTR_WELL_KNOWN, ATTR_LOCALPREF,
		    &tmp, sizeof(tmp)) == -1)
			goto fail;
	}

	for (i = 0; i < mre->nattrs; i++) {
		if (mrt_attr_add(ba, &mre->attrs[i]) == -1)
			goto fail;
	}

	return ba;

 fail:
	bgp_attr_free(ba);
	return NULL;
}
