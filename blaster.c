#include <sys/types.h>

#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bgpd.h"
#include "session.h"
#include "bgp.h"
#include "log.h"
#include "mrtparser.h"

static struct timer_head timers;

static void mrt_dump(struct mrt_rib *mr, struct mrt_peer *mp, void *arg);
static void blast(struct peer *);

static struct mrt_parser mrt_ctx = { mrt_dump, NULL, NULL };

void
global_setup(struct bgpd_config *conf)
{
	int mrtfd;

	TAILQ_INIT(&timers);
#if 0
	timer_set(&timers, Timer_Metric, 15);
#endif

	attr_init();
	ometric_init();

	mrtfd = open(conf->mrt_path, O_RDONLY | O_CLOEXEC);
	if (mrtfd == -1)
		fatal("mrt file %s", conf->mrt_path);

	mrt_ctx.arg = conf;
	mrt_parse(mrtfd, &mrt_ctx, 1);
}

void
global_shutdown(void)
{
	ometric_free();
}

void
global_parse_update(struct peer *p, struct ibuf *buf)
{
}

void
global_peer_up(struct peer *p)
{
	log_peer_warnx(&p->conf, "session up");
	blast(p);
}

void
global_peer_down(struct peer *p)
{
	log_peer_warnx(&p->conf, "session down");
}

void
global_timer_handle(struct bgpd_config *conf, monotime_t now)
{
	struct timer *t;

	/* check timers */
	if ((t = timer_nextisdue(&timers, now)) != NULL) {
		switch (t->type) {
		case Timer_Metric:
#if 0
			timer_set(&timers, Timer_Metric, 15);
			ometric_dump(conf);
#endif
			break;
		default:
			break;
		}
	}
}

monotime_t
global_timer_next(monotime_t timeout)
{
	monotime_t nextaction;

	nextaction = timer_nextduein(&timers);
	if (monotime_valid(nextaction) &&
	    monotime_cmp(nextaction, timeout) < 0)
		timeout = nextaction;

	return timeout;
}

void
global_ometric_stats(struct bgpd_config *conf)
{
}

static struct peer *
get_peer(struct bgpd_config *conf, struct mrt_peer_entry *mpe)
{
	struct peer *p;

	if (mpe == NULL)
		return NULL;

	/* we might want a more effective way to find peers by IP */
	 RB_FOREACH(p, peer_head, &conf->peers)
		if (memcmp(&p->conf.local_addr, &mpe->addr,
		    sizeof(mpe->addr)) == 0)
			return p;
	return NULL;
}

static struct bgp_prefix *
bp_new(struct bgpd_addr *prefix, uint8_t plen, uint32_t path_id)
{
	struct bgp_prefix *bp;

	if ((bp = calloc(1, sizeof(*bp))) == NULL)
		fatal(NULL);
	bp->prefix = *prefix;
	bp->path_id = path_id;
	bp->prefixlen = plen;
	return bp;
}

static void
mrt_dump(struct mrt_rib *mr, struct mrt_peer *mp, void *arg)
{
	struct bgpd_config *conf = arg;
	struct mrt_peer_entry *mpe;
	struct mrt_rib_entry *mre;
	struct bgp_attr *ba, *prev;
	struct bgp_prefix *bp;
	struct peer *p;
	uint16_t i;

	/* XXX ignore add-path */
	if (mr->add_path)
		return;

	for (i = 0; i < mr->nentries; i++) {
		mre = &mr->entries[i];

		if (mre->peer_idx < mp->npeers)
			mpe = &mp->peers[mre->peer_idx];
		else
			mpe = NULL;

		/* filter by neighbor */
		if ((p = get_peer(conf, mpe)) == NULL)
			continue;

		ba = mrt_to_bgp_attr(mre, !p->conf.ebgp);
		if (ba == NULL) {
			log_peer_warnx(&p->conf,
			   "failed to create attrs for %s/%d",
			   log_addr(&mr->prefix), mr->prefixlen);
			continue;
		}

		ba->hash = bgp_attr_calc_hash(ba);
		if (CH_INSERT(rib, &p->rib, ba, &prev) == -1)
			fatal("CH_INSERT");
		if (prev != NULL)
			bgp_attr_free(ba);
		else
			prev = ba;

		bp = bp_new(&mr->prefix, mr->prefixlen, mre->path_id);
		TAILQ_INSERT_TAIL(&prev->prefixes, bp, entry);
//log_peer_warnx(&p->conf, "inserted %s/%d, at %p rib %d", log_addr(&mr->prefix),
//    mr->prefixlen, prev, p->rib.ch_table.ch_num_elm);
	}
}

static struct ibuf *
blast_attrs(struct peer *p, struct bgp_attr *ba)
{
	struct ibuf *buf;
	struct attr *oa = NULL;
	int i, oalen = 0;

	if ((buf = ibuf_dynamic(4, MAX_PKTSIZE - MSGSIZE_HEADER - 4)) == NULL)
		goto fail;

	if (ba->nattrs > 0)
		oa = ba->attrs[oalen++];

	/* dump attributes */
	for (i = ATTR_ORIGIN; i < 255; i++) {
		while (oa && oa->type < i) {
			if (oalen < ba->nattrs)
				oa = ba->attrs[oalen++];
			else
				oa = NULL;
		}

		switch (i) {
		case ATTR_NEXTHOP:
			if (ba->nexthop.aid == AID_INET) {
				if (attr_writebuf(buf, ATTR_WELL_KNOWN,
				    ATTR_NEXTHOP, &ba->nexthop.v4,
				    sizeof(ba->nexthop.v4)) == -1)
					goto fail;
			}
			break;
		default:
			if (oa == NULL && i >= ATTR_FIRST_UNKNOWN) {
				i = 255;
				break;
			}
			if (oa == NULL || oa->type != i)
				break;

			if (attr_writebuf(buf, oa->flags, oa->type,
			    oa->data, oa->len) == -1)
				goto fail;
		}
	}

	return buf;
 fail:
	ibuf_free(buf);
	return NULL;
}

static int
blast_send(struct peer *p, struct ibuf *attrs, struct ibuf *nlri)
{
	struct ibuf *buf;

	if ((buf = ibuf_dynamic(4, MAX_PKTSIZE - MSGSIZE_HEADER)) == NULL)
		goto fail;

	/* withdrawn routes length field is 0 */
	if (ibuf_add_n16(buf, 0) == -1)
		goto fail;
	/* 2-byte path attribute length */
	if (ibuf_add_n16(buf, ibuf_size(attrs)) == -1)
		goto fail;
	if (ibuf_add_ibuf(buf, attrs) == -1)
		goto fail;
	if (ibuf_add_ibuf(buf, nlri) == -1)
		goto fail;

log_peer_warnx(&p->conf, "sending one update, size %zu", ibuf_size(buf));
	session_update(p, buf);
	return 0;
 fail:
	ibuf_free(buf);
	return -1;
}

static void
blast_one(struct peer *p, struct bgp_attr *ba)
{
	struct ibuf *attrs, *nlris = NULL;
	struct bgp_prefix *bp;
	size_t nlen;

	if ((attrs = blast_attrs(p, ba)) == NULL)
		goto fail;

	if ((nlris = ibuf_dynamic(4, MAX_PKTSIZE)) == NULL)
		goto fail;

	nlen = ibuf_left(attrs);
	TAILQ_FOREACH(bp, &ba->prefixes, entry) {
		if (nlri_len(bp) + ibuf_size(nlris) > nlen) {
			/* need to send packet out now */
			if (blast_send(p, attrs, nlris) == -1)
				goto fail;
			ibuf_truncate(nlris, 0);
		}

		if (nlri_writebuf(nlris, bp) == -1)
			goto fail;
	}
	if (ibuf_size(nlris) > 0)
		if (blast_send(p, attrs, nlris) == -1)
			goto fail;

	ibuf_free(attrs);
	ibuf_free(nlris);
	return;

 fail:
	log_peer_warnx(&p->conf, "generating update failed");
	ibuf_free(attrs);
	ibuf_free(nlris);
	/* TODO reset session? */
}

static void
blast(struct peer *p)
{
	struct bgp_attr *ba;
	struct ch_iter iter;

	CH_FOREACH(ba, rib, &p->rib, &iter) {
		log_peer_warnx(&p->conf, "generating one update");
		blast_one(p, ba);
	}
	log_peer_warnx(&p->conf, "blast done");
}
