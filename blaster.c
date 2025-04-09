#include <sys/types.h>

#include <endian.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

#include "bgpd.h"
#include "session.h"
#include "bgp.h"
#include "log.h"
#include "mrtparser.h"

static struct timer_head timers;

static void mrt_dump(struct mrt_rib *mr, struct mrt_peer *mp, void *arg);

static struct mrt_parser mrt_ctx = { mrt_dump, NULL, NULL };

void
global_setup(struct bgpd_config *conf)
{
	int mrtfd;
	const char *mrtfile = "/tmp/blaster.mrt";

	TAILQ_INIT(&timers);
	timer_set(&timers, Timer_Metric, 15);

	ometric_init();

	mrtfd = open(mrtfile, O_RDONLY | O_CLOEXEC);
	if (mrtfd == -1)
		fatal("mrt file %s", mrtfile);

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
global_timer_handle(struct bgpd_config *conf, monotime_t now)
{
	struct timer *t;

	/* check timers */
	if ((t = timer_nextisdue(&timers, now)) != NULL) {
		switch (t->type) {
		case Timer_Metric:
			timer_set(&timers, Timer_Metric, 15);
			ometric_dump(conf);
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

static void
mrt_dump(struct mrt_rib *mr, struct mrt_peer *mp, void *arg)
{
	struct bgpd_config *conf = arg;
	struct mrt_peer_entry *mpe;
	struct mrt_rib_entry *mre;
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

log_debug("%s: %s/%d", __func__, log_addr(&mr->prefix), mr->prefixlen);
	}
}

void
global_peer_up(struct peer *p)
{
}

void
global_peer_down(struct peer *p)
{
}
