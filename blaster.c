#include <sys/types.h>

#include <endian.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include "bgpd.h"
#include "session.h"
#include "bgp.h"
#include "log.h"
#include "mrtparser.h"

static struct timer_head timers;
static struct peer *canary;

//static struct mrt_parser mrt_parser = { mrt_dump, NULL, NULL };

void
global_setup(struct bgpd_config *conf)
{
	TAILQ_INIT(&timers);

	canary = RB_MIN(peer_head, &conf->peers);
	if (canary == NULL)
		fatalx("no canary peer found");

	timer_set(&timers, Timer_Metric, 15);
	ometric_init();
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
