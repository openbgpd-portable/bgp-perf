#include <sys/types.h>

#include <endian.h>
#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "bgpd.h"
#include "session.h"
#include "bgp.h"
#include "log.h"
#include "ometric.h"

static struct timer_head timers;
static struct peer *canary;

struct canary_stat {
	unsigned long long sent;
	unsigned long long recv;
	unsigned long long missed;
	double sum;
	double sumsq;
	double min;
	double max;
	uint32_t num;
	uint32_t last_seq;
};

static struct canary_stat cstat;

struct ometric *canary_count;
struct ometric *canary_min, *canary_max, *canary_avg, *canary_stddev;

static void
canary_ometric_init(void)
{
	canary_count = ometric_new(OMT_COUNTER, "bgpd_canary_updates",
	    "number of round-trip mesurements");

	canary_min = ometric_new(OMT_GAUGE, "bgpd_canary_min",
	    "minimum round-trip time seen");
	canary_max = ometric_new(OMT_GAUGE, "bgpd_canary_max",
	    "maximum round-trip time seen");
	canary_avg = ometric_new(OMT_GAUGE, "bgpd_canary_avg",
	    "avarage round-trip time seen");
	canary_stddev = ometric_new(OMT_GAUGE, "bgpd_canary_stddev",
	    "std-dev of round-trip time seen");
}

void
global_setup(struct bgpd_config *conf)
{
	TAILQ_INIT(&timers);

	canary = RB_MIN(peer_head, &conf->peers);
	if (canary == NULL)
		fatalx("no canary peer found");

	timer_set(&timers, Timer_Canary, 1);
	timer_set(&timers, Timer_Metric, 15);
	cstat.min = INFINITY;
	ometric_init();
	canary_ometric_init();
}

void
global_shutdown(void)
{
	ometric_free();
}

static void
canary_generate_update(struct peer *p)
{
	static uint32_t seq;	/* XXX */
	struct ibuf *buf;
	size_t off;
	struct in_addr nh = p->local.v4;
	monotime_t now;
	long long usec;
	uint16_t len;
	uint8_t origin = ORIGIN_INCOMPLETE;

	if ((buf = ibuf_dynamic(4, MAX_PKTSIZE - MSGSIZE_HEADER)) == NULL)
		goto fail;

	/* withdrawn routes length field is 0 */
	if (ibuf_add_zero(buf, sizeof(len)) == -1)
		goto fail;
	/* reserve space for 2-byte path attribute length */
	off = ibuf_size(buf);
	if (ibuf_add_zero(buf, sizeof(len)) == -1)
		goto fail;

	/* dump attributes */
	if (attr_writebuf(buf, ATTR_WELL_KNOWN, ATTR_ORIGIN, &origin, 1) == -1)
		goto fail;
	if (attr_writebuf(buf, ATTR_WELL_KNOWN, ATTR_ASPATH, NULL, 6) == -1 ||
	    ibuf_add_n8(buf, AS_SEQUENCE) == -1 ||
	    ibuf_add_n8(buf, 1) == -1 ||
	    ibuf_add_n32(buf, p->conf.local_as) == -1)
		goto fail;
	if (attr_writebuf(buf, ATTR_WELL_KNOWN, ATTR_NEXTHOP, &nh,
	    sizeof(nh)) == -1)
		goto fail;
	if (!p->conf.ebgp) {
		if (attr_writebuf(buf, ATTR_WELL_KNOWN, ATTR_LOCALPREF,
		    NULL, sizeof(uint32_t)) == -1 ||
		    ibuf_add_n32(buf, 100) == -1)
			goto fail;
	}
	/* communities */
	now = getmonotime();
	usec = monotime_to_usec(now);
	
	if (attr_writebuf(buf, ATTR_OPTIONAL | ATTR_TRANSITIVE,
	    ATTR_LARGE_COMMUNITIES, NULL, 3*12) == -1 ||
	    ibuf_add_n32(buf, p->conf.local_as) == -1 ||
	    ibuf_add_n32(buf, 0xc0ffee01) == -1 ||
	    ibuf_add_n32(buf, usec >> 32) == -1 ||
	    ibuf_add_n32(buf, p->conf.local_as) == -1 ||
	    ibuf_add_n32(buf, 0xc0ffee02) == -1 ||
	    ibuf_add_n32(buf, usec & 0xffffffff) == -1 ||
	    ibuf_add_n32(buf, p->conf.local_as) == -1 ||
	    ibuf_add_n32(buf, 0xc0ffee03) == -1 ||
	    ibuf_add_n32(buf, ++seq) == -1)
		goto fail;

	/* update attribute length field */
	len = ibuf_size(buf) - off - sizeof(len);
	if (ibuf_set_n16(buf, off, len) == -1)
		goto fail;

	/* last but not least dump the IPv4 nlri */
	if (ibuf_add_n8(buf, 24) == -1 ||
	    ibuf_add_n8(buf, 192) == -1 ||
	    ibuf_add_n8(buf, 0) == -1 ||
	    ibuf_add_n8(buf, 2) == -1)
		goto fail;

	session_update(p, buf);
	cstat.sent++;

	ibuf_free(buf);
	return;

 fail:
	log_peer_warnx(&p->conf, "generating canary update failed");
	ibuf_free(buf);
}

static int
attr_parse_hdr(struct ibuf *attrbuf, struct ibuf *attr, uint8_t *type,
    uint8_t *flags)
{
	uint16_t len;

	if (ibuf_get_n8(attrbuf, flags) == -1 ||
	    ibuf_get_n8(attrbuf, type) == -1)
		return -1;

	if (*flags & ATTR_EXTLEN) {
		uint16_t attr_len;
		if (ibuf_get_n16(attrbuf, &attr_len) == -1)
			return -1;
		len = attr_len;
	} else {
		uint8_t attr_len;
		if (ibuf_get_n8(attrbuf, &attr_len) == -1)
			return -1;
		len = attr_len;
	}
	if (ibuf_get_ibuf(attrbuf, len, attr) == -1)
		return -1;
	return 0;
}

static void
canary_observe(struct peer *p, long long usec, uint32_t seq)
{
	double t = usec;

	cstat.recv++;
	cstat.num++;
	cstat.sum += t;
	cstat.sumsq += t * t;
	if (t < cstat.min || cstat.min == 0.0)
		cstat.min = t;
	if (t > cstat.max)
		cstat.max = t;

	cstat.missed += seq - 1 - cstat.last_seq;
	cstat.last_seq = seq;
}

void
global_parse_update(struct peer *p, struct ibuf *buf)
{
	struct ibuf attrbuf, attr;
	uint16_t len;
	uint32_t val1, val2, val3, seq;
	long long usec = 0;
	monotime_t now;
	uint8_t type, flags;

	/* withdraws */
	if (ibuf_get_n16(buf, &len) == -1 || len != 0)
		goto fail;
	/* attributes */
	if (ibuf_get_n16(buf, &len) == -1 ||
	    ibuf_get_ibuf(buf, len, &attrbuf) == -1)
		goto fail;

	while (ibuf_size(&attrbuf) > 0) {
		if (attr_parse_hdr(&attrbuf, &attr, &type, &flags) == -1)
			goto fail;

		switch (type) {
		case ATTR_LARGE_COMMUNITIES:
			while (ibuf_size(&attr) > 0) {
				if (ibuf_get_n32(&attr, &val1) == -1 ||
				    ibuf_get_n32(&attr, &val2) == -1 ||
				    ibuf_get_n32(&attr, &val3) == -1)
					goto fail;
				if (val2 == 0xc0ffee01)
					usec |= (uint64_t)val3 << 32;
				if (val2 == 0xc0ffee02)
					usec |= val3;
				if (val2 == 0xc0ffee03)
					seq = val3;
			}
			if (usec != 0) {
				now = getmonotime();
				usec = monotime_to_usec(now) - usec;
				canary_observe(p, usec, seq);
			}
			break;
		default:
			break;
		}
	}

 fail:
	/* XXX */
	;
}

void
global_peer_up(struct peer *p)
{
}

void
global_peer_down(struct peer *p)
{
}

void
global_timer_handle(struct bgpd_config *conf, monotime_t now)
{
	struct timer *t;

	/* check timers */
	if ((t = timer_nextisdue(&timers, now)) != NULL) {
		switch (t->type) {
		case Timer_Canary:
			timer_rearm(&timers, Timer_Canary, 1);
			if (canary->state == STATE_ESTABLISHED)
				canary_generate_update(canary);
			break;
		case Timer_Metric:
			timer_rearm(&timers, Timer_Metric, 15);
			ometric_dump(conf);
			cstat.min = INFINITY;
			cstat.max = cstat.sum = cstat.sumsq = 0.0;
			cstat.num = 0;
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
	double avg, stddev;

	ometric_set_int_with_labels(canary_count, cstat.sent,
	    OKV("type"), OKV("sent"), NULL);
	ometric_set_int_with_labels(canary_count, cstat.recv,
	    OKV("type"), OKV("recv"), NULL);
	ometric_set_int_with_labels(canary_count, cstat.missed,
	    OKV("type"), OKV("missed"), NULL);

	/* only update if data was sampled */
	if (cstat.num > 0) {
		ometric_set_float(canary_min, cstat.min / 1e6, NULL);
		ometric_set_float(canary_max, cstat.max / 1e6, NULL);
		avg = (cstat.sum / cstat.num);
		ometric_set_float(canary_avg, avg / 1e6, NULL);
		stddev = sqrt(fmax(0, cstat.sumsq / cstat.num - avg * avg));
		ometric_set_float(canary_stddev, stddev / 1e6, NULL);

log_warnx("round-trip min/avg/max/std-dev = %.3f/%.3f/%.3f/%.3f ms",
    cstat.min / 1e3, avg / 1e3, cstat.max / 1e3, stddev / 1e3);
	}
}
