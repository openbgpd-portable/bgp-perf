#	$OpenBSD: Makefile,v 1.39 2023/04/17 08:02:21 claudio Exp $

BINDIR?=	/usr/local/sbin

PROGS =	bgp-canary bgp-blaster
SRCS_common = attr.c config.c log.c logmsg.c main.c pfkey.c \
		printconf.c session.c session_bgp.c timer.c util.c monotime.c \
		ometric.c output_ometric.c chash.c

SRCS_bgp-canary = canary.c canary_parse.y ${SRCS_common}
SRCS_bgp-blaster = blaster.c blaster_parse.y mrtparser.c ${SRCS_common}

CFLAGS+= -Wall -I${.CURDIR}
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith -Wcast-qual
CFLAGS+= -Wsign-compare
YFLAGS=
LDADD+=	-lutil
DPADD+= ${LIBUTIL}
MAN=	bgp-blaster.8

.include <bsd.prog.mk>
