/*	$OpenBSD: bgpd.c,v 1.280 2024/12/03 13:46:53 claudio Exp $ */

/*
 * Copyright (c) 2025 Claudio Jeker <claudio@openbsd.org>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "bgpd.h"
#include "session.h"
#include "log.h"
#include "version.h"

void		sighdlr(int);
__dead void	usage(void);

int			 cflags;
volatile sig_atomic_t	 quit;

void
sighdlr(int sig)
{
	switch (sig) {
	case SIGTERM:
	case SIGINT:
	case SIGHUP:
		quit = 1;
		break;
	}
}

__dead void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-cdnvV] [-D macro=value] -f file\n",
	    __progname);
	exit(1);
}

int	 cmd_opts;

int
main(int argc, char *argv[])
{
	struct bgpd_config	*conf;
	const char		*conffile = NULL;
	int			 ch;

	log_init(1, LOG_DAEMON);	/* log to stderr until daemonized */
	log_setverbose(1);

	while ((ch = getopt(argc, argv, "D:f:nvV")) != -1) {
		switch (ch) {
		case 'D':
			if (cmdline_symset(optarg) < 0)
				log_warnx("could not parse macro definition %s",
				    optarg);
			break;
		case 'f':
			conffile = optarg;
			break;
		case 'n':
			cmd_opts |= BGPD_OPT_NOACTION;
			break;
		case 'v':
			cmd_opts |= BGPD_OPT_VERBOSE;
			break;
		case 'V':
			fprintf(stderr, "bgp-canary %s\n", BGPD_VERSION);
			return 0;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;
	if (argc > 0 || conffile == NULL)
		usage();

	if (cmd_opts & BGPD_OPT_NOACTION) {
		if ((conf = parse_config(conffile, NULL)) == NULL)
			exit(1);

		if (cmd_opts & BGPD_OPT_VERBOSE)
			print_config(conf);
		else
			fprintf(stderr, "configuration OK\n");

		free_config(conf);
		exit(0);
	}

	if (geteuid())
		errx(1, "need root privileges");

	if (getpwnam(BGPD_USER) == NULL)
		errx(1, "unknown user %s", BGPD_USER);

	if ((conf = parse_config(conffile, NULL)) == NULL) {
		log_warnx("config file %s has errors", conffile);
		exit(1);
	}

	if (prepare_listeners(conf) == -1)
		exit(1);

	log_setverbose(cmd_opts & BGPD_OPT_VERBOSE);

	log_info("startup");

	signal(SIGTERM, sighdlr);
	signal(SIGINT, sighdlr);
	signal(SIGHUP, sighdlr);
	signal(SIGPIPE, SIG_IGN);

	global_setup(conf);
	session_main(conf);
	global_shutdown();

	return (0);
}
