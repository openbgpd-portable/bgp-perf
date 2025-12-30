# OpenBGPD performance test suite

This repository holds two applications for performance measurements.
The code of these tools are based on the OpenBGPD core and behave very much like real BGP peers.

# SYNOPSIS

**bgp-blaster**
\[**-nvV**]
\[**-D**&nbsp;*macro*=*value*]
**-f**&nbsp;*file*  
**bgp-canary**
\[**-nvV**]
\[**-D**&nbsp;*macro*=*value*]
**-f**&nbsp;*file*

# DESCRIPTION

**bgp-blaster**
and
**bgp-canary**
are programs for Border Gateway Protocol (BGP) performance measurements.

The
**bgp-blaster**
tool can load mrtdump files into a table and emulate many peers using
that table in an efficient way.

The
**bgp-canary**
tool sends special UPDATE messages to the system under test and measures
the latency through the system.

The statistics for these measurements are available as an openmetric file.

**-D** *macro*=*value*

> Define
> *macro*
> to be set to
> *value*
> on the command line.
> Overrides the definition of
> *macro*
> in the configuration file.

**-f** *file*

> Use
> *file*
> as the configuration file.

**-n**

> Configtest mode.
> Only check the configuration file for validity.

**-v**

> Produce more verbose output.

**-V**

> Show the version and exit.

# EXAMPLES

The configuration file for both tools supports a subset of the
bgpd.conf(5)
configuration syntax.
A minimal
*bgp-blaster.conf*
contains

	# testdump is an mrtdump file
	mrt dump "/path/to/testdump"

A minimal
*bgp-canary.conf*
contains

	# configure where to write the ometric output
	dump metric "/path/to/metric"

and it also requires the configuration of peers via the
**neighbor**
directive as in
bgpd.conf(5).

# SEE ALSO

bgpd.conf(5),
bgpctl(8),
bgpd(8)

# STANDARDS

*A Border Gateway Protocol 4 (BGP-4)*,
[RFC 4271](http://www.rfc-editor.org/rfc/rfc4271.html),
January 2006.

*Multi-Threaded Routing Toolkit (MRT) Routing Information Export Format*,
[RFC 6396](http://www.rfc-editor.org/rfc/rfc6396.html),
October 2011.

OpenBSD 7.8 - December 30, 2025 - BGP-BLASTER(8)
