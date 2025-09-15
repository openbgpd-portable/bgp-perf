OpenBGPD performance test suite
===============================

This repository holds two applications for performance measurements.
The code of these tools are based on the OpenBGPD core and behave very much like real BGP peers.

bgp-blaster
-----------
The bgp-blaster tool can load mrtdump files and emulate many peers using that table in an efficent way.

bgp-canary
----------
The bgp-canary tool sends special UPDATE messages to the system under test and measures the latency through the system.
The statistics for these measurements are available as an openmetric file.
