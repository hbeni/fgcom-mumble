#!/bin/bash
#
# Small script to setup two clients
#

# EDDM
LAT_1=48.3440238
LON_1=11.765083
LAT_2=48.3440238
LON_2=11.769083

#./test/geotest $LAT $LON 2   40.0850000 12.000000 2
echo "CALLSIGN=Test-1111,COM1_FRQ=118.700,LAT=$LAT_1,LON=$LON_1,ALT=6.6" | nc -q0 -u localhost 16661 -p 19991
echo "echo CALLSIGN=Test-1111,COM1_FRQ=118.700,LAT=$LAT_1,LON=$LON_1,ALT=6.6 | nc -q0 -u localhost 16661 -p 19991"

echo "CALLSIGN=Test-2222,COM1_FRQ=118.70,LAT=$LAT_2,LON=$LON_2,ALT=6.6" | nc -q0 -u localhost 16662 -p 19992
echo "echo CALLSIGN=Test-2222,COM1_FRQ=118.70,LAT=$LAT_2,LON=$LON_2,ALT=6.6 | nc -q0 -u localhost 16662 -p 19992"
