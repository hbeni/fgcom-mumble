#!/bin/bash
#
# Spawns fake pilots. Hordes of them!

spacing=0.25
botsleep=30
host="localhost"
channel="fgcom-mumble"
startat=1
numBots=1

if [[ -z "$1" ]]; then
	echo "Usage $0 <startAtNr> <numberOfBots> <spacingInSeconds> <checkInterval> <host> <channel>"
fi
if [[ -n $1 ]]; then startat=$1; fi
if [[ -n $2 ]]; then numBots=$2; fi
if [[ -n $3 ]]; then spacing=$3; fi
if [[ -n $4 ]]; then botsleep=$4; fi
if [[ -n $5 ]]; then host=$5; fi
if [[ -n $6 ]]; then channel=$6; fi


function spawnBot {
    bcmd="luajit test/fgcom-fakepilot.bot.lua --id=$1 --cert=$2 --key=$3 --sample=$4 --sleep=$6 --host=$7 --channel=$8"
    echo "  cmd=$bcmd >$5 2>$5 &"
    $bcmd >$5 2>$5 &
}


for i in $(seq $startat $(expr $startat + $numBots - 1)); do
	echo "spawning bot: $i"

	# give every bot his own cert/key
	openssl genrsa -out /tmp/fgcom-bot-$i.key 2048 2> /dev/null
	openssl req -new -sha256 -key /tmp/fgcom-bot-$i.key -out /tmp/fgcom-bot-$i.csr -subj "/"
	openssl x509 -req -in /tmp/fgcom-bot-$i.csr -signkey /tmp/fgcom-bot-$i.key -out /tmp/fgcom-bot-$i.pem 2> /dev/null
	
	# and his own sample file
	cp recordings/fgcom.rec.testsample.fgcs /tmp/fgcom.rec.testsample-$i.fgcs

	spawnBot $i /tmp/fgcom-bot-$i.pem /tmp/fgcom-bot-$i.key /tmp/fgcom.rec.testsample-$i.fgcs /tmp/fgcom-bot-$i.log $botsleep $host $channel

	sleep $spacing
done
