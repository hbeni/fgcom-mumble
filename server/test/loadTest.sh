#!/bin/bash
#
# Spawns fake pilots. Hordes of them!

spacing=0.25
botsleep=30

if [[ -z "$1" ]]; then
	echo "Usage $0 <numberOfBots> <spacingInSeconds>" 
fi
if [[ -n $2 ]]; then spacing=$2; fi
if [[ -n $3 ]]; then botsleep=$3; fi


function spawnBot {
    echo "  CMD=test/fgcom-fakepilot.bot.lua --id=$1 --cert=$2 --key=$3 --sample=$4 --sleep=$6 >$5 2>$5 &"
    lua test/fgcom-fakepilot.bot.lua --id=$1 --cert=$2 --key=$3 --sample=$4 --sleep=$6 >$5 2>$5 &
}


for i in $(seq 1 $1); do
	echo "spawning: $i"

	# give every bot his own cert/key
	openssl genrsa -out /tmp/fgcom-bot-$i.key 2048 2> /dev/null
	openssl req -new -sha256 -key /tmp/fgcom-bot-$i.key -out /tmp/fgcom-bot-$i.csr -subj "/"
	openssl x509 -req -in /tmp/fgcom-bot-$i.csr -signkey /tmp/fgcom-bot-$i.key -out /tmp/fgcom-bot-$i.pem 2> /dev/null
	
	# and his own sample file
	cp recordings/fgcom.rec.testsample.fgcs /tmp/fgcom.rec.testsample-$i.fgcs

	spawnBot $i /tmp/fgcom-bot-$i.pem /tmp/fgcom-bot-$i.key /tmp/fgcom.rec.testsample-$i.fgcs /tmp/fgcom-bot-$i.log $botsleep

	sleep $spacing
done
