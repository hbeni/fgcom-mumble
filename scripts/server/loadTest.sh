#!/bin/bash
#
# Spawns fake pilots. Hordes of them!
# Supposed to be called from the server directory

spacing=0.25
startat=1
numBots=1

if [[ ! -d test ]]; then echo "Please call me from the server directory, thank you" && exit 1; fi
if [ "$#" -lt 3 -o "$1" = "-h" -o "$1" = "--help" ]; then
	echo "Usage $0 <startAtNr> <numberOfBots> <spacingInSeconds> [... more bot args ...]"
	echo "  'more-bot-args' are just passed as-is to the bot instances."
	echo "  the generated bot-id is passed as --id=\$id."
	echo ""
	echo "Example: "
	echo "  # spawn 5 bots (ids: 1-5), 0.25s apart, and jon that host"
	echo "  $0 1 5 0.25 --host=fgcom.hallinger.org"
	echo "--------------"
	echo "Bot help:"
	luajit test/fgcom-fakepilot.bot.lua --help
	exit 1
fi
if [[ -n $1 ]]; then startat=$1; fi
if [[ -n $2 ]]; then numBots=$2; fi
if [[ -n $3 ]]; then spacing=$3; fi
shift; shift; shift
bot_args=$@


function spawnBot {
	# 1=id, 2=cert, 3=key, 4=sample, 5=log, 6+=more-bot-args
    bcmd="luajit test/fgcom-fakepilot.bot.lua --id=$1 --cert=$2 --key=$3 --sample=$4 $6"
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

	spawnBot $i /tmp/fgcom-bot-$i.pem /tmp/fgcom-bot-$i.key /tmp/fgcom.rec.testsample-$i.fgcs /tmp/fgcom-bot-$i.log "$bot_args"

	sleep $spacing
done
