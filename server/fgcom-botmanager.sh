#!/bin/bash
#####################################################################################
# This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
# Copyright (c) 2020 Benedikt Hallinger
# 
# This program is free software: you can redistribute it and/or modify  
# it under the terms of the GNU General Public License as published by  
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License 
# along with this program. If not, see <http://www.gnu.org/licenses/>. ]]
#####################################################################################
#
# FGCOM-mumble bot manager
# 
# This script is intendet as the main server side "executable".
# It will:
#   - setup a fifo filenode
#   - spawn a radio recorder bot into the channel and instructs it to notify to the generated fifo
#   - read from the fifo to call playback bots for new samples
#


# Define defaults
host="localhost"
port="64738"
channel="fgcom-mumble"
rcert="recbot.pem"
rkey="recbot.key"
rname="$(grep "local botname" fgcom-radio-recorder.bot.lua |head -n1 |sed 's/.\+"\(.\+\)".*/\1/')"
pcert="playbot.pem"
pkey="playbot.key"
pname="$(grep "local callsignPrefix" fgcom-radio-playback.bot.lua |head -n1 |sed 's/.\+"\(.\+\)".*/\1/')"
scert="statusbot.pem"
skey="statusbot.key"
path="./recordings"
limit="120" # default time limit for recordings in secs
ttl="7200"  # default time-to-live after recordings in secs
fnotify="/tmp/fgcom-fnotify-fifo"
statusbot_db="/tmp/fgcom-web.db"
statusbot_web=""
statusbot_stats=""
sname="$(grep "fgcom.callsign" statuspage/fgcom-status.bot.lua |head -n1 |sed 's/.\+"\(.\+\)".*/\1/')"
debug="0"

recorderbot_log=/dev/null
playbackbot_log=/dev/null
statusbot_log=/dev/null

run_recorderbot="1"
run_playbackbot="1"
run_statusbot="1"

verify="0"

# function for nicer output
log() { echo "$(date '+%F %T.%N'): $1"; }

# print usage information
function usage() {
    echo "Manage FGCOM-mumble bots"
    echo "Options:"
    echo "    --help -h  print usage and exit"
    echo "    --verify   print set optins and exit"
    echo ""
    echo "Common options, that will be passed to bots:"
    echo "    --host=    host to connect to               (default=$host)"
    echo "    --port=    port to connect to               (default=$port)"
    echo "    --channel= channel to join                  (default=$channel)"
    echo "    --debug    enable debug mode"
    echo ""
    echo "Recording bot options:"
    echo "    --rname=   Name for the bot                 (default=$rname)"
    echo "    --norec    Do not run recorder bot"
    echo "    --rcert=   path to PEM encoded cert         (default=$rcert)"
    echo "    --rkey=    path to the certs key            (default=$rkey)"
    echo "    --path=    Path to store the recordings to  (default=$path)"
    echo "    --limit=   Max limit to record, in seconds  (default=$limit)"
    echo "               (how long ATIS samples can be)"
    echo "    --ttl=     Max timeToLive in seconds        (default=$ttl)"
    echo "               (for how long ATIS samples will loop)"
    echo "    --fnotify= fifo to where the recorder notifies (default=$fnotify)"
    echo "    --rlog=    Recorder bot logfile (\"-\"=STDOUT) (default=$recorderbot_log)"
    echo ""
    echo "Playback bot options:"
    echo "    --pname    Name for the bot          (default=$pname)"
    echo "               (%s will be replaced by random numbers)"
    echo "    --noplay   Do not run playback bots"
    echo "    --pcert=   path to PEM encoded cert         (default=$pcert)"
    echo "    --pkey=    path to the certs key            (default=$pkey)"
    echo "    --plog=    Playback bot logfile (\"-\"=STDOUT) (default=$playbackbot_log)"
    echo ""
    echo "Statuspage bot options:"
    echo "    --sname=   Name for the bot                 (default=$sname)"
    echo "    --nostatus Do not run status bot"
    echo "    --scert=   path to PEM encoded cert         (default=$scert)"
    echo "    --skey=    path to the certs key            (default=$skey)"
    echo "    --slog=    Playback bot logfile (\"-\"=STDOUT) (default=$statusbot_log)"
    echo "    --sdb=     Database file to write           (default=$statusbot_db)"
    echo "    --sweb=    Advertise url in comment         (default=no commercials!)"
    echo "    --sstats=  generate stats to this file      (default=no)"
}

# Parse cmdline args
for opt in "$@"; do
    case $opt in
       --help)  usage; exit 0  ;;
       -h)      usage; exit 0 ;;
       --verify) verify="1" ;;
       --host=*)  host=$(echo $opt|cut -d"=" -f2);;
       --port=*)  port=$(echo $opt|cut -d"=" -f2);;
       --channel=*)   channel=$(echo $opt|cut -d"=" -f2);;
       --rname=*) rname=$(echo $opt|cut -d"=" -f2);;
       --rcert=*) rcert=$(echo $opt|cut -d"=" -f2);;
       --rkey=*)  rkey=$(echo $opt|cut -d"=" -f2);;
       --pname=*) pname=$(echo $opt|cut -d"=" -f2);;
       --pcert=*) pcert=$(echo $opt|cut -d"=" -f2);;
       --pkey=*)  pkey=$(echo $opt|cut -d"=" -f2);;
       --scert=*) scert=$(echo $opt|cut -d"=" -f2);;
       --skey=*)  skey=$(echo $opt|cut -d"=" -f2);;
       --path=*)  path=$(echo $opt|cut -d"=" -f2);;
       --limit=*) limit=$(echo $opt|cut -d"=" -f2);;
       --ttl=*)   ttl=$(echo $opt|cut -d"=" -f2);;
       --fnotify=*)   fnotify=$(echo $opt|cut -d"=" -f2);;
       --plog=*)  playbackbot_log=$(echo $opt|cut -d"=" -f2);;
       --rlog=*)  recorderbot_log=$(echo $opt|cut -d"=" -f2);;
       --slog=*)  statusbot_log=$(echo $opt|cut -d"=" -f2);;
       --sdb=*)   statusbot_db=$(echo $opt|cut -d"=" -f2);;
       --sweb=*)  statusbot_web=$(echo $opt|cut -d"=" -f2);;
       --sstats=*)  statusbot_stats=$(echo $opt|cut -d"=" -f2);;
       --sname=*) sname=$(echo $opt|cut -d"=" -f2);;
       --debug)   debug="1";;
       --norec)    run_recorderbot="0";;
       --noplay)   run_playbackbot="0";;
       --nostatus) run_statusbot="0";;
       *) echo "unknown option $opt!"; usage; exit 1;;
   esac
done

# Print a nice message when starting, so its clear what will happen
log "Starting FGCom-mumble bot manager..."
log "pwd: $(pwd)"
log "commandline used: $0$(for opt in "$@"; do echo -n " $opt"; done)"
log "effective options:"
log "  --host=$host"
log "  --port=$port"
log "  --channel=$channel"
log "  --rname=$rname"
log "  --rcert=$rcert"
log "  --rkey=$rkey"
log "  --pname=$pname"
log "  --pcert=$pcert"
log "  --pkey=$pkey"
log "  --scert=$scert"
log "  --skey=$skey"
log "  --path=$path"
log "  --limit=$limit"
log "  --ttl=$ttl"
log "  --rlog=$recorderbot_log"
log "  --plog=$playbackbot_log"
log "  --sname=$sname"
log "  --slog=$statusbot_log"
log "  --sdb=$statusbot_db"
log "  --sweb=$statusbot_web"
log "  --sstats=$statusbot_stats"
[[ $debug == "1" ]] && log "  --debug"

# define cmd options for the bot callups
common_opts="--host=$host --port=$port --channel=$channel"
[[ $debug == "1" ]] && common_opts="$common_opts --debug"
playback_opts="$common_opts --name=$pname --cert=$pcert --key=$pkey"
recorder_opts="$common_opts --name=$rname --cert=$rcert --key=$rkey --path=$path --limit=$limit --ttl=$ttl"
status_opts="$common_opts --name=$sname --cert=$scert --key=$skey --db=$statusbot_db"

if [[ $verify == "1" ]] then
    log "basic playback_opts=$playback_opts"
    log "basic recorder_opts=$recorder_opts"
    log "basic status_opts=$status_opts"
    exit 0
fi


# define cleanup routine
function cleanup()
{
    log "cleanup..."
    rm -f $fnotify
    sleep 1  # so the watchdog can shut down properly, removing the notify pipe signals this
    pkill -f "fgcom-radio-recorder.bot.lua"
    pkill -f "fgcom-status.bot.lua"
}
trap cleanup EXIT


# setup the fifo
log "Setup fifo '$fnotify'"

if [[ ! -p $fnotify ]]; then
    mkfifo $fnotify
fi

if [[ ! -p "$fnotify" ]]; then
    log "error creating/opening fifo $fnotify"
    exit 1
fi


# Botmanager watchdog
{
    log "watchdog starting..."
    trap cleanup EXIT
    while [[ -p $fnotify ]]; do
        # Spawn the radio recorder bot
	botPID=$(pgrep -f -- "fgcom-radio-recorder.bot.lua.*--host=$host")
        if [[ $run_recorderbot -gt "0" && -z "$botPID" ]]; then
            recorderbot_cmd="luajit fgcom-radio-recorder.bot.lua $recorder_opts --fnotify=$fnotify"
            log "Spawn recorder bot: $recorderbot_cmd"
            if [ -n $recorderbot_log ] && [ $recorderbot_log != "-" ]; then
                $recorderbot_cmd > $recorderbot_log &
            else
                $recorderbot_cmd &
            fi
        fi

        # Spawn the statusPage bot
        botPID=$(pgrep -f -- "fgcom-status.bot.lua.*--host=$host")
        if [[ $run_statusbot -gt "0" && -z "$botPID" ]]; then
            statusbot_cmd="luajit statuspage/fgcom-status.bot.lua $status_opts"
            [[ -n "$statusbot_web" ]] && statusbot_cmd="$statusbot_cmd --web=$statusbot_web"
            [[ -n "$statusbot_stats" ]] && statusbot_cmd="$statusbot_cmd --stats=$statusbot_stats"
            log "Spawn status bot: $statusbot_cmd"
            if [ -n $statusbot_log ] && [ $statusbot_log != "-" ]; then
                $statusbot_cmd > $statusbot_log &
            else
                $statusbot_cmd &
            fi
        fi
        
        sleep 1
    done
    log "watchdog finished"
    
} &


# wait for new recordings and call playback bots
while true; do
    if read line <$fnotify; then
        if [[ "$line" == 'quit' ]]; then
            break
        fi
        date "+[%Y-%m-%d %H:%M:%S] notification received: '$line'"
        
        # Parse the info
        # fifo data is expected to be pipe-delimited data:
        #  field 1: sample name
        #  field 2: optional ID of the recording mumble session
        samplefile=$(echo $line|cut -d"|" -f1)
        ownersession=$(echo $line|cut -d"|" -f2 -s)
        
        if [[ $run_playbackbot -gt "0" ]]; then
            # See if there is already a playback bot instance with that sample
            botPID=$(pgrep -f -- "--sample=$samplefile")
            if [[ -n "$botPID" ]]; then
                log "Spawn playback bot ignored (found already running instance): $playbackbot_cmd"
                continue
            fi
            
            #spawn bot
            owner_opt=""
            if [[ -n $ownersession ]]; then owner_opt="--owntoken=$ownersession"; fi
            playbackbot_cmd="luajit fgcom-radio-playback.bot.lua $playback_opts $owner_opt --sample=$samplefile"
            log "Spawn playback bot: $playbackbot_cmd"
            if [ -n $playbackbot_log ] && [ $playbackbot_log != "-" ]; then
                $playbackbot_cmd > $playbackbot_log &
            else
                $playbackbot_cmd &
            fi
        fi
    fi
done

log "Botmanager exiting"
