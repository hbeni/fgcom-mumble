--[[ 
This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
Copyright (c) 2020 Benedikt Hallinger
 
This program is free software: you can redistribute it and/or modify  
it under the terms of the GNU General Public License as published by  
the Free Software Foundation, version 3.

This program is distributed in the hope that it will be useful, but 
WITHOUT ANY WARRANTY; without even the implied warranty of 
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
General Public License for more details.

You should have received a copy of the GNU General Public License 
along with this program. If not, see <http://www.gnu.org/licenses/>. ]]


--[[        FGCom-mumble Recorder Bot

The purpose of this bot is to monitor `fgcom-mumble` channel traffic on so called
"recorder" frequencies. Samples sent on those are recorded to a file using a custom
file format (FGCS) that can later be read from the FGCom-mumble playback bot.

The bot can optionally notify about finished new recordings using a linux FIFO, which
is currently the standard method of invoking playback bots. A monitor script is
reading that fifo and invokes fgcom-radio-playback bots.

Currently the recording takes place for transmisisons in the fgcom-mumble channel
for the following tuned frequencies (bots own geographic location is not relevant):
(see isClientTalkingToUs() for current implementations)
  - "910.00"           FGCom Echotest frequency.
  - "RECORD_<tgtFrq>"  ATIS/Radio Recordings for target frequency <tgtFrq>.


The bot is depending on lua-mumble from  bkacjios (https://github.com/bkacjios/lua-mumble).
Installation of this plugin is described in the projects readme: https://github.com/bkacjios/lua-mumble/blob/master/README.md

]]

dofile("sharedFunctions.inc.lua")  -- include shared functions
fgcom.botversion  = "1.8.0"
local botname     = "FGCOM-Recorder"
fgcom.callsign    = "FGCOM-REC"
local voiceBuffer = Queue:new()

-- Parse cmdline args
local host  = "localhost"
local port  = 64738
local cert  = "recbot.pem"
local key   = "recbot.key"
local path  = "./recordings"
local limit = 120     -- default time limit for recordings in secs
local ttl   = 120*60  -- default time-to-live after recordings in secs
local spawn = false
local fnotify  = ""      -- notify about recorded samples into this file


if arg[1] then
    if arg[1]=="-h" or arg[1]=="--help" then
        print(botname..", "..fgcom.getVersion())
        print("usage: "..arg[0].." [opt=val ...]")
        print("  Options:")
        print("    --name=    Change Bot's name                (default="..botname..")")
        print("    --host=    host to connect to               (default="..host..")")
        print("    --port=    port to connect to               (default="..port..")")
        print("    --channel= channel to join                  (default="..fgcom.channel..")")
        print("    --cert=    path to PEM encoded cert         (default="..cert..")")
        print("    --key=     path to the certs key            (default="..key..")")
        print("    --path=    Path to store the recordings to  (default="..path..")")
        print("    --limit=   Max limit to record, in seconds  (default="..limit..")")
        print("    --ttl=     Max timeToLive in seconds        (default="..ttl..")")
        print("    --fnotify= notify about recorded sample into this file.")
        --print("    --spawn    Spawn playback bots after recording")
        print("    --debug    print debug messages             (default=no)")
        print("    --version  print version and exit")
        os.exit(0)
    end
    
    for _, opt in ipairs(arg) do
        _, _, k, v = string.find(opt, "--(%w+)=(.+)")
        --print("KEY='"..k.."'; VAL='"..v.."'")
        if k=="name"      then botname=v end
        if k=="host"      then host=v end
        if k=="port"      then port=v end
        if k=="channel"   then fgcom.channel=v end
        if k=="cert"      then cert=v end
        if k=="key"       then key=v end
        if k=="path"      then path=v end
        if k=="limit"     then limit=v end
        if k=="ttl"       then ttl=v end
        if opt=="--spawn" then spawn=true end
        if k=="fnotify"   then fnotify=v end
        if opt == "--debug" then fgcom.debugMode = true end
        if opt == "--version" then print(botname..", "..fgcom.getVersion()) os.exit(0) end
    end
    
end

if fnotify:len() > 0 then
    fgcom.log("will notify about new recordings via file '"..fnotify.."'.")
end

-- BUG pending: Prevent users from trying --spawn. This will not work:
--     lua will spawn the bot, but somehow the recorder cant let go of the child process.
--     this will kill the recorder shortly after.
if spawn then fgcom.log("--spawn does not work good currently, sorry.") os.exit(1) end


-- Check target dir:
-- try to create and delete a file at path, so we check if its there and writabl
local tdir = io.open(path.."/hello", "wb")
if tdir then
    tf=tdir:write("ok")
    if not tf then
        fgcom.log("unable to write into recording dir: "..path)
        os.exit(1)
    else
        io.close(tdir)
        os.remove(path.."/hello")
    end
else
    fgcom.log("unable to open recording dir: "..path)
    os.exit(1)
end


-- Connect to server, so we get the API
fgcom.log(botname..": connecting as '"..fgcom.callsign.."' to "..host.." on port "..port.." (cert: "..cert.."; key: "..key.."), joining: '"..fgcom.channel.."'")
local client = assert(mumble.connect(host, port, cert, key))
client:auth(botname)
fgcom.log("connect and bind: OK")



-- Function to Check if a user currently speaks to us;
-- that is the case if he:
--   - tuned the FGCom test frequency 910.000
--   - tuned RECORD_<tgtFrq>
-- @param user mumble.user to check
-- @return nil if not, otherwise <identity>,<radio>: table with the matched radio
local isClientTalkingToUs = function(user)
    if fgcom_clients[user:getSession()] then
        local rmt_client = fgcom_clients[user:getSession()]
        for iid,remote in pairs(rmt_client) do
            fgcom.dbg("we know this client: callsign="..remote.callsign)
            for radio_id,radio in pairs(remote.radios) do
                fgcom.dbg("  check frequency: radio #"..radio_id..", ptt='"..radio.ptt.."', frq='"..radio.frequency.."'")
                
                -- ATIS/Radio Recording request for tgt frequency
                local record_tgtFrq = ""
                local record_tgtChn = ""
                _, _, record_tgtFrq = radio.frequency:find("^RECORD_(.+)")
                _, _, record_tgtChn = radio.dialedFRQ:find("^RECORD_(.+)")
                if record_tgtFrq and radio.ptt == "1" then
                    -- remote is on Recording-TGT frequency AND his ptt is active
                    remote.record_mode = "NORMAL"
                    remote.record_tgt_frq = record_tgtFrq
                    remote.record_tgtChn  = record_tgtChn
                    fgcom.dbg("   RECORD frequency match at radio #"..radio_id.." (tgtFreq="..remote.record_tgt_frq.." / CHN="..remote.record_tgtChn..")")
                    return remote, radio
                end
                
                -- FGCom ECHOTEST Frequency recording request
                if (radio.frequency:find("^910$") or radio.frequency:find("^910.0+$")) and radio.ptt == "1" then
                    -- remote is on echotest-frequency AND his ptt is active
                    remote.record_mode = "ECHOTEST"
                    remote.record_tgt_frq = "910.00"
                    remote.record_tgtChn  = remote.record_tgt_frq
                    fgcom.dbg("   ECHOTEST frequency match at radio #"..radio_id.." (tgtFreq="..remote.record_tgt_frq.." / CHN="..remote.record_tgtChn..")")
                    return remote, radio
                end
                
                
            end
        end
    end

    return nil
end


-- Function to get a FGCS filename based on mode
-- @param remote  table of the remote user state in question
-- @return calculated filename
local getFGCSfileName = function(remote)
    if remote==nil or remote.record_mode==nil or remote.record_tgt_frq=="" then a="" end
    
    local name = ""
    if     remote.record_mode == "NORMAL" then
        -- This will update newer ATIS samples for the target frequency
        name = "fgcom.rec."..remote.callsign.."-"..remote.record_tgt_frq..".fgcs"
    elseif remote.record_mode == "ECHOTEST" then
        -- Echotest: name is depending solely on user
        name = "fgcom.echotest."..remote.callsign..".fgcs"
    end
    
    return path.."/"..name
end


-- Function to invole a playback bot
-- @param s path to the sample file to play
-- @param user optional user to make owner of the payback bot to be calles
callPlaybackBot = function(s, user)
    if fnotify:len() > 0 then
        fgcom.dbg("notify via file '"..fnotify.."': "..s)
        local fifo = io.open(fnotify, "ab")
        if user then s = s.."|"..user:getSession() end
        fifo:write(s.."\n")  -- write recorded sample file to fifo.
        fifo:close()
        return
    end
    
    if spawn then
        local cmd = "lua fgcom-radio-playback.bot.lua"
                .." --sample="..s
                .." --host="..host
                .." --port="..port
                .." --cert="..cert
                .." --key="..key
                --todo .." --owntoken="..user.getSession()
                --.." --nodel"
        fgcom.dbg("spawning new playback bot: "..cmd)
        local handle = io.popen(cmd)  -- BUG pending: this is currently blocking the bot and killing him after a short while. use --fifo instead.
    end
end


-- Function to see if we need to ignore the client
-- @param user mumble.user table
-- @return boolean
isIgnored = function(user)
    if user:getName():find("FGCOM%-RADIO%.*") then return true end
    
    return false
end


-- function to get all channel users
-- this updates the global playback_target table
local playback_targets = nil -- holds updated list of all channel users
updateAllChannelUsersforSend = function(cl)
    --fgcom.dbg("udpate channelusers")
    local ch = cl:getChannel(fgcom.channel)
    playback_targets = ch:getUsers()
end


-- Called when the bot successfully connected to the server
-- and has received all current channel and client data
client:hook("OnServerSync", function(client, event)
    if (event.welcome_text == nil) then event.welcome_text = "-" end
    fgcom.log("Sync done; server greeted with: "..event.welcome_text)
    
    -- try to join fgcom-mumble channel
    local ch = client:getChannel(fgcom.channel)
    event.user:move(ch)
    fgcom.log("joined channel "..fgcom.channel)
           
    -- ask all already present clients for their data
    updateAllChannelUsersforSend(client)
    client:sendPluginData("FGCOM:ICANHAZDATAPLZ", "orly!", playback_targets)
           
    -- Adjust comment
    client:setComment("<b><i><u>FGCom:</u></i></b><br/>Listening on the following frequencies:"
                      .."<ul>"
                      .."<li><tt>910.00</tt>: Echotest; speak and i will reply!</li>"
                      .."<li><tt>RECORD_</tt><i>&lt;tgtFreq&gt;</i>: record ATIS for <i>&lt;tgtFreq&gt;</i> at your Callsign and location</li>"
                      .."</ul>")
end)


client:hook("OnPluginData", function(client, event)
    --["sender"] = mumble.user sender, -- Who sent this data packet
	--["id"]     = Number id,          -- The data ID of this packet
	--["data"]   = String data,        -- The data sent (can be binary data)
	--["receivers"]				= {  -- A table of who is receiving this data
	--	[1] = mumble.user,
	--},
    fgcom.dbg("DATA INCOMING FROM="..event.sender:getSession())
           
    if isIgnored(event.sender) then return end   -- ignore other bots!

    fgcom.data.parsePluginData(event.id, event.data, event.sender)

    -- clean up stale entries
    fgcom.data.cleanupPluginData()

end)


client:hook("OnUserStartSpeaking", function(client, user)
    fgcom.dbg("OnUserStartSpeaking, user["..user:getSession().."]="..user:getName())
end)

client:hook("OnUserSpeak", function(client, event)
    --fgcom.dbg("OnUserSpeak, from=["..event.user:getSession().."] '"..event.user:getName().."'")
    --fgcom.dbg("  codec="..event.codec)
    --fgcom.dbg("  target="..event.target)
    --fgcom.dbg("  sequence="..event.sequence)

    if isIgnored(event.user) then return end   -- ignore other bots!
           
    -- If the user is speaking to us, record its samples and push them to the buffer
    local remote, matchedRadio = isClientTalkingToUs(event.user)
    if remote and matchedRadio and matchedRadio.frequency then
        fgcom.dbg("OnUserSpeak:  radio connected: "..matchedRadio.frequency)
        fgcom.dbg("remote="..tostring(remote))
        if remote and not remote.record_filename and not remote.record_fh then
            -- we had no filehandle so far, so we open a new file and write the header
            remote.record_filename = getFGCSfileName(remote)..".part"
            fgcom.dbg("OnUserSpeak:  FGCS file '"..remote.record_filename.."' not open, opening...")
            if remote.record_filename then
                fgcom.dbg("OnUserSpeak: prepare FGCS header for file '"..remote.record_filename.."'")
                local ch = client:getChannel(fgcom.channel)
                ch:message(event.user:getName().." ("..remote.callsign.."): Recording for frequency '"..remote.record_tgt_frq.."' started.")
           
                local header = {
                    version      = "1.1 FGCS",
                    callsign     = remote.callsign,
                    lat          = remote.lat,
                    lon          = remote.lon,
                    height       = remote.alt,
                    frequency    = remote.record_tgt_frq,
                    dialedFRQ    = remote.record_tgtChn,
                    txpower      = matchedRadio.power,
                    playbacktype = "looped",
                    timetolive   = ttl,
                    timestamp    = os.time(),
                    voicecodec   = event.codec,
                    samplespeed  = 0.02          -- TODO: fixed for now; we should calulate this (otherwise speech might play too fast/slow), see: https://github.com/bkacjios/lua-mumble/issues/16
                }
            
                -- define current recording limit
                rlimit = limit -- basic limit from parameters
                
                -- Echotest handling: short lived, oneshot sample
                if remote.record_mode == "ECHOTEST" then
                    header.callsign     = "ECHO:"..remote.callsign
                    header.playbacktype = "oneshot"
                    header.timetolive   = 30
                    rlimit = 10    -- secs max recording length
                end
            
                remote.record_fh = io.open(remote.record_filename, "wb")
                if remote.record_fh then
                    local res = fgcom.io.writeFGCSHeader(remote.record_fh, header)
                    fgcom.dbg("FGCS header write result '"..remote.record_filename.."': "..tostring(res))
                    if not res then
                        io.close(remote.record_fh)
                        remote.record_fh       = nil
                        remote.record_filename = ""
                    end
                    
                    remote.record_timeout = os.time()+rlimit -- note when the recording will time out
                end
                
            end
        end
    
        if remote.record_filename and remote.record_fh then
            local recordingSecsLeft = remote.record_timeout - os.time() +1
            if recordingSecsLeft > 0 then
                fgcom.dbg(remote.record_filename..": recording sample, len="..#event.data.." ("..recordingSecsLeft.."s rectime left)")
                fgcom.io.writeFGCSSample(remote.record_fh, event.data)
            else
                fgcom.dbg(remote.record_filename..": sample discarded: recording time exceeded ("..recordingSecsLeft.."s)")
            end
        end
    
    else
        fgcom.dbg("OnUserSpeak:  radio not matched: "..tostring(matchedRadio))
    end
           
end)


client:hook("OnUserStopSpeaking", function(client, user)
    fgcom.dbg("OnUserStopSpeaking, user["..user:getSession().."]="..user:getName())
           
    if isIgnored(user) then return end   -- ignore other bots!

    -- see if there is an active recording, if so, end it now
    if fgcom_clients[user:getSession()] then
        local rmt_client = fgcom_clients[user:getSession()]
        for iid,remote in pairs(rmt_client) do
            if remote.record_filename and remote.record_fh then
                fgcom.dbg("closing recording '"..remote.record_filename.."'")
                remote.record_fh:flush()
                io.close(remote.record_fh)
                remote.record_fh = nil
                
                local record_filename_final = remote.record_filename:gsub("%.part", "")
                os.remove (record_filename_final) -- remove target file silently, if already there
                --fgcom.dbg("RENAME: "..remote.record_filename.." -> "..record_filename_final)
                ren_rc, ren_message = os.rename(remote.record_filename, record_filename_final)
                remote.record_filename = nil
                fgcom.log("recording ready: '"..record_filename_final.."'")

                local ch = client:getChannel(fgcom.channel)
                ch:message(user:getName().." ("..remote.callsign.."): Recording for frequency '"..remote.record_tgt_frq.."' completed!")
                
                -- spawn a bot that replays the sample.
                -- he is responsible fo killing himself and also to delete the sample file if it is not valid anymore.
                if remote.record_mode == "NORMAL" then
                    callPlaybackBot(record_filename_final, user)
                else
                    callPlaybackBot(record_filename_final)
                end
            else
                fgcom.dbg(remote.callsign..": no active recording detected")
            end
        end
    else
        fgcom.dbg("remote uknown")
    end       
end)


-- Chat admin interface
-- be sure to chat privately to the bot!
client:hook("OnMessage", function(client, event)
    -- ["actor"]    = mumble.user actor,
    -- ["message"]  = String message,
    -- ["users"]    = Table users,
    -- ["channels"] = Table channels - set when its no direct message

    if event.actor and not event.channels then  -- only process when it's a direct message to the bot
        event.message = event.message:gsub("%b<>", "")  -- strip html tags
        fgcom.dbg("message from actor: "..event.actor:getName().." (session="..event.actor:getSession()..")="..event.message)

        -- parse command
        local command = nil
        local param   = nil
        _, _, command = string.find(event.message, "^/(%w+)")
        _, _, param   = string.find(event.message, "^/%w+ (%w+)")
        if command then
            --print("DBG: parsed command: command="..command)
            --if param then print("DBG:   param="..param) end

            -- handle auth request
            if command == "auth" then
                if not param then event.actor:message("/auth needs a tokenstring as argument!") return end
                fgcom.auth.handleAuthentication(event.actor, param)
                return
           end

            if command == "help" then
                event.actor:message(botname..", "..fgcom.getVersion().." commands:"
                    .."<table>"
                    .."<tr><th style=\"text-align:left\"><tt>/help</tt></th><td>show this help.</td></tr>"
                    --.."<tr><th style=\"text-align:left\"><tt>/auth &lt;token&gt;</tt></th><td>Authenticate to be able to execute advanced commands.</td></tr>"
                    --.."<tr><th style=\"text-align:left\"><tt>/exit</tt></th><td>Terminate the bot.</td></tr>"
                    .."</table>"
                    .."<br>I do not obey to chat commands so far."
                )
                return
            end

            -- secure the following authenticated commands:
            if not fgcom.auth.handleAuthentication(event.actor) then
                fgcom.dbg("ignoring command, user not authenticated: "..event.actor:getName())
                return
            end

            -- no commands so far

        end
        
    end
end)

mumble.loop()
