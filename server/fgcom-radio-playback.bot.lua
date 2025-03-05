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


--[[        FGCom-mumble Recordings playback Bot

The purpose of this bot is to playback previously recorded samples into the
`fgcom-mumble` channel.
When playing back, it takes a fixed position on earth and sets up a virtual radio
station at this point. It is important that the sender has some altitude, because
especially VHF broadcasts are subject to range limits by line-of-sight.
This information is usually read from the FGCS-fileheader, but can also be
given on commandline, overriding the file header.

The specified sample is read into memory and then replayed. After every cycle,
the bot tests if the sample file is still there and valid.
The header and contents are reevalued.

The bot is depending on lua-mumble from  bkacjios (https://github.com/bkacjios/lua-mumble).
Installation of this plugin is described in the projects readme: https://github.com/bkacjios/lua-mumble/blob/master/README.md

]]
dofile("fgcom-sharedFunctions.inc.lua")  -- include shared functions
fgcom.botversion = "1.8.2"

-- init random generator using /dev/random, if poosible (=linux)
fgcom.rng.initialize()

local botname     = "FGCOM-radio-playback"
fgcom.callsign    = "FGCOM-RADIO-"..math.random(1, 99999)

local voiceBuffer = nil -- Queue voice buffer holding the cached samples
local lastHeader  = nil -- holds last header data
local overwriteHeader  = {}  -- holds overwrite data from the commands
local playback_targets = nil -- holds updated list of all channel users

-- Parse cmdline args
local host   = "localhost"
local port   = 64738
local cert   = "playbot.pem"
local key    = "playbot.key"
local sample = ""
local nodel  = false
local pause  = "0"
local pingT  = 10  -- ping time spacing in seconds
local updateComment_t = 60 --time in seconds to update the comment
local owntoken = nil
local verify = false

local printhelp = function()
    print(botname..", "..fgcom.getVersion())
    print("usage: "..arg[0].." [opt=val ...]")
    print("  Options:")
    print("    --host=     host to connect to           (default="..host..")")
    print("    --port=     port to connect to           (default="..port..")")
    print("    --channel=  channel to join              (default="..fgcom.channel..")")
    print("    --cert=     path to PEM encoded cert     (default="..cert..")")
    print("    --key=      path to the certs key        (default="..key..")")
    print("    --sample=   Path to the FGCS or OGG sample file")
    print("                If the sample file is an OGG, --lat, --lon, --hgt,")
    print("                --frq, --callsign and --ttl overrides are mandatory.")
    print("    --nodel     Don't delete outdated samples from disk")
    print("    --pause=    When looped, add a pause between iterations (default="..pause..")")
    print("                Either seconds, or '<min>,<max>' for randomisation")
    print("    --lat=      Latitude override            (default: use FGCS header)")
    print("    --lon=      Longitude override           (default: use FGCS header)")
    print("    --loop      set looped mode")
    print("    --oneshot   set to oneshot mode")
    print("    --hgt=      Height override              (default: use FGCS header)")
    print("    --frq=      Frequency override           (default: use FGCS header)")
    print("    --pwr=      Power in Watts override      (default: use FGCS header)")
    print("    --callsign= Callsign override            (default: use FGCS header)")
    print("    --ttl=      Time to live (seconds) for OGG playback (default: use FGCS header)")
    print("                0=persistent sample (played in an endless loop).")
    print("    --owntoken= Inform the given sessionID about the generated token")
    print("    --debug     print debug messages         (default=no)")
    print("    --verify    Load and show FGCS header, then quit")
    print("    --version   print version and exit")
    print("\nNotice:")
    print("  * OGG sample type implies --nodel (files are never deleted from disk by the bot).")
    print("  * --ttl=0 (loop) has precedence over --oneshot.")
    print("  * --ttl=n overwrites the FGCS stored timestamp, so that ttl gives the remaining new validity from 'now'.")
    os.exit(0)
end

if arg[1] then
    for _, opt in ipairs(arg) do
        _, _, k, v = string.find(opt, "--(%w+)=(.+)")
        if k=="host"   then host=v end
        if k=="port"   then port=v end
        if k=="channel"   then fgcom.channel=v end
        if k=="cert"   then cert=v end
        if k=="key"    then key=v end
        if k=="sample" then sample=v end
        if opt=="--nodel" then nodel=true end
        if k=="pause"  then pause=v end
        if k=="lat"    then overwriteHeader.lat=v end
        if k=="lon"    then overwriteHeader.lon=v end
        if opt=="--loop"   then overwriteHeader.playbacktype="looped" end
        if opt=="--oneshot" then overwriteHeader.playbacktype="oneshot" end
        if k=="hgt"    then overwriteHeader.height=v end
        if k=="frq"    then overwriteHeader.frequency=v overwriteHeader.dialedFRQ=v end
        if k=="pwr"    then overwriteHeader.txpower=v end
        if k=="ttl"    then overwriteHeader.timetolive=v end
        if k=="callsign" then overwriteHeader.callsign=v end
        if k=="owntoken" then owntoken=v end
        if opt == "--debug" then fgcom.debugMode = true end
        if opt == "--version" then print(botname..", "..fgcom.getVersion()) os.exit(0) end
        if opt == "--verify" then verify = true end
        if opt == "-h" or opt == "--help" then printhelp() end
    end
else
    printhelp()
end

-- parameter checks
if sample == "" then print("parameter --sample is mandatory!") os.exit(1) end
local sampleType = "FGCS"
 -- TODO: check for supported filetypes based on postfix .fgcs

if sample:match(".+[.]ogg") then
    local checkParamsMap = {}  --map params to values for mandatory-check
        checkParamsMap["--frq"]      = overwriteHeader.frequency  or ""
        checkParamsMap["--callsign"] = overwriteHeader.callsign   or ""
        checkParamsMap["--lat"]      = overwriteHeader.lat        or ""
        checkParamsMap["--lon"]      = overwriteHeader.lon        or ""
        checkParamsMap["--hgt"]      = overwriteHeader.height     or ""
        checkParamsMap["--ttl"]      = overwriteHeader.timetolive or ""
    for k, v in pairs(checkParamsMap) do
        if not v or v == "" then print("with OGG files, parameter "..k.." is mandatory!") os.exit(1) end
    end

    nodel = false -- never delete OGG files

    -- prepare a faked FGCS header
    sampleType = "OGG"
    lastHeader = {}
    --lastHeader.callsign     = overwriteHeader.callsign
    --lastHeader.lat          = overwriteHeader.lat
    --lastHeader.lon          = overwriteHeader.lon
    --lastHeader.height       = overwriteHeader.height
    --lastHeader.frequency    = overwriteHeader.frequency
    --lastHeader.dialedFRQ    = overwriteHeader.frequency
    lastHeader.txpower      = 10
    lastHeader.playbacktype = "looped"
    --lastHeader.timetolive   = overwriteHeader.timetolive
    lastHeader.timestamp    = os.time()
    lastHeader.voicecodec   = sampleType
    --if overwriteHeader.txpower then
    --    lastHeader.txpower  = overwriteHeader.txpower
    --end
    -- apply overrides
    for k,v in pairs(overwriteHeader) do
        lastHeader[k] = v
    end
end

-----------------------------
--[[ DEFINE SOME FUNCTIONS ]]
-----------------------------

-- Function to read the sample file and return its data
-- @param file path to the sample file
-- @return header table, Queue.sampledata  or false on error
readFGCSSampleFile = function(file)
    local sampleFH = io.open(sample, "rb")
    if not sampleFH then return false end
    local sampleHeader = fgcom.io.readFGCSHeader(sampleFH)
    if not sampleHeader then return false end
    
    -- now read the samples into a queue
    local vb = Queue:new()
    local endOfSamples = false
    while not endOfSamples do
        local nextSample = fgcom.io.readFGCSSample(sampleFH)
        --fgcom.dbg("sample: len="..nextSample.len.."; eof='"..tostring(nextSample.eof).."'; data='"..nextSample.data.."'")
        if nextSample.len > 0 and not nextSample.eof then
            vb:pushright(nextSample) -- write the sample structure to the buffer
        end
        endOfSamples = nextSample.eof;
    end
    
    io.close(sampleFH)
    return sampleHeader, vb
end

-- Function to remove samples according to nodel parameter
-- @param s filename of sample
delSample = function(s)
    if nodel then
        fgcom.dbg("preserving file (--nodel in effect): "..s)
    else
        os.remove(s)
    end
end

-- Function to return a pause in seconds from the parameter
getPause = function(p_opt)
    local p = tonumber(p_opt)
    local min,max = p_opt:match('([0-9]+),([0-9]+)')
    min   = tonumber(min)  max = tonumber(max)

    if min and max then
        -- random mode
        if min > max then print("Parameter --pause="..p_opt..": <min> must be less or equal <max>!") os.exit(1) end
        p = math.random(min, max)
    end
    
    if p==nil then
        print("Parameter --pause="..p_opt..": invalid syntax") os.exit(1)
    end

    fgcom.dbg("Loop pause (from param="..p_opt.."): "..p.." seconds")
    return p
end

-----------------------------
--[[      BOT RUNTIME      ]]
-----------------------------

fgcom.log(botname..": "..fgcom.getVersion())
getPause(pause)   -- silent invocation to check the param

-- read the file the first time and see if it parses.
-- usually we want the file deleted after validity expired, but for that we need
-- to make sure its a FGCS file... otherwise its another rm tool... ;)
if sampleType == "FGCS" then
    fgcom.log("Sample format: FGCS")
    lastHeader, voiceBuffer = readFGCSSampleFile(sample)
    if not lastHeader then  fgcom.log("ERROR: '"..sample.."' not readable or no FGCS file") os.exit(1) end

    -- AFTER THIS CODE we can be confident it was a valid FGCS file!
    --   lastHeader is initialized with the header data
    --   voiceBuffer is initialized with the read samples
    fgcom.log(sample..": successfully loaded.")

    if verify then
        fgcom.log("verify header (loaded):")
        for k,v in pairs(lastHeader) do
            fgcom.log(string.format("  %s=%s", k, v))
        end
    end

    -- apply overrides
    for k,v in pairs(overwriteHeader) do
        lastHeader[k] = v
    end
    if overwriteHeader.timetolive then
        if overwriteHeader.timetolive == "0" then lastHeader.playbacktype = "looped" end
        if tonumber(overwriteHeader.timetolive) > 0 then
            -- when --ttl was given explicitely, make it relative to "now" instead of the original sample
            lastHeader.timestamp = os.time()
            overwriteHeader.timestamp = os.time()
        end
    end
    
    local timeLeft = fgcom.data.getFGCSremainingValidity(lastHeader)
    local persistent = false
    if lastHeader.timetolive == "0" then
        fgcom.log(sample..": This is a persistent sample.")
        timeLeft   = 1337   -- just some arbitary dummy value in the future
        persistent = true   -- loops forever!
    end

    if not persistent and timeLeft < 0 then
        fgcom.log(sample..": sample is invalid, since "..timeLeft.."s. Aborting.")
    else
        fgcom.log(sample..": sample is valid, remaining time: "..timeLeft.."s")
    end

    if verify then
        fgcom.log("verify header (effective/overrriden):")
        for k,v in pairs(lastHeader) do
            fgcom.log(string.format("  %s=%s", k, v));
        end
        os.exit(0)
    end

    -- exit, if sample is not vaid anymore
    if not persistent and timeLeft < 0 then  os.exit(0)  end

else if sampleType == "OGG" then
    fgcom.log("Sample format: OGG")

    if verify then
        fgcom.log("verify header (generated):")
        for k,v in pairs(lastHeader) do
            fgcom.log(string.format("  %s=%s", k, v))
        end
        os.exit(0)
    end
else
    fgcom.log("ERROR: '"..sample.."' not readable or no FGCS or no OGG file") os.exit(1) end
end


-- Connect to server, so we get the API
fgcom.log("connecting as '"..fgcom.callsign.."' to "..host.." on port "..port.." (cert: "..cert.."; key: "..key.."), joining: '"..fgcom.channel.."'")
local client = mumble.client()
assert(client:connect(host, port, cert, key))

client:hook("OnConnect", function(client)
    client:auth(fgcom.callsign)
    fgcom.dbg("connect and bind: OK")
end)



-- function to get all channel users
-- this updates the global playback_target table
updateAllChannelUsersforSend = function(cl)
    --fgcom.dbg("udpate channelusers")
    local ch = cl:getChannel(fgcom.channel)
    playback_targets = ch:getUsers()
end

-- function to disconnect the bot
shutdownBot = function()
    fgcom.log("shutdownBot(): requested")
    updateAllChannelUsersforSend(client)

    -- send update to mute our radio
    -- TODO: send deregister request, once implemented
    local msg = "FRQ="..lastHeader.frequency
             ..",CHN="..lastHeader.dialedFRQ
             ..",PWR="..lastHeader.txpower
             ..",PTT=0"
    client:sendPluginData("FGCOM:UPD_COM:0:0", msg, playback_targets)
    fgcom.log("shutdownBot(): COM0 deactiated")
    
    -- finally disconnect from the server
    client:disconnect()
    fgcom.log("shutdownBot(): disconnected")
    os.exit(0)
end


--[[
  Playback loop (FGCS): we use a mumble timer for this. The timer loops in
  the playback-rate and looks if there are samples buffered. If so,
  he fetches them and plays them, one packet per timer tick.
]]
local playbackTimer_fgcs = mumble.timer()
local playbackTimer_fgcs_func = function(t)
    fgcom.dbg("playback timer (fgcs): tick")
    --fgcom.dbg("  duration="..t:getDuration().."; repeat="..t:getRepeat());
    
    -- Debug out: header
    --[[for k,v in pairs(lastHeader) do
        fgcom.dbg("header read: '"..k.."'='"..v.."'")
    end]]
    
    -- So, a new timer tick started.
    -- See if we have still samples in the voice buffer. If not, reload it from file, if it was a looped one.
    if voiceBuffer:size() > 0 then
        fgcom.dbg("voiceBuffer is still filled, samples: "..voiceBuffer:size().." (speed: "..lastHeader.samplespeed..")")
        
        -- get the next sample from the buffer and play it
        local nextSample  = voiceBuffer:popleft()
        local endofStream = false
        if voiceBuffer:size() == 0 then endofStream = true end

        fgcom.dbg("transmit next sample")
        --fgcom.dbg("  tgt="..playback_target:getSession())
        --fgcom.dbg("  eos="..tostring(endofStream))
        --fgcom.dbg("  cdc="..lastHeader.voicecodec)
        --fgcom.dbg("  dta="..#nextSample.data)
        --fgcom.dbg("  dta="..nextSample.data)
        client:transmit(lastHeader.voicecodec, nextSample.data, not endofStream) -- Transmit the single frame as an audio packet (the bot "speaks")
        fgcom.dbg("transmit ok")
        if endofStream then
            -- no samples left? Just loop around to trigger all the checks
            fgcom.dbg("no samples left, playback complete")
        end
        
    else
        -- Voicebuffer is emtpy.
        
        -- Check if this is a oneshot sample. if so, delete the file now as we just played it, and go home
        if lastHeader.playbacktype == "oneshot" then
            fgcom.log("Oneshot sample detected, not looping.")
            local persistent = false
            if lastHeader.timetolive ~= "0" then
                fgcom.log("deleting oneshot non-persistent sample file.")
                delSample(sample)
            end
            shutdownBot()
            fgcom.dbg("disconnected: we are done.")
            t:stop() -- Stop the timer
        
        else
            -- It was a looped timer: we reread the file to see if its still there,
            -- then check validity and if so, refill the voiceBuffer
            fgcom.dbg("Looped timer: update voice buffer from file")
            
            -- See if we need to add a pause
            local sleep = getPause(pause)
            if sleep > 0 then
                --fgcom.dbg("Looped timer: pause for "..sleep.."s")
                t:stop() -- Stop the loop timer
                local pauseTimer = mumble.timer()
                pauseTimer:start(
                function()
                    --fgcom.dbg("Looped timer: pause done, restarting playback timer")
                    t:again()
                    end
                , sleep, 0)
            end
    
            -- Read/update FGCS data file
            local lastHeader_tmp
            lastHeader_tmp, voiceBuffer = readFGCSSampleFile(sample)
            if not lastHeader_tmp then
                -- file could not be loaded - most probably it got deleted.
                -- shut down the bot.
                fgcom.log("'"..sample.."' not readable or no FGCS file, probably deleted from filesystem.")
                shutdownBot()
                fgcom.dbg("disconnected: we are done.")
                t:stop() -- Stop the timer

            else
                -- File was successfully reloaded from disk
                fgcom.dbg("update from file successful")

                -- apply overrides
                for k,v in pairs(overwriteHeader) do
                    lastHeader_tmp[k] = v
                end
                if overwriteHeader.timetolive and overwriteHeader.timetolive == "0" then lastHeader_tmp.playbacktype = "looped" end

                -- take new data
                lastHeader = lastHeader_tmp
        
                -- check if the file is still valid
                local timeLeft = fgcom.data.getFGCSremainingValidity(lastHeader)
                local persistent = false
                if lastHeader.timetolive == "0" then
                    fgcom.dbg(sample..": This is a persistent sample.")
                    timeLeft   = 1337   -- just some arbitary dummy value in the future
                    persistent = true   -- loops forever!
                end
                if not persistent and timeLeft < 0 then
                    fgcom.log(sample..": FGCS file outdated since "..timeLeft.." seconds; removing")
                    delSample(sample)
                    shutdownBot()
                    fgcom.dbg("disconnected: we are done.")
                    t:stop() -- Stop the timer
                else
                    -- Samples are still valid;
                    -- we alreay updated the global voiceBuffer, so we need not do anything here.
                    fgcom.dbg(sample..": FGCS file still valid for "..timeLeft.."s: looping over.")
                    
                    --[[for k,v in pairs(lastHeader) do
                        fgcom.dbg("header read: '"..k.."'='"..v.."'")
                    end
                    fgcom.dbg("\nread samples:")
                    for k,v in ipairs(data) do
                        fgcom.dbg("  sample: len="..v.len.."; eof='"..tostring(v.eof).."'; data='"..v.data.."'")
                    end--]]
                    
                    -- TODO: when active, loop hangs... why? Not so important right now, because samplespeed should only change with new recordings from new clients.
                    --t:set(0.10, lastHeader.samplespeed) -- update timer to sample speed in case it was changed
                    
                end
            end
        end
    end
    --fgcom.dbg("playback timer (fgcs): tick done")
end


--[[
  Playback loop (FGCS): we use a mumble timer for this. The timer loops
  and checks if the audio buffer is played and still valid. If not,
  the bot is shutdown.
]]
--[[  EXPERIMENTAL
local decoder = mumble.decoder()
local playbackTimer_fgcs = mumble.timer()
local fgcs_playedCount = 0
playbackTimer_fgcs_func_streamed = function(t)
    fgcom.dbg("playback timer (fgcs): tick")
    --fgcom.dbg("  duration="..t:getDuration().."; repeat="..t:getRepeat());
    
    -- Debug out: header
    --for k,v in pairs(lastHeader) do
    --    fgcom.dbg("header read: '"..k.."'='"..v.."'")
    --end
    
    -- So, a new timer tick started.
    local isPlaying = (not fgcs_audiostream == nil and not fgcs_audiostream:isEmpty())
    print("DBG; isPlaying:"..tostring(isPlaying))

    if not isPlaying then
        -- See if we need to add a pause
        local sleep = getPause(pause)
        if sleep > 0 then
            --fgcom.dbg("Looped timer: pause for "..sleep.."s")
            t:stop() -- Stop the loop timer
            local pauseTimer = mumble.timer()
            pauseTimer:start(
            function()
                --fgcom.dbg("Looped timer: pause done, restarting playback timer")
                t:again()
                end
            , sleep, 0)
        end

        -- check if the file is still valid
        local timeLeft = fgcom.data.getFGCSremainingValidity(lastHeader)
        local persistent = false
        if lastHeader.timetolive == "0" then
            fgcom.dbg(sample..": This is a persistent sample.")
            timeLeft   = 1337   -- just some arbitary dummy value in the future
            persistent = true   -- loops forever!
        end
        if not persistent and timeLeft < 0 then
            fgcom.log(sample..": FGCS file outdated since "..timeLeft.." seconds; removing")
            delSample(sample)
            shutdownBot()
            fgcom.dbg("disconnected: we are done.")
            t:stop() -- Stop the timer
        else
            -- Samples are still valid;  and start to play
            if lastHeader.playbacktype == "oneshot" and fgcs_playedCount >= 1 then
                fgcom.log("Oneshot sample detected, not looping.")
                local persistent = false
                if lastHeader.timetolive ~= "0" then
                    fgcom.log("deleting oneshot non-persistent sample file.")
                    delSample(sample)
                end
                shutdownBot()
                fgcom.dbg("disconnected: we are done.")
                t:stop() -- Stop the timer

            else
                -- loop over (or start playing the first time)
                if (fgcs_playedCount == 0) then
                    fgcom.dbg(sample..": FGCS file still valid for "..timeLeft.."s: start playing sample.")
                    -- prepare audio buffer
                    --fgcom.dbg("building audio buffer...")
                    fgcs_audiostream = client:createAudioBuffer(48000, 2)
                    for k,nextSample in pairs(voiceBuffer) do 
                        --fgcom.dbg("  tgt="..playback_target:getSession())
                        --fgcom.dbg("  eos="..tostring(endofStream))
                        --fgcom.dbg("  cdc="..lastHeader.voicecodec)
                        if type(nextSample) == "table" then
                            --fgcom.dbg("  dta="..#nextSample.data)
                            --fgcom.dbg("  dta="..nextSample.data)
                            local decoded = decoder:decodeFloat(nextSample.data)
                            fgcs_audiostream:write(decoded)
                        end
                    end
                else
                    fgcom.dbg(sample..": FGCS file still valid for "..timeLeft.."s: looping over.")
                end

                fgcs_playedCount = fgcs_playedCount + 1
                --fgcs_audiostream:stop() --reset audio stream to start
                --fgcs_audiostream:play()

            end
        end
    else
        fgcom.dbg("buffer still playing")
    end

    --fgcom.dbg("playback timer (fgcs): tick done")
end
--]]


--[[
  Playback loop (ogg): we use a mumble timer for this.
  The timer loops every half second or so and checks if the ogg was finished.
  If it is not playing, it checks wether it should terminate or play another round.
]]
local playbackTimer_ogg = mumble.timer()
local stream
playbackTimer_ogg_func = function(t)
    fgcom.dbg("playback timer (ogg): tick")
    --fgcom.dbg("  duration="..t:getDuration().."; repeat="..t:getRepeat());

    local timeLeft = fgcom.data.getFGCSremainingValidity(lastHeader)
    local persistent = false
    if lastHeader.timetolive == "0" then
        fgcom.dbg(sample..": This is a persistent sample.")
        timeLeft   = 1337   -- just some arbitary dummy value in the future
        persistent = true   -- loops forever!
    end
    
    if not persistent and timeLeft < 0 then
        fgcom.log(sample..": OGG file outdated since "..timeLeft.." seconds")
        shutdownBot()
        t.stop() -- Stop the timer
    else
        fgcom.dbg(sample..": OGG file still valid for "..timeLeft.."s")
        if not stream or not stream:isPlaying() then
            -- See if we need to add a pause
            local sleep = getPause(pause)
            if sleep > 0 then
                --fgcom.dbg("Looped timer: pause for "..sleep.."s")
                t:stop() -- Stop the loop timer
                local pauseTimer = mumble.timer()
                pauseTimer:start(
                function()
                    --fgcom.dbg("Looped timer: pause done, restarting playback timer")
                    t:again()
                    end
                , sleep, 0)
            end
            
            fgcom.dbg(sample..": starting sample")
            stream = assert( client:openAudio(sample) )
            stream:stop() -- reset to start
            stream:play()
        else
            -- client is still playing, let him finish the current sample
            fgcom.dbg("OGG still playing")
        end
    end
    --fgcom.dbg("playback timer (ogg): tick done")
end


notifyUserdata = function(tgts)
    if overwriteHeader.callsign then lastHeader.callsign = overwriteHeader.callsign end
    local msg = "CALLSIGN="..lastHeader.callsign
    fgcom.dbg("Bot sets userdata: "..msg)
    client:sendPluginData("FGCOM:UPD_USR:0", msg, tgts)
end

notifyLocation = function(tgts)
    if overwriteHeader.lat    then lastHeader.lat    = overwriteHeader.lat end
    if overwriteHeader.lon    then lastHeader.lon    = overwriteHeader.lon end
    if overwriteHeader.height then lastHeader.height = overwriteHeader.height end
    local msg = "LON="..lastHeader.lon
              ..",LAT="..lastHeader.lat
              ..",ALT="..lastHeader.height
    fgcom.dbg("Bot sets location: "..msg)
    client:sendPluginData("FGCOM:UPD_LOC:0", msg, tgts)
end

notifyRadio = function(tgts)
    if overwriteHeader.frequency then lastHeader.frequency = overwriteHeader.frequency end
    if overwriteHeader.dialedFRQ then lastHeader.dialedFRQ = overwriteHeader.dialedFRQ end
    if overwriteHeader.txpower   then lastHeader.txpower   = overwriteHeader.txpower end
    local msg = "FRQ="..lastHeader.frequency
             ..",CHN="..lastHeader.dialedFRQ
             ..",PWR="..lastHeader.txpower
             ..",PTT=1"
    fgcom.dbg("Bot sets radio: "..msg)
    client:sendPluginData("FGCOM:UPD_COM:0:0", msg, tgts)
end

-- Adjust comment
local updateCommentTimer = mumble.timer()
updateComment = function()
    fgcom.dbg("updating comment...")
    local ttl = fgcom.data.getFGCSremainingValidity(lastHeader)
    local ttl_str
    if ttl <= 0 then
        ttl_str = "endless"
    else
        local hours   = math.floor((ttl%86400)/3600)
        local minutes = math.floor((ttl%3600)/60)
        local seconds = math.floor(ttl%60)
        ttl_str = string.format("%02d:%02d:xx", hours, minutes, seconds)
    end
    client:setComment("<b><i><u>FGCom:</u></i></b><table>"
                      .."<tr><th>Callsign:</th><td><tt>"..lastHeader.callsign.."</tt></td></tr>"
                     .."<tr><th>Channel:</th><td><tt>"..lastHeader.dialedFRQ.."</tt></td></tr>"
                     .."<tr><th>Frequency:</th><td><tt>"..lastHeader.frequency.."</tt></td></tr>"
                     .."<tr><th>Power:</th><td><tt>"..lastHeader.txpower.."W</tt></td></tr>"
                     .."<tr><th>Position:</b></th><td><table><tr><td>Lat:</td><td><tt>"..lastHeader.lat.."</tt></td></tr><tr><td>Lon:</td><td><tt>"..lastHeader.lon.."</tt></td></tr><tr><td>Height:</td><td><tt>"..lastHeader.height.."</tt></td></tr></table></td></tr>"
                     .."<tr><th>Valid for:</th><td><tt>"..ttl_str.."</tt></td></tr>"
                     .."</table>")
end

client:hook("OnServerSync", function(client, event)
    if (event.welcome_text == nil) then event.welcome_text = "-" end
    fgcom.log("Sync done; server greeted with: "..event.welcome_text)
    
    -- try to join fgcom-mumble channel
    local ch = client:getChannel(fgcom.channel)
    event.user:move(ch)
    fgcom.log("joined channel "..fgcom.channel)

    -- update current users of channel
    updateAllChannelUsersforSend(client)

    -- Establish authentication token
    -- try to get the matching user for the sessionID in owntoken
    local owntoken_user = nil
    for key,value in ipairs(playback_targets) do
        if value:getSession() == tonumber(owntoken) then owntoken_user = value break end
    end
    fgcom.auth.generateToken(owntoken_user)

    -- Setup the Bots location on earth
    notifyUserdata(playback_targets)
    notifyLocation(playback_targets)
        
    -- Setup a radio to broadcast from
    notifyRadio(playback_targets)
        
    -- periodically update the comment
    updateCommentTimer:start(updateComment, 0.0, updateComment_t)
        
    fgcom.log("start playback ("..sampleType..")")
    if sampleType == "FGCS" then
        -- start the playback timer.
        -- this will control playback validity time. The actual FGCS sample
        -- is payed until the bot is shutdown from the check timer or the FGCS is invalid.
        playbackTimer_fgcs:start(playbackTimer_fgcs_func, 0.0, lastHeader.samplespeed)
        -- TODO experimental stream FGCS player: playbackTimer_fgcs:start(playbackTimer_fgcs_func_streamed, 0.0, 0.5)
    end
    if sampleType == "OGG" then
        -- start the OGG playback timer loop
        playbackTimer_ogg:start(playbackTimer_ogg_func, 0.0, 0.5)
    end

    -- A timer that will send PING packets from time to time
    local pingTimer = mumble.timer()
    pingTimer:start(function(t)
        fgcom.dbg("sending PING packet")
        updateAllChannelUsersforSend(client)
        client:sendPluginData("FGCOM:PING", "0", playback_targets)
    end, pingT, pingT)
    
end)


client:hook("OnPluginData", function(client, event)
    --["sender"] = mumble.user sender, -- Who sent this data packet
	--["id"]     = Number id,          -- The data ID of this packet
	--["data"]   = String data,        -- The data sent (can be binary data)
	--["receivers"]				= {  -- A table of who is receiving this data
	--	[1] = mumble.user,
	--},
	fgcom.dbg("OnPluginData(): DATA INCOMING FROM="..tostring(event.id)..", "..tostring(event.sender))

    -- Answer data requests
    if event.id:len() > 0 and event.id:find("FGCOM:ICANHAZDATAPLZ") then
        fgcom.dbg("OnPluginData(): client asks for data: "..tostring(event.sender))
        notifyUserdata({event.sender})
        notifyLocation({event.sender})
        notifyRadio({event.sender})
    end

end)


client:hook("OnUserChannel", function(client, event)
	--["user"]	= mumble.user user,
	--["actor"]	= mumble.user actor,
	--["from"]	= mumble.channel from,
	--["to"]	= mumble.channel to,

    -- someone else joined the fgcom.channel
    if event.to:getName() == fgcom.channel
      and not event.user == client:getSelf() then
        fgcom.dbg("OnUserChannel(): client joined fgcom.channel: "..event.user:getName())
        notifyUserdata({event.user})
        notifyLocation({event.user})
        notifyRadio({event.user})
    end

    -- the bot itself joined the fgcom.channel
    if event.user == client:getSelf() then
        -- nothing to do right now
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
        _, _, param   = string.find(event.message, "^/%w+ (.+)")
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
                    .."<tr><th style=\"text-align:left\"><tt>/help</tt></th><td>Show this help.</td></tr>"
                    .."<tr><th style=\"text-align:left\"><tt>/auth &lt;token&gt;</tt></th><td>Authenticate to be able to execute advanced commands.</td></tr>"
                    .."<tr><th style=\"text-align:left\"><tt>/exit</tt></th><td>Terminate the bot.</td></tr>"
                    .."<tr><th style=\"text-align:left\"><tt>/frq &lt;mhz&gt;</tt></th><td>Switch frequency to this real-wave-frequency (Mhz in <tt>x.xxxx</tt>).</td></tr>"
                    .."<tr><th style=\"text-align:left\"><tt>/pwr &lt;watts&gt;</tt></th><td>Change output watts.</td></tr>"
                    .."<tr><th style=\"text-align:left\"><tt>/move &lt;lat lon hgt&gt;</tt></th><td>Move to new coordinates. lat/lon are decimal degrees (<tt>x.xxx</tt>), hgt is meters above ground.</td></tr>"
                    .."<tr><th style=\"text-align:left\"><tt>/rename &lt;callsign&gt;</tt></th><td>Rename to new callsign.</td></tr>"
                    .."</table>"
                )
                return
            end

            -- secure the following authenticated commands:
            if not fgcom.auth.handleAuthentication(event.actor) then
                fgcom.dbg("ignoring command, user not authenticated: "..event.actor:getName())
                return
            end

            if command == "frq" then
                if not param then event.actor:message("/frq needs a frequency as argument!") return end
                _, _, f = string.find(param, "([%d.]+)")
                if not f then event.actor:message("/frq param mhz is not a decimal!") return end
                overwriteHeader.frequency = f
                overwriteHeader.dialedFRQ = f
                updateAllChannelUsersforSend(client)
                notifyRadio(playback_targets)
                updateComment()
                event.actor:message("now sending on: "..f.." Mhz")
                return
            end

            if command == "pwr" then
                if not param then event.actor:message("/pwr needs a number as argument!") return end
                _, _, f = string.find(param, "([%d.]+)")
                if not f then event.actor:message("/pwr param is not a decimal!") return end
                overwriteHeader.txpower = f
                updateAllChannelUsersforSend(client)
                notifyRadio(playback_targets)
                updateComment()
                event.actor:message("now sending with: "..f.." Watts")
                return
            end

           if command == "move" then
                if not param then event.actor:message("/move needs new x,y,z coordinates as argument!") return end
                _, _, ly, lx, la = string.find(param, "([-%d.]+) ([-%d.]+) ([%d.]+)")
                if not ly or not lx or not la then event.actor:message("/move params need to be proper decimals!") return end
                overwriteHeader.lat    = ly
                overwriteHeader.lon    = lx
                overwriteHeader.height = la
                updateAllChannelUsersforSend(client)
                notifyLocation(playback_targets)
                updateComment()
                event.actor:message("moved to new position: lat="..ly..", lon="..lx..", hgt="..la)
                return
            end

           if command == "rename" then
                if not param then event.actor:message("/rename needs an argument!") return end
                _, _, cs = string.find(param, "([-%w]+)")
                if not cs then event.actor:message("/move param need to be ASCII chars!") return end
                overwriteHeader.callsign = cs
                updateAllChannelUsersforSend(client)
                notifyUserdata(playback_targets)
                updateComment()
                event.actor:message("renamed to new callsign: "..cs)
                return
            end

            if command == "exit" then
                fgcom.dbg("exit command received")
                event.actor:message("goodbye!")
                shutdownBot()
            end

        end
        
    end
end)


mumble.loop()
shutdownBot()
fgcom.log(botname.." with callsign "..fgcom.callsign.." completed.")
