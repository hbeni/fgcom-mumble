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
dofile("sharedFunctions.inc.lua")  -- include shared functions

-- init random generator using /dev/random, if poosible (=linux)
fgcom.rng.initialize()

local botname     = "FGCOM-radio-playback"
fgcom.callsign    = "FGCOM-RADIO-"..math.random(1, 99999)

local voiceBuffer = nil -- Queue voice buffer holding the cached samples
local lastHeader  = nil -- holds last header data
local playback_targets = nil -- holds updated list of all channel users

-- Parse cmdline args
local host   = "localhost"
local port   = 64738
local cert   = "bot.pem"
local key    = "bot.key"
local sample = ""

if arg[1] then
    if arg[1]=="-h" or arg[1]=="--help" then
        print(botname)
        print("usage: "..arg[0].." [opt=val ...]")
        print("  opts:")
        print("    --host=    host to connect to           (default="..host..")")
        print("    --port=    port to connect to           (default="..port..")")
        print("    --cert=    path to PEM encoded cert     (default="..cert..")")
        print("    --key=     path to the certs key        (default="..key..")")
        print("    --sample=  Path to the FGCS sample file (default="..sample..")")
        os.exit(0)
    end
    
    for _, opt in ipairs(arg) do
        _, _, k, v = string.find(arg[1], "--(%w+)=(.+)")
        --print("KEY='"..k.."'; VAL='"..v.."'")
        if k=="host"   then host=v end
        if k=="port"   then port=v end
        if k=="cert"   then cert=v end
        if k=="key"    then key=v end
        if k=="sample" then sample=v end
    end
    
end

-- parameter checks
if sample == "" then print("parameter --sample is mandatory!") os.exit(1) end
local sampleType = "FGCS"
-- TODO: check for supported filetypes based on postfix .fgcs


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
        --print("sample: len="..nextSample.len.."; eof='"..tostring(nextSample.eof).."'; data='"..nextSample.data.."'")
        if nextSample.len > 0 and not nextSample.eof then
            vb:pushright(nextSample) -- write the sample structure to the buffer
        end
        endOfSamples = nextSample.eof;
    end
    
    io.close(sampleFH)
    return sampleHeader, vb
end


-- function to get all channel users
-- this updates the global playback_target table
updateAllChannelUsersforSend = function(cl)
    --print("udpate channelusers")
    local ch = cl:getChannel(fgcom.channel)
    local users = ch:getUsers()
    playback_targets = {}
    --print("ok: "..ch:getName())
    for k,v in pairs(users) do
        --print("  k",k,"v=",v)
        table.insert(playback_targets, v)
    end
end

-- function to disconnect the bot
shutdownBot = function()
    updateAllChannelUsersforSend(client)

    -- send update to mute our radio
    local msg = "FRQ="..lastHeader.frequency
             ..",PWR="..lastHeader.txpower
             ..",PTT=1"
    client:sendPluginData("FGCOM:UPD_COM:0", msg, playback_targets)
    
    -- finally disconnect from the server
    client:disconnect()
end


-----------------------------
--[[      BOT RUNTIME      ]]
-----------------------------


-- read the file the first time and see if it parses.
-- usually we want the file deleted after validity expired, but for that we need
-- to make sure its a FGCS file... otherwise its another rm tool... ;)
lastHeader, voiceBuffer = readFGCSSampleFile(sample)
if not lastHeader then  print("ERROR: '"..sample.."' not readable or no FGCS file") os.exit(1) end

-- AFTER THIS CODE we can be confident it was a valid FGCS file!
--   lastHeader is initialized with the header data
--   voiceBuffer is initialized with the read samples
print(sample..": successfully loaded.")



-- Connect to server, so we get the API
print(botname..": connecting as '"..fgcom.callsign.."' to "..host.." on port "..port.." (cert: "..cert.."; key: "..key..")")
local client = assert(mumble.connect(host, port, cert, key))
client:auth(fgcom.callsign)
print("connect and bind: OK")


--[[
  Playback loop: we use a mumble timer for this. The timer loops in
  the playback-rate and looks if there are samples buffered. If so,
  he fetches them and plays them, one packet per timer tick.
]]
local playbackTimer = mumble.timer()
playbackTimer_func = function(t)
    print("playback timer started")
    
    -- So, a new timer tick started.
    -- See if we have still samples in the voice buffer. If not, reload it from file, if it was a looped one.
    if voiceBuffer:size() > 0 then
        print("voiceBuffer is still filled, samples: "..voiceBuffer:size())
        
        -- get the next sample from the buffer and play it
        local nextSample  = voiceBuffer:popleft()
        local endofStream = false
        if voiceBuffer:size() == 0 then endofStream = true end

        print("transmit next sample")
        --print("  tgt="..playback_target:getSession())
        print("  eos="..tostring(endofStream))
        print("  cdc="..lastHeader.voicecodec)
        print("  dta="..#nextSample.data)
        --print("  dta="..nextSample.data)
        client:transmit(lastHeader.voicecodec, nextSample.data, not endofStream) -- Transmit the single frame as an audio packet (the bot "speaks")
        print("transmit ok")
        if endofStream then
            -- no samples left? Just loop around to trigger all the checks
            print("no samples left, playback complete")
        end
        
    else
        -- Voicebuffer is emtpy.
        
        -- Check if this is a oneshot sample. if so, delete the file now as we just played it, and go home
        if lastHeader.playbacktype == "oneshot" then
            print("Oneshot sample detected: delete sample and go home.")
            os.remove(sample)
            shutdownBot()
            print("disconnected: we are done.")
            t:stop() -- Stop the timer
        
        else
            -- It was a looped timer: we reread the file to see if its still there,
            -- then check validity and if so, refill the voiceBuffer
    
            -- Read/update FGCS data file
            local lastHeader, voiceBuffer = readFGCSSampleFile(sample)
            if not hdr then
                -- file could not be loaded - most probably it got deleted.
                -- shut down the bot.
                print("'"..sample.."' not readable or no FGCS file, probably deleted from filesystem.")
                shutdownBot()
                print("disconnected: we are done.")
                t:stop() -- Stop the timer

            else
                -- File was successfully reloaded from disk
        
                -- check if the file is still valid
                local timeLeft = fgcom.data.getFGCSreaminingValidity(hdr)
                if fgcom.data.getFGCSreaminingValidity(hdr) < 0 then
                    print(sample..": FGCS file outdated since "..timeLeft.." seconds; removing")
                    os.remove(sample)
                    shutdownBot()
                    print("disconnected: we are done.")
                    t:stop() -- Stop the timer
                else
                    -- Samples are still valid;
                    -- we alreay updated the global voiceBuffer, so we need not do anything here.
                    print(sample..": FGCS file still valid: looping over.")
                    
                    --[[for k,v in pairs(hdr) do
                        print("header read: '"..k.."'='"..v.."'")
                    end
                    print("\nread samples:")
                    for k,v in ipairs(data) do
                        print("  sample: len="..v.len.."; eof='"..tostring(v.eof).."'; data='"..v.data.."'")
                    end--]]
                    
                    mumble.timer:set(0.0, lastHeader.samplespeed) -- update timer to sample speed in case it was changed
                end
            end
        end
    end
end


client:hook("OnServerSync", function(event)
    print("Sync done; server greeted with: ", event.welcome_text)
    
    -- try to join fgcom-mumble channel
    local ch = client:getChannel(fgcom.channel)
    event.user:move(ch)
    print("joined channel "..fgcom.channel)
    
    -- update current users of channel
    updateAllChannelUsersforSend(client)

    -- Setup the Bots location on earth
    local msg = "CALLSIGN="..lastHeader.callsign
             ..",LON="..lastHeader.lon              
             ..",LAT="..lastHeader.lat
             ..",ALT="..lastHeader.height
    print("Bot sets location: "..msg)
    client:sendPluginData("FGCOM:UPD_LOC", msg, playback_targets)
        
    -- Setup a radio to broadcast from
    local msg = "FRQ="..lastHeader.frequency
             ..",PWR="..lastHeader.txpower
             ..",PTT=1"
    print("Bot sets radio: "..msg)
    client:sendPluginData("FGCOM:UPD_COM:0", msg, playback_targets)
        
    -- start the playback timer.
    -- this will process the voice buffer.
    playbackTimer:start(playbackTimer_func, 0.25, lastHeader.samplespeed)
    
end)


mumble.loop()
print(botname.." with callsign "..fgcom.callsign.." completed.")
