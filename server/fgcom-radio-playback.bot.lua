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
fgcom.botversion = "1.0"

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
local cert   = "playbot.pem"
local key    = "playbot.key"
local sample = ""
local nodel  = false
local lat    = ""
local lon    = ""
local hgt    = ""

if arg[1] then
    if arg[1]=="-h" or arg[1]=="--help" then
        print(botname..", "..fgcom.getVersion())
        print("usage: "..arg[0].." [opt=val ...]")
        print("  Options:")
        print("    --host=    host to connect to           (default="..host..")")
        print("    --port=    port to connect to           (default="..port..")")
        print("    --cert=    path to PEM encoded cert     (default="..cert..")")
        print("    --key=     path to the certs key        (default="..key..")")
        print("    --sample=  Path to the FGCS sample file (default="..sample..")")
        print("    --nodel    Don't delete outdated samples")
        print("    --lat      Latitude override        (default: use FGCS header)")
        print("    --lon      Longitude override       (default: use FGCS header)")
        print("    --hgt      Height override          (default: use FGCS header)")
        print("    --debug    print debug messages             (default=no)")
        print("    --version  print version and exit")
        os.exit(0)
    end
    
    for _, opt in ipairs(arg) do
        _, _, k, v = string.find(opt, "--(%w+)=(.+)")
        if k=="host"   then host=v end
        if k=="port"   then port=v end
        if k=="cert"   then cert=v end
        if k=="key"    then key=v end
        if k=="sample" then sample=v end
        if opt=="--nodel" then nodel=true end
        if k=="lat"    then lat=v end
        if k=="lon"    then lon=v end
        if k=="hgt"    then hgt=v end
        if opt == "--debug" then fgcom.debugMode = true end
        if opt == "--version" then print(botname..", "..fgcom.getVersion()) os.exit(0) end
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

-----------------------------
--[[      BOT RUNTIME      ]]
-----------------------------


-- read the file the first time and see if it parses.
-- usually we want the file deleted after validity expired, but for that we need
-- to make sure its a FGCS file... otherwise its another rm tool... ;)
lastHeader, voiceBuffer = readFGCSSampleFile(sample)
if not lastHeader then  fgcom.log("ERROR: '"..sample.."' not readable or no FGCS file") os.exit(1) end

-- AFTER THIS CODE we can be confident it was a valid FGCS file!
--   lastHeader is initialized with the header data
--   voiceBuffer is initialized with the read samples
fgcom.log(sample..": successfully loaded.")

local timeLeft = fgcom.data.getFGCSremainingValidity(lastHeader)
local persistent = false
if lastHeader.timetolive == "0" then
    fgcom.log(sample..": This is a persistent sample.")
    timeLeft   = 1337   -- just some arbitary dummy value in the future
    persistent = true   -- loops forever!
end
if not persistent and timeLeft < 0 then
    fgcom.log(sample..": sample is invalid, since "..timeLeft.."s. Aborting.")
    os.exit(0)
else
    fgcom.log(sample..": sample is valid, remaining time: "..timeLeft.."s")
end


-- Connect to server, so we get the API
fgcom.log(botname..": connecting as '"..fgcom.callsign.."' to "..host.." on port "..port.." (cert: "..cert.."; key: "..key..")")
local client = assert(mumble.connect(host, port, cert, key))
client:auth(fgcom.callsign)
fgcom.dbg("connect and bind: OK")



-- function to get all channel users
-- this updates the global playback_target table
updateAllChannelUsersforSend = function(cl)
    --fgcom.dbg("udpate channelusers")
    local ch = cl:getChannel(fgcom.channel)
    local users = ch:getUsers()
    playback_targets = {}
    --fgcom.dbg("ok: "..ch:getName())
    for k,v in pairs(users) do
        --fgcom.dbg("  k="..tostring(k).."v="..tostring(v))
        table.insert(playback_targets, v)
    end
end

-- function to disconnect the bot
shutdownBot = function()
    fgcom.log("shutdownBot(): requested")
    updateAllChannelUsersforSend(client)

    -- send update to mute our radio
    -- TODO: send deregister request, once implemented
    local msg = "FRQ="..lastHeader.frequency
             ..",PWR="..lastHeader.txpower
             ..",PTT=0"
    client:sendPluginData("FGCOM:UPD_COM:0", msg, playback_targets)
    fgcom.log("shutdownBot(): COM0 deactiated")
    
    -- finally disconnect from the server
    client:disconnect()
    fgcom.log("shutdownBot(): disconnected")
    os.exit(0)
end


--[[
  Playback loop: we use a mumble timer for this. The timer loops in
  the playback-rate and looks if there are samples buffered. If so,
  he fetches them and plays them, one packet per timer tick.
]]
local playbackTimer = mumble.timer()
playbackTimer_func = function(t)
    fgcom.dbg("playback timer: tick")
    
    -- So, a new timer tick started.
    -- See if we have still samples in the voice buffer. If not, reload it from file, if it was a looped one.
    if voiceBuffer:size() > 0 then
        fgcom.dbg("voiceBuffer is still filled, samples: "..voiceBuffer:size())
        
        -- get the next sample from the buffer and play it
        local nextSample  = voiceBuffer:popleft()
        local endofStream = false
        if voiceBuffer:size() == 0 then endofStream = true end

        fgcom.dbg("transmit next sample")
        --fgcom.dbg("  tgt="..playback_target:getSession())
        fgcom.dbg("  eos="..tostring(endofStream))
        fgcom.dbg("  cdc="..lastHeader.voicecodec)
        fgcom.dbg("  dta="..#nextSample.data)
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
    
            -- Read/update FGCS data file
            lastHeader, voiceBuffer = readFGCSSampleFile(sample)
            if not lastHeader then
                -- file could not be loaded - most probably it got deleted.
                -- shut down the bot.
                fgcom.log("'"..sample.."' not readable or no FGCS file, probably deleted from filesystem.")
                shutdownBot()
                fgcom.dbg("disconnected: we are done.")
                t:stop() -- Stop the timer

            else
                -- File was successfully reloaded from disk
                fgcom.dbg("update from file successful")
        
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
end


notifyUserdata = function(tgts)
    local msg = "CALLSIGN="..lastHeader.callsign
    fgcom.dbg("Bot sets userdata: "..msg)
    client:sendPluginData("FGCOM:UPD_USR", msg, tgts)
end

notifyLocation = function(tgts)
    local latitude  = lastHeader.lat       if lat ~= "" then latitude  = lat end
    local longitude = lastHeader.lon       if lon ~= "" then longitude = lon end
    local height    = lastHeader.height    if hgt ~= "" then height    = hgt end
    local msg = ",LON="..longitude
              ..",LAT="..latitude
              ..",ALT="..height
    fgcom.dbg("Bot sets location: "..msg)
    client:sendPluginData("FGCOM:UPD_LOC", msg, tgts)
end

notifyRadio = function(tgts)
local msg = "FRQ="..lastHeader.frequency
             ..",PWR="..lastHeader.txpower
             ..",PTT=1"
    fgcom.dbg("Bot sets radio: "..msg)
    client:sendPluginData("FGCOM:UPD_COM:0", msg, tgts)
end

client:hook("OnServerSync", function(event)
    fgcom.log("Sync done; server greeted with: "..event.welcome_text)
    
    -- try to join fgcom-mumble channel
    local ch = client:getChannel(fgcom.channel)
    event.user:move(ch)
    fgcom.log("joined channel "..fgcom.channel)
    
    -- update current users of channel
    updateAllChannelUsersforSend(client)

    -- Setup the Bots location on earth
    notifyUserdata(playback_targets)
    notifyLocation(playback_targets)
        
    -- Setup a radio to broadcast from
    notifyRadio(playback_targets)
           
    -- Adjust comment
    client:setComment("<b><i><u>FGCom:</u></i></b><table>"
                      .."<tr><th>Callsign:</th><td><tt>"..lastHeader.callsign.."</tt></td></tr>"
                     .."<tr><th>Frequency:</th><td><tt>"..lastHeader.frequency.."</tt></td></tr>"
                     .."<tr><th>Power:</th><td><tt>"..lastHeader.txpower.."</tt></td></tr>"
                     .."<tr><th>Position:</b></th><td><table><tr><td>Lat:</td><td><tt>"..lastHeader.lat.."</tt></td></tr><tr><td>Lon:</td><td><tt>"..lastHeader.lon.."</tt></td></tr><tr><td>Height:</td><td><tt>"..lastHeader.height.."</tt></td></tr></table></td></tr>"
                     .."</table>")
        
    -- start the playback timer.
    -- this will process the voice buffer.
    playbackTimer:start(playbackTimer_func, 0.0, lastHeader.samplespeed)
    
end)


client:hook("OnPluginData", function(event)
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


client:hook("OnUserChannel", function(event)
	--["user"]	= mumble.user user,
	--["actor"]	= mumble.user actor,
	--["from"]	= mumble.channel from,
	--["to"]	= mumble.channel to,

    if event.to:getName() == fgcom.channel then
        fgcom.dbg("OnUserChannel(): client joined fgcom.channel: "..event.user:getName())
        notifyUserdata({event.user})
        notifyLocation({event.user})
        notifyRadio({event.user})
    end
end)


mumble.loop()
shutdownBot()
fgcom.log(botname.." with callsign "..fgcom.callsign.." completed.")
