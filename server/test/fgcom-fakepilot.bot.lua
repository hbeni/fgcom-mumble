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


--[[        FGCom-mumble fake pilot bot

The bot tries to simulate a fake pilot flying around.
He connects and changes position randomly.
Every some seconds, he will contemplate about if he wants to make a short radio transmission.
The frequency is choosen randomly from a predefined set.
The location is choosen at a random position around 0,0.

Expected results:
- the overall system performance is mainly depending on mumbles own performance.
- additional to that, the bandwith will be congested with the plugin-IO exchanges.


The bot is depending on lua-mumble from  bkacjios (https://github.com/bkacjios/lua-mumble).
Installation of this plugin is described in the projects readme: https://github.com/bkacjios/lua-mumble/blob/master/README.md

]]
dofile("sharedFunctions.inc.lua")  -- include shared functions

-- init random generator using /dev/random, if poosible (=linux)
fgcom.rng.initialize()

--print(math.random(-150, 150)/100 + math.random(-100000, 100000)/100000)  os.exit(1)
--print(math.random(-100, 100)/100000) os.exit(1)
local botid   = ""
local botname = "FGCOM-fakepilot"

local voiceBuffer = Queue:new() -- Queue voice buffer holding the cached samples
local lastHeader  = nil -- holds last header data
local playback_targets = nil -- holds updated list of all channel users
local ptt = false -- signals if the bot is currently transmitting

local sleep = 30              -- time beween checks if to transmit
local chance_transmit = 0.25  -- chance that he will transmit
local chance_echotest = 0.01  -- chance that the pilot wants to try 910 echo frequency instead of a random one
local testfrequencies = {
    "110.00", "110.25", "110.50", "110.75",
    "111.00", "111.25", "111.50", "111.75",
    "112.00", "112.25", "112.50", "112.75",
}

local locs = 0.5  -- seconds between location updates

-- Parse cmdline args
local host   = "localhost"
local port   = 64738
local cert   = "bot.pem"
local key    = "bot.key"
local sample = "recordings/fgcom.rec.testsample.fgcs"

if arg[1] then
    if arg[1]=="-h" or arg[1]=="--help" then
        print(botname)
        print("usage: "..arg[0].." [opt=val ...]")
        print("  Options:")
        print("    --id=      id to join with              (default=random)")
        print("    --host=    host to connect to           (default="..host..")")
        print("    --port=    port to connect to           (default="..port..")")
        print("    --channel= channel to join                  (default="..fgcom.channel..")")
        print("    --cert=    path to PEM encoded cert     (default="..cert..")")
        print("    --key=     path to the certs key        (default="..key..")")
        print("    --sample=  FGCS sample file to transmit")
        print("    --locs=    Seconds between location updates (default="..locs..")")
        print("    --sleep=   Time interval between checks (default="..sleep..")")
        print("    --chancet= Chance for transmission      (default="..chance_transmit..")")
        print("    --chancee= Chance that transmit is echotest   (default="..chance_echotest..")")
        os.exit(0)
    end
    
    for _, opt in ipairs(arg) do
        _, _, k, v = string.find(opt, "--(%w+)=(.+)")
        if k=="id"      then botid=v end
        if k=="host"    then host=v end
        if k=="port"    then port=v end
        if k=="channel"   then fgcom.channel=v end
        if k=="cert"    then cert=v end
        if k=="key"     then key=v end
        if k=="sample"  then sample=v end
        if k=="locs"    then locs=v end
        if k=="sleep"   then sleep=tonumber(v) end
        if k=="chancet" then chance_transmit=tonumber(v) end
        if k=="chancee" then chance_echotest=tonumber(v) end
    end
    
end

-- parameter checks
--if sample == "" then print("parameter --sample is mandatory!") os.exit(1) end

fgcom.callsign = "FGCOM-BOTPILOT-"
if botid == "" then
    fgcom.callsign = fgcom.callsign..math.random(1, 99999)
else
    fgcom.callsign = fgcom.callsign..botid
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
        --print("sample: len="..nextSample.len.."; eof='"..tostring(nextSample.eof).."'; data='"..nextSample.data.."'")
        if nextSample.len > 0 and not nextSample.eof then
            vb:pushright(nextSample) -- write the sample structure to the buffer
        end
        endOfSamples = nextSample.eof;
    end
    
    io.close(sampleFH)
    return sampleHeader, vb
end

function table.clone(org)
  return {table.unpack(org)}
end


-----------------------------
--[[      BOT RUNTIME      ]]
-----------------------------

-- read the file into the queue.
lastHeader, _ = readFGCSSampleFile(sample)
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


--[[
  Playback loop: we use a mumble timer for this. The timer loops in
  the playback-rate and looks if there are samples buffered. If so,
  he fetches them and plays them, one packet per timer tick.
]]
local playbackTimer = mumble.timer()
local freq = testfrequencies[1]
playbackTimer_func = function(t)
    --print("playback timer: tick; ptt=",ptt)
    
    -- So, a new timer tick started.
    if ptt then
        -- PTT is active: setup voice buffer and radio (if not done already)
        if voiceBuffer:size() <= 0 then
            print("fgcom.callsign.. Starting new transmission...")
            
            -- fill temporary buffer
            lastHeader, voiceBuffer = readFGCSSampleFile(sample)
            if not lastHeader then  print("ERROR: '"..sample.."' not readable or no FGCS file") os.exit(1) else print(sample..": successfully refreshed ("..voiceBuffer:size().." samples)") end
            
            -- choose a random frequency
            freq = testfrequencies[math.random(1,#testfrequencies)]
            local ce = tonumber(math.random(0, 100)/100)
            if ce < chance_echotest then
                freq = "910.00"
                print("  (Echotest transmission @"..freq..")")
            else
                print("  (Normal transmission @"..freq..")")
            end
            
            -- Broadcast radio
            updateAllChannelUsersforSend(client)
            if #playback_targets > 0 then
                local msg = "FRQ="..freq
                        ..",CHN="..freq
                        ..",PWR=10"
                        ..",PTT=1"
                print(fgcom.callsign.."  Bot sets radio: "..msg)
                client:sendPluginData("FGCOM:UPD_COM:0:0", msg, playback_targets)
            end
        end
            
        -- Play the samples, then stop transmission.
        if voiceBuffer:size() > 0 then
            --print("voiceBuffer is still filled, samples: "..voiceBuffer:size())
            
            -- get the next sample from the buffer and play it
            local nextSample  = voiceBuffer:popleft()
            local endofStream = false
            if voiceBuffer:size() == 0 then endofStream = true end

            print("transmit next sample @"..freq)
            --print("  tgt="..playback_target:getSession())
            print("  eos="..tostring(endofStream))
            print("  cdc="..lastHeader.voicecodec)
            print("  dta="..#nextSample.data)
            --print("  dta="..nextSample.data)
            client:transmit(lastHeader.voicecodec, nextSample.data, not endofStream) -- Transmit the single frame as an audio packet (the bot "speaks")
            print("  transmit ok")
            if endofStream then
                -- no samples left? Just loop around to trigger all the checks
                print(fgcom.callsign.."  no samples left, playback complete")
                
                ptt = false;
            
                -- broadcast radio
                updateAllChannelUsersforSend(client)
                if #playback_targets > 0 then
                    local msg = "FRQ="..freq
                            ..",CHN="..freq
                            ..",PWR=10"
                            ..",PTT=0"
                    print("  Bot sets radio: "..msg)
                    client:sendPluginData("FGCOM:UPD_COM:0:0", msg, playback_targets)
                end
                
                t:stop() -- Stop the timer
                print(fgcom.callsign.." Transmission complete.")
            end
        end
        
    else
        -- PTT is false.
        -- (This should never be reached, because the only place ptt is reset to false is, if the voicebuffer is empty. Somehow the timer was not stopped...)
        print("ERROR: PTT=0 invalid state reached.")
        t:stop()
        voiceBuffer = Queue.new()
        --os.exit(1)
    end
    
    io.flush()
end


local locUpd     = mumble.timer()
local checkTimer = mumble.timer()
local lat   = math.random(-150, 150)/100 + math.random(-100000, 100000)/100000
local lon   = math.random(-150, 150)/100 + math.random(-100000, 100000)/100000
local alt   = math.random(15, 8000)
local latmv = math.random(-100, 100)/100000
local lonmv = math.random(-100, 100)/100000
client:hook("OnServerSync", function(client, event)
    print("Sync done; server greeted with: ", event.welcome_text)
    
    -- try to join fgcom-mumble channel
    local ch = client:getChannel(fgcom.channel)
    event.user:move(ch)
    print(fgcom.callsign.." joined channel "..fgcom.channel)
    
    updateAllChannelUsersforSend(client)
    local msg = "CALLSIGN="..fgcom.callsign
    client:sendPluginData("FGCOM:UPD_USR:0", msg, playback_targets)
           
    -- update location       
    locUpd:start(function(t)
        --print("locUpd: tick")
        -- update current users of channel
        updateAllChannelUsersforSend(client)
        if #playback_targets > 0 then
            -- Setup the Bots location on earth
            lat = lat + latmv
            lon = lon + lonmv
            alt = alt + math.random(-50, 50)
            if alt < 100 then alt = math.abs(alt) end
            local msg = "LON="..lat
                    ..",LAT="..lon
                    ..",ALT="..alt
            --print("Bot sets location: "..msg)
            client:sendPluginData("FGCOM:UPD_LOC:0", msg, playback_targets)
        end
            
    end, 0.00, locs)
    
    -- let the pilot check every n seconds if he wants to do a transmission
    checkTimer:start(function(t)
        --print("checkTimer: tick")
        local ct = math.random(0, 100)/100
        if chance_transmit  < ct then
            -- triggerTransmit, if not already transmitting
            if not ptt then
                --print("activating PTT")
                ptt = true
                playbackTimer:start(playbackTimer_func, 0.0, lastHeader.samplespeed)
            else
                -- print("(not activating PTT, its still active)")
            end
        end
    end, 0.00, sleep)           
   
end)

client:hook("OnPluginData", function(client, event)
    --["sender"] = mumble.user sender, -- Who sent this data packet
	--["id"]     = Number id,          -- The data ID of this packet
	--["data"]   = String data,        -- The data sent (can be binary data)
	--["receivers"]				= {  -- A table of who is receiving this data
	--	[1] = mumble.user,
	--},
	--print("OnPluginData(): DATA INCOMING FROM="..tostring(event.id)..", "..tostring(event.sender))

    -- Answer data requests
    if event.id:len() > 0 and event.id:find("FGCOM:ICANHAZDATAPLZ") then
        print("OnPluginData(): client asks for data: "..tostring(event.sender))
        
        local msg = "CALLSIGN="..fgcom.callsign
        client:sendPluginData("FGCOM:UPD_USR:0", msg, {event.sender})
        --event.sender:sendPluginData("FGCOM:UPD_USR:0", msg)
           
        local msg = "LON="..lat
                ..",LAT="..lon
                ..",ALT="..alt
        client:sendPluginData("FGCOM:UPD_LOC:0", msg, {event.sender})
        --event.sender:sendPluginData("FGCOM:UPD_LOC:0", msg)
           
        local msg = "FRQ="..freq
                ..",CHN="..freq
                ..",PWR=10"
                ..",PTT=0"
        client:sendPluginData("FGCOM:UPD_COM:0", msg, {event.sender})
        --event.sender:sendPluginData("FGCOM:UPD_COM:0", msg)
    end

end)


mumble.loop()
print(botname.." with callsign "..fgcom.callsign.." completed.")
