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


--[[        FGCom-mumble ECHO Bot
TODO: Should be easily replaceable with a generic radio-playback bot once he is available. The bot-manager-bot (or a specialized recorder bot?) can then record the voice and after that automsatically spawn a playback bot at the pilots location! Currently we have only signle user support and this will be fixed thereby.

The bot is depending on lua-mumble from  bkacjios (https://github.com/bkacjios/lua-mumble).
Installation of this plugin is described in the projects readme: https://github.com/bkacjios/lua-mumble/blob/master/README.md

The purpose of this bot is to allow easy test of the system from a clients perspective.
He monitors the `fgcom-mumble` channel for transmissions. If he detects one, the special
frequency is checked. If it is an echo test frequency, the bot will record the voice
and play it back to the user.

TODO: Implement 911.000 MHz? looped sound playback of a test sample? -> Better a specific radio bot?
TODO: concurrency not implemented. Currently the bot can only respond to one tester.

]]
local botname = "FGOM-Echotest"

dofile("sharedFunctions.inc.lua")  -- include shared functions
fgcom.callsign = "FGOM-ECHO"
local voiceBuffer = Queue:new()


-- Parse cmdline args
local host = "localhost"
local port = 64738
local cert = "bot.pem"
local key  = "bot.key"
local fgcomchannel = "fgcom-mumble"
local l_echo_frequency = "^910.0+$"


if arg[1] then
    if arg[1]=="-h" or arg[1]=="--help" then
        print(botname)
        print("usage: "..arg[0].." [opt=val ...]")
        print("  opts:")
        print("    --host=    host to coennct to")
        print("    --port=    port to connect to")
        print("    --cert=    path to PEM encoded cert")
        print("    --key=     path to the certs key")
        os.exit(0)
    end
    
    for _, opt in ipairs(arg) do
        _, _, k, v = string.find(opt, "--(%w+)=(.+)")
        print("KEY='"..k.."'; VAL='"..v.."'")
        if k=="host" then host=v end
        if k=="port" then port=v end
        if k=="cert" then cert=v end
        if k=="key" then  key=v end
    end
    
end


-- Connect to server, so we get the API
print(botname..": connecting to "..host.." on port "..port.." (cert: "..cert.."; key: "..key..")")
local client = assert(mumble.connect(host, port, cert, key))
client:auth(botname)
print("connect and bind: OK")


-- Function to Check if a user currently speaks to us;
-- that is the case if he tuned the frequency 910.000
-- @param user mumble.user to check
-- @return bool true, if he is
isClientTalkingToUs = function(user)
    rv = false
    if fgcom_clients[user:getSession()] then
        remote = fgcom_clients[user:getSession()]
        print("we know this client: callsign="..remote.callsign)
        for radio_id,radio in pairs(remote.radios) do
            print("  check frequency: radio #"..radio_id..", ptt='"..radio.ptt.."', frq='"..radio.frequency.."'")
            if radio.frequency:find(l_echo_frequency) and radio.ptt then
                -- remote is on out frequency AND his ptt is active
                print("   frequency match at radio #"..radio_id)
                rv = true
                break
            end
        end
    end
    return rv
end


--[[
  Playback loop: we use a mumble timer for this. The timer loops in
  the playback-rate and looks if there are samples buffered. If so,
  he fetches them and plays them, one packet per timer tick.
]]
local playbackTimer_delay = 0.90 -- delay start of playback this much seconds
local playbackTimer_rate  = 0.02 -- playback speed (seconds between packets): it can vary from 0.01, 0.02, 0.04, and 0.06 and is subject to user client settings ("Audio per packet")
local playbackTimer = mumble.timer()
local playback_target = {}
playbackTimer_func = function(t)
    print("playback timer started")
    -- get the next sample from the buffer and play it
    local nextSample  = voiceBuffer:popleft()
    local endofStream = 0
    if voiceBuffer:size() == 0 then endofStream = 1 end

    print("transmit next sample")
    print("  tgt="..playback_target:getSession())
    print("  eos="..endofStream)
    print("  cdc="..nextSample.codec)
    print("  dta="..#nextSample.data)
    client:transmit(nextSample.codec, nextSample.data)--, endofStream) -- Transmit the single frame as an audio packet (the bot "speaks")
    print("transmit ok")
    if endofStream==1 then
        -- no samples left?
        print("no samples left, playback complete")
        client:sendPluginData("FGCOM:UPD_COM:0", "FRQ=910.0,PTT=0", {playback_target})
        t:stop() -- Stop the audio timer
        print("timer done.")
    end
    
end



client:hook("OnServerSync", function(event)
    print("Sync done; server greeted with: ", event.welcome_text)
    
    -- try to join fgcom-mumble channel
    local ch = client:getChannel(fgcomchannel)
    event.user:move(ch)
    print("joined channel "..fgcomchannel)
end)


client:hook("OnPluginData", function(event)
    --["sender"] = mumble.user sender, -- Who sent this data packet
	--["id"]     = Number id,          -- The data ID of this packet
	--["data"]   = String data,        -- The data sent (can be binary data)
	--["receivers"]				= {  -- A table of who is receiving this data
	--	[1] = mumble.user,
	--},
    print("DATA INCOMING FROM="..event.sender:getSession())
    fgcom.data.parsePluginData(event.id, event.data, event.sender)

end)


client:hook("OnUserStartSpeaking", function(user)
    print("OnUserStartSpeaking, user["..user:getSession().."]="..user:getName())
           
end)


client:hook("OnUserSpeak", function(event)
    -- should work with any codec now
    --if event.codec ~= CODEC_OPUS then 
    --       print("ERROR: Only CODEC_OPUS is supported for now!")
    --       return -- Only supports OPUS voice data..
    --end

    print("OnUserSpeak, from=["..event.user:getSession().."] '"..event.user:getName().."'")
    --print("  codec="..event.codec)
    --print("  target="..event.target)
    --print("  sequence="..event.sequence)

    -- If the user is speaking to us, record its samples and push them to the buffer
    if isClientTalkingToUs(event.user) then
        len = #event.data
        print("  recording sample, len="..len)
        voiceBuffer:pushright({codec=event.codec, data=event.data})
        print("  recording ok")
    end
           
end)


client:hook("OnUserStopSpeaking", function(user)
    print("OnUserStopSpeaking, user["..user:getSession().."]="..user:getName())
    
    if isClientTalkingToUs(user) then
        print("  user had talked to me!")
        remote = fgcom_clients[user:getSession()] -- get remote known state
        playback_target = user  -- so the timer knows about the target mumble.user
        -- send location and radio update, so the sender can hear us.
        -- we set the bot to the senders location.
        -- it is important to do it this way, so the normal client plugin
        -- operation can be verified!
        local msg = ",LON="..remote.lon              
                  ..",LAT="..remote.lat
                  ..",ALT="..remote.alt
        print("  msg="..msg..", to: "..playback_target:getSession())
        client:sendPluginData("FGCOM:UPD_LOC", msg, {playback_target})
        
        local msg = "CALLSIGN="..fgcom.callsign
        client:sendPluginData("FGCOM:UPD_USR", msg, playback_targets)
        
        client:sendPluginData("FGCOM:UPD_COM:0", "FRQ=910.0,PTT=1", {playback_target})
        
        -- start the playback timer
        playbackTimer:start(playbackTimer_func, playbackTimer_delay, playbackTimer_rate)
    end
    
end)



mumble.loop()
