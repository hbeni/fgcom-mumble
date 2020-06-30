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

The bot is depending on lua-mumble from  bkacjios (https://github.com/bkacjios/lua-mumble).
Installation of this plugin is described in the projects readme: https://github.com/bkacjios/lua-mumble/blob/master/README.md

The purpose of this bot is to allow easy test of the system from a clients perspective.
He monitors the `fgcom-mumble` channel for transmissions. If he detects one, the special
frequency is checked. If it is an echo test frequency, the bot will record the voice
and play it back to the user.

TODO: Implement 911.000 MHz? looped sound playback of a test sample?

]]
local botname = "FGOM-Echotest"

dofile("sharedFunctions.inc.lua")  -- include shared functions

fgcom_voicebuffer = {}  -- Voicebuffer contains as key the userID and as value the recorded data

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
        _, _, k, v = string.find(arg[1], "--(%w+)=(.+)")
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
    --print("DATA INCOMING FROM="..event.sender:getSession())
    fgcom.data.parsePluginData(event.id, event.data, event.sender)

end)


client:hook("OnUserStartSpeaking", function(user)
    print("OnUserStartSpeaking, user["..user:getSession().."]="..user:getName())
           
    -- lets see if the user speaks to us...
    -- that is the case if he tuned the frequency 910.000
    if fgcom_clients[user:getSession()] then
        remote = fgcom_clients[user:getSession()]
        print("we know this client: callsign="..remote.callsign)
        for radio_id,radio in pairs(remote.radios) do
            print("  check frequency: radio #"..radio_id..", ptt='"..radio.ptt.."', frq='"..radio.frequency.."'")
            if radio.frequency:find(l_echo_frequency)
               and radio.ptt then
                print("   frequency match at radio #"..radio_id)
                remote.filename = "echotest-"..user:getSession()..".rec"
                remote.file = assert(io.open(remote.filename, "wb"))
                remote.recording = true
            end
        end
    end
  
    print("open file test.rec")
    fgcom_voicebuffer.out = assert(io.open("test.rec", "wb"))
end)

client:hook("OnUserSpeak", function(event)
    if event.codec ~= CODEC_OPUS then 
           print("ERROR: Only CODEC_OPUS is supported for now!")
           return -- Only supports OPUS voice data..
    end

    print("OnUserSpeak, from=["..event.user:getSession().."] '"..event.user:getName().."'")
    print("  codec="..event.codec)
    print("  target="..event.target)
    print("  sequence="..event.sequence)
           
    if fgcom_clients[event.user:getSession()] then
        remote = fgcom_clients[event.user:getSession()]
        if remote.recording then
            local pcm = event.data
            fgcom.io.writeShort(remote.file, #pcm) -- Store the size of the audio frame so we know how much to read
            remote.file:write(pcm) -- Save the entire PCM data
            print("wrote pcm to file "..remote.filename.." ("..#pcm.."b)")
        end
    end
end)

client:hook("OnUserStopSpeaking", function(user)
    print("OnUserStopSpeaking, user["..user:getSession().."]="..user:getName())
    
           
    if fgcom_clients[user:getSession()] then
        remote = fgcom_clients[user:getSession()]
        if remote.recording then
            print("TEST close FH")
            assert(remote.file:close())
            print("TEST close FH OK")
            
            fgcom.io.playRecording(client, remote.filename)
        end
    end
           
end)




mumble.loop()
