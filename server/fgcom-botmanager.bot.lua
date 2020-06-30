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


--[[        FGCom-mumble ATIS Manager Bot

The bot is depending on lua-mumble from  bkacjios (https://github.com/bkacjios/lua-mumble).
Installation of this plugin is described in the projects readme: https://github.com/bkacjios/lua-mumble/blob/master/README.md

The purpose of this bot is to enable ATIS recording/playback infrastruture.:

  1. He monitors the `fgcom-mumble` channel for ATIS recoding requests. If he detects one,
     the ATIS message will be recorded and stored for further usage.
     The special frequency beeing monitored is "RECORD_<target-frequency>".
  2. Manage ATIS-playback bots. If ATIS messages have been recorded, the bot will spawn
     appropriate `radio-playback` bots serving the ATIS message.
]]
local botname = "FGOM-ATIS-manager"

local mumble = require("mumble")

fgcom_clients = {}
fgcom_voicebuffer = {}  -- Voicebuffer contains as key the userID and as value the recorded data

-- Parse cmdline args
local host = "localhost"
local port = 64738
local cert = "bot.pem"
local key  = "bot.key"
local fgcomchannel = "fgcom-mumble"
local frequencyRE = "RECORD_(%.+)"   -- special frequency syntax to detect recording and tgt freq

if arg[1] then
    if arg[1]=="-h" or arg[1]=="--help" then
        print(botname)
        print("usage: "..arg[0].." [opt=val ...]")
        print("  opts:")
        print("    --host=    host to coennct to")
        print("    --port=    port to connect to")
        print("    --cert=    path to PEM encoded cert")
        print("    --key=     path to the certs key")
        os.exit(0);
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
    if event.id:len() > 0 and event.id:find("FGCOM:") then
        print("Received FGCOM-plugin data, dataID='"..event.id.."', from=["..event.sender:getID().."] '"..event.sender:getName().."'")
            print("  data='"..event.data.."'")
    end

end)


client:hook("OnUserStartSpeaking", function(user)
    print("OnUserStartSpeaking, user["..user:getID().."]="..user:getName())
  
    print("open file test.rec")
    fgcom_voicebuffer.out = assert(io.open("test.rec", "wb"))
end)

local CODEC_OPUS = 4

local bit = require("bit")

local function writeShort(f, short)
    -- Convert our 16 bit number into two bytes
    local b1 = bit.band(bit.rshift(short, 8), 0xFF)
    local b2 = bit.band(short, 0xFF)
    f:write(string.char(b1, b2))
end

local function readShort(f)
    local short = f:read(2) -- Read two characters from the file
    if not short or short == "" then return end -- End of file
    local b1, b2 = string.byte(short, 1, 2) -- Convert the two characters to bytes
    return bit.bor(bit.lshift(b1, 8), bit.lshift(b2, 0)) -- Combine the two bytes into a number
end

local decoder = mumble.decoder()
decoder:setBitRate(48000)

client:hook("OnUserSpeak", function(event)
    if event.codec ~= CODEC_OPUS then return end -- Only supports OPUS voice data..

    print("OnUserSpeak, from=["..event.user:getID().."] '"..event.user:getName().."'")
    print("  codec="..event.codec)
    print("  target="..event.target)
    print("  sequence="..event.sequence)

    bitrate = decoder:getBitRate()
    print(" decoder decoding at "..bitrate)
    --local pcm = decoder:decode_float(event.data) -- Decode the encoded voice data back to usable PCM
    local pcm = event.data
print("OK1")
--    fgcom_voicebuffer.out:writeShort(#pcm) -- Store the size of the audio frame so we know how much to read from the file later
      writeShort(fgcom_voicebuffer.out, #pcm) -- Store the size of the audio frame so we know how much to read
      --print("OK2")
    fgcom_voicebuffer.out:write(pcm) -- Save the entire PCM data
    print("wrote pcm to file ("..#pcm.."b)")
end)

client:hook("OnUserStopSpeaking", function(user)
    print("OnUserStopSpeaking, user["..user:getID().."]="..user:getName())
    
    print("TEST close FH")
    assert(fgcom_voicebuffer.out:close())
    print("TEST close FH OK")
           
    client:playRecording("test.rec")
end)

local encoder = mumble.encoder()
encoder:setBitRate(decoder:getBitRate())
--encoder:setBitRate(48000)

function mumble.client:playRecording(file)
    local f = assert(io.open(file, "rb"))
    print("file "..file.." opened")

    local timer = mumble.timer()
    print("timer initialized")
    
    local timer_rate = 0.02  -- packet separation, must comply to the data stream rate, otherwise voice is too fast/too slow

    local seq = 0
    timer:start(function(t)
        if f then
            print("timer: read packet "..seq)
            seq = seq+1
            local len = readShort(f)
            print("timer:   header read ok, packet_len="..len)
            local pcm = f:read(len)
               
            print("timer:   data read ok")

            if not pcm or pcm == "" then
                print("timer: stop timer")
                t:stop() -- Stop the audio timer
                f:close()
                return
            end

            print("timer: encode and transmit")
            bitrate = encoder:getBitRate()
            print(" encoder encoding at "..bitrate)
            --local encoded = encoder:encode_float(1, pcm) -- encode PCM packet to 1 opus frame
            local encoded = pcm
            print("timer:   encoded ok")
            client:transmit(encoded) -- Transmit the single frame as an audio packet
            print("timer:   transmit ok")
        end
    end, 0.00, timer_rate) -- Create a timer that will loop every 20ms - must correlate with the
end



mumble.loop()
