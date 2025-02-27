--[[  This is a simple echo bot, showing how to capture and replay some samples. ]]


-- Define a voicebuffer to store the recording samples.
-- We treat this table as fifo queue containing the recorded samples.
-- We can just use the (OO-adapted) code from https://www.lua.org/pil/11.4.html
FiFo = {}
function FiFo:new (o)
    o = o or {}   -- create object if user does not provide one
    o.first = 0
    o.last = -1
    setmetatable(o, self)
    self.__index = self
    return o
end
function FiFo:pushleft (value)
    local first = self.first - 1
    self.first = first
    self[first] = value
end
function FiFo:pushright (value)
    local last = self.last + 1
    self.last = last
    self[last] = value
end
function FiFo:popleft ()
    local first = self.first
    if first > self.last then return nil end
    local value = self[first]
    self[first] = nil        -- to allow garbage collection
    self.first = first + 1
    return value
end
function FiFo:popright ()
    local last = self.last
    if self.first > last then return nil end
    local value = self[last]
    self[last] = nil         -- to allow garbage collection
    self.last = last - 1
    return value
end

-- finally, initialize our voicebuffer using the FiFo prototype
local voiceBuffer = FiFo:new()

-- Protocol constant for the codec. Currently only OPUS
-- encoded packets are supported (experimentation could yield that
-- other packets might work too, as we are just replaying them)
local CODEC_OPUS = 4

mumble = require("mumble")  -- get the mumble API

--[[
   It is nice if the bot can be called with parameters from the outside:
   lua echobot.lua --host=someHost --cert=mycert.pem --key=mykey.key

   The cert and key can be generated with openssl like this:
     $> openssl genrsa -out bot.key 2048 2> /dev/null
     $> openssl req -new -sha256 -key bot.key -out bot.csr -subj "/"
     $> openssl x509 -req -in bot.csr -signkey bot.key -out bot.pem 2> /dev/null
]]

-- define defaults
local botname = "echobot"
local host    = "localhost"
local port    = 64738      -- standard mumble port
local cert    = "bot.pem"
local key     = "bot.key"

-- Parse cmdline args
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
print(botname..": "..fgcom.getVersion())
print("connecting as '"..fgcom.callsign.."' to "..host.." on port "..port.." (cert: "..cert.."; key: "..key.."), joining: '"..fgcom.channel.."'")
local client = mumble.client()
assert(client:connect(host, port, cert, key))

client:hook("OnConnect", function(client)
    client:auth(botname)
    print("connect and bind: OK")
end)



--[[
  Playback loop: we use a mumble timer for this. The timer loops in
  the playback-rate and looks if there are samples buffered. If so,
  he fetches them and plays them, one packet per timer tick.
]]
local playbackTimer_rate = 0.02 -- playback speed: it can vary from 0.01, 0.02, 0.04, and 0.06 and is subject to user client settings ("Audio per packet")
local playbackTimer = mumble.timer()
playbackTimer:start(function(t)
    -- get the next sample from the buffer and play it
    nextEntry = voiceBuffer:popleft()
    if nextEntry then
        print("transmit next sample",nextEntry)
        print("  codec="..nextEntry.codec)
        print("  data="..nextEntry.data)
        client:transmit(nextEntry.codec, nextEntry.data)  -- Transmit the single frame as an audio packet (the bot "speaks")
    end
end, 0.00, playbackTimer_rate)



--[[
  Define mumble hooks to collect the samples
]]

-- The hook is called whenever someone speaks.
-- We record the samples into the buffer.
client:hook("OnUserSpeak", function(event)
    print("OnUserSpeak, codec="..event.codec.." from=["..event.user:getSession().."] '"..event.user:getName().."'")
    -- should work now with any codec
    --if event.codec ~= CODEC_OPUS then 
    --    print("ERROR: Only CODEC_OPUS is supported for now!")
    --    return -- Only supports OPUS voice data... -> ignore other codecs
    --end

    -- Now record the samples to the buffer
    len = #event.data
    print("  recording sample, len="..len)
    print("codec=",event.codec)
    print("data=",#event.data)
    voiceBuffer:pushright({codec=event.codec, data=event.data})
           
end)



-- Done with setup, lets enter the bots main loop
mumble.loop()
