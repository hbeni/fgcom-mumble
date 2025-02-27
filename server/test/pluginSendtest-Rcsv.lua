mumble = require("mumble")  -- get the mumble API

local host = "localhost"
local port = 64738
local channel = "fgcom-mumble"
local cert = "bot.pem"
local key  = "bot.key"

-- Parse cmdline args
if arg[1] then
    if arg[1]=="-h" or arg[1]=="--help" then
        print(botname)
        print("usage: "..arg[0].." [opt=val ...]")
        print("  Options:")
        print("    --host=    host to connect to           (default="..host..")")
        print("    --port=    port to connect to           (default="..port..")")
        print("    --channel= channel to join                  (default="..channel..")")
        print("    --cert=    path to PEM encoded cert     (default="..cert..")")
        print("    --key=     path to the certs key        (default="..key..")")
        os.exit(0)
    end
    
    for _, opt in ipairs(arg) do
        _, _, k, v = string.find(opt, "--(%w+)=(.+)")
        if k=="host"    then host=v end
        if k=="port"    then port=v end
        if k=="channel"   then channel=v end
        if k=="cert"    then cert=v end
        if k=="key"     then key=v end
    end
    
end



print("connecting to "..host.." on port "..port.." (cert: "..cert.."; key: "..key.."), joining: '"..channel.."'")
local client = mumble.client()
client:hook("OnConnect", function(client)
    client:auth("test-rcv")
    print("connect and bind: OK")
end)
assert(client:connect(host, port, cert, key))


client:hook("OnServerSync", function(client, event)
    print("Sync done; server greeted with: ", event.welcome_text)
           
    -- try to join fgcom-mumble channel
    local ch = client:getChannel(channel)
    event.user:move(ch)
    print("joined channel "..ch:getName())

    -- Ask present clients for data
    client:sendPluginData("FGCOM:ICANHAZDATAPLZ", "orly!", ch:getUsers())
end)
    
    

client:hook("OnPluginData", function(client, event)
    --["sender"] = mumble.user sender, -- Who sent this data packet
	--["id"]     = Number id,          -- The data ID of this packet
	--["data"]   = String data,        -- The data sent (can be binary data)
	--["receivers"]				= {  -- A table of who is receiving this data
	--	[1] = mumble.user,
	--},
    print("DATA INCOMING FROM="..event.sender:getSession())
    print("  ID="..event.id)
    print("  DATA="..event.data)

end)

mumble.loop()
