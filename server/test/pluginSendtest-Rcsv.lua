mumble = require("mumble")  -- get the mumble API

local host = "localhost"
local port = 64738
local cert = "bot.pem"
local key  = "bot.key"

print("connecting to "..host.." on port "..port.." (cert: "..cert.."; key: "..key..")")
local client = assert(mumble.connect(host, port, cert, key))
client:auth("test-rcv")
print("  connect and bind: OK")


client:hook("OnServerSync", function(client, event)
    print("Sync done; server greeted with: ", event.welcome_text)
           
    -- try to join fgcom-mumble channel
    local ch = client:getChannel("fgcom-mumble")
    event.user:move(ch)
    print("joined channel fgcom-mumble")
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
