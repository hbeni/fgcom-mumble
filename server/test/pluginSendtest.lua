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
        print("    --channel= channel to join                  (default="..fgcom.channel..")")
        print("    --cert=    path to PEM encoded cert     (default="..cert..")")
        print("    --key=     path to the certs key        (default="..key..")")
        os.exit(0)
    end
    
    for _, opt in ipairs(arg) do
        _, _, k, v = string.find(opt, "--(%w+)=(.+)")
        if k=="host"    then host=v end
        if k=="port"    then port=v end
        if k=="channel"   then fgcom.channel=v end
        if k=="cert"    then cert=v end
        if k=="key"     then key=v end
    end
    
end



print("connecting to "..host.." on port "..port.." (cert: "..cert.."; key: "..key..")")
local client = assert(mumble.connect(host, port, cert, key))
client:auth("test-send")
print("  connect and bind: OK")

local timer = mumble.timer()
client:hook("OnServerSync", function(client, event)
    print("Sync done; server greeted with: ", event.welcome_text)
           
    -- try to join fgcom-mumble channel
    local ch = client:getChannel(channel)
    event.user:move(ch)
    print("joined channel "..channel)
    
    o=0
    timer:start(function(t)
	    o=o+1
        print(o..": send plugin message to all users ")
        users = ch:getUsers()
        u_tbl = {}
        i = 0
        for s,u in pairs(users) do
            i=i+1
            print("  "..i.." ("..s.."): "..u:getName())
            --not advisable: client:sendPluginData("FGCOM:UPD_USR:0", "CALLSIGN=test-"..i, u)
            table.insert(u_tbl, u)
        end
            
        client:sendPluginData("FGCOM:UPD_USR:0", "CALLSIGN=test-"..i, u_tbl)
        client:sendPluginData("FGCOM:UPD_COM:0:0", "FRQ=123,PTT=0"..i, users)
        
    end, 1, 1)

    print("send ok")
end)

client:hook("OnPluginData", function(client, event)
    --["sender"] = mumble.user sender, -- Who sent this data packet
	--["id"]     = Number id,          -- The data ID of this packet
	--["data"]   = String data,        -- The data sent (can be binary data)
	--["receivers"]				= {  -- A table of who is receiving this data
	--	[1] = mumble.user,
	--},

    --print("DATA INCOMING FROM="..event.sender:getSession())
    --print("  ID="..event.id)
    --print("  DATA="..event.data)

    -- Answer data requests
    if event.id:len() > 0 and event.id:find("FGCOM:ICANHAZDATAPLZ") then
        print("OnPluginData(): client asks for data: "..tostring(event.sender))
        event.sender:sendPluginData("FGCOM:TESTREPLY:0", "1234567890")
    end

end)

mumble.loop()
