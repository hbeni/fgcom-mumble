mumble = require("mumble")  -- get the mumble API

local host = "localhost"
local port = 64738
local cert = "bot.pem"
local key  = "bot.key"

print("connecting to "..host.." on port "..port.." (cert: "..cert.."; key: "..key..")")
local client = assert(mumble.connect(host, port, cert, key))
client:auth("test")
print("  connect and bind: OK")

local timer = mumble.timer()
client:hook("OnServerSync", function(event)
    print("Sync done; server greeted with: ", event.welcome_text)
           
    -- try to join fgcom-mumble channel
    local ch = client:getChannel("fgcom-mumble")
    event.user:move(ch)
    print("joined channel fgcom-mumble")
    
    o=0
    timer:start(function(t)
	    o=o+1
        print(o..": send plugin message to all users ")
        users = client:getUsers()
        i = 0
        for s,u in pairs(users) do
            i=i+1
            print("  "..i.." ("..s.."): "..u:getName())
            
            client:sendPluginData("FGCOM:UPD_USR:0", "CALLSIGN=test-"..i, {u})
            client:sendPluginData("FGCOM:UPD_COM:0:0", "FRQ=123,PTT=0"..i, users)
        end
    end, 1, 1)
    
    --segfault client:sendPluginData("FGCOM:UPD_LOC", "CALLSIGN=test", client:getUsers()) 

    print("send ok")
end)

mumble.loop()
