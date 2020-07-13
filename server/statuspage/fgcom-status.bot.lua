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


--[[        FGCom-mumble Statuspage Bot

The purpose of this bot is to monitor `fgcom-mumble` channel traffic and
write the data periodically to a database. This database can then be read from the
status page implementation.

The bot approach is currently needed, because the status page has no access to the plugin
data via ICE bus. One approach for the future might be to let the plugins set specially formatted
client comment data which can be parsed from the statuspage.
Currently however this is a good approach, because it allows separation of services (only the
bot and the statuspage need to be on the same machine or share the db file over network)
and also because the statuspage can be really fast, avoiding the danger of overloading the
mumble backend with excessive requests.


The bot is depending on lua-mumble from  bkacjios (https://github.com/bkacjios/lua-mumble).
Installation of this plugin is described in the projects readme: https://github.com/bkacjios/lua-mumble/blob/master/README.md

]]

dofile("sharedFunctions.inc.lua")  -- include shared functions
json = require("json")
local botname     = "FGCOM-Status"
fgcom.callsign    = "FGCOM-Status"

-- Parse cmdline args
local host  = "localhost"
local port  = 64738
local cert  = "statusbot.pem"
local key   = "statusbot.key"
local db    = "/tmp/fgcom-web.db"
local speed = 5  -- update interval in seconds
local weburl = "";


if arg[1] then
    if arg[1]=="-h" or arg[1]=="--help" then
        print(botname)
        print("usage: "..arg[0].." [opt=val ...]")
        print("  Options:")
        print("    --host=    host to connect to               (default="..host..")")
        print("    --port=    port to connect to               (default="..port..")")
        print("    --cert=    path to PEM encoded cert         (default="..cert..")")
        print("    --key=     path to the certs key            (default="..key..")")
        print("    --db=      Path to the db                   (default="..db..")")
        print("    --speed=   update interval in seconds       (default="..speed..")")
        print("    --web=     Advertise url in comment         (default=no commercials!)")
        os.exit(0)
    end
    
    for _, opt in ipairs(arg) do
        _, _, k, v = string.find(opt, "--(%w+)=(.+)")
        --print("KEY='"..k.."'; VAL='"..v.."'")
        if k=="host"      then host=v end
        if k=="port"      then port=v end
        if k=="cert"      then cert=v end
        if k=="key"       then key=v end
        if k=="db"        then db=v end
        if k=="speed"     then speed=v end
        if k=="web"       then weburl=v end
    end
    
end


-- Connect to server, so we get the API
print(botname..": connecting as '"..fgcom.callsign.."' to "..host.." on port "..port.." (cert: "..cert.."; key: "..key..")")
local client = assert(mumble.connect(host, port, cert, key))
client:auth(botname)
print("connect and bind: OK")


-- Generate JSON data data from state
--   Expected format is a JSON array representing one user record each:
--   {"type":"client",  "callsign":"Calls-1",   "freqencies":["123.456"],
--    "lat":12.3456, "lon":20.11111,  "alt":1234.45,  "updated":1111111122}
local generateOutData = function()
    local allUsers = client:getUsers()
    local data     = {}  -- final return array
    
    print("generateOutData(): number of known users: "..#fgcom_clients)
    for sid, user in pairs(fgcom_clients) do
        print("generateOutData(): processing user: "..sid)
        local userData = {}
        local mumbleUser = allUsers[sid]
        if not mumbleUser then
            print("User sid="..sid.." not connected anymore!")
            -- push out old data.
            userData.updated = fgcom_clients[sid].lastUpdate
            userData.type    = fgcom_clients[sid].type
            -- TODO: remove dataset from fgcom_clients after some timeout
        else 
            fgcom_clients[sid].lastUpdate = os.time()
            fgcom_clients[sid].type = "client"
            if mumbleUser:getName():find("FGCOM%-.*") then fgcom_clients[sid].type = "playback-bot" end
            userData.type = fgcom_clients[sid].type
        end
        
        userData.callsign = user.callsign
        
        userData.frequencies = {}
        for radio_id,radio in pairs(user.radios) do
            print("  check frequency: radio #"..radio_id..", ptt='"..radio.ptt.."', frq='"..radio.frequency.."'")
            if radio.frequency ~= "<del>" then
                table.insert(userData.frequencies, radio.frequency)
            end
        end
        userData.lat = user.lat
        userData.lon = user.lon
        userData.alt = user.alt
        userData.updated = fgcom_clients[sid].lastUpdate
        
        table.insert(data, userData)
    end
    
    dataJsonString = json.stringify(data)
    print("JSON RESULT", dataJsonString)
    return dataJsonString
end


-- function to get all channel users
-- this updates the global playback_target table
local playback_targets = nil -- holds updated list of all channel users
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


-- Timed loop to update the database
local dbUpdateTimer = mumble.timer()
dbUpdateTimer_func = function(t)
    print("Update db '"..db.."'")

    -- first, try to open a new temporary target file
    local tmpdb = db..".part";
    local tmpdb_fh = io.open(tmpdb, "wb")
    
    if tmpdb_fh then
        print("opened db '"..tmpdb.."'")
        -- tmpdb is open, write out the data
        local data = generateOutData()
        local writeRes = tmpdb_fh:write(data)
        if not writeRes then
            print("unable to write into db: "..tmpdb)
            -- lets try in next iteration  os.exit(1)
            io.close(tmpdb_fh)
        else
            -- write was okay
            print("wrote db '"..tmpdb.."'")
            tmpdb_fh:flush()
            io.close(tmpdb_fh)
            
            os.remove(db)
            ren_rc, ren_message = os.rename(tmpdb, db)
            -- TODO: handle errors
            print("published db '"..db.."'")
        end
        
    else
        print("ERROR: unable to open db: "..tmpdb)
        -- lets try again in the next iteration.... os.exit(1)
    end

end




-- Called when the bot successfully connected to the server
-- and has received all current channel and client data
client:hook("OnServerSync", function(event)
    print("Sync done; server greeted with: ", event.welcome_text)
    
    -- try to join fgcom-mumble channel
    local ch = client:getChannel(fgcom.channel)
    event.user:move(ch)
    print("joined channel "..fgcom.channel)
           
    -- Adjust comment
    if weburl:len() > 0 then
        print("Advetising web url: "..weburl)
        client:setComment("<b><i><u>FGCom:</u></i></b><br/>Visit the status page at:<br/>"
                      .."<a href=\""..weburl.."\">"..weburl.."</a>")
    end

    -- ask all already prsent lients for their data
    updateAllChannelUsersforSend(client)
    client:sendPluginData("FGCOM:ICANHAZDATAPLZ", "orly!", playback_targets)
           
    -- start update timer
    dbUpdateTimer:start(dbUpdateTimer_func, 0.0, speed)
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




mumble.loop()
