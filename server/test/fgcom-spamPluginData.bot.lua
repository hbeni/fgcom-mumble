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


--[[        FGCom-mumble fake plugindata spam bot

The bot connects and then spams FGCOM location update messages.
This is to generate load on the plugin-io interface and thus network.


The bot is depending on lua-mumble from  bkacjios (https://github.com/bkacjios/lua-mumble).
Installation of this plugin is described in the projects readme: https://github.com/bkacjios/lua-mumble/blob/master/README.md

]]
dofile("sharedFunctions.inc.lua")  -- include shared functions

playback_targets = {} -- global targets for send

-- init random generator using /dev/random, if poosible (=linux)
fgcom.rng.initialize()

--print(math.random(-150, 150)/100 + math.random(-100000, 100000)/100000)  os.exit(1)
--print(math.random(-100, 100)/100000) os.exit(1)
local botid   = ""
local botname = "FGCOM-pluginspam"

local locs = 0.5  -- seconds between location updates


-- Parse cmdline args
local host   = "localhost"
local port   = 64738
local cert   = "bot.pem"
local key    = "bot.key"

if arg[1] then
    if arg[1]=="-h" or arg[1]=="--help" then
        print(botname)
        print("usage: "..arg[0].." [opt=val ...]")
        print("  Options:")
        print("    --id=      id to join with              (default=random)")
        print("    --host=    host to connect to           (default="..host..")")
        print("    --port=    port to connect to           (default="..port..")")
        print("    --cert=    path to PEM encoded cert     (default="..cert..")")
        print("    --key=     path to the certs key        (default="..key..")")
        print("    --locs=    Seconds between location updates (default="..locs..")")
        os.exit(0)
    end
    
    for _, opt in ipairs(arg) do
        _, _, k, v = string.find(opt, "--(%w+)=(.+)")
        if k=="id"      then botid=v end
        if k=="host"    then host=v end
        if k=="port"    then port=v end
        if k=="cert"    then cert=v end
        if k=="key"     then key=v end
        if k=="locs"    then locs=v end
    end
    
end

-- parameter checks
--if sample == "" then print("parameter --sample is mandatory!") os.exit(1) end

fgcom.callsign = "FGCOM-PLUGINSPAM-"
if botid == "" then
    fgcom.callsign = fgcom.callsign..math.random(1, 99999)
else
    fgcom.callsign = fgcom.callsign..botid
end




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


-- timer loop for sending
local locUpd     = mumble.timer()
local checkTimer = mumble.timer()
local lat   = math.random(-150, 150)/100 + math.random(-100000, 100000)/100000
local lon   = math.random(-150, 150)/100 + math.random(-100000, 100000)/100000
local alt   = math.random(15, 8000)
local latmv = math.random(-100, 100)/100000
local lonmv = math.random(-100, 100)/100000
updateLocData = function(t)
    --print("locUpd: tick")
    -- update current users of channel
    updateAllChannelUsersforSend(client)
    if #playback_targets > 0 then
        -- Setup the Bots location on earth
        lat = lat + latmv
        lon = lon + lonmv
        alt = alt + math.random(-50, 50)
        local msg = ",LON="..lat
                  ..",LAT="..lon
                  ..",ALT="..alt
        --print("Bot sets location: "..msg)
        client:sendPluginData("FGCOM:UPD_LOC", msg, playback_targets)
    end
end


client:hook("OnServerSync", function(event)
    print("Sync done; server greeted with: ", event.welcome_text)
    
    -- try to join fgcom-mumble channel
    local ch = client:getChannel(fgcom.channel)
    event.user:move(ch)
    print(fgcom.callsign.." joined channel "..fgcom.channel)
    
    updateAllChannelUsersforSend(client)
    local msg = "CALLSIGN="..fgcom.callsign
    client:sendPluginData("FGCOM:UPD_USR", msg, playback_targets)
           
    -- update location       
    locUpd:start(updateLocData, 0.00, locs)
   
end)



mumble.loop()
print(botname.." with callsign "..fgcom.callsign.." completed.")
