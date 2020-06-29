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
  2. Manage ATIS-playback bots. If ATIS messages have been recorded, the bot will spawn
     appropriate `radio-playback` bots serving the ATIS message.
]]
local botname = "FGOM-ATIS-manager";
local mumble = require("mumble")

-- Parse cmdline args
local host = "localhost"
local port = 64738
local cert = "bot.pem"
local key  = "bot.key"

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


-- Connect to server
print(botname..": connecting to "..host.." on port "..port.." (cert: "..cert.."; key: "..key..")")
local client = assert(mumble.connect(host, port, cert, key))
client:auth("FGOM-ATIS-manager")


mumble.loop()
