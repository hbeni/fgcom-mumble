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


--[[        FGCom-mumble Recordings playback Bot

The purpose of this bot is to playback previously recorded samples into the
`fgcom-mumble` channel.
When playing back, it takes a fixed position on earth and sets up a virtual radio
station at this point. It is important that the sender has some altitude, because
especially VHF broadcasts are subject to range limits by line-of-sight.
This information is usually read from the FGCS-fileheader, but can also be
given on commandline, overriding the file header.

The specified sample is read into memory and then replayed. After every cycle,
the bot tests if the sample file is still there and valid.
The header and contents are reevalued.

The bot is depending on lua-mumble from  bkacjios (https://github.com/bkacjios/lua-mumble).
Installation of this plugin is described in the projects readme: https://github.com/bkacjios/lua-mumble/blob/master/README.md

]]

dofile("sharedFunctions.inc.lua")  -- include shared functions
local botname     = "FGCOM-radio-playback"
fgcom.callsign    = "FGCOM-RADIO"
local voiceBuffer = Queue:new()

-- Parse cmdline args
local host  = "localhost"
local port  = 64738
local cert  = "bot.pem"
local key   = "bot.key"
local path  = "./recordings"
local limit = 120     -- default time limit for recordings in secs


if arg[1] then
    if arg[1]=="-h" or arg[1]=="--help" then
        print(botname)
        print("usage: "..arg[0].." [opt=val ...]")
        print("  opts:")
        print("    --host=    host to coennct to               (default="..host..")")
        print("    --port=    port to connect to               (default="..port..")")
        print("    --cert=    path to PEM encoded cert         (default="..cert..")")
        print("    --key=     path to the certs key            (default="..key..")")
        print("    --path=    Path to store the recordings to  (default="..path..")")
        print("    --limit=   Max limit to record, in seconds  (default="..limit..")")
        os.exit(0)
    end
    
    for _, opt in ipairs(arg) do
        _, _, k, v = string.find(arg[1], "--(%w+)=(.+)")
        --print("KEY='"..k.."'; VAL='"..v.."'")
        if k=="host"  then host=v end
        if k=="port"  then port=v end
        if k=="cert"  then cert=v end
        if k=="key"   then key=v end
        if k=="path"  then path=v end
        if k=="limit" then limit=v end
    end
    
end

-- Check target dir:
-- try to create and delete a file at path, so we check if its there and writabl
local tdir = io.open(path.."/hello", "wb")
if tdir then
    tf=tdir:write("ok")
    if not tf then
        print("unable to write into recording dir: "..path)
        os.exit(1)
    else
        io.close(tdir)
        os.remove(path.."/hello")
    end
else
    print("unable to open recording dir: "..path)
    os.exit(1)
end


-- Connect to server, so we get the API
print(botname..": connecting to "..host.." on port "..port.." (cert: "..cert.."; key: "..key..")")
local client = assert(mumble.connect(host, port, cert, key))
client:auth(botname)
print("connect and bind: OK")


 
