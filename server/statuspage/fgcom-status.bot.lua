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
The bot also can optionally create usage statistic data, usable for example by gnuplot.

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

dofile("fgcom-sharedFunctions.inc.lua")  -- include shared functions
fgcom.botversion = "1.8.3"
json = require("dkjson")
local botname     = "FGCOM-Status"
fgcom.callsign    = "FGCOM-Status"

-- Parse cmdline args
local host  = "localhost"
local port  = 64738
local cert  = "statusbot.pem"
local key   = "statusbot.key"
local db    = "/tmp/fgcom-web.db"
local speed = 5  -- update interval in seconds
local weburl = ""
local stats = ""
local speedStats = 60 -- write interval for statistic entries in seconds


if arg[1] then
    if arg[1]=="-h" or arg[1]=="--help" then
        print(botname..", "..fgcom.getVersion())
        print("usage: "..arg[0].." [opt=val ...]")
        print("  Options:")
        print("    --name=    Change Bot's name                (default="..botname..")")
        print("    --host=    host to connect to               (default="..host..")")
        print("    --port=    port to connect to               (default="..port..")")
        print("    --channel= channel to join                  (default="..fgcom.channel..")")
        print("    --cert=    path to PEM encoded cert         (default="..cert..")")
        print("    --key=     path to the certs key            (default="..key..")")
        print("    --db=      Path to the db                   (default="..db..")")
        print("    --speed=   db update interval               (seconds, default="..speed..")")
        print("    --web=     Advertise url in comment         (default=no commercials!)")
        print("    --stats=   append usage stats to this file  (default=no)")
        print("    --speedst= usage stats update interval      (seconds, default="..speedStats..")")
        print("    --debug    print debug messages             (default=no)")
        print("    --version  print version and exit")
        os.exit(0)
    end
    
    for _, opt in ipairs(arg) do
        _, _, k, v = string.find(opt, "--(%w+)=(.+)")
        --print("KEY='"..k.."'; VAL='"..v.."'")
        if k=="name"      then botname=v end
        if k=="host"      then host=v end
        if k=="port"      then port=v end
        if k=="channel"   then fgcom.channel=v end
        if k=="cert"      then cert=v end
        if k=="key"       then key=v end
        if k=="db"        then db=v end
        if k=="speed"     then speed=v end
        if k=="speedst"   then speedStats=v end
        if k=="web"       then weburl=v end
        if k=="stats"     then stats=v end
        if opt == "--debug" then fgcom.debugMode = true end
        if opt == "--version" then print(botname..", "..fgcom.getVersion()) os.exit(0) end
    end
    
end

-- Connect to server, so we get the API
fgcom.log(botname..": connecting as '"..fgcom.callsign.."' to "..host.." on port "..port.." (cert: "..cert.."; key: "..key.."), joining: '"..fgcom.channel.."'")
local client = assert(mumble.connect(host, port, cert, key))
client:auth(botname)
fgcom.log("connect and bind: OK")


-- Store for last highscore
--   date is a unix timestamp
local highscore = {num=0, date=0}
local hsdb_fh = io.open(db, "rb")
if hsdb_fh then
    fgcom.log("loading past highscore from db "..db)
    local hsdb_fhdbcontent = hsdb_fh:read("*all")
    local json_parse_res = json.decode(hsdb_fhdbcontent)
    hsdb_fhdbcontent = nil
    io.close(hsdb_fh)
    highscore.num  = json_parse_res.meta.highscore_clients
    highscore.date = json_parse_res.meta.highscore_date
    fgcom.log("  highscore: "..highscore.num.." clients at "..os.date('%Y-%m-%d %H:%M:%S', highscore.date).." ("..highscore.date..")")
end


-- Generate JSON data data from state
--   Expected format is a JSON array representing the data; in the "clients" member, one user record each:
--   {
--     "clients": [{"type":"client", "callsign":"Calls-1", "freqencies":["123.456"], "lat":12.3456, "lon":20.11111, "alt":1234.45, "updated":1111111122}, ...],
--     "meta": {"highscore_clients":12, "highscore_date":1599719381}
--   }
local generateOutData = function()
    local allUsers = {} -- sid=>mumbleUser table
    for i, mc in ipairs(client:getUsers()) do  allUsers[mc:getSession()] = mc  end
    local data     = {clients={}, meta={}}  -- final return array

    -- Record already processed entries (Issue #177)
    -- TODO: probably I''m just to dumb to properly use lua in the first place. So consider this a workaround.
    --       If you ever see this comment and think otherwise, let me know so I can remove this embarrassing bit of comment and/or code. :)
    local already_processed_clients = {}
    
    -- generate list of current users
    local users_alive = 0
    for sid, remote_client in pairs(fgcom_clients) do
        for iid,user in pairs(remote_client) do
            fgcom.dbg("generateOutData(): evaluating user: "..sid.." with idty="..iid)
            
            -- Skip, if already processed (Issue #177).
            -- I really have no Idea, why table entries are sometimes iterated more than once.
            local already_processed_clients_key = string.format("%s:%s", sid, iid)
            if already_processed_clients[already_processed_clients_key] ~= nil then
                fgcom.dbg("skipping entry '"..already_processed_clients_key.."'); already processed")
                
            else
                fgcom.dbg("processing entry '"..already_processed_clients_key.."'")
                already_processed_clients[already_processed_clients_key] = true
                
                
                -- prepare the return structure for generating the message
                local userData = {
                    callsign="",
                    type="invalid",
                    radios = {},
                    lat="",
                    lon="",
                    alt="",
                    updated=0
                }
                
                -- populate users metadata
                local mumbleUser = allUsers[sid]
                local last_updated_since = os.time() - fgcom_clients[sid][iid].lastUpdate
                if not mumbleUser then
                    fgcom.dbg("User sid="..sid.." not connected anymore!")
                    -- push out old data for a while;
                    -- fgcom.data.cleanupPluginData() (called from dbUpdateTimer) will clean up for us.
                    -- once that happened, we will not see the entry here anymore.
                else
                    if userData.type == "client" then  users_alive = users_alive + 1  end
                end
                userData.updated = fgcom_clients[sid][iid].lastUpdate
                fgcom.dbg("  updated="..userData.updated.. " ("..last_updated_since.."s ago)")
                
                -- populate users callsign
                userData.type     = fgcom_clients[sid][iid].type
                userData.callsign = user.callsign
                fgcom.dbg("  callsign="..userData.callsign.." (type="..userData.type..")")
                
                -- populate users radios
                for radio_id,radio in pairs(user.radios) do
                    fgcom.dbg("  radio #"..radio_id..", ptt='"..radio.ptt.."', frq='"..radio.frequency.."', dialedFRQ='"..radio.dialedFRQ.."', operable="..radio.operable)
                    if radio.frequency ~= "<del>" then
                        table.insert(userData.radios, radio_id, radio)
                    end
                end
                
                -- populate users location
                userData.lat = user.lat
                userData.lon = user.lon
                userData.alt = user.alt
                fgcom.dbg("  lat="..userData.lat.."; lon="..userData.lon.."; alt="..userData.alt)
                
                -- finally push the prepared data into the client result
                table.insert(data.clients, userData)
            end
        end
    end
    
    
    -- generate metadata
    fgcom.dbg("generateOutData(): generating highscore data...")
    if highscore.num < users_alive then
        highscore.num  = users_alive
        highscore.date = os.time()
        fgcom.log("new highscore: "..highscore.num.." clients at "..os.date('%Y-%m-%d %H:%M:%S', highscore.date).." ("..highscore.date..")")
    end
    data.meta.highscore_clients = highscore.num
    data.meta.highscore_date    = highscore.date
    
    
    -- generate JSON structure
    fgcom.dbg("generateOutData(): generating db content...")
    dataJsonString = json.encode(data)
    fgcom.dbg("JSON RESULT: "..dataJsonString)
    return dataJsonString
end


-- function to get all channel users
-- this updates the global playback_target table
local playback_targets = nil -- holds updated list of all channel users
updateAllChannelUsersforSend = function(cl)
    --fgcom.dbg("udpate channelusers")
    local ch = cl:getChannel(fgcom.channel)
    playback_targets = ch:getUsers()
end


-- Timed loop to update the database
local dbUpdateTimer = mumble.timer()
dbUpdateTimer_func = function(t)
    fgcom.dbg("Update db '"..db.."'")

    -- first, try to open a new temporary target file
    local tmpdb = db..".part";
    local tmpdb_fh = io.open(tmpdb, "wb")
    
    if tmpdb_fh then
        fgcom.dbg("opened db '"..tmpdb.."'")
        -- tmpdb is open, write out the data
        local data = generateOutData()
        fgcom.dbg("db data generating completed")
        local writeRes = tmpdb_fh:write(data)
        if not writeRes then
            fgcom.log("unable to write into db: "..tmpdb)
            -- lets try in next iteration  os.exit(1)
            io.close(tmpdb_fh)
        else
            -- write was okay
            fgcom.dbg("wrote db '"..tmpdb.."'")
            tmpdb_fh:flush()
            io.close(tmpdb_fh)
            
            os.remove(db)
            local ren_rc, ren_message = os.rename(tmpdb, db)
            if not ren_rc then
                fgcom.log("error publishing db: "..db)
            else
                fgcom.dbg("published db '"..db.."'")
            end
        end
        
        -- clean up stale entries
        fgcom.data.cleanupTimeout = 60  -- enhance timeout, so we can display them longer
        fgcom.data.cleanupPluginData()
        
    else
        fgcom.log("ERROR: unable to open db: "..tmpdb)
        -- lets try again in the next iteration.... os.exit(1)
    end

end


-- Timed loop to write usage statistics file
-- The data is intendet to be compatible to gnuplot: "<YYYYMMDDhhmmss> <clientcount> <playbacks>" for each line
local statsWriterTimer = mumble.timer()
statsWriterTimer_func = function(t)
    -- get the current alive number of users
    local allUsers = {} -- sid=>mumbleUser table
    for i, mc in ipairs(client:getUsers()) do  allUsers[mc:getSession()] = mc  end
    local users_alive      = 0
    local broadcasts_alive = 0
    for sid, remote_client in pairs(fgcom_clients) do
        for iid,user in pairs(remote_client) do
            local userData = {}   -- the return structure for generating the message
            local mumbleUser = allUsers[sid]
            if mumbleUser then
                -- client is still connected to mumble
                if fgcom_clients[sid][iid].type == "client" then
                    users_alive = users_alive + 1
                end
                if fgcom_clients[sid][iid].type == "playback-bot" then
                    broadcasts_alive = broadcasts_alive + 1
                end
            end
        end
    end


    local stats_fh = io.open(stats, "ab")
    assert(stats_fh, "unable to open stats file"..stats)
    fgcom.dbg("opened stats file '"..stats.."'")
    
    -- write the data
    --   starting the time format with "!" means UTC
    local statsData = os.date("!%Y%m%d%H%M%S").." "..users_alive.." "..broadcasts_alive.."\n"
    local writeRes  = stats_fh:write(statsData)
    if not writeRes then
        fgcom.log("unable to write into stats file: "..stats)
        -- lets try in next iteration  os.exit(1)
        io.close(stats_fh)
    else
        -- write was okay
        fgcom.dbg("wrote stats to '"..stats.."' ("..users_alive.." users)")
        stats_fh:flush()
        io.close(stats_fh)
    end
end


-- Called when the bot successfully connected to the server
-- and has received all current channel and client data
client:hook("OnServerSync", function(client, event)
    if (event.welcome_text == nil) then event.welcome_text = "-" end
    fgcom.log("Sync done; server greeted with: "..event.welcome_text)
    
    -- try to join fgcom-mumble channel
    local ch = client:getChannel(fgcom.channel)
    event.user:move(ch)
    fgcom.log("joined channel "..fgcom.channel)
           
    -- Adjust comment
    if weburl:len() > 0 then
        fgcom.log("Advetising web url: "..weburl)
        client:setComment("<b><i><u>FGCom:</u></i></b><br/>Visit the status page at:<br/>"
                      .."<a href=\""..weburl.."\">"..weburl.."</a>")
    end

    -- ask all already present clients for their data
    updateAllChannelUsersforSend(client)
    client:sendPluginData("FGCOM:ICANHAZDATAPLZ", "orly!", playback_targets)
           
    -- start update timer
    dbUpdateTimer:start(dbUpdateTimer_func, 0.0, speed)
    
    -- start statistics collection
    if stats:len() > 0 then
        fgcom.log("Writing statistics to: "..stats)
        statsWriterTimer:start(statsWriterTimer_func, 60, speedStats)
    end
end)


client:hook("OnPluginData", function(client, event)
    --["sender"] = mumble.user sender, -- Who sent this data packet
	--["id"]     = Number id,          -- The data ID of this packet
	--["data"]   = String data,        -- The data sent (can be binary data)
	--["receivers"]				= {  -- A table of who is receiving this data
	--	[1] = mumble.user,
	--},
    fgcom.dbg("DATA INCOMING FROM="..event.sender:getSession())

    fgcom.data.parsePluginData(event.id, event.data, event.sender)

end)


-- Chat admin interface
-- be sure to chat privately to the bot!
client:hook("OnMessage", function(client, event)
    -- ["actor"]    = mumble.user actor,
    -- ["message"]  = String message,
    -- ["users"]    = Table users,
    -- ["channels"] = Table channels - set when its no direct message

    if event.actor and not event.channels then  -- only process when it's a direct message to the bot
        event.message = event.message:gsub("%b<>", "")  -- strip html tags
        fgcom.dbg("message from actor: "..event.actor:getName().." (session="..event.actor:getSession()..")="..event.message)

        -- parse command
        local command = nil
        local param   = nil
        _, _, command = string.find(event.message, "^/(%w+)")
        _, _, param   = string.find(event.message, "^/%w+ (%w+)")
        if command then
            --print("DBG: parsed command: command="..command)
            --if param then print("DBG:   param="..param) end

            -- handle auth request
            if command == "auth" then
                if not param then event.actor:message("/auth needs a tokenstring as argument!") return end
                fgcom.auth.handleAuthentication(event.actor, param)
                return
           end

            if command == "help" then
                event.actor:message(botname..", "..fgcom.getVersion().." commands:"
                    .."<table>"
                    .."<tr><th style=\"text-align:left\"><tt>/help</tt></th><td>show this help.</td></tr>"
                    --.."<tr><th style=\"text-align:left\"><tt>/auth &lt;token&gt;</tt></th><td>Authenticate to be able to execute advanced commands.</td></tr>"
                    --.."<tr><th style=\"text-align:left\"><tt>/exit</tt></th><td>Terminate the bot.</td></tr>"
                    .."</table>"
                    .."<br>I do not obey to chat commands so far."
                )
                return
            end

            -- secure the following authenticated commands:
            if not fgcom.auth.handleAuthentication(event.actor) then
                fgcom.dbg("ignoring command, user not authenticated: "..event.actor:getName())
                return
            end

            -- no commands so far

        end
        
    end
end)


-- Implement fgcom hooks
fgcom.hooks.parsePluginData_updateKnownClient = function(sid, iid)
    -- called when parsePluginData() detected that the client was known.
    fgcom.dbg("fgcom.hooks.parsePluginData_updateKnownClient("..sid..","..iid..") called")
end

fgcom.hooks.parsePluginData_newClient = function(sid, iid)
    -- called when parsePluginData() detected that the client was not seen before.
    fgcom.dbg("fgcom.hooks.parsePluginData_newClient("..sid..","..iid..") called")
end

--fgcom.hooks.parsePluginData_afterParseIID = function(sid, iid)
--    -- called when parsePluginData() received data for a given iid
--    fgcom.dbg("fgcom.hooks.parsePluginData_afterParseIID("..sid..","..iid..") called")
--end

fgcom.hooks.parsePluginData_processedPacket = function(mumble_user, packtype, dataID_t)
    -- called after processing the packet, passing raw data
    fgcom.dbg("fgcom.hooks.parsePluginData_processedPacket("..packtype..") called")
    if packtype == "UPD_USR" then
        local iid = dataID_t[3]          -- identity selector
        local sid = mumble_user:getSession()  -- mumble session id
        
        -- Update type of client based on client name;
        -- We know, that bot clients use FGCOM- as prefix for their mumble username.
        local newType = "client" -- assume client as default
        if mumble_user:getName():find("FGCOM%-.*")         then newType = "playback-bot" end
        if mumble_user:getName():find("FGCOM%-BOTPILOT.*") then newType = "client" end
        
        if fgcom_clients[sid][iid].type ~= newType then
            fgcom.dbg("  update type to '"..newType.."'")
            fgcom_clients[sid][iid].type = newType
        end
    end
end




-- Finally start the bot
mumble.loop()
