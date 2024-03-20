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

--[[       Some shared functionality for the FGCom lua bots     ]]

-- lua-mumble from  bkacjios (https://github.com/bkacjios/lua-mumble).
-- (needs the shared object in your lua installation; instructions see lua-mumble project)
mumble = require("mumble")

local bit = require("bit") -- bit manipulation libraray implementation

fgcom_clients = {}      -- known clients from fgcom-mumble plugin broadcasts

-- A simple queue implementation, taken and adapted from https://www.lua.org/pil/11.4.html
Queue = {}
function Queue:new (o)
    o = o or {}   -- create object if user does not provide one
    o.first = 0
    o.last = -1
    setmetatable(o, self)
    self.__index = self
    return o
end
function Queue:pushleft (value)
    local first = self.first - 1
    self.first = first
    self[first] = value
end
function Queue:pushright (value)
    local last = self.last + 1
    self.last = last
    self[last] = value
end
function Queue:popleft ()
    local first = self.first
    if first > self.last then return nil end
    local value = self[first]
    self[first] = nil        -- to allow garbage collection
    self.first = first + 1
    return value
end
function Queue:popright ()
    local last = self.last
    if self.first > last then return nil end
    local value = self[last]
    self[last] = nil         -- to allow garbage collection
    self.last = last - 1
    return value
end
function Queue:size ()
    size = self.last - self.first + 1
    if size < 0 then return 0 end
    return size
end

-- math average implementation, in case lua runtime does not have one
if not math.average then
    math.average = function(arr)
        local sum = 0
        for _, x in ipairs(arr) do
            sum = sum + x
        end
        return sum / #(arr)
    end
end

-- FGCom functions
fgcom = {
    botversion = "unknown",
    libversion = "1.8.0",
    gitver     = "",   -- will be set from makefile when bundling
    channel    = "fgcom-mumble",
    callsign   = "FGCOM-someUnknownBot",
    
    -- return version string
    getVersion = function()
        local gv = ""
        if fgcom.gitver ~= "" then gv = " (git "..fgcom.gitver..")" end
        return "bot v"..fgcom.botversion.." / func v"..fgcom.libversion..gv
    end,
    
    -- Log / debug log
    debugMode = false,
    dbg = function(s)
        if fgcom.debugMode then print(os.date("%Y-%m-%d %X [DBG] ")..s) end
    end,
    log = function(s)
        print(os.date("%Y-%m-%d %X [LOG] ")..s)
    end,
    
    
    rng={
        -- initialize random number generator
        initialize = function()
            local devrandom = io.open('/dev/random', 'rb')
            if devrandom then
                local res = 0;
                for f = 1, 4 do res = res*256+(devrandom:read(1)):byte(1, 1); end;
                devrandom:close();
                math.randomseed(res+1);
            else
                fgcom.log("Notice: unable to open /dev/random, falling back to time()")
                math.randomseed(os.time())
            end
        end,

        -- generate random string
        randStr = function(length, chars)
            if not chars then chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-={}|[]`~' end

            local randomString = ''
            math.randomseed(os.time())

            charTable = {}
            for c in chars:gmatch"." do
                table.insert(charTable, c)
            end

            for i = 1, length do
                randomString = randomString .. charTable[math.random(1, #charTable)]
            end

            return randomString
         end,
    },
    
    -- io provides some basic IO functions
    --   writeShort/readShort/playrecording was written from bkacjios: https://github.com/bkacjios/lua-mumble/issues/12
    io={
        
        -- Read and parse FGCS header
        -- | Line | Content                                |
        -- |------|----------------------------------------|
        -- |   1  | Version and Type field: "1.1 FGCS"     |
        -- |   2  | Callsign                               |
        -- |   3  | LAT          (decimal)                 |
        -- |   4  | LON          (decimal)                 |
        -- |   5  | HGT          (altitude in meter AGL)   |
        -- |   6  | Frequency    (real wave carrier)       |
        -- |   7  | Dialed Frequency                       |
        -- |   8  | TX-Power     (in Watts)                |
        -- |   9  | PlaybackType (`oneshot` or `loop`)     |
        -- |  10  | TimeToLive   (seconds; `0`=persistent) |
        -- |  11  | RecTimestamp (unix timestamp)          |
        -- |  12  | VoiceCodec   (`int` from lua-mumble)   |
        -- |  13  | SampleSpeed  (seconds between samples) |
        --
        -- @param fh filehandle to read from
        -- @return table with the header data or false on error
        readFGCSHeader = function(fh)
            local header = {}
            header.version      = fh:read("*line")
            header.callsign     = fh:read("*line")
            header.lat          = fh:read("*line")
            header.lon          = fh:read("*line")
            header.height       = fh:read("*line")
            header.frequency    = fh:read("*line")
            header.dialedFRQ    = fh:read("*line")
            header.txpower      = fh:read("*line")
            header.playbacktype = fh:read("*line")
            header.timetolive   = fh:read("*line")
            header.timestamp    = fh:read("*line")
            header.voicecodec   = fh:read("*line")
            header.samplespeed  = fh:read("*line")
            if not header.version then return false end
            _, _, ver, const = string.find(header.version, "(%d%.%d+) FGCS")
            if not ver then return false end
            if not header.version:find("1.1 FGCS") then fgcom.log("ERROR: Incompatible FGCS version: "..ver) return false end
            -- TODO: better header checks
            
            return header
        end,
        
        -- Write a FGCS header
        -- @param fh filehandle to write to
        -- @param header table with the header data, as returned from readFGCSHeader()
        -- @return boolean showing success or failure
        writeFGCSHeader = function(fh, header)
            if fh and header.version:find("1.1 FGCS") then
                fh:write(header.version.."\n")
                fh:write(header.callsign.."\n")
                fh:write(header.lat.."\n")
                fh:write(header.lon.."\n")
                fh:write(header.height.."\n")
                fh:write(header.frequency.."\n")
                fh:write(header.dialedFRQ.."\n")
                fh:write(header.txpower.."\n")
                fh:write(header.playbacktype.."\n")
                fh:write(header.timetolive.."\n")
                fh:write(header.timestamp.."\n")
                fh:write(header.voicecodec.."\n")
                fh:write(header.samplespeed.."\n")
                return true
            else
                fgcom.log("ERROR: Incompatible FGCS version: "..header.version)
                return false
            end
        end,
        
        -- Read a sample from a FGCS file.
        -- must be called after retrieving header.
        -- len is 0 if no data could be read.
        -- On the last valid data read, eof will be true to signal that the next read will contian no more data
        -- @param fh filehandle to read from
        -- @return table: {len=<bytes>, data=<data>, eof=<bool>}
        readFGCSSample = function(fh)
            local sample = {len = 0, data = "", eof=true}  -- default: signal EOF
        
            -- first read two bytes, thats a short vlaue designating how much data to read
            local short = fh:read(2) -- Read two characters from the file
            if not short or short == "" then return sample end -- End of file
            local b1, b2 = string.byte(short, 1, 2) -- Convert the two characters to bytes
            if nil==b1 or nil==b2 then return sample end -- premature End of file or error parsing
            sample.len = bit.bor(bit.lshift(b1, 8), bit.lshift(b2, 0)) -- Combine the two bytes into a number
            sample.data = fh:read(sample.len) -- read data
            
            -- see if we are at the end of the file
            local cp    = fh:seek()      -- get current position
            local cp_fs = fh:seek("end") -- filesize
            if cp == cp_fs then sample.eof = true else sample.eof = false end
            fh:seek("set", cp)        -- restore position
            
            return sample
        end,
        
        -- Write a sample to a FGCS file.
        -- must be called after writing header.
        -- @param fh filehandle to write to
        -- @param s binary sample data
        writeFGCSSample = function(fh, s)
            -- write sampe length so we later know how much data to read
            local len = #s
            -- Convert our 16 bit number into two bytes
            local b1 = bit.band(bit.rshift(len, 8), 0xFF)
            local b2 = bit.band(len, 0xFF)
            fh:write(string.char(b1, b2))   -- write two bytes to fh
            fh:write(s) -- write the entire sample data
        end,
        
    },
    
    -- Data handling functions
    data={
        
        -- Return remainig validity time
        -- File is outdated if result is negative
        -- @param header FGCS header table
        -- @return boolean if it is valid
        getFGCSremainingValidity = function(header)
            return header.timestamp+header.timetolive-os.time()
        end,
        
        -- single char string splitter, sep *must* be a single char pattern
        -- *probably* escaped with % if it has any special pattern meaning, eg "%." not "."
        -- so good for splitting paths on "/" or "%." which is a common need
        -- taken from http://lua-users.org/wiki/SplitJoin
        csplit = function (str,sep)
            local ret={}
            local n=1
            for w in str:gmatch("([^"..sep.."]*)") do
                ret[n] = ret[n] or w -- only set once (so the blank after a string is ignored)
                if w=="" then
                    n = n + 1
                end -- step forwards on a blank but not a string
            end
            return ret
        end,
          
        -- Parse incoming plugin data and populate fgcom_clients array with it
        -- @param string dataID mumble dataID
        -- @param string data payload
        -- @param mumble.user sender of the data
        parsePluginData = function(dataID, data, sender)
            if dataID:len() > 0 and dataID:find("FGCOM:") then
                fgcom.dbg("Received FGCOM-plugin data, dataID='"..dataID.."', from=["..sender:getSession().."] '"..sender:getName().."'")
                fgcom.dbg("  data='"..data.."'")
          
                -- split the dataid into fields
                local dataID_t = fgcom.data.csplit(dataID, ":")
                local datatype = dataID_t[1] -- should always be "FGCOM"
                local packtype = dataID_t[2] -- UPD_LOC, etc
                local iid = "0"              -- default identity iid
                fgcom.dbg("  datatype='"..datatype.."'")
                fgcom.dbg("  packtype='"..packtype.."'")

                if packtype == "UPD_USR" or packtype == "UPD_LOC" or packtype == "UPD_COM" then
                    local iid = dataID_t[3]          -- identity selector
                    local sid = sender:getSession()  -- mumble session id
                    fgcom.dbg("  iid='"..iid.."'")

                    -- check if we already have state for this client; if not add
                    if not fgcom_clients[sid] then
                        fgcom_clients[sid] = {}
                        fgcom.dbg("added new client state: "..sid)
                    end
          
                    -- check if we already know this clients identity with given iid; if not, add template
                    if fgcom_clients[sid][iid] then
                        if fgcom.hooks.parsePluginData_updateKnownClient ~= nil then fgcom.hooks.parsePluginData_updateKnownClient(sid, iid) end
                    else
                        fgcom_clients[sid][iid] = {
                            callsign="",
                            lat="",
                            lon="",
                            alt="",
                            radios={},
                            lastUpdate=0
                        }
                        if fgcom.hooks.parsePluginData_newClient ~= nil then fgcom.hooks.parsePluginData_newClient(sid, iid) end
                    end
          
                    -- record that we had an data update
                    fgcom_clients[sid][iid].lastUpdate = os.time()
            
                    -- OK, go ahead and try to parse;
                    -- we are interested in the callsign and the location.
                    -- For proper recording, also the PTT state is important to us.
                    -- for token in string.gmatch(data, ",") do
                    for index,token in ipairs(fgcom.data.csplit(data, ",")) do
                        field = fgcom.data.csplit(token, "=")
                        if #field == 2 then
                            fgcom.dbg("parsing field: "..field[1].."="..field[2])

                            -- Udpates to location/user state
                            if packtype == "UPD_LOC" or packtype == "UPD_USR" then
                                if "CALLSIGN" == field[1] then fgcom_clients[sid][iid].callsign = field[2] end
                                if "LAT" == field[1] then fgcom_clients[sid][iid].lat = field[2] end
                                if "LON" == field[1] then fgcom_clients[sid][iid].lon = field[2] end
                                if "ALT" == field[1] then fgcom_clients[sid][iid].alt = field[2] end
                            end
                            
                            -- Updates to radios
                            if packtype == "UPD_COM" then
                                -- the dataID says, which radio to update (starting at zero)
                                radioID = dataID_t[4]
                                fgcom.dbg("  radioID='"..radioID.."'")
                                if not fgcom_clients[sid][iid].radios[radioID] then
                                    -- if radio unknown yet, add template
                                    fgcom_clients[sid][iid].radios[radioID] = {
                                        frequency = "",
                                        dialedFRQ = "",
                                        ptt = 0,
                                        power = 10,
                                        pbt   = 1,
                                        vlt   = 12,
                                        srv   = 1,
                                        operable = 1,
                                        -- todo: more needed?
                                    }
                                end
                                
                                if "FRQ" == field[1] then fgcom_clients[sid][iid].radios[radioID].frequency = field[2] end
                                if "CHN" == field[1] then fgcom_clients[sid][iid].radios[radioID].dialedFRQ = field[2] end
                                if "PTT" == field[1] then fgcom_clients[sid][iid].radios[radioID].ptt = field[2] end
                                if "PWR" == field[1] then fgcom_clients[sid][iid].radios[radioID].power = field[2] end
                                if "OPR" == field[1] then fgcom_clients[sid][iid].radios[radioID].operable = field[2] end
                            end
                        else
                            fgcom.dbg("parsing field failed! "..#field.." tokens seen")
                        end
                    end
                    
                    if fgcom.hooks.parsePluginData_afterParseIID ~= nil then fgcom.hooks.parsePluginData_afterParseIID(sid, iid) end
          
                elseif packtype == "PING" then
                    -- update the contained identites lastUpdate timestamps
                    local sid       = sender:getSession()  -- mumble session id
                    for _,iid in ipairs(fgcom.data.csplit(data, ",")) do
                        fgcom.dbg("ping packet for sid="..sid.."; iid="..iid)
                        if fgcom_clients[sid][iid] then 
                            fgcom_clients[sid][iid].lastUpdate = os.time()
                        end
                        
                        if fgcom.hooks.parsePluginData_afterParseIID ~= nil then fgcom.hooks.parsePluginData_afterParseIID(sid, iid) end
                    end
          
                elseif packtype == "ICANHAZDATAPLZ" then
                    -- ignore for now
                end
                
                fgcom.dbg("Packet fully processed.")
                if fgcom.hooks.parsePluginData_processedPacket ~= nil then fgcom.hooks.parsePluginData_processedPacket(sender, packtype, dataID_t) end
            end
            
            fgcom.dbg("Parsing done. New remote state:")
            for uid,remote_client in pairs(fgcom_clients) do
                for iid,idty in pairs(remote_client) do
                    for k,v in pairs(idty) do
                        --print(uid, k, v)
                        if k=="radios" then
                            for radio_id,radio in pairs(idty.radios) do
                                fgcom.dbg("sid="..uid.."; idty="..iid.."    radio #"..radio_id.." frequency='"..radio.frequency.."'")
                                fgcom.dbg("sid="..uid.."; idty="..iid.."    radio #"..radio_id.." dialedFRQ='"..radio.dialedFRQ.."'")
                                fgcom.dbg("sid="..uid.."; idty="..iid.."    radio #"..radio_id.."       ptt='"..radio.ptt.."'")
                                fgcom.dbg("sid="..uid.."; idty="..iid.."    radio #"..radio_id.."       pwr='"..radio.power.."'")
                                fgcom.dbg("sid="..uid.."; idty="..iid.."    radio #"..radio_id.."       opr='"..radio.operable.."'")
                            end
                        elseif k == "lastUpdate" then
                            local last_updated_since = os.time() - v
                            fgcom.dbg("sid="..uid.."; idty="..iid.."\t"..k..":\t"..tostring(v).." ("..last_updated_since.."s ago)")
                        else
                            fgcom.dbg("sid="..uid.."; idty="..iid.."\t"..k..":\t"..tostring(v))
                        end
                    end
                end
            end
            fgcom.dbg("-----------")
        end,
          
        -- Clean up fgcom_clients array from stale entries
        -- fgcom.data.cleanupTimeout variable holds the timeout in seconds
        cleanupTimeout = 30,  -- timeout in seconds
        cleanupPluginData = function()
            for uid,remote_client in pairs(fgcom_clients) do
                for iid,idty in pairs(remote_client) do
                    local stale_since = os.time() - idty.lastUpdate
                    if stale_since > fgcom.data.cleanupTimeout then
                        fgcom.dbg("cleanup remote data: sid="..uid.."; idty="..iid.."  stale_since="..stale_since)
                        local process = true
                        if fgcom.hooks.cleanupPluginData_entry ~= nil then process=fgcom.hooks.cleanupPluginData_entry(uid, iid) end
                        
                        if process then fgcom_clients[uid][iid] = nil end
                    end
                end
            end
        end
    },

    -- Bot chat admin authentication
    -- Requires established and synced connection to the server
    auth = {
        authedUsers = {},  -- holds authenticated users from which we accept chat commands
        authToken   = nil,  -- random string needed to add oneself to the authed users

        -- Establish the admin Token for auth.
        -- If user was given, inform the user about it and authenticate him
        generateToken = function(user)
            local chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
            if not fgcom.auth.authToken then fgcom.auth.authToken = fgcom.rng.randStr(32, chars) end
            fgcom.log(fgcom.callsign..": Admin authToken: "..fgcom.auth.authToken)
            if user then
                table.insert(fgcom.auth.authedUsers, user)
                user:message("This is my admin authToken, in case you want to let others manage me"
                             .." (<i>You</i> are already authenticated)."
                             .."<td style=\"border:1px solid black;\"><tt>"..fgcom.auth.authToken.."</tt></td>")
            end
        end,

        -- check if the user is authenticated
        -- returns true/false if authenticated
        isAuthenticated = function(user)
            local isauthenticated = false
            if user then
                for key,value in ipairs(fgcom.auth.authedUsers) do
                    if value == user then isauthenticated = true break end
                end
            end
            return isauthenticated
        end,

        -- handle authentication
        -- registers user as authenticated if the optionally supplied token matches
        -- returns true/false if authenticated
        handleAuthentication = function(user, token)
            if token then
                if not fgcom.auth.isAuthenticated(user) then
                    fgcom.dbg("auth token given, trying it")
                    if token and fgcom.auth.authToken and token == fgcom.auth.authToken then
                        table.insert(fgcom.auth.authedUsers, user)
                        fgcom.log("successfully authenticated user "..user:getName().." (session="..user:getSession()..")")
                        user:message("successfully authenticated")
                    else
                        fgcom.dbg("auth token failed for "..user:getName().." (session="..user:getSession()..")")
                    end
                else
                    fgcom.dbg("auth token given, but user is already authenticated: "..user:getName().." (session="..user:getSession()..")")
                    user:message("already authenticated")
                end
            end
            return fgcom.auth.isAuthenticated(user)
        end,
    },
    
    -- Various hooks, bots can implement to have event based adjustment options.
    -- If they are not defined, they will not be called.
    hooks = {
        -- parsePluginData_afterParseIID(sid, iid)
        --   called when parsePluginData() received data for a given iid
        
        -- fgcom.hooks.parsePluginData_newClient(sid, iid)
        --   called when parsePluginData() detected that the client was not seen before.
        --   is called before any datas is parsed/added.
        
        -- fgcom.hooks.parsePluginData_updateKnownClient(sid, iid)
        --   called when parsePluginData() detected that the client was known.
        --   is called before any datas is parsed/updated.
        
        -- fgcom.hooks.parsePluginData_processedPacket(mumble_user, packtype, dataID_t)
        --   called after processing the packet, passing raw data
        
        -- fgcom.hooks.cleanupPluginData_entry(sid, iid)
        --   called when cleaning up an entry. return false to prevent the entry to be cleaned out.
    }
}
    

