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


-- FGCom functions
fgcom = {
    channel  = "fgcom-mumble",
    callsign = "FGCOM-someUnknownBot",
    
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
                print ("Notice: unable to open /dev/random, falling back to time()")
                math.randomseed(os.time())
            end
        end
    },
    
    -- io provides some basic IO functions
    --   writeShort/readShort/playrecording was written from bkacjios: https://github.com/bkacjios/lua-mumble/issues/12
    io={
        
        -- Play a recorded OPUS sample file to the channel
        -- @param client mumble.client instance
        -- @param file path to the recored samples
        -- @param timer_rate how fast the packets are played - 0.02 should be fine in most cases; must comply to the data stream rate, otherwise voice is too fast/too slow
        playRecording = function(client, file, timer_rate)
            if not timer_rate then timer_rate=0.02 end
            
            local f = assert(io.open(file, "rb"))
            print("file "..file.." opened")

            local timer = mumble.timer()
            local deltimer = mumble.timer()
            print("timer initialized")

            local seq = 0
            timer:start(function(t)
                if f then
                    print("timer: read packet "..seq)
                    seq = seq+1
                    local len = fgcom.io.readShort(f)
                    if not len or len == "" then
                        print("timer: stop timer")
                        t:stop() -- Stop the audio timer
                        f:close()
                        return
                    end
                    print("timer:   header read ok, packet_len="..len)
                    local pcm = f:read(len)
                    
                    print("timer:   data read ok")

                    if not pcm or pcm == "" then
                        print("timer: stop timer")
                        t:stop() -- Stop the audio timer
                        f:close()
                        return
                    end

                    print("timer: encode and transmit")
            --        bitrate = encoder:getBitRate()
            --        print(" encoder encoding at "..bitrate)
                    --local encoded = encoder:encode_float(1, pcm) -- encode PCM packet to 1 opus frame
                    local encoded = pcm
                    print("timer:   encoded ok")
                    client:transmit(encoded) -- Transmit the single frame as an audio packet
                    print("timer:   transmit ok")
                end
            end, 0.00, timer_rate) -- Create a timer that will loop every 20ms - must correlate with the
            
            -- Delete the file after playing
            deltimer:start(function(dt)
                dt:stop()
                os.remove (file)
                print("file "..file.." closed and deleted")
                return
            end, 60, 0)
        end,
        
        -- Read and parse FGCS header
        -- | Line | Content                                |
        -- |------|----------------------------------------|
        -- |   1  | Version and Type field: "1.0 FGCS"     |
        -- |   2  | Callsign                               |
        -- |   3  | LAT          (decimal)                 |
        -- |   4  | LON          (decimal)                 |
        -- |   5  | HGT          (altitude in meter AGL)   |
        -- |   6  | Frequency                              |
        -- |   7  | TX-Power     (in Watts)                |
        -- |   8  | PlaybackType (`oneshot` or `loop`)     |
        -- |   9  | TimeToLive   (seconds; `0`=persistent) |
        -- |  10  | RecTimestamp (unix timestamp)          |
        -- |  11  | VoiceCodec   (`int` from lua-mumble)   |
        -- |  12  | SampleSpeed  (seconds between samples) |
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
            header.txpower      = fh:read("*line")
            header.playbacktype = fh:read("*line")
            header.timetolive   = fh:read("*line")
            header.timestamp    = fh:read("*line")
            header.voicecodec   = fh:read("*line")
            header.samplespeed  = fh:read("*line")
            if not header.version then return false end
            _, _, ver, const = string.find(header.version, "(%d%.%d+) FGCS")
            if not ver then return false end
            -- TODO: better header checks
            
            return header
        end,
        
        -- Write a FGCS header
        -- @param fh filehandle to write to
        -- @param header table with the header data, as returned from readFGCSHeader()
        -- @return boolean showing success or failure
        writeFGCSHeader = function(fh, header)
            if fh and header.version then
                fh:write(header.version.."\n")
                fh:write(header.callsign.."\n")
                fh:write(header.lat.."\n")
                fh:write(header.lon.."\n")
                fh:write(header.height.."\n")
                fh:write(header.frequency.."\n")
                fh:write(header.txpower.."\n")
                fh:write(header.playbacktype.."\n")
                fh:write(header.timetolive.."\n")
                fh:write(header.timestamp.."\n")
                fh:write(header.voicecodec.."\n")
                fh:write(header.samplespeed.."\n")
                return true
            else
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
        getFGCSreaminingValidity = function(header)
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
                print("Received FGCOM-plugin data, dataID='"..dataID.."', from=["..sender:getSession().."] '"..sender:getName().."'")
                    print("  data='"..data.."'")
          
                sid = sender:getSession()

                -- check if we already have state for this client; if not add template
                if not fgcom_clients[sid] then
                    fgcom_clients[sid] = {
                        callsign="",
                        lat="",
                        lon="",
                        alt="",
                        radios={}
                    }
                    print("added new client state: "..sid)
                end
          
                -- OK, go ahead and try to parse;
                -- we are interested in the callsign and the location.
                -- For proper recording, also the PTT state is important to us.
                -- for token in string.gmatch(data, ",") do
                for index,token in ipairs(fgcom.data.csplit(data, ",")) do
                    field = fgcom.data.csplit(token, "=")
                    
                    -- Udpates to location/user state
                    if dataID:find("FGCOM:UPD_LOC") then
                        if "CALLSIGN" == field[1] then fgcom_clients[sid].callsign = field[2] end
                        if "LAT" == field[1] then fgcom_clients[sid].lat = field[2] end
                        if "LON" == field[1] then fgcom_clients[sid].lon = field[2] end
                        if "ALT" == field[1] then fgcom_clients[sid].alt = field[2] end
                    end
                    
                    -- Updates to radios
                    if dataID:find("FGCOM:UPD_COM:") then
                        -- the dataID says, which radio to update (starting at zero)
                        dataID_t = fgcom.data.csplit(dataID, ":")
                        radioID = dataID_t[3]
                        if not fgcom_clients[sid].radios[radioID] then
                            -- if radio unknown yet, add template
                            fgcom_clients[sid].radios[radioID] = {
                                frequency = "",
                                ptt = 0
                                -- todo: more needed?
                            }
                        end
                        
                        if "FRQ" == field[1] then fgcom_clients[sid].radios[radioID].frequency = field[2] end
                        if "PTT" == field[1] then fgcom_clients[sid].radios[radioID].ptt = field[2] end
                        if "PWR" == field[1] then fgcom_clients[sid].radios[radioID].power = field[2] end
                    end
                end
            end
            
            print("Parsing done. New remote state:")
            for uid,remote in pairs(fgcom_clients) do
                for k,v in pairs(remote) do
                    print(uid, k, v)
                    if k=="radios" then
                        for radio_id,radio in pairs(remote.radios) do
                            print(uid,"    radio #"..radio_id.." frequency='"..radio.frequency.."'")
                            print(uid,"    radio #"..radio_id.."       ptt='"..radio.ptt.."'")
                        end
                    end
                end
            end
            print("-----------")
        end
    }
}
    

