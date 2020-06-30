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

CODEC_OPUS = 4

fgcom_clients = {}      -- known clients from fgcom-mumble plugin broadcasts


local bit = require("bit")

-- FGCom functions
--   they where written from bkacjios: https://github.com/bkacjios/lua-mumble/issues/12
fgcom = {
    
    -- io provides some basic IO functions
    io={
        --[[ write short byte to filehandle
            @param f is the filehandle
            @param short is the short data to write
        --]]
        writeShort = function (f, short)
            -- Convert our 16 bit number into two bytes
            local b1 = bit.band(bit.rshift(short, 8), 0xFF)
            local b2 = bit.band(short, 0xFF)
            f:write(string.char(b1, b2))
        end,

        --[[ read a short byte from filehandle
            @param f is the filehandle
        --]]
       readShort = function (f)
            local short = f:read(2) -- Read two characters from the file
            if not short or short == "" then return end -- End of file
            local b1, b2 = string.byte(short, 1, 2) -- Convert the two characters to bytes
            return bit.bor(bit.lshift(b1, 8), bit.lshift(b2, 0)) -- Combine the two bytes into a number
        end,
        
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
        end
    },
    
    -- Data handling functions
    data={
          
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
    

-- lua-mumble from  bkacjios (https://github.com/bkacjios/lua-mumble).
-- (needs the shared object in your lua installation; instructions see lua-mumble project)
mumble = require("mumble")

