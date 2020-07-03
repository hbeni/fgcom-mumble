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


dofile("sharedFunctions.inc.lua")  -- include shared functions
local botname     = "FGOM-Recorder"
fgcom.callsign    = "FGOM-REC"

 
-- | Line | Content                               |
        -- |------|---------------------------------------|
        -- |   1  | Version and Type field: "1.0 FGCS"    |
        -- |   2  | Callsign                              |
        -- |   3  | LAT          (decimal)                |
        -- |   4  | LON          (decimal)                |
        -- |   5  | HGT          (altitude in meter AGL)  |
        -- |   6  | Frequency                             |
        -- |   7  | TX-Power     (in Watts)               |
        -- |   8  | PlaybackType (`oneshot` or `loop`)    |
        -- |   9  | TimeToLive   (seconds; `0`=persistent)|
        -- |  10  | VoiceCodec   (`int` from lua-mumble)  |
        -- |  11  | SampleSpeed  (seconds between samples)|
local header = {
    version      = "1.1 FGCS",
    callsign     = fgcom.callsign,
    lat          = "12.345678",
    lon          = "23.456789",
    height       = 12.345,
    frequency    = "124.05",
    txpower      = 10.5,
    playbacktype = "oneshot",
    timetolive   = 0,
    voicecodec   = 4,
    samplespeed  = 0.0222
}

outfile = assert(io.open("test.fgcs", "wb"))
fgcom.io.writeFGCSHeader(outfile, header)
fgcom.io.writeFGCSSample(outfile, "sample1")
fgcom.io.writeFGCSSample(outfile, "sample2")
fgcom.io.writeFGCSSample(outfile, "sample3")
io.close(outfile)
print("done with writing.")

infile = assert(io.open("test.fgcs", "rb"))
print("read header:")
local h = fgcom.io.readFGCSHeader(infile)
for k,v in pairs(h) do
    print("header read: '"..k.."'='"..v.."'")
end
print("\nread samples:")
local endOfSamples = false
while not endOfSamples do
    nextSample = fgcom.io.readFGCSSample(infile)
    print("sample: len="..nextSample.len.."; eof='"..tostring(nextSample.eof).."'; data='"..nextSample.data.."'")
    endOfSamples = nextSample.eof;
end
io.close(infile)
print("done with reading.")
