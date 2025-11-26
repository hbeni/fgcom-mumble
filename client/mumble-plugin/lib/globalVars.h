/* 
 * This file is part of the FGCom-mumble distribution (https://github.com/hbeni/fgcom-mumble).
 * Copyright (c) 2020 Benedikt Hallinger
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

// Define some global structures
//

#ifndef FGCOM_GLOBALS_H
#define FGCOM_GLOBALS_H

#include <vector>
#include <string>
#include <mutex>
#include <map>
#include <chrono>
#include "mumble/MumblePlugin_v_1_0_x.h"
#include "radio_model.h"


// Plugin runtime configuration
//
// Currently the configuration cannot be done trough mumble, but that is planned.
// Changing runtime configuration can be done trough the inbound RDP interface for now.
struct fgcom_config {
    bool        allowHearingNonPluginUsers;
    bool        radioAudioEffects;
    bool        addNoiseSquelch;       // if true, add noise when squelch is open
    bool        useLocationBasedNoise; // if true, use location-based noise floor calculations
    std::string specialChannel;
    std::string udpServerHost;
    int         udpServerPort;
    std::string logfile;
    std::map<int, bool> mapMumblePTT;  // which radios to activate when mumble-internal talk activation is used
    bool        alwaysMumblePTT;       // if true, always enable mumble PTT on COM/PTT, even if plugin not active
    std::string updaterURL;
    bool        autoJoinChannel;
    std::string autoJoinChannelPW;
    
    fgcom_config() noexcept {
        allowHearingNonPluginUsers = false;
        radioAudioEffects = true;
        addNoiseSquelch = true;
        useLocationBasedNoise = true;
        specialChannel    = "^fgcom-mumble.*";
        udpServerHost     = "127.0.0.1";
        udpServerPort     = 16661;
        logfile           = "";
        mapMumblePTT      = {{0,true}};
        alwaysMumblePTT   = false;
        updaterURL        = "";
        autoJoinChannel   = false;
        autoJoinChannelPW = "";
    };
};
// Plugin runtime configuration (header-only definition using C++17 inline)
inline struct fgcom_config fgcom_cfg;


// This represents a clients metadata
struct fgcom_client {
    mumble_userid_t mumid;  // mumble client ID
    uint16_t clientPort;    // client port of the identity, for identification
    uint16_t clientTgtPort; // client port of the identity, we may send packets to this port
    std::string clientHost; // client host of the identity
    std::chrono::system_clock::time_point lastUpdate;       // when we received the last data
    std::chrono::system_clock::time_point lastNotification; // when we sent the last answer for incoming NTF_ASK packets
    float lon;
    float lat;
    float alt;  // in meters
    std::string  callsign;
    std::vector<fgcom_radio> radios;
    float lastSeenSignal;
    fgcom_client()  {
        lon = -130.000;   // 60°S / 130°W is somewhere in the middle of the pacific ocean... 
        lat = -60.000;
        alt = -1;
        callsign = "ZZZZ";
        lastUpdate = std::chrono::system_clock::now();
        lastNotification = std::chrono::system_clock::from_time_t((std::time_t)0);
        lastSeenSignal = -1;
    };
};



// Global mutex for read/write access.
// This needs to be locked everytime one wants to read/write
// to the data to fgcom_local_client or fgcom_remote_clients
inline std::mutex fgcom_localcfg_mtx;

// Local plugin datastore
// this is written from by the udp server and read by the plugin
// Note: Some data is only stored at the default identity: mumid
inline std::map<int, struct fgcom_client> fgcom_local_client;   // local client data

// Remote plugin state
// this is written to from the plugins receive data function and read from other plugin functions
inline std::mutex fgcom_remotecfg_mtx;  // mutex lock for remote data
inline std::map<mumble_userid_t, std::map<int, fgcom_client> > fgcom_remote_clients; // remote radio config

// Global plugin state
inline std::vector<mumble_channelid_t>  fgcom_specialChannelID;  // filled from plugin init in fgcom-mumble.cpp

// Thread-safe cache for radio info used in audio callbacks
// This reduces lock contention and prevents skipped noise generation frames
struct CachedRadioInfo {
    float squelch;
    double lat;
    double lon;
    float freq_mhz;
    bool operable;
    std::chrono::system_clock::time_point last_updated;
    
    CachedRadioInfo() : squelch(1.0f), lat(0.0), lon(0.0), freq_mhz(0.0f), operable(false) {
        last_updated = std::chrono::system_clock::now();
    }
};

// Cache for radio info (updated periodically, read lock-free in audio callback)
inline std::vector<CachedRadioInfo> cached_radio_infos;
inline std::mutex cached_radio_infos_mtx;



/**
 * Utils
 */

/*
 * inplace replace all occurences of from with to in source
 * 
 * std::string s = "abcde";
 * replace_all(s, "bc", "xxx");  // s = "axxxde"
 */
inline void replace_all(std::string& source, const std::string& from, const std::string& to) {
    if (from.empty()) return;  // prevent infinite loop

    std::size_t pos = 0;
    while ((pos = source.find(from, pos)) != std::string::npos)
    {
        source.replace(pos, from.length(), to);
        pos += to.length(); // advance past the replaced segment
    }
}

#endif
