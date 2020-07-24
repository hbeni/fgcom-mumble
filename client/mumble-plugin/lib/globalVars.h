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
#include "MumblePlugin.h"
#include "radio_model.h"


// Plugin runtime configuration
//
// Currently the configuration cannot be done trough mumble, but that is planned.
// Changing runtime configuration can be done trough the inbound RDP interface for now.
struct fgcom_config {
    int rdfPort;  // defines RDF output port
    bool radioAudioEffects;
    
    fgcom_config()  {
        radioAudioEffects   = true;
    };
};
extern struct fgcom_config fgcom_cfg;


// This represents the state of a radio
struct fgcom_radio {
	std::string  frequency; // tuned frequency
	bool  power_btn;     // true if switched on
	float volts;         // how much electric power it has (>0 = on)
	bool  serviceable;   // false if broken
	bool  ptt;           // true if PTT is pushed
	float volume;        // volume, 0.0->1.0
	float pwr;           // tx power in watts
	float squelch;       // squelch setting (cutoff signal below this quality)
	struct fgcom_radiowave_signal signal; 
	
	fgcom_radio()  {
        frequency   = "";
        power_btn   = true;
        volts       = 12;
        serviceable = true;
        ptt         = false;
        volume      = 1.0;
        pwr         = 10;
        squelch     = 0.1;
    };
};

// This represents a clients metadata
struct fgcom_client {
	unsigned int mumid;  // mumble client ID
	std::chrono::system_clock::time_point lastUpdate;
    float lon;
	float lat;
	float alt;  // in meters
	std::string  callsign;
	std::vector<fgcom_radio> radios;
	fgcom_client()  {
		lon = -130.000;   // 60°S / 130°W is somewhere in the middle of the pacific ocean... 
		lat = -60.000;
		alt = -1;
		callsign = "ZZZZ";
        lastUpdate = std::chrono::system_clock::now();
	};
};



// Global mutex for read/write access.
// This needs to be locked everytime one wants to read/write
// to the data to fgcom_local_client or fgcom_remote_clients
extern std::mutex fgcom_localcfg_mtx;

// Local plugin datastore
// this is written from by the udp server and read by the plugin
// Note: Some data is only stored at the default identity: mumid
extern std::map<int, struct fgcom_client> fgcom_local_client;   // local client data

// Remote plugin state
// this is written to from the plugins receive data function and read from other plugin functions
extern std::mutex fgcom_remotecfg_mtx;  // mutex lock for remote data
extern std::map<mumble_userid_t, std::map<int, fgcom_client> > fgcom_remote_clients; // remote radio config

// Global plugin state
extern int fgcom_specialChannelID;  // filled from plugin init in fgcom-mumble.cpp


#endif
