// Define some global structures
//

#ifndef FGCOM_GLOBALS_H
#define FGCOM_GLOBALS_H

#include <vector>
#include <string>
#include <mutex>
#include "MumblePlugin.h"


// This represents the state of a radio
struct fgcom_radio {
	std::string  frequency; // tuned frequency
	bool  power_btn;     // true if switched on
	float volts;         // how much electric power it has (>0 = on)
	bool  serviceable;   // false if broken
	bool  ptt;           // true if PTT is pushed
	float volume;        // volume, 0.0->1.0
	float pwr;           // tx power in watts
	fgcom_radio()  {
        frequency   = "";
        power_btn   = true;
        volts       = 12;
        serviceable = true;
        ptt         = false;
        volume      = 1.0;
        pwr         = 10;
    };
};

// This represents a clients metadata
struct fgcom_client {
	float lon;
	float lat;
	int   alt;  // in meters
	std::string  callsign;
	std::vector<fgcom_radio> radios;
	fgcom_client()  {
		lon = -1;
		lat = -1;
		alt = -1;
		callsign = "ZZZZ";
	};
};



// Global mutex for read/write access.
// This needs to be locked everytime one wants to read/write
// to the data to fgcom_local_client or fgcom_remote_clients
extern std::mutex fgcom_localcfg_mtx;

// Local plugin datastore
// this is written from by the udp server and read by the plugin
extern struct fgcom_client fgcom_local_client;   // local client data

// Remote plugin state
// this is written to from the plugins receive data function and read from other plugin functions
extern std::mutex fgcom_remotecfg_mtx;  // mutex lock for remote data
extern std::vector<fgcom_radio> fgcom_remote_clients; // remote radio config



#endif
