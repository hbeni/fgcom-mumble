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
#include <set>

// Common  shared functions of plugin i/o

#ifndef FGCOM_IO_PLUGIN_H
#define FGCOM_IO_PLUGIN_H


#define NOTIFYINTERVAL      1000  // minimal time between notifications (ms)
#define NOTIFYPINGINTERVAL 10000  // time between pings (ms), if no notification was done

#define MAX_PLUGINIO_FIELDLENGTH      32    // maximum plugin-io field size, should correspond to MAX_UDPSRV_FIELDLENGTH

#define MIN_NTFYANSWER_INTVAL 1000   // minimum time interval between answers to incoming NTF_ASK requests

// Mubmle API global vars.
// They get initialized from the plugin interface (see fgcom-mumble.cpp)
extern MumbleAPI_v_1_0_x mumAPI;
extern mumble_connection_t activeConnection;
extern mumble_plugin_id_t ownPluginID;
extern mumble_userid_t localMumId;

// Notification types
//0=all local info; 1=location data; 2=comms, 3=ask for data, 4=userdata, 5=ping
enum FGCOM_NOTIFY_T {
    NTFY_ALL = -1,
    NTFY_USR = 4,
    NTFY_LOC = 1,
    NTFY_COM = 2,
    NTFY_ASK = 3,
    NTFY_PNG = 5
};

/*
 * Debug/Log functions
 * 
 * log to mumble client chat window: mumAPI.log(ownPluginID, "Received API functions");
 * log to terminal/stdout:  pluginLog("Registered Mumble's API functions");
 */
std::ostream& pLog(std::ostream& stream);

template<typename T>
void pluginLog(T log);

// debug=true: only log if compiled in DEBUG mode
template<typename T>
void pluginDbg(T log);


/*
 * Notify other clients on changes to local data.
 * This will construct a datastream message and push
 * it to the mumble plugin send function.
 * 
 * @param iid:      identity selector; -1=any, 0=default, >0=others
 * @param what:     0=all local info; 1=location data; 2=comms, 3=ask for data, 4=userdata, 5=ping
 * @param selector: ignored, when 'what'=2: id of radio (0=COM1,1=COM2,...)
 * @param tgtUser:  0: notify all, otherwise just the specified ID (note: 0 is the superuserID)
 */
void notifyRemotes(int iid, FGCOM_NOTIFY_T what, int selector=-1, mumble_userid_t tgtUser=0);


/*
 * Handle incoming mumble plugin data
 * 
 * @param mumble_userid_t sender of the data (that looks like an unsigned int)
 * @param dataID string with dataID ("FGCOM.....")
 * @param data   string with the payload
 * @return true if the data could be processed
 */
bool handlePluginDataReceived(mumble_userid_t senderID, std::string dataID, std::string data);

/*
 * Thread to detect notification changes and trigger non-urgent notifications.
 * The intent here is that fast changing data (like LAT/LON/ALT) will not
 * be transmitted with every incoming UDP change, because that can be used to
 * spam the infrastructure (like changing LAT with 100Hz or so).
 * We differentiate between urgent and non-urgent changes:
 *   - urgent is a change of user- and radio state, like frequency or especially PTT
 *     => handled from the UDP input parser.
 *   - non-urgent are changes to location. We can skip to notify
 *     if the changes are very frequent and not significant enough.
 *     => handled here.
 *     => regarding the FGFS input stream this will probably result in the maximum
 *        rate defined in NOTIFYINTERVAL during flight.
 */
void fgcom_notifyThread();

/*
 * Check if we are connected to a server
 *
 * @return bool
 */
bool fgcom_isConnectedToServer();


#endif
