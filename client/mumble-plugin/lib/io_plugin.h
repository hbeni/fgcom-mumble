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

/**
 * @brief Template function for logging messages to the plugin log
 * 
 * This template function provides a generic logging interface that can
 * accept any type of data and convert it to a string for logging.
 * 
 * @tparam T Type of data to log (must be convertible to string)
 * @param log The data to log
 * 
 * @note This function is used for general plugin logging
 * @note The data is converted to string using stream operators
 * 
 * @example
 * // Log various types of data
 * pluginLog("Plugin started");
 * pluginLog(42);
 * pluginLog(3.14f);
 */
template<typename T>
void pluginLog(T log);

/**
 * @brief Debug logging function that only logs in DEBUG builds
 * 
 * This function provides debug logging that is only active when the
 * plugin is compiled in DEBUG mode. In release builds, this function
 * does nothing to avoid performance overhead.
 * 
 * @param log Debug message to log
 * 
 * @note Only logs if compiled with DEBUG flag
 * @note Use this for debugging information that shouldn't appear in release builds
 * 
 * @example
 * // Debug logging
 * pluginDbg("Processing audio sample: " + std::to_string(sample));
 */
void pluginDbg(std::string log);


// holds the last data we did sent out, so we can detect changes for notification (and how much)
struct fgcom_notificationState {
    fgcom_client data;   // last data we notified
    std::chrono::system_clock::time_point lastPing;  // when we last sent a ping packet
    
    fgcom_notificationState()  {
        data = fgcom_client();
        lastPing = std::chrono::system_clock::now();
    };
};
extern std::map<int, fgcom_notificationState> lastNotifiedState;

/**
 * @brief Notify other clients about changes to local data
 * 
 * This function constructs and sends a datastream message to other Mumble
 * clients to notify them about changes to local plugin data. The notification
 * can be targeted to specific users or broadcast to all users.
 * 
 * @param iid Identity selector (-1=any, 0=default, >0=specific identity)
 * @param what Type of notification (see FGCOM_NOTIFY_T enum)
 * @param selector Radio selector (ignored unless what=NTFY_COM, 0=COM1, 1=COM2, etc.)
 * @param tgtUser Target user ID (0=all users, >0=specific user)
 * 
 * @note The function constructs a datastream message and sends it via Mumble API
 * @note Rate limiting is applied to prevent excessive notifications
 * @note Different notification types carry different data payloads
 * 
 * @see FGCOM_NOTIFY_T for notification types
 * @see notifyRemotesCombined() for rate-throttled notifications
 * 
 * @example
 * // Notify all users about location changes
 * notifyRemotes(0, NTFY_LOC, -1, 0);
 * 
 * // Notify specific user about radio changes
 * notifyRemotes(0, NTFY_COM, 1, targetUserId);
 */
void notifyRemotes(int iid, FGCOM_NOTIFY_T what, int selector=-1, mumble_userid_t tgtUser=0);

/**
 * @brief Combined notification function for rate throttling
 * 
 * This function sends a single combined notification message instead of
 * multiple separate calls to notifyRemotes(). This helps reduce network
 * traffic and improves performance by batching notifications.
 * 
 * @param iid Identity selector (-1=any, 0=default, >0=specific identity)
 * @param tgtUser Target user ID (0=all users, >0=specific user)
 * 
 * @note This function is more efficient than multiple notifyRemotes() calls
 * @note Rate throttling is automatically applied to prevent spam
 * @note The combined message includes all relevant data changes
 * 
 * @see notifyRemotes() for individual notifications
 * 
 * @example
 * // Send combined notification to all users
 * notifyRemotesCombined(0, 0);
 * 
 * // Send combined notification to specific user
 * notifyRemotesCombined(0, targetUserId);
 */
void notifyRemotesCombined(int iid, mumble_userid_t tgtUser);

/**
 * @brief Handle incoming Mumble plugin data from other clients
 * 
 * This function processes incoming plugin data messages from other Mumble
 * clients. It parses the data ID and payload to extract client information
 * and update the local state accordingly.
 * 
 * @param senderID Mumble user ID of the sender
 * @param dataID Data identifier string (typically "FGCOM.....")
 * @param data Payload data containing client information
 * @return true if the data was successfully processed, false otherwise
 * 
 * @note This function is called by the Mumble plugin system for incoming data
 * @note The data ID identifies the type of data being transmitted
 * @note The payload contains serialized client state information
 * @note Processing failures are logged for debugging purposes
 * 
 * @example
 * // Handle incoming data (called by Mumble plugin system)
 * bool processed = handlePluginDataReceived(senderId, "FGCOM_LOC", locationData);
 */
bool handlePluginDataReceived(mumble_userid_t senderID, std::string dataID, std::string data);

/**
 * @brief Notification thread for handling non-urgent data changes
 * 
 * This function runs in a separate thread to detect and handle non-urgent
 * data changes that don't require immediate notification. It helps prevent
 * spam by throttling frequent location updates while still maintaining
 * reasonable update rates.
 * 
 * The thread differentiates between urgent and non-urgent changes:
 * - Urgent changes (radio state, PTT, frequency) are handled immediately
 * - Non-urgent changes (location data) are throttled to prevent spam
 * 
 * @note This function runs continuously in a background thread
 * @note It prevents excessive notifications from high-frequency data updates
 * @note The maximum notification rate is defined by NOTIFYINTERVAL
 * @note Location changes are throttled to prevent infrastructure spam
 * 
 * @see NOTIFYINTERVAL for notification rate configuration
 * @see fgcom_isConnectedToServer() for connection status checking
 */
void fgcom_notifyThread();

/**
 * @brief Check if the plugin is connected to a Mumble server
 * 
 * This function checks the connection status to determine if the plugin
 * is currently connected to a Mumble server. This is important for
 * determining whether notifications can be sent and data can be received.
 * 
 * @return true if connected to a server, false otherwise
 * 
 * @note This function should be called before attempting to send notifications
 * @note The connection status is maintained by the Mumble plugin system
 * @note Disconnected state prevents data transmission and reception
 * 
 * @example
 * // Check connection before sending notification
 * if (fgcom_isConnectedToServer()) {
 *     notifyRemotes(0, NTFY_LOC, -1, 0);
 * }
 */
bool fgcom_isConnectedToServer();


#endif
