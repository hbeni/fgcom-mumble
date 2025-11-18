#include "globalVars.h"
#include "radio_model.h"
#include <mutex>
#include <cstring>

// Global variable definitions
std::map<int, struct fgcom_client> fgcom_local_client;
std::mutex fgcom_localcfg_mtx;
fgcom_config fgcom_cfg;

// Mumble API variables
MumbleAPI_v_1_0_x mumAPI;
mumble_connection_t activeConnection;
mumble_plugin_id_t ownPluginID;
mumble_userid_t localMumId;

// Initialize global variables
void initializeGlobalVars() {
    // Initialize fgcom_cfg with default values
    fgcom_cfg = fgcom_config();
    
    // Initialize Mumble API variables
    memset(&mumAPI, 0, sizeof(mumAPI));
    activeConnection = 0;
    ownPluginID = 0;
    localMumId = 0;
}
