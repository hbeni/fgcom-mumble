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
#ifndef FGCOM_SHARED_DATA_H
#define FGCOM_SHARED_DATA_H

#include <mutex>
#include <map>
#include <vector>
#include <memory>
#include "globalVars.h"
#include "radio_model.h"

/**
 * Centralized shared data structure to replace global variable access
 * This provides thread-safe access to all shared data in the FGCom-mumble plugin
 */
class FGCom_SharedData {
private:
    mutable std::mutex data_mutex_;
    
    // Local client data
    std::map<int, fgcom_client> local_clients_;
    
    // Remote client data
    std::map<mumble_userid_t, std::map<int, fgcom_client>> remote_clients_;
    
    // Server state
    bool udp_server_running_;
    bool udp_client_running_;
    bool gc_thread_running_;
    bool debug_thread_running_;
    
    // Configuration data
    std::map<std::string, std::string> config_data_;
    
public:
    FGCom_SharedData();
    ~FGCom_SharedData();
    
    // Local client access
    void addLocalClient(int id, const fgcom_client& client);
    fgcom_client getLocalClient(int id) const;
    void updateLocalClient(int id, const fgcom_client& client);
    size_t getLocalClientCount() const;
    void removeLocalClient(int id);
    
    // Remote client access
    void addRemoteClient(mumble_userid_t userid, int radio_id, const fgcom_client& client);
    fgcom_client getRemoteClient(mumble_userid_t userid, int radio_id) const;
    void updateRemoteClient(mumble_userid_t userid, int radio_id, const fgcom_client& client);
    void removeRemoteClient(mumble_userid_t userid, int radio_id);
    std::map<int, fgcom_client> getRemoteClientsForUser(mumble_userid_t userid) const;
    
    // Server state management
    void setUdpServerRunning(bool running);
    bool isUdpServerRunning() const;
    
    void setUdpClientRunning(bool running);
    bool isUdpClientRunning() const;
    
    void setGcThreadRunning(bool running);
    bool isGcThreadRunning() const;
    
    void setDebugThreadRunning(bool running);
    bool isDebugThreadRunning() const;
    
    // Configuration access
    void setConfigValue(const std::string& key, const std::string& value);
    std::string getConfigValue(const std::string& key, const std::string& default_value = "") const;
    bool hasConfigValue(const std::string& key) const;
    
    // Thread-safe operations
    void lock() const;
    void unlock() const;
    
    // Cleanup
    void clearAllData();
    void clearLocalClients();
    void clearRemoteClients();
};

// Global shared data instance
extern std::unique_ptr<FGCom_SharedData> g_shared_data;

// Convenience functions for backward compatibility
inline FGCom_SharedData* getSharedData() {
    if (!g_shared_data) {
        g_shared_data = std::make_unique<FGCom_SharedData>();
    }
    return g_shared_data.get();
}

#endif // FGCOM_SHARED_DATA_H
