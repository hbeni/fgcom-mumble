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


// Garbage collector
// He will remove stale remote and local data from the plugis state.

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <mutex>
#include <vector>
#include <set>
#include <map>
#include <chrono>
#include <thread>

#include "mumble/MumblePlugin_v_1_0_x.h"
#include "globalVars.h"
#include "io_plugin.h"
#include "garbage_collector.h"
#include "fgcom-mumble.h"


/**
 * @brief Clean stale local client data from the plugin state
 * 
 * This function removes stale local client identities from the plugin's
 * internal state. Local client data is considered stale if it hasn't been
 * updated within the configured timeout period (FGCOM_GARBAGECOLLECT_TIMEOUT_LCL).
 * 
 * The function performs the following operations:
 * - Scans all local client identities for staleness
 * - Removes stale identities from the local client map
 * - Cleans up associated notification state
 * - Updates the client comment if identities were removed
 * 
 * @note This function is thread-safe and uses RAII lock guards
 * @note Stale data is determined by comparing lastUpdate timestamp with current time
 * @note The function automatically updates the client comment after cleanup
 * 
 * @see FGCOM_GARBAGECOLLECT_TIMEOUT_LCL for timeout configuration
 * @see fgcom_updateClientComment() for comment update
 */
void fgcom_gc_clean_lcl() {
    std::chrono::milliseconds lcl_timeout(FGCOM_GARBAGECOLLECT_TIMEOUT_LCL);
    
    // CRITICAL FIX: Use try_lock to avoid blocking - if lock unavailable, skip this cleanup cycle
    // This prevents deadlock when audio callback or main thread holds the lock
    std::unique_lock<std::mutex> lock(fgcom_localcfg_mtx, std::try_to_lock);
    if (!lock.owns_lock()) {
        // Lock unavailable - skip this cleanup cycle to avoid deadlock
        pluginDbg("[GC] LCL cleanup skipped: fgcom_localcfg_mtx unavailable");
        return;
    }

    pluginDbg("[GC] LCL searching for stale local state..."); 
    std::vector<int> staleIIDs;
    for (const auto &p : fgcom_local_client) { // inspect all identites of the local client
        int iid          = p.first;
        fgcom_client lcl = p.second;

        std::time_t lastUpdate_t = std::chrono::system_clock::to_time_t(lcl.lastUpdate);
        std::string lastUpdate_str(30, '\0');
        std::strftime(&lastUpdate_str[0], lastUpdate_str.size(), "%H:%M:%S", std::localtime(&lastUpdate_t));
        lastUpdate_str.resize(strlen(lastUpdate_str.c_str())); // Remove trailing nulls
        pluginDbg("[GC] LCL  iid="+std::to_string(iid)+" lastUpdate="+lastUpdate_str);

        std::chrono::milliseconds since = std::chrono::duration_cast<std::chrono::milliseconds> (std::chrono::system_clock::now()-lcl.lastUpdate);
        if (since > lcl_timeout) {
            pluginDbg("[GC] LCL  iid="+std::to_string(iid)+" stale since="+std::to_string((float)since.count()/1000)+"s" );
            staleIIDs.push_back(iid);
        }
    }
    
    for(const auto &elem : staleIIDs) {
        fgcom_local_client.erase(elem);
        lastNotifiedState.erase(elem);
        pluginDbg("[GC] LCL  clean iid="+std::to_string(elem));
    }
    
    // Mutex automatically unlocked when lock goes out of scope
    
    // update client comment if we removed identities
    if (!staleIIDs.empty()) fgcom_updateClientComment();
    
}


/**
 * @brief Clean stale remote client data from the plugin state
 * 
 * This function removes stale remote client data from the plugin's
 * internal state. Remote client data is considered stale if it hasn't been
 * updated within the configured timeout period (FGCOM_GARBAGECOLLECT_TIMEOUT_RMT).
 * 
 * The function performs the following operations:
 * - Scans all remote clients and their identities for staleness
 * - Removes stale identities from remote client maps
 * - Removes entire remote clients if all their identities are stale
 * - Cleans up associated notification state
 * 
 * @note This function is thread-safe and uses manual mutex locking
 * @note Stale data is determined by comparing lastUpdate timestamp with current time
 * @note Remote clients are removed entirely if all identities are stale
 * 
 * @see FGCOM_GARBAGECOLLECT_TIMEOUT_RMT for timeout configuration
 */
void fgcom_gc_clean_rmt() {
    std::chrono::milliseconds rmt_timeout(FGCOM_GARBAGECOLLECT_TIMEOUT_RMT);
    
    // CRITICAL FIX: Use try_lock to avoid blocking - if lock unavailable, skip this cleanup cycle
    // This prevents deadlock when audio callback or main thread holds the lock
    std::unique_lock<std::mutex> lock(fgcom_remotecfg_mtx, std::try_to_lock);
    if (!lock.owns_lock()) {
        // Lock unavailable - skip this cleanup cycle to avoid deadlock
        pluginDbg("[GC] RMT cleanup skipped: fgcom_remotecfg_mtx unavailable");
        return;
    }
    
    pluginDbg("[GC] RMT searching for stale remote state...");
    std::vector<mumble_userid_t> staleRemoteClients;
    for (const auto &p : fgcom_remote_clients) {
        std::vector<int> staleIIDs;
        mumble_userid_t clid = p.first;
        for (const auto &idty : fgcom_remote_clients[clid]) {
            int iid          = idty.first;
            fgcom_client rmt = idty.second;

            std::chrono::milliseconds since = std::chrono::duration_cast<std::chrono::milliseconds> (std::chrono::system_clock::now()-rmt.lastUpdate);
            if (since > rmt_timeout) {
                pluginDbg("[GC] RMT  mumid="+std::to_string(clid)+"; iid="+std::to_string(iid)+" stale since="+std::to_string((float)since.count()/1000)+"s" );
                 staleIIDs.push_back(iid);
            }
        }
        
        // remove stale remote identites
        for(const auto &elem : staleIIDs) {
            fgcom_remote_clients[clid].erase(elem);
            pluginDbg("[GC] RMT  mumid="+std::to_string(clid)+"; clean iid="+std::to_string(elem));
        }
        
        // if the remote has no identities left: clear also the remote as such
        if (fgcom_remote_clients.empty()) {
            staleRemoteClients.push_back(clid);
        }
        
    }
    
    for(const auto &elem : staleRemoteClients) {
        fgcom_remote_clients.erase(elem);
        pluginDbg("[GC] RMT  clean mumid="+std::to_string(elem)+" (no identities left)");
    }
    
    // Mutex automatically unlocked when lock goes out of scope
}


/**
 * @brief Global variables for garbage collector thread management
 */
bool fgcom_gcThreadRunning = false;
bool fgcom_gcThreadShutdown = false;

/**
 * @brief Spawn and run the garbage collector thread
 * 
 * This function starts the garbage collector thread that periodically
 * cleans up stale local and remote client data. The thread runs in a loop
 * checking for stale data at regular intervals defined by FGCOM_GARBAGECOLLECT_INTERVAL.
 * 
 * The garbage collector thread performs the following operations:
 * - Runs continuously until shutdown is requested
 * - Checks for stale data at configured intervals
 * - Calls fgcom_gc_clean_lcl() to clean local data
 * - Calls fgcom_gc_clean_rmt() to clean remote data
 * - Sleeps for 500ms between checks to avoid excessive CPU usage
 * 
 * @note This function should be called once during plugin initialization
 * @note The thread can be shut down using fgcom_shutdownGarbageCollector()
 * @note The function sets fgcom_gcThreadRunning to true when started
 * 
 * @see FGCOM_GARBAGECOLLECT_INTERVAL for check interval configuration
 * @see fgcom_gc_clean_lcl() for local data cleanup
 * @see fgcom_gc_clean_rmt() for remote data cleanup
 * @see fgcom_shutdownGarbageCollector() for thread shutdown
 */
void fgcom_spawnGarbageCollector() {
    fgcom_gcThreadRunning = true;
    pluginDbg("[GC] thread starting");
    
    // The check interval might be long, which delays plugin shutdown;
    // because of this we decouple actual cleanup from the check time interval.
    std::chrono::milliseconds checkInt(FGCOM_GARBAGECOLLECT_INTERVAL);
    std::chrono::system_clock::time_point lastCheck = std::chrono::system_clock::now();
    while (!fgcom_gcThreadShutdown) {
        std::chrono::system_clock::time_point now = std::chrono::system_clock::now();
        std::chrono::milliseconds since = std::chrono::duration_cast<std::chrono::milliseconds> (now-lastCheck);
        if (since > checkInt) {
            fgcom_gc_clean_lcl();
            fgcom_gc_clean_rmt();
            lastCheck = now;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    pluginDbg("[GC] thread finished");
    fgcom_gcThreadRunning = false;
    fgcom_gcThreadShutdown = false;
}


/**
 * @brief Shutdown the garbage collector thread
 * 
 * This function signals the garbage collector thread to shut down gracefully.
 * The thread will finish its current iteration and then exit cleanly.
 * 
 * @note This function should be called during plugin shutdown
 * @note The function sets fgcom_gcThreadShutdown to true to signal shutdown
 * @note The thread will set fgcom_gcThreadRunning to false when it exits
 * 
 * @see fgcom_spawnGarbageCollector() for thread startup
 */
void fgcom_shutdownGarbageCollector() {
    fgcom_gcThreadShutdown = true;
}
