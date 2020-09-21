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


/*
 * Clean stale local data
 */
void fgcom_gc_clean_lcl() {
    std::chrono::milliseconds lcl_timeout(FGCOM_GARBAGECOLLECT_TIMEOUT_LCL);
    
    fgcom_localcfg_mtx.lock();

    pluginDbg("[GC] LCL searching for stale local state..."); 
    std::vector<int> staleIIDs;
    for (const auto &p : fgcom_local_client) { // inspect all identites of the local client
        int iid          = p.first;
        fgcom_client lcl = p.second;

        std::chrono::milliseconds since = std::chrono::duration_cast<std::chrono::milliseconds> (std::chrono::system_clock::now()-lcl.lastUpdate);
        if (since > lcl_timeout) {
            pluginDbg("[GC] LCL  iid="+std::to_string(iid)+" stale since="+std::to_string((float)since.count()/1000)+"s" );
            staleIIDs.push_back(iid);
        }
    }
    
    for(const auto &elem : staleIIDs) {
        fgcom_local_client.erase(elem);
        pluginDbg("[GC] LCL  clean iid="+std::to_string(elem));
    }
    
    fgcom_localcfg_mtx.unlock();
    
    // update client comment if we removed identities
    if (staleIIDs.size() > 0) fgcom_updateClientComment();
    
}


/*
 * Clean stale remote data
 */
void fgcom_gc_clean_rmt() {
    std::chrono::milliseconds rmt_timeout(FGCOM_GARBAGECOLLECT_TIMEOUT_RMT);
    
    fgcom_remotecfg_mtx.lock();
    
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
        if (fgcom_remote_clients.size() == 0) {
            staleRemoteClients.push_back(clid);
        }
        
    }
    
    for(const auto &elem : staleRemoteClients) {
        fgcom_remote_clients.erase(elem);
        pluginDbg("[GC] RMT  clean mumid="+std::to_string(elem)+" (no identities left)");
    }
    
    

    fgcom_remotecfg_mtx.unlock();
}


/*
 * GC thread
 */
void fgcom_spawnGarbageCollector() {
    while (true) {
        fgcom_gc_clean_lcl();
        fgcom_gc_clean_rmt();
        std::this_thread::sleep_for(std::chrono::milliseconds(FGCOM_GARBAGECOLLECT_INTERVAL));
    }
}
