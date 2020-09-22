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

#ifndef FGCOM_IO_UDPSERVER_H
#define FGCOM_IO_UDPSERVER_H


#define MAXLINE             1024  // max byte size of a udp packet


#ifdef DEBUG
    // Debug code: Allow override of signal quality for debugging purposes
    extern float fgcom_debug_signalstrength;  // <0 to disable
#endif


/*
 * Spawn the udp server thread.
 * He should constantly monitor the port for incoming data.
 * 
 * @param ??? TODO: Pointer to the shared data structure. Currently access is via globalvar
 * @return nothing so far. Maybe thread handle?
 */
void fgcom_spawnUDPServer();


/*
 * Trigger shutdown of the udp server
 */
void fgcom_shutdownUDPServer();


/*
 * Return type for indicating what did change by UDP input
 */
struct fgcom_udp_parseMsg_result {
    bool          userData;
    bool          locationData;
    std::set<int> radioData;
    fgcom_udp_parseMsg_result()  {
        userData = false;
        locationData = false;
    };
};

#endif
