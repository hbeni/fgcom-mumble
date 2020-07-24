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

// RDF UDP client
//
// Simple UDP client sending RDF packets.
// The RDF client must be configured and started trough special 
// settings to the UDP server.

#include <iostream>
#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sstream> 
#include <regex>
#include <sys/types.h> 

#ifdef MINGW_WIN64
    #include <winsock2.h>
    //#include <windows.h>
    //#include <ws2tcpip.h>
    typedef int socklen_t;
#else
    #include <sys/socket.h> 
    #include <arpa/inet.h> 
    #include <netinet/in.h>
#endif

#include <thread>
#include <mutex>
#include <vector>
#include <set>
#include <map>
#include <clocale> // setlocale() 

#include "globalVars.h"
#include "plugin_io.h"
#include "fgcom-mumble.h"

    
#define FGCOM_RDFCLIENT_RATE 10       // datarate in packets/seconds

/*****************************************************
 *                 RDF UDP Client                    *
 * The UDP interface is the plugins port to send     *
 * RDF data to the outside world.                    *
 * It is used for example from ATC clients or        *
 * FlightSims to detect radio transmissions (RDF).   *
 ****************************************************/

/*
 * Generates a message from current radio state
 */
std::string fgcom_rdf_generateMsg() {
    std::string clientMsg;
    
    /*
     * RDF generation
     * This inspects all radios for RDF information.
     * (The RDF information is updated from the plugin-io parser and signal signal processing)
     */
    fgcom_remotecfg_mtx.lock();
    for (const auto &cl : fgcom_remote_clients) {
        for (const auto &idty : fgcom_remote_clients[cl.first]) {
            fgcom_client remote = idty.second;
            //pluginDbg("[UDP] client fgcom_udp_generateMsg(): check remote="+std::to_string(remote.mumid)+", callsign="+remote.callsign);
            for (int ri=0; ri<remote.radios.size(); ri++) {
                fgcom_radiowave_signal signal = remote.radios[ri].signal;
                //pluginDbg("[UDP] client fgcom_udp_generateMsg(): check radio["+std::to_string(ri)+"]");
                //pluginDbg("[UDP] client fgcom_udp_generateMsg():   signal.quality="+std::to_string(signal.quality));
                //pluginDbg("[UDP] client fgcom_udp_generateMsg():   signal.direction="+std::to_string(signal.direction));
                //pluginDbg("[UDP] client fgcom_udp_generateMsg():   signal.angle="+std::to_string(signal.verticalAngle));
                //pluginDbg("[UDP] client fgcom_udp_generateMsg():   signal.rdfEnabled="+std::to_string(signal.rdfEnabled));
                if (signal.rdfEnabled && signal.quality > 0.0) {
                    clientMsg += "RDF_"+std::to_string(remote.mumid)+"-"+std::to_string(idty.first)+"_"+"-"+std::to_string(ri)+":";
                    clientMsg += ",FRQ="+remote.radios[ri].frequency;
                    clientMsg += ",DIR="+std::to_string(signal.direction);
                    clientMsg += ",VRT="+std::to_string(signal.verticalAngle);
                    clientMsg += ",QLY="+std::to_string(signal.quality);
                    clientMsg += "\n";
                }
                
                // reset the quality. If the user is still speaking, this will get set to the true value
                // with the next received audio sample (see fgcom-mumble.cpp handler).
                // This is needed here, because currently we have no other means to detect
                // if a client stopped speaking (PTT off is not enough: the client may suddenly disconnect too!)
                fgcom_remote_clients[cl.first][idty.first].radios[ri].signal.quality       = -1;
                fgcom_remote_clients[cl.first][idty.first].radios[ri].signal.verticalAngle = -1;
                fgcom_remote_clients[cl.first][idty.first].radios[ri].signal.direction     = -1;
            }
        }
    }
    fgcom_remotecfg_mtx.unlock();
    
    
    // Finally return data
    //pluginDbg("[UDP] client fgcom_udp_generateMsg(): data buld finished, length="+std::to_string(clientMsg.length())+", content="+clientMsg);
    if (clientMsg.length() > 0 ) {
        return clientMsg+'\n';
    } else {
        return clientMsg;
    }
}


// Spawns the UDP client thread
bool rdfClientRunning = false;
void fgcom_spawnRDFUDPClient() {
    pluginLog("[RDF] client on port "+std::to_string(fgcom_cfg.rdfPort)+" initializing at rate "+std::to_string(FGCOM_RDFCLIENT_RATE)+" pakets/s");
    const float packetrate = FGCOM_RDFCLIENT_RATE;
    const int datarate = 1000000 * (1/packetrate);  //datarate in seconds*microseconds
    int fgcom_UDPClient_sockfd, rc, port;  
    struct sockaddr_in cliAddr, remoteServAddr;
    bool portEstablished = false;

    // Prepare addressing
    remoteServAddr.sin_family = AF_INET;
    remoteServAddr.sin_port = htons(port);
#ifdef MINGW_WIN64
    remoteServAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);    // 127.0.0.1 on purpose: don't change for securites sake
#else
	inet_pton(AF_INET, "localhost", &remoteServAddr.sin_addr);  // 127.0.0.1 on purpose: don't change for securites sake
#endif
    //bzero(&(remoteServAddr.sin_zero), 8);     /* zero the rest of the struct */
    
    // Creating socket file descriptor 
    if ( (fgcom_UDPClient_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        pluginLog("[RDF] client ERROR: socket creation failed");
        return;
    }
    
    // bind client port
    cliAddr.sin_family = AF_INET;
    cliAddr.sin_port = htons(0);
    cliAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // restricted to 127.0.0.1 on purpose: don't change
    rc = bind ( fgcom_UDPClient_sockfd, (struct sockaddr *) &cliAddr, sizeof(cliAddr) );
    if (rc < 0) {
        pluginLog("[RDF] client ERROR: local binding on port "+std::to_string(port)+" failed");
        return;
    }

    rdfClientRunning = true;
    
    // Generate Data packets and send them in a loop
    while (true) {
        // Check if target port changed; if so, switch binding
        if (fgcom_cfg.rdfPort == 0) {
            break; // stop main loop -> finish
            
        } else if (fgcom_cfg.rdfPort != port) {
            // establish/switch target port
            pluginLog("[RDF] client on port "+std::to_string(port)+" switching to port "+std::to_string(fgcom_cfg.rdfPort));
            port = fgcom_cfg.rdfPort;
            remoteServAddr.sin_port = htons(port);
            mumAPI.log(ownPluginID, std::string("RDF sending to port "+std::to_string(fgcom_cfg.rdfPort)+" activated").c_str());
        }

        
        // sleep for datarate-time microseconds
        //pluginDbg("[RDF] client sleep for "+std::to_string(datarate)+" microseconds");
        if(usleep(datarate) < 0) {
            pluginLog("[RDF] client socket creation failed"); 
            break;
        }
        
        // generate data.
        std::string udpdata = fgcom_rdf_generateMsg();
        if (udpdata.length() > 0) {
            pluginDbg("[RDF] client sending msg '"+udpdata+"'");
            rc = sendto (fgcom_UDPClient_sockfd, udpdata.c_str(), strlen(udpdata.c_str()) + 1, 0,
                 (struct sockaddr *) &remoteServAddr,
                 sizeof (remoteServAddr));
            if (rc < 0) {
                pluginLog("[RDF] client ERROR sending "+std::to_string(strlen(udpdata.c_str()))+" bytes of data");
                close (fgcom_UDPClient_sockfd);
                return;
            }
            
            pluginDbg("[RDF] client sending OK ("+std::to_string(strlen(udpdata.c_str()))+" bytes of data)");
            
        } else {
            // no data generated: do not send anything.
            pluginDbg("[RDF] client sending skipped: no data to send.");
        }
        
    }
    
    
    close(fgcom_UDPClient_sockfd);
    rdfClientRunning = false;
    pluginLog("[RDF] client on port "+std::to_string(port)+" finished.");
}
