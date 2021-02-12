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

// UDP client
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
#include "io_plugin.h"
#include "fgcom-mumble.h"
#include "io_UDPClient.h"

    
#define FGCOM_UDPCLIENT_RATE 10       // datarate in packets/seconds

/*****************************************************
 *                   UDP Client                      *
 * The UDP interface is the plugins port to send     *
 * RDF data to the outside world.                    *
 * It is used for example from ATC clients or        *
 * FlightSims to detect radio transmissions (RDF).   *
 ****************************************************/


/*
 * Register new signal data
 */
std::recursive_mutex fgcom_rdfInfo_mtx;
std::map<std::string, fgcom_rdfInfo> fgcom_rdf_activeSignals;
void fgcom_rdf_registerSignal(std::string rdfID, fgcom_rdfInfo rdfInfo) {
    fgcom_rdfInfo_mtx.lock();
    fgcom_rdf_activeSignals[rdfID] = rdfInfo;
    fgcom_rdfInfo_mtx.unlock();
}


/*
 * Generates a message from current radio state.
 * For that we inspect all recorded RDF info of this iteration.
 */
std::string fgcom_rdf_generateMsg(std::string selectedHost, uint16_t selectedPort) {
    std::setlocale(LC_NUMERIC,"C"); // decial points always ".", not ","
    fgcom_rdfInfo_mtx.lock();
    
    std::vector<std::string> processed;
    
    // generate message string
    std::string clientMsg;
    for (const auto &rdf : fgcom_rdf_activeSignals) { // inspect all identites of the local client
        std::string rdfID     = rdf.first;
        fgcom_rdfInfo rdfInfo = rdf.second;
        bool hostPortMatches = rdfInfo.rxIdentity.clientHost == selectedHost && rdfInfo.rxIdentity.clientPort == selectedPort;
        if (hostPortMatches && rdfInfo.signal.quality > 0.0) {
            clientMsg += "RDF:";
            clientMsg += "CS_TX="+rdfInfo.txIdentity.callsign;
            //clientMsg += ",CS_RX="+rdfInfo.rxIdentity.callsign;
            clientMsg += ",FRQ="+rdfInfo.txRadio.frequency;
            clientMsg += ",DIR="+std::to_string(rdfInfo.signal.direction);
            clientMsg += ",VRT="+std::to_string(rdfInfo.signal.verticalAngle);
            clientMsg += ",QLY="+std::to_string(rdfInfo.signal.quality);
            clientMsg += "\n";
            processed.push_back(rdfID);
        }
    }
    
    // clear up
    for(const auto &elem : processed) {
        fgcom_rdf_activeSignals.erase(elem);
    }

    

    // Finally return data
    //pluginDbg("[UDP] client fgcom_udp_generateMsg(): data buld finished, length="+std::to_string(clientMsg.length())+", content="+clientMsg);
    fgcom_rdfInfo_mtx.unlock();
    return clientMsg;
}


// Spawns the UDP client thread
bool udpClientRunning = false;
bool udpClientTerminate = false;
std::map<int, std::string> fgcom_cliudp_HostCfg;
std::map<int, uint16_t> fgcom_cliudp_portCfg;
void fgcom_spawnUDPClient() {
    pluginLog("[UDP-client] client initializing at rate "+std::to_string(FGCOM_UDPCLIENT_RATE)+" pakets/s");
    const float packetrate = FGCOM_UDPCLIENT_RATE;
    const int datarate = 1000000 * (1/packetrate);  //datarate in seconds*microseconds
    int fgcom_UDPClient_sockfd, rc; 
    struct sockaddr_in cliAddr;
    bool portEstablished = false;

    
    
    // Creating socket file descriptor 
    if ( (fgcom_UDPClient_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        pluginLog("[UDP-client] client ERROR: socket creation failed");
        return;
    }
    
    // bind client source port
    cliAddr.sin_family = AF_INET;
    cliAddr.sin_port = htons(0);
    cliAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    rc = bind ( fgcom_UDPClient_sockfd, (struct sockaddr *) &cliAddr, sizeof(cliAddr) );
    if (rc < 0) {
        pluginLog("[UDP-client] client ERROR: local source port binding failed");
        return;
    }

    udpClientRunning = true;
    udpClientTerminate = false;
    
    // Generate Data packets and send them in a loop
    while (!udpClientTerminate) {
        // sleep for datarate-time microseconds
        //pluginDbg("[UDP-client] client sleep for "+std::to_string(datarate)+" microseconds");
        std::this_thread::sleep_for(std::chrono::microseconds(datarate));
        //if(usleep(datarate) < 0) {
        //    pluginLog("[UDP-client] client socket creation failed"); 
        //    break;
        //}
        
        // evaluate all local identites and generate messages to their configured ports
        for (const auto &lcl_idty : fgcom_local_client) {
            int iid          = lcl_idty.first;
            fgcom_client lcl = lcl_idty.second;
            
            // fetch+configure host+port for that identities current port config
            if (lcl.clientHost == "" || lcl.clientPort <=0) {
                pluginDbg("[UDP-client] client sending skipped: no valid port config for identity="+std::to_string(iid));
                continue;
            }
            // Prepare addressing
            struct sockaddr_in remoteServAddr;
            remoteServAddr.sin_family = AF_INET;

            //bzero(&(remoteServAddr.sin_zero), 8);     /* zero the rest of the struct */
            remoteServAddr.sin_port = htons(lcl.clientPort);
#ifdef MINGW_WIN64
            remoteServAddr.sin_addr.s_addr = inet_addr(lcl.clientHost.c_str());
#else
            int pton_rc = inet_pton(AF_INET, lcl.clientHost.c_str(), &remoteServAddr.sin_addr);
            if (pton_rc < 0) {
                pluginLog("[UDP-client] pton ERROR: "+std::to_string(pton_rc));
                continue;
            }
#endif


            // Report if the identities port changed
            if (fgcom_cliudp_portCfg[iid] == 0 || fgcom_cliudp_portCfg[iid] != lcl.clientPort) {
                pluginLog("[UDP-client] client for '"+lcl.callsign+"' (iid="+std::to_string(iid)+") port="+std::to_string(fgcom_cliudp_portCfg[iid])+" switching to port "+std::to_string(lcl.clientPort));
                mumAPI.log(ownPluginID, std::string("UDP sending for '"+lcl.callsign+"' to client "+lcl.clientHost+":"+std::to_string(lcl.clientPort)+" enabled").c_str());
                fgcom_cliudp_HostCfg[iid] = lcl.clientHost;
                fgcom_cliudp_portCfg[iid] = lcl.clientPort;
            }
        
            // generate data.
            std::string udpdata = fgcom_rdf_generateMsg(lcl.clientHost, lcl.clientPort);
            //udpdata += "TEST-DEBUG";
            
            // send data
            if (udpdata.length() > 0) {
                // If there was data generated, add a FGCOM header
                if (udpdata.length() > 0) udpdata = "FGCOM v" 
                        + std::to_string(FGCOM_VERSION_MAJOR) + "."
                        + std::to_string(FGCOM_VERSION_MINOR) + "."
                        + std::to_string(FGCOM_VERSION_PATCH) 
                        + "\n"
                        + udpdata;
    
                pluginDbg("[UDP-client] client sending msg for iid="+std::to_string(iid)+" to client="+lcl.clientHost+":"+std::to_string(lcl.clientPort)+": '"+udpdata+"'");
                rc = sendto (fgcom_UDPClient_sockfd, udpdata.c_str(), strlen(udpdata.c_str()) + 1, 0,
                    (struct sockaddr *) &remoteServAddr,
                    sizeof (remoteServAddr));
                if (rc < 0) {
                    pluginLog("[UDP-client] client ERROR ("+std::to_string(rc)+") sending "+std::to_string(strlen(udpdata.c_str()))+" bytes of data");
                    close (fgcom_UDPClient_sockfd);
                    return;
                }
                
                pluginDbg("[UDP-client] client sending OK ("+std::to_string(strlen(udpdata.c_str()))+" bytes of data)");
                
            } else {
                // no data generated: do not send anything.
                pluginDbg("[UDP-client] client sending skipped: no data to send for iid="+std::to_string(iid)+" to client="+lcl.clientHost+":"+std::to_string(lcl.clientPort)+".");
            }
        }
        
    }
    
    
    close(fgcom_UDPClient_sockfd);
    udpClientRunning = false;
    udpClientTerminate = false;
    pluginLog("[UDP-client] thread finished.");
}

void fgcom_stopUDPClient() {
    udpClientTerminate = true;
}
