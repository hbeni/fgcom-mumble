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


// Plugin IO
//
// A) A simple udp input interface for the FGCom mumble plugin.
//    It spawns an UDP server that accepts state inforamtion.
//    The information is parsed and then put into a shared data
//    structure, from where the plugin can read the current state.
// B) Mumble internal plugin IO
//    Handles sending and receiving messages from mumbles interface.
//    Sending of messages ("notifications") is differentiated between
//    "urgent" and "not-urgent" messages. "urgent" ones are sent directly
//    after change, whereas "not-urgent" ones are handled by a separate
//    notification thread to cap the maximum of sent updates by time.
//

#include <iostream>
#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sstream> 
#include <regex>
#include <sys/types.h> 
#include <math.h>

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
#include "rdfUDP.h"
#include "MumblePlugin.h"
#include "fgcom-mumble.h"


// These are just some utility functions facilitating writing logs and the like
// The actual implementation of the plugin is further down
std::ostream& pLog() {
    std::cout << "FGCom: ";
    return std::cout;
}

template<typename T>
void pluginLog(T log) {
    pLog() << log << std::endl;
}
template<typename T>
void pluginDbg(T log) {
    #ifdef DEBUG
    // only log if we build in debug mode
    pLog() << "[DBG] " << log << std::endl;
    #endif
}



/*****************************************************
 *               Plugin communications               *
 ****************************************************/

bool fgcom_isConnectedToServer() {
    //pluginDbg("fgcom_isConnectedToServer(): checking connection");
    bool synchronized;
    int resCode = mumAPI.isConnectionSynchronized(ownPluginID, activeConnection, &synchronized);
    if (STATUS_OK != resCode) {
   //     pluginDbg("fgcom_isConnectedToServer(): internal error executing isConnectionSynchronized(): rc="+std::to_string(resCode));
        return false;
    } else {
    //    pluginDbg("fgcom_isConnectedToServer(): synchstate="+std::to_string(synchronized));
    }
    return synchronized;
}

void notifyRemotes(int iid, FGCOM_NOTIFY_T what, int selector, mumble_userid_t tgtUser) {
    std::setlocale(LC_NUMERIC,"C"); // decial points always ".", not ","
    std::string dataID("");  // FGCOM<something>
    std::string message(""); // the message as sting data (yeah, i'm lazy but it parses so easily and is human readable and therefore easy to debug)
    
    // check if we are connected and synchronized
    pluginDbg("notifyRemotes("+std::to_string(iid)+","+std::to_string(what)+","+std::to_string(selector)+","+std::to_string(tgtUser)+") called");
    if (!fgcom_isConnectedToServer()) {
        pluginDbg("notifyRemotes(): not connected, so not notifying.");
        return;
    } else {
        pluginDbg("notifyRemotes(): we are connected, so notifications will be sent.");
    }
    
    // If all identities are selected, invoke notifyRemotes() for each of them
    if (iid == NTFY_ALL) {
        pluginDbg("notifyRemotes(): identities: all selected, resolving...");
        for (const auto &idty : fgcom_local_client) {
            notifyRemotes(idty.first, what, selector, tgtUser);
        }
        return;
    } else {
        // skip notification attempts if we don't have an state yet
        pluginDbg("notifyRemotes(): no local state yet, skipping notifications.");
        if (fgcom_local_client.size() == 0 ) return;
    }

    // resolve selected identity
    fgcom_client lcl;
    if (fgcom_local_client.count(iid) > 0) {
        lcl = fgcom_local_client[iid];
        pluginDbg("notifyRemotes(): successfully resolved identity='"+std::to_string(iid)+"' (callsign="+lcl.callsign+")");
    } else {
        pluginLog("notifyRemotes(): ERROR resolving identity='"+std::to_string(iid)+"'!");
        return;
    }
    
    // @param what:  0=all local info; 1=location data; 2=comms, 3=ask for data, 4=userdata, 5=ping
    // @param selector: ignored, when 'what'=NTFY_COM: id of radio (0=COM1,1=COM2,...); -1 sends all radios
    switch (what) {
        case NTFY_ALL:
            // notify all info
            pluginDbg("notifyRemotes(): selected: all");
            notifyRemotes(iid, NTFY_USR, NTFY_ALL, tgtUser);  // userdata
            notifyRemotes(iid, NTFY_LOC, NTFY_ALL, tgtUser);  // location
            notifyRemotes(iid, NTFY_COM, NTFY_ALL, tgtUser);  // radios
            return;
            
        case NTFY_LOC:
            // Notify on location
            pluginDbg("notifyRemotes(): selected: location");
            dataID  = "FGCOM:UPD_LOC:"+std::to_string(iid);
            message = "LAT="+std::to_string(lcl.lat)+","
                     +"LON="+std::to_string(lcl.lon)+","
                     +"ALT="+std::to_string(lcl.alt)+",";
            break;
            
        case NTFY_COM:
            // notify on radio state
            pluginDbg("notifyRemotes(): selected radio");            
            if (selector == NTFY_ALL) {
                pluginDbg("notifyRemotes():    all radios selected");
                for (int ri=0; ri < lcl.radios.size(); ri++) {  
                    notifyRemotes(iid, NTFY_COM, ri, tgtUser);
                }
            } else {
                pluginDbg("notifyRemotes():    send state of COM"+std::to_string(selector+1) );
                dataID  = "FGCOM:UPD_COM:"+std::to_string(iid)+":"+std::to_string(selector);
                message = "FRQ="+lcl.radios[selector].frequency+","
                        //+ "VLT="+std::to_string(lcl.radios[selector].volts)+","
                        //+ "PBT="+std::to_string(lcl.radios[selector].power_btn)+","
                        //+ "SRV="+std::to_string(lcl.radios[selector].serviceable)+","
                        + "PTT="+std::to_string(lcl.radios[selector].ptt)+","
                        //+ "VOL="+std::to_string(lcl.radios[selector].volume)+","
                        + "PWR="+std::to_string(lcl.radios[selector].pwr);
                    // ^^ Save bandwith: We do not need all state on the other clients currently. Once we do, we can just uncomment this and the code to handle it is already implemented :)
                    // Ah yeah, and we must uncomment the change-detection down at fgcom_udp_parseMsg(), otherwise the changes get not detected
            }
            
            break;
        
        case NTFY_ASK:
            // we ask all other clients to send us their data
            dataID  = "FGCOM:ICANHAZDATAPLZ";
            message = "allYourDataBelongsToUs!";
            break;
            
        case NTFY_USR:
            // userstate
            pluginDbg("notifyRemotes(): selected: userdata");
            dataID  = "FGCOM:UPD_USR:"+std::to_string(iid);
            message = "CALLSIGN="+lcl.callsign;
            break;

        case NTFY_PNG:
            // Ping-Packet: notify that we are still alive, but data did not change
            dataID  = "FGCOM:PING";
            message = "";
            for (const auto &idty : fgcom_local_client) {
                if (message.length() > 0) message += ",";
                message += std::to_string(idty.first);
            }
            break;
            
        default: 
            pluginDbg("notifyRemotes("+std::to_string(iid)+","+std::to_string(what)+","+std::to_string(selector)+","+std::to_string(tgtUser)+"): 'what' unknown");
            return;
    }
    
    
    // Now get all known FGCom users of the current channel.
    // to those we will push the update.
    size_t userCount;
	mumble_userid_t *userIDs;
	if (fgcom_specialChannelID > -1) {
        //if (mumAPI.getAllUsers(ownPluginID, activeConnection, &userIDs, &userCount) != STATUS_OK) {
        if (mumAPI.getUsersInChannel(ownPluginID, activeConnection, fgcom_specialChannelID, &userIDs, &userCount) != STATUS_OK) {
            pluginLog("[ERROR]: Can't obtain user list");
            return;
        } else {
            pluginDbg("There are "+std::to_string(userCount)+" users on this channel.");
            if (userCount > 1) {
                if (tgtUser > 0) {
                    // a specific user was requested
                    // (note: 0 is usually the id of the superuser, ordinary users star with 1)
                    if (tgtUser != lcl.mumid) {
                        pluginDbg("  sending message to targeted user: "+std::to_string(tgtUser));
                        int send_res = mumAPI.sendData(ownPluginID, activeConnection, &tgtUser, 1, message.c_str(), strlen(message.c_str()), dataID.c_str());
                        if (send_res != STATUS_OK) {
                            pluginDbg("  message sent ERROR: "+std::to_string(send_res));
                        } else {
                            pluginDbg("  message sent to "+std::to_string(userCount-1)+" clients");
                        }
                    } else {
                        pluginDbg("  ignored targeted user; he is local: id="+std::to_string(tgtUser));
                    }
                } else {
                    // Notify all users;
                    // remove local id from that array to prevent sending updates to ourselves
                    mumble_userid_t exclusiveUserIDs[userCount-1];
                    int o = 0;
                    for(size_t i=0; i<userCount; i++) {
                        if (userIDs[i] != lcl.mumid) {
                            exclusiveUserIDs[o] = userIDs[i];
                            pluginDbg("  sending message to: "+std::to_string(userIDs[i]));
                            o++;
                        } else {
                            pluginDbg("  ignored local user: id="+std::to_string(userIDs[i]));
                        }
                    }
                
                    int send_res = mumAPI.sendData(ownPluginID, activeConnection, exclusiveUserIDs, userCount-1, message.c_str(), strlen(message.c_str()), dataID.c_str());
                    if (send_res != STATUS_OK) {
                        pluginDbg("  message sent ERROR: "+std::to_string(send_res));
                    } else {
                        pluginDbg("  message sent to "+std::to_string(userCount-1)+" clients");
                    }
                }

            }

            mumAPI.freeMemory(ownPluginID, userIDs);
            pluginDbg("  notification for dataID='"+dataID+"' done.");
        }
    } else {
        pluginDbg("  notification not possible: unable to get local fgcom special channel id");
    }
    
    
}

std::mutex fgcom_remotecfg_mtx;  // mutex lock for remote data
std::map<mumble_userid_t, std::map<int, fgcom_client> > fgcom_remote_clients; // remote radio config
bool handlePluginDataReceived(mumble_userid_t senderID, std::string dataID, std::string data) {
    // Handle the incoming data (if it belongs to us)
    std::setlocale(LC_NUMERIC,"C"); // decial points always ".", not ","
    
    if (dataID.substr(0,5) == "FGCOM") {
        // Data is for our plugin
        mumble_userid_t clientID = senderID;  // get mumble client id
        std::regex parse_key_value ("^(\\w+)=(.+)"); // prepare a regex for simpler parsing
        
        // Get identity id
        int iid = -1;
        std::regex get_iid_re ("^FGCOM:\\w+:(\\d+)");
        std::smatch smc_iid;
        if (std::regex_search(dataID, smc_iid, get_iid_re)) {
            iid = stoi(smc_iid[1]);
            if (iid < 0) return false; // enforce >= 0 for supplied id
        }
        std::string iid_str = std::to_string(iid);
        
        fgcom_remotecfg_mtx.lock();
        
        // check if user is already known to us; if not add him to the local clients store
        auto search = fgcom_remote_clients.find(clientID);
        if (iid > -1 && search == fgcom_remote_clients.end()) {
            pluginDbg("[mum_pluginIO] registering new remote: Sender="+std::to_string(clientID)+" identity="+std::to_string(iid));
            fgcom_remote_clients[clientID][iid]       = fgcom_client();
        }
        
        // store that we have seen something for a valid identity
        if (iid > -1 ) {
            fgcom_remote_clients[clientID][iid].lastUpdate = std::chrono::system_clock::now();
            fgcom_remote_clients[clientID][iid].mumid = clientID; // update mumble client id for that identity
        }
        
        // Parse the data, depending on packet type
        if (dataID == "FGCOM:ICANHAZDATAPLZ") {
            // client asks for our current state
            pluginDbg("Data update requested: Sender="+std::to_string(clientID)+" DataID="+dataID);
            notifyRemotes(NTFY_ALL, NTFY_ALL, -1, clientID); // notify the sender with all our data
        
        
        } else if (dataID == "FGCOM:PING") {
            // ping packet contains list of IIDs which are alive.
            pluginDbg("FGCom: [mum_pluginIO] ping received, idtys="+data);
            std::stringstream streambuffer(data);
            std::string segment;
            while(std::getline(streambuffer, segment, ',')) {
                try {
                    int rmt_iid = stoi(segment);
                    if (fgcom_remote_clients[clientID].count(rmt_iid) > 0) {
                        fgcom_remote_clients[clientID][rmt_iid].lastUpdate = std::chrono::system_clock::now();
                    }
                
                } catch (const std::exception& e) {
                    pluginDbg("[mum_pluginIO] Parsing ping packet throw exception, ignoring token "+segment);
                }
            }
            
        
        // Userdata and Location data update are treated the same
        } else if (dataID == "FGCOM:UPD_USR:"+iid_str
                || dataID == "FGCOM:UPD_LOC:"+iid_str) {
            pluginDbg("USR/LOC UPDATE: Sender="+std::to_string(clientID)+" DataID="+dataID+" DATA="+data);
            
            // update properties
            std::stringstream streambuffer(data);
            std::string segment;
            while(std::getline(streambuffer, segment, ',')) {
                // example: FRQ=1234,VLT=12,000000,PBT=1,SRV=1,PTT=0,VOL=1,000000,PWR=10,000000   segment=FRQ=1234
                pluginDbg("[mum_pluginIO] Segment="+segment);
                
                try {
                                
                    std::smatch sm;
                    if (std::regex_search(segment, sm, parse_key_value)) {
                        // this is a valid token. Lets parse it!
                        std::string token_key   = sm[1];
                        std::string token_value = sm[2];
                        pluginDbg("[mum_pluginIO] Parsing token: "+token_key+"="+token_value);
                        
                        // Location data
                        if (token_key == "LON")      fgcom_remote_clients[clientID][iid].lon      = std::stof(token_value);
                        if (token_key == "LAT")      fgcom_remote_clients[clientID][iid].lat      = std::stof(token_value);
                        if (token_key == "ALT")      fgcom_remote_clients[clientID][iid].alt      = std::stof(token_value);  // ALT in meters above ground!
                        
                        // Userdata
                        if (token_key == "CALLSIGN") fgcom_remote_clients[clientID][iid].callsign = token_value; 
                        
                    } else {
                        // ignore, segment was not in key=value format
                    }
                 
                // done with parsing?
                } catch (const std::exception& e) {
                    pluginDbg("[mum_pluginIO] Parsing throw exception, ignoring token "+segment);
                }
            }
        
        
        } else if (dataID.substr(0, 15+iid_str.length()) == "FGCOM:UPD_COM:"+iid_str+":") {
            // Radio data update. Here the radio in question was given in the dataid.
            pluginDbg("COM UPDATE: Sender="+std::to_string(clientID)+" DataID="+dataID+" DATA="+data);
            int radio_id = std::stoi(dataID.substr(15+iid_str.length())); // when segfault: indicates problem with the implemented udp protocol
            
            // if the selected radio does't exist, create it now
            if (fgcom_remote_clients[clientID][iid].radios.size() < radio_id+1) {
                for (int cr = fgcom_remote_clients[clientID][iid].radios.size(); cr < radio_id+1; cr++) {
                    fgcom_remote_clients[clientID][iid].radios.push_back(fgcom_radio()); // add new radio instance with default values
                }
            }
            
            // update the radios properties
            std::stringstream streambuffer(data);
            std::string segment;
            while(std::getline(streambuffer, segment, ',')) {
                // example: FRQ=1234,VLT=12,000000,PBT=1,SRV=1,PTT=0,VOL=1,000000,PWR=10,000000   segment=FRQ=1234
                pluginDbg("[mum_pluginIO] Segment="+segment);
                
                try {        
                    std::smatch sm;
                    if (std::regex_search(segment, sm, parse_key_value)) {
                        // this is a valid token. Lets parse it!
                        //printf("Parsing token: %s=%s\n", token_key.c_str(), token_value.c_str());
                        std::string token_key   = sm[1];
                        std::string token_value = sm[2];
                        pluginDbg("[mum_pluginIO] Parsing token: "+token_key+"="+token_value);
                        
                        if (token_key == "FRQ") {
                            // expected is real wave carrier frequency, so something with at least 4 decimals
                            fgcom_remote_clients[clientID][iid].radios[radio_id].frequency = token_value;
                        }
                        if (token_key == "VLT") fgcom_remote_clients[clientID][iid].radios[radio_id].volts       = std::stof(token_value);
                        if (token_key == "PBT") fgcom_remote_clients[clientID][iid].radios[radio_id].power_btn   = (token_value == "1")? true : false;
                        if (token_key == "SRV") fgcom_remote_clients[clientID][iid].radios[radio_id].serviceable = (token_value == "1")? true : false;
                        if (token_key == "PTT") {
                            bool v = (token_value == "1")? true : false;
                            fgcom_remote_clients[clientID][iid].radios[radio_id].ptt = v;
                        }
                        if (token_key == "VOL") fgcom_remote_clients[clientID][iid].radios[radio_id].volume      = std::stof(token_value);
                        if (token_key == "PWR") fgcom_remote_clients[clientID][iid].radios[radio_id].pwr         = std::stof(token_value);      
                        
                    } else {
                        // ignore, segment was not in key=value format
                    }
                 
                // done with parsing?
                } catch (const std::exception& e) {
                    pluginLog("[mum_pluginIO] Parsing throw exception, ignoring token "+segment);
                }
            }


            
        } else {
            pluginDbg("FGCom: [mum_pluginIO] dataID='"+dataID+"' not known. Ignoring.");
        }
        
        fgcom_remotecfg_mtx.unlock();
        
        pluginDbg("FGCom: [mum_pluginIO] Parsing done.");
        return true; // signal to other plugins that the data was handled already
        
    } else {
        return false; // packet does not belong to us. other plugins should also receive it
    }

}


std::map<int, fgcom_client> lastNotifiedState;  // holds the last data we did sent out, so we can detect changes (and how much)
const std::chrono::milliseconds notifyPingInterval = std::chrono::milliseconds(NOTIFYPINGINTERVAL);
auto lastPing = std::chrono::system_clock::now();
void fgcom_notifyThread() {
    while (true) {
        if (fgcom_isPluginActive()) {
            // if plugin is active, check if we need to send notifications.
            
            // Note: we are just looking at location and userdata. Radio data is "urgent" and notified directly.
            // Difference with 3 decimals is about 100m: http://wiki.gis.com/wiki/index.php/Decimal_degrees
            for (const auto &idty : fgcom_local_client) {
                int iid          = idty.first;
                fgcom_client lcl = idty.second;
                bool notifyUserData     = false;
                bool notifyLocationData = false;
                fgcom_remotecfg_mtx.lock();
                
                if (fabs(lcl.lat - lastNotifiedState[iid].lat) >= 0.0005) { // about 40-50m
                    lastNotifiedState[iid].lat = lcl.lat;
                    notifyLocationData = true;
                }
                if (fabs(lcl.lon - lastNotifiedState[iid].lon) >= 0.0005) { // about 40-50m
                    lastNotifiedState[iid].lon = lcl.lon;
                    notifyLocationData = true;
                }
                if (fabs(lcl.alt - lastNotifiedState[iid].alt) >= 5) {  // 5 meters
                    lastNotifiedState[iid].alt = lcl.alt;
                    notifyLocationData = true;
                }
                if (lcl.callsign != lastNotifiedState[iid].callsign) {
                    lastNotifiedState[iid].callsign = lcl.callsign;
                    notifyUserData = true;
                }
                
                fgcom_remotecfg_mtx.unlock();
                
                // We did not have a change for several seconds.
                // We should send something so other clients know we are still alive!
                if (!notifyUserData && std::chrono::system_clock::now() > lastPing + notifyPingInterval) {
                    pluginDbg("FGCom: [mum_pluginIO] fgcom_notifyThread() Ping is due.");
                    lastPing = std::chrono::system_clock::now();
                    notifyRemotes(iid, NTFY_PNG);
                }
                
                // Location has changed significantly: notify!
                if (notifyLocationData) {
                    pluginDbg("FGCom: [mum_pluginIO] fgcom_notifyThread() locationdata was changed.");
                    lastPing = std::chrono::system_clock::now();
                    notifyRemotes(iid, NTFY_LOC);
                }
                
                // userdata has changed: notify!
                if (notifyUserData) {
                    pluginDbg("FGCom: [mum_pluginIO] fgcom_notifyThread() userdata was changed.");
                    lastPing = std::chrono::system_clock::now();
                    notifyRemotes(iid, NTFY_USR);
                }
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(NOTIFYINTERVAL));
    }
}





/*****************************************************
 *                     UDP Server                    *
 * The UDP interface is the plugins port to receive  *
 * configuration state from the outside world.       *
 * It is used for example from ATC clients or        *
 * FlightSims to inform the plugin of local state.   *
 ****************************************************/



/*
 * Process a received message:
 * Read the contents and put them into the shared structure.
 * This will be called from the UDP server thread when receiving new data.
 * 
 * Note: uses the global fgcom_local_client structure and fgcom_localcfg_mtx!
 * Note: Radio changes and userstate must trigger instant notification to other clients, but
 *       location data is not that urgent and changes often fractionally. We use the notification threat for that.
 *
 * @param buffer The char buffer to parse
 * @return map that indicates applied changes per identity
 */
std::mutex fgcom_localcfg_mtx;
std::map<int, fgcom_client> fgcom_local_client;
std::map<uint16_t, int> fgcom_udp_portMap; // port2iid
bool fgcom_com_ptt_compatmode = false;
std::map<int, fgcom_udp_parseMsg_result> fgcom_udp_parseMsg(char buffer[MAXLINE], uint16_t clientPort) {
    pluginDbg("[UDP] received message (clientPort="+std::to_string(clientPort)+"): "+std::string(buffer));
    //std::cout << "DBG: Stored local userID=" << localMumId <<std::endl;
    std::setlocale(LC_NUMERIC,"C"); // decial points always ".", not ","
    
    // prepare return map
    std::map<int, fgcom_udp_parseMsg_result> parseResult;
    
    int iid = -1; // current IID selector for this message
    
    // markers for ALT/HGT resolution
    // iid => new_value
    std::map<int, float> hgt_value;
    std::map<int, float> alt_value;

    // convert to stringstream so we can easily tokenize
    // TODO: why not simply refactor to strtok()?
    std::stringstream streambuffer(buffer); //std::string(buffer)
    std::string segment;
    std::regex parse_key_value ("^(\\w+)=(.+)");
    std::regex parse_COM ("^(COM)(\\d+)_(.+)");
    fgcom_localcfg_mtx.lock();
    while(std::getline(streambuffer, segment, ',')) {
        pluginDbg("[UDP] Segment='"+segment+"'");

        try {
            std::smatch sm;
            if (std::regex_search(segment, sm, parse_key_value)) {
                // this is a valid token. Lets parse it!
                std::string token_key   = sm[1];
                std::string token_value = sm[2];
                pluginDbg("[UDP] Parsing token: "+token_key+"="+token_value);
                
                /* Get IID for this connection.
                * Either it is overridden from the IID token,
                * othwerwise an IID from the client portmapper.
                */
                if (token_key == "IID") {
                    // Token override:
                    // let's see if we can find the IID in the portmapper.
                    // so we will return the proper ID
                    bool iid_port_found = false;
                    iid = stoi(token_value);
                    for (const auto &pm : fgcom_udp_portMap) {
                        
                        if (pm.second == iid) {
                            // we had seen that iid before, use it's port
                            iid_port_found = true;
                            clientPort = pm.first;
                            break;
                        }
                    }
                    if (!iid_port_found) {
                        // we did not see this iid so far so we need to establish it new.
                        // this happens automatically and defaults to the current client port.
                        // it may later be overridden by RDP_PORT= field.
                        fgcom_udp_portMap[clientPort] = iid;  // add info to portmapper, so it reports the right iid
                    }
                }


                // Get IID from client portmapper (if not overridden already)
                // This will map UDP client ports to identity IDs, so basicly we establish
                // that each UDP client is a unique identity (unless already overridden).
                if (iid == -1) {
                    if (fgcom_udp_portMap.count(clientPort) == 0) {
                        // register new client port to portmap.
                        // (IIDs are counted upwards from zero, so we save bandwith when transmitting packets)
                        int freeIID = 0;
                        for (const auto &fc : fgcom_udp_portMap) {
                            if (fc.second >= freeIID) freeIID = fc.second + 1;
                        }
                        fgcom_udp_portMap[clientPort] = freeIID;
                    }
                    iid = fgcom_udp_portMap[clientPort];
                    pluginDbg("[UDP] identity portmap result: port("+std::to_string(clientPort)+") => iid("+std::to_string(iid)+")");
                }
                
                // see if we need to establish the local client state for the iid
                if (fgcom_local_client.count(iid) == 0 ) {
                    fgcom_local_client[iid]       = fgcom_client();
                    fgcom_local_client[iid].mumid = localMumId; // copy default id
                    pluginDbg("[UDP] new identity registered: iid="+std::to_string(iid)+"; clientPort="+std::to_string(clientPort));
                } else {
                    // Update that we have received some data
                    if (token_key != "IID") {
                        fgcom_local_client[iid].lastUpdate = std::chrono::system_clock::now();
                    }
                    
                    fgcom_local_client[iid].clientPort = clientPort; // ensure valid and current clientPort
                }
                
                std::smatch smc;
                if (std::regex_search(token_key, smc, parse_COM)) {
                    /*
                     * COM Radio mode detected
                     */
                    
                    std::string radio_type = smc[1];
                    std::string radio_nr   = smc[2];
                    std::string radio_var  = smc[3];
                    
                    // if the selected radio does't exist, create it now
                    int radio_id = std::stoi(radio_nr.c_str());  // COM1 -> 1
                    if (radio_id < 1){
                        pluginLog("[UDP] Token ignored: radio_id outOfBounds (COM starts at 'COM1'!) "+token_key+"="+token_value);
                        continue; // if radio index not valid (ie. "COM0"): skip the token
                    }
                    if (fgcom_local_client[iid].radios.size() < radio_id) {
                        for (int cr = fgcom_local_client[iid].radios.size(); cr < radio_id; cr++) {
                            pluginLog("[UDP]   create new local radio instance: "+std::to_string(cr));
                            fgcom_local_client[iid].radios.push_back(fgcom_radio()); // add new radio instance with default values
                            parseResult[iid].radioData.insert(radio_id-1);
                        }
                    }
                    radio_id--; // convert to array index
                    
                    if (radio_var == "FRQ") {
                        // Frequency handling is a bit difficult (see https://github.com/hbeni/fgcom-mumble/issues/34):
                        // - we expect real wave frequencies here.
                        // - old FGCom interface had sended channel names (which, in 8.33 spacing do not translate directly to real wave frequencies)
                        // - result is, we must convert in some circumstances.
                        //
                        // also the provided value may be containing illegal stuff like trailing/leading spaces/zeroes; so, it must be normalized.
                        fgcom_radiowave_freqConvRes frq_parsed = fgcom_radiowave_splitFreqString(token_value);  // results in a cleaned frequency
                        std::string finalParsedFRQ;
                        if (frq_parsed.isNumeric) {
                            // frequency is a numeric string.
                            // Let's check the decimals to decide if it is new or old format
                            if (std::regex_match(frq_parsed.frequency, std::regex("^\\d+\\.\\d{4,}$") )) {
                                // numeric frequency detected with >=4 decimals: treat as real wave frequency
                                pluginDbg("[UDP] detected real wave frequency format="+token_value);
                                finalParsedFRQ = frq_parsed.prefix + frq_parsed.frequency;
                                
                            } else {
                                // FGCom 3.0 compatibility mode:
                                // we expect 25kHz or 8.33 channel names here.
                                // So if we encounter such data, we probably need to convert the frequency part
                                pluginDbg("[UDP] detected old FGCom frequency format="+token_value);
                                finalParsedFRQ = frq_parsed.prefix + fgcom_radiowave_conv_chan2freq(frq_parsed.frequency);
                                pluginDbg("[UDP] conversion result to realFreq="+finalParsedFRQ);
                            }
                        } else {
                            // not numeric: use as-is.
                            finalParsedFRQ = frq_parsed.frequency;  // already cleaned value
                            pluginDbg("[UDP] using FRQ as-is (non-numeric)");
                        }
                        
                        // handle final COMn_FRQ parsing result
                        std::string oldValue = fgcom_local_client[iid].radios[radio_id].frequency;
                        fgcom_radiowave_freqConvRes frq_ori = fgcom_radiowave_splitFreqString(oldValue);
                        fgcom_local_client[iid].radios[radio_id].frequency = finalParsedFRQ; // already cleaned value
                        
                        // see if we need to notify:
                        // - for changed non-numeric, always if its different
                        // - for change in numeric/non-numeric, also always if its different
                        // - for numeric ones, if the prefix did change, or the frequency is different for more than rounding errors
                        fgcom_radiowave_freqConvRes frq_new = fgcom_radiowave_splitFreqString(finalParsedFRQ);
                        if (frq_ori.isNumeric && frq_new.isNumeric && frq_ori.prefix == frq_new.prefix) {
                            // both are numeric and the prefix did not change: only notify if frequency changed that much
                            float frq_diff = std::fabs(std::stof(frq_ori.frequency) - std::stof(frq_new.frequency));
                            //pluginDbg("[UDP] COMM frq diff="+std::to_string(frq_diff)+"; old="+oldValue+"; new="+finalParsedFRQ);
                            if ( frq_diff > 0.000010 ) parseResult[iid].radioData.insert(radio_id);
                        } else {
                            if (fgcom_local_client[iid].radios[radio_id].frequency != oldValue ) parseResult[iid].radioData.insert(radio_id);
                        }
                    }
                    if (radio_var == "VLT") {
                        float oldValue = fgcom_local_client[iid].radios[radio_id].volts;
                        fgcom_local_client[iid].radios[radio_id].volts       = std::stof(token_value);
                        // do not send right now: if (fgcom_local_client[iid].radios[radio_id].volts != oldValue ) parseResult[iid].radioData.insert(radio_id);
                    }
                    if (radio_var == "PBT") {
                        bool oldValue = fgcom_local_client[iid].radios[radio_id].power_btn;
                        fgcom_local_client[iid].radios[radio_id].power_btn   = (token_value == "1" || token_value == "true")? true : false;
                        // do not send right now: if (fgcom_local_client[iid].radios[radio_id].power_btn != oldValue ) parseResult[iid].radioData.insert(radio_id);
                    }
                    if (radio_var == "SRV") {
                        bool oldValue = fgcom_local_client[iid].radios[radio_id].serviceable;
                        fgcom_local_client[iid].radios[radio_id].serviceable = (token_value == "1" || token_value == "true")? true : false;
                        // do not send right now: if (fgcom_local_client[iid].radios[radio_id].serviceable != oldValue ) parseResult[iid].radioData.insert(radio_id);
                    }
                    if (radio_var == "PTT") {
                        // depends if we are previously have been in old compat mode (a single PTT property)
                        // if yes: we need to ignore the "PTT disabled" request, because it is probably always 0
                        bool parsedPTT = (token_value == "1" || token_value == "true")? true : false;
                        
                        // PTT was set to true with the new way: we disable compat mode and take it
                        if (parsedPTT && fgcom_com_ptt_compatmode) fgcom_com_ptt_compatmode = false; 
                        
                        if (!fgcom_com_ptt_compatmode) {
                            bool oldValue = fgcom_local_client[iid].radios[radio_id].ptt;
                            fgcom_local_client[iid].radios[radio_id].ptt = parsedPTT;
                            if (fgcom_local_client[iid].radios[radio_id].ptt != oldValue ) parseResult[iid].radioData.insert(radio_id);
                            fgcom_handlePTT();
                        }

                    }
                    if (radio_var == "VOL") {
                        float oldValue = fgcom_local_client[iid].radios[radio_id].volume;
                        fgcom_local_client[iid].radios[radio_id].volume      = std::stof(token_value);
                        // do not send right now: if (fgcom_local_client[iid].radios[radio_id].volume != oldValue ) parseResult[iid].radioData.insert(radio_id);
                    }
                    if (radio_var == "PWR") {
                        float oldValue = fgcom_local_client[iid].radios[radio_id].pwr;
                        fgcom_local_client[iid].radios[radio_id].pwr = std::stof(token_value);
                        if (fgcom_local_client[iid].radios[radio_id].pwr != oldValue ) parseResult[iid].radioData.insert(radio_id);
                    }
                    if (radio_var == "SQC") {
                        float oldValue = fgcom_local_client[iid].radios[radio_id].squelch;
                        fgcom_local_client[iid].radios[radio_id].squelch = std::stof(token_value);
                        // do not send right now: if (fgcom_local_client[iid].radios[radio_id].squelch != oldValue ) parseResult[iid].radioData.insert(radio_id);
                    }
                    if (radio_var == "RDF") {
                        bool oldValue = fgcom_local_client[iid].radios[radio_id].rdfEnabled;
                        fgcom_local_client[iid].radios[radio_id].rdfEnabled = (token_value == "1" || token_value == "true")? true : false;
                        // do not send this: its only ever local state!  parseResult[iid].radioData.insert(radio_id);

                        // start new UDP client thread if requested
                        //pluginDbg("[UDP] RDF start thread check: registeredClientPort="+std::to_string(fgcom_local_client[iid].clientPort)+"; rdfClientRunning="+std::to_string(rdfClientRunning));
                        if (fgcom_local_client[iid].clientPort > 0 && !rdfClientRunning) {
                            pluginDbg("[UDP] RDF client requested: "+std::to_string(fgcom_local_client[iid].clientPort));
                            std::thread rdfudpClientThread(fgcom_spawnRDFUDPClient);
                            rdfudpClientThread.detach();
                            //std::cout << "FGCOM: udp client started; id=" << udpClientThread_id << std::endl;
                            pluginDbg("[UDP] RDF udp client started");
                        }
                    }
                  
                }
                
                
                /* 
                 * User client values.
                 */
                if (token_key == "LON") {
                    float oldValue = fgcom_local_client[iid].lon;
                    fgcom_local_client[iid].lon = std::stof(token_value);
                    parseResult[iid].locationData = true;
                }
                if (token_key == "LAT") {
                    float oldValue = fgcom_local_client[iid].lat;
                    fgcom_local_client[iid].lat = std::stof(token_value);
                    parseResult[iid].locationData = true;
                }
                if (token_key == "HGT") {
                    // HGT comes in ft ASL. We need meters however
                    hgt_value[iid] = std::stof(token_value) / 3.2808;
                    // note: value not stored here, because it may conflict with ALT; see some lines below
                    parseResult[iid].locationData = true;
                }
                if (token_key == "CALLSIGN") {
                    std::string oldValue = fgcom_local_client[iid].callsign;
                    fgcom_local_client[iid].callsign = token_value;
                    if (fgcom_local_client[iid].callsign != oldValue ) parseResult[iid].userData = true;
                }
                
                
                /*
                 * FGCom 3.0 compatibility
                 */
                if (token_key == "ALT") {
                    // ALT comes in ft ASL. We need meters however
                    alt_value[iid] = std::stof(token_value) / 3.2808;
                    // note: value not stored here, because it may conflict with ALT; see some lines below
                    parseResult[iid].locationData = true;
                }
                if (token_key == "PTT") {
                    // PTT contains the ID of the used radio (0=none, 1=COM1, 2=COM2)
                    int ptt_id = std::stoi(token_value);
                    
                    // handle compat mode switch: if we receive PTT in the old way, we switch it on
                    if (ptt_id > 0) fgcom_com_ptt_compatmode = true;
                    
                    if (fgcom_com_ptt_compatmode) {
                        pluginDbg("DBG_PTT:  ptt_id="+std::to_string(ptt_id));
                        for (int i = 0; i<fgcom_local_client[iid].radios.size(); i++) {
                            pluginDbg("DBG_PTT:    check i("+std::to_string(i)+")==ptt_id-1("+std::to_string(ptt_id-1)+")");
                            if (i == ptt_id - 1) {
                                if (fgcom_local_client[iid].radios[i].ptt != 1){
                                    parseResult[iid].radioData.insert(i);
                                    fgcom_local_client[iid].radios[i].ptt = 1;
                                }
                            } else {
                                if (fgcom_local_client[iid].radios[i].ptt == 1){
                                    parseResult[iid].radioData.insert(i);
                                    fgcom_local_client[iid].radios[i].ptt = 0;
                                }
                            }
                        }
                    }
                    fgcom_handlePTT();
                }
                if (token_key == "OUTPUT_VOL") {
                    // Set all radio instances to the selected volume
                    float comvol = std::stof(token_value);
                    for (int i = 0; i<fgcom_local_client[iid].radios.size(); i++) {
                        fgcom_local_client[iid].radios[i].volume = comvol;
                    }
                }
                
                
                /*
                 * Plugin Configuration
                 */
                if (token_key == "UDP_TGT_PORT") {
                    // RDF Port change request: we need to adjust portmapper and local port
                    clientPort                         = std::stoi(token_value);
                    fgcom_local_client[iid].clientPort = clientPort;
                    fgcom_udp_portMap[clientPort]      = iid;        // add info to portmapper, so it reports the right iid
                    if (rdfClientRunning) {
                        pluginDbg("[UDP] RDF port info change: iid="+std::to_string(iid)+"; port="+std::to_string(fgcom_local_client[iid].clientPort));
                        // running thread will handle the change to fgcom_local_client[iid].clientPort
                    }
                }
                
                
                // Enable/Disable radio audio effects
                if (token_key == "AUDIO_FX_RADIO") {
                    fgcom_cfg.radioAudioEffects = (token_value == "0" || token_value == "false" || token_value == "off")? false : true;
                }
            
           
            } else {
                // this was an invalid token. skip it silently.
                pluginDbg("[UDP] segment invalid (is no key=value format): "+segment);
            }
            
        // done with parsing?
        } catch (const std::exception& e) {
            pluginDbg("[UDP] Parsing throw exception, ignoring segment "+segment);
        }
        
    }  //endwhile
    
    
    /*
     * Inspect HGT/ALT state
     * 
     * NOTE: The old FGcom protocol transmit above sea level. As long as we are not
     * using ground terrain information to get the height above surface, we have a too high
     * range for the radios...
     * The geoid however is some meanASL, so the difference between sea level and ground
     * level is falsely added to our height, resulting in a much further radio horizon.
     * This should be only an issue with VFR and low flight levels, however, as the
     * decreases with fly altitude. The only good option is to incorporate a terrain model
     * to be able to calculate the true AGL from the ASL value.
     */
    for (const auto &p : alt_value) {   // we walk all ALT changes and convert them to HGT ones, if there is no HGT already.
        if (hgt_value.count(p.first) <= 0) {
            hgt_value[p.first] = p.second;
        }
    }
    for (const auto &p : hgt_value) {   // Then we apply all HGT changes to all identities.
        fgcom_local_client[p.first].alt = p.second;
        parseResult[iid].locationData = true;
    }
    
    
    // All done
    fgcom_localcfg_mtx.unlock();
    pluginDbg("[UDP] packet fully processed");
    return parseResult;
}


int fgcom_udp_port_used = FGCOM_SERVER_PORT;
bool fgcom_udp_shutdowncmd = false;
void fgcom_spawnUDPServer() {
    pluginLog("[UDP] server starting");
    int  fgcom_UDPServer_sockfd; 
    char buffer[MAXLINE]; 
    struct sockaddr_in servaddr, cliaddr; 
      
    // Creating socket file descriptor 
    if ( (fgcom_UDPServer_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        pluginLog("FGCom: [UDP] socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
      
    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 
      
    // Filling server information 
    servaddr.sin_family    = AF_INET; // IPv4 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
      
    // Bind the socket with the server address
    bool bind_ok = false;
    for (fgcom_udp_port_used = FGCOM_SERVER_PORT; fgcom_udp_port_used < FGCOM_SERVER_PORT + 10; fgcom_udp_port_used++) {
        servaddr.sin_port = htons(fgcom_udp_port_used); 
        if ( bind(fgcom_UDPServer_sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) >= 0 ) { 
            perror("FGCom: [UDP] udp socket bind succeeded");
            bind_ok = true;
            break;
        }
    }
    if (!bind_ok) {
        perror("FGCom: [UDP] udp socket bind to port failed");
        exit(EXIT_FAILURE); 
    }
    
    
    pluginLog("[UDP] server up and waiting for data at port "+std::to_string(fgcom_udp_port_used));
    mumAPI.log(ownPluginID, std::string("UDP server up and waiting for data at port "+std::to_string(fgcom_udp_port_used)).c_str());
    
    // wait for incoming data
    int n; 
    socklen_t len;
    std::map<uint16_t, bool> firstdata;
    uint16_t clientPort;
    while (true) {
        len = sizeof(cliaddr);  //len is value/result 
        n = recvfrom(fgcom_UDPServer_sockfd, (char *)buffer, MAXLINE,  
                    MSG_WAITALL, ( struct sockaddr *) &cliaddr, &len); 
        buffer[n] = '\0';
        clientPort = ntohs(cliaddr.sin_port);
        
        // Print info to client, so we know what ports are in use
        if (firstdata.count(clientPort) == 0 && sizeof(buffer) > 4) {
            firstdata[clientPort] = true;
            mumAPI.log(ownPluginID, std::string("UDP server connection established from port "+std::to_string(clientPort)).c_str());
        }
        
        // Allow the udp server to be shut down when receiving SHUTDOWN command
        if (strstr(buffer, "SHUTDOWN") && fgcom_udp_shutdowncmd) {
            pluginLog("[UDP] shutdown command recieved, server stopping now");
            fgcom_udp_shutdowncmd = false;
            close(fgcom_UDPServer_sockfd);
            mumAPI.log(ownPluginID, std::string("UDP server at port "+std::to_string(fgcom_udp_port_used)+" stopped").c_str());
            break;
            
        } else {
            // let the incoming data be handled
            
            std::map<int, fgcom_udp_parseMsg_result> updates; // so we can send updates to remotes
            updates = fgcom_udp_parseMsg(buffer, clientPort);
            
            /* Process pending urgent notifications
             * (not-urgent updates are dealt from the notification thread) */
            for (const auto &p : updates) {
                int iid = p.first;
                fgcom_udp_parseMsg_result ures = p.second;
                
                // If we got userdata changed, notify immediately.
                if (ures.userData) {
                    pluginDbg("[UDP] userData for iid='"+std::to_string(iid)+"' has changed, notifying other clients");
                    notifyRemotes(iid, NTFY_USR);
                }
                // See if we had a radio update. This is an "urgent" update: we must inform other clients instantly!
                for (std::set<int>::iterator it=ures.radioData.begin(); it!=ures.radioData.end(); ++it) {
                    // iterate trough changed radio instances
                    //std::cout << "ITERATOR: " << ' ' << *it;
                    pluginDbg("FGCom: [UDP] radioData for iid='"+std::to_string(iid)+"', radio_id="+std::to_string(*it)+" has changed, notifying other clients");
                    notifyRemotes(iid, NTFY_COM, *it);
                }
                // If we got locationdata changed, do NOT notify. This is handled asynchronusly from the notify thread.
                /*if (ures.locationData) {
                    pluginDbg("[UDP] locationData for iid='"+std::to_string(iid)+"' has changed, notifying other clients");
                    notifyRemotes(iid, 1);
                }*/
            }
            
            
        }
    }
      
    return;
}

void fgcom_shutdownUDPServer() {
    // Trigger shutdown: this just sends some magic UDP message.
    // This is neccessary because of the blocking state of the socket.
    pluginDbg("sending UDP shutdown request to port "+std::to_string(fgcom_udp_port_used));
    std::string message = "SHUTDOWN";
    fgcom_udp_shutdowncmd = true;

	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;

	// creates binary representation of server name
	// and stores it as sin_addr
	// http://beej.us/guide/bgnet/output/html/multipage/inet_ntopman.html
#ifdef MINGW_WIN64
    server_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);    // 127.0.0.1 on purpose: don't change for securites sake
#else
	inet_pton(AF_INET, "localhost", &server_address.sin_addr);  // 127.0.0.1 on purpose: don't change for securites sake
#endif

	// htons: port in network order format
	server_address.sin_port = htons(fgcom_udp_port_used);

	// open socket
	int sock;
	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		pluginLog("could not create udp cliet socket");
		return;
	}

	// send data
	int len = sendto(sock, message.c_str(), strlen(message.c_str()), 0,
	           (struct sockaddr*)&server_address, sizeof(server_address));

}
