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
// Mumble internal plugin IO
// Handles sending and receiving messages from mumbles interface.
// Sending of messages ("notifications") is differentiated between
// "urgent" and "not-urgent" messages. "urgent" ones are sent directly
// after change, whereas "not-urgent" ones are handled by a separate
// notification thread to cap the maximum of sent updates by time.
//

#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sstream> 
#include <regex>
#include <sys/types.h> 
#include <math.h>

#include <chrono>
#include <iomanip>

#if defined(MINGW_WIN64) || defined(MINGW_WIN32)
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
#include "io_UDPClient.h"
#include "mumble/MumblePlugin_v_1_0_x.h"
#include "fgcom-mumble.h"


// These are just some utility functions facilitating writing logs and the like
// The actual implementation of the plugin is further down
std::mutex fgcom_plog_mtx; // thread safety for logging
std::ostream& pLog(std::ostream& stream) {
    fgcom_plog_mtx.lock();
    // make milliseconds timestamp
    const auto now = std::chrono::system_clock::now();
    const auto nowAsTimeT = std::chrono::system_clock::to_time_t(now);
    const auto nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::stringstream nowStringStream;
    nowStringStream
      << std::put_time(std::localtime(&nowAsTimeT), "%Y-%m-%d %H:%M:%S")
      << '.' << std::setfill('0') << std::setw(3) << nowMs.count();

    stream << "FGCom [" << nowStringStream.str() <<"]: ";
    fgcom_plog_mtx.unlock();
    return stream;
}

std::ofstream fgcom_logfile_outfh("", std::ios_base::out);
bool fgcom_logfile_outfh_opentry = false;
void fgcom_log_openFile() {
    
    // in case logfile writing was requested and the FH is not open, do it now and write
    if (fgcom_cfg.logfile.length() > 0 && ! fgcom_logfile_outfh.is_open() && !fgcom_logfile_outfh_opentry) {
        fgcom_plog_mtx.lock();
        fgcom_logfile_outfh_opentry = true;
        fgcom_logfile_outfh.open(fgcom_cfg.logfile);
        fgcom_plog_mtx.unlock();

        std::string ores(!fgcom_logfile_outfh.good()? "failed" : "success");
        pLog(std::cout)           << "[LOG] Logfile opening: " << fgcom_cfg.logfile << "; result=" << ores << std::endl;
        pLog(fgcom_logfile_outfh) << "[LOG] FGCom-mumble plugin version: "<<FGCOM_VERSION_MAJOR<<"."<<FGCOM_VERSION_MINOR<<"."<<FGCOM_VERSION_PATCH<<"."<<std::endl;
        pLog(fgcom_logfile_outfh) << "[LOG] Logfile opening: " << fgcom_cfg.logfile << "; result=" << ores << std::endl;
    }

}

template<typename T>
void pluginLog(T log) {
    fgcom_log_openFile();
    pLog(std::cout) << log << std::endl;
    if (fgcom_logfile_outfh.good())  pLog(fgcom_logfile_outfh) << log << std::endl;
}

void pluginDbg(std::string log) {
#ifdef DEBUG
    // only log if we build in debug mode
    fgcom_log_openFile();
    pLog(std::cout) << "[DBG] " << log << std::endl;
    if (fgcom_logfile_outfh.good())  pLog(fgcom_logfile_outfh) << "[DBG] " << log << std::endl;
#endif
}


std::string fgcom_udp_escape(std::string s) {
    replace_all(s, ",", "\\,");
    replace_all(s, "=", "\\=");
    return s;
}


/*****************************************************
 *               Plugin communications               *
 ****************************************************/

bool fgcom_isConnectedToServer() {
    //pluginDbg("fgcom_isConnectedToServer(): checking connection");
    bool synchronized;
    int resCode = mumAPI.isConnectionSynchronized(ownPluginID, activeConnection, &synchronized);
    if (MUMBLE_STATUS_OK != resCode) {
   //     pluginDbg("fgcom_isConnectedToServer(): internal error executing isConnectionSynchronized(): rc="+std::to_string(resCode));
        return false;
    } else {
    //    pluginDbg("fgcom_isConnectedToServer(): synchstate="+std::to_string(synchronized));
    }
    return synchronized;
}

void notifyRemotes(int iid, FGCOM_NOTIFY_T what, int selector, mumble_userid_t tgtUser) {
    setlocale(LC_NUMERIC,"C"); // decimal points always ".", not ","
    std::string dataID("");  // FGCOM<something>
    std::string message(""); // the message as sting data (yeah, i'm lazy but it parses so easily and is human readable and therefore easy to debug)
    
    // check if we are connected and synchronized
    pluginDbg("[mum_pluginIO] notifyRemotes("+std::to_string(iid)+","+std::to_string(what)+","+std::to_string(selector)+","+std::to_string(tgtUser)+") called");
    if (!fgcom_isConnectedToServer()) {
        pluginDbg("[mum_pluginIO] notifyRemotes(): not connected, so not notifying.");
        return;
    } else {
        pluginDbg("[mum_pluginIO] notifyRemotes(): we are connected, so notifications will be sent.");
    }
    
    // If all identities are selected, invoke notifyRemotes() for each of them
    if (iid == NTFY_ALL) {
        pluginDbg("[mum_pluginIO] notifyRemotes(): identities: all selected, resolving...");
        for (const auto &idty : fgcom_local_client) {
            notifyRemotes(idty.first, what, selector, tgtUser);
        }
        return;
    }

    // For reading local state, resolve the local identity.
    // (note this is not neccessary for NTFY_ASK packets - they should be sent always)
    fgcom_client lcl; // resolved local identity
    if (what != NTFY_ASK) {
        // skip notification attempts if we don't have any local state yet
        if (fgcom_local_client.empty()) {
            pluginDbg("[mum_pluginIO] notifyRemotes(): no local state yet, skipping notifications.");
            return;
        }

        // resolve selected identity.
        // if this fails, bail out, because we can't sent the packet type then
        if (fgcom_local_client.count(iid) > 0) {
            lcl = fgcom_local_client[iid];
            pluginDbg("[mum_pluginIO] notifyRemotes(): successfully resolved identity='"+std::to_string(iid)+"' (callsign="+lcl.callsign+")");
        } else {
            pluginLog("[mum_pluginIO] notifyRemotes(): ERROR resolving identity='"+std::to_string(iid)+"'!");
            return;
        }
    }
    

    // @param what:  0=all local info; 1=location data; 2=comms, 3=ask for data, 4=userdata, 5=ping
    // @param selector: ignored, when 'what'=NTFY_COM: id of radio (0=COM1,1=COM2,...); -1 sends all radios
    // TODO: to help with rate throtteling, the summarizing selectors should generate a single message. Currently they just invoke the single message invocations. Alternatively: We may also make a new fast running thread that looks at a "urgent" notification queue and summarizes messages there?
    switch (what) {
        case NTFY_ALL:
            // notify all info
            pluginDbg("[mum_pluginIO] notifyRemotes(): selected: all");
            notifyRemotes(iid, NTFY_USR, NTFY_ALL, tgtUser);  // userdata
            notifyRemotes(iid, NTFY_LOC, NTFY_ALL, tgtUser);  // location
            notifyRemotes(iid, NTFY_COM, NTFY_ALL, tgtUser);  // radios
            return;
            
        case NTFY_LOC:
            // Notify on location
            pluginDbg("[mum_pluginIO] notifyRemotes(): selected: location");
            dataID  = "FGCOM:UPD_LOC:"+std::to_string(iid);
            message = "LAT="+std::to_string(lcl.lat)+","
                     +"LON="+std::to_string(lcl.lon)+","
                     +"ALT="+std::to_string(lcl.alt)+",";
            break;
            
        case NTFY_COM:
            // notify on radio state
            pluginDbg("[mum_pluginIO] notifyRemotes(): selected radio");            
            if (selector == NTFY_ALL) {
                pluginDbg("[mum_pluginIO] notifyRemotes():    all radios selected");
                for (long unsigned int ri=0; ri < lcl.radios.size(); ri++) {  
                    notifyRemotes(iid, NTFY_COM, ri, tgtUser);
                }
            } else {
                if (lcl.radios[selector].publish) {
                    pluginDbg("[mum_pluginIO] notifyRemotes():    send state of COM"+std::to_string(selector+1) );
                    dataID  = "FGCOM:UPD_COM:"+std::to_string(iid)+":"+std::to_string(selector);
                    message = "FRQ="+fgcom_udp_escape(lcl.radios[selector].frequency)+","
                            + "CHN="+fgcom_udp_escape(lcl.radios[selector].dialedFRQ)+","
                            //+ "VLT="+std::to_string(lcl.radios[selector].volts)+","
                            //+ "PBT="+std::to_string(lcl.radios[selector].power_btn)+","
                            //+ "SRV="+std::to_string(lcl.radios[selector].serviceable)+","
                            + "PTT="+std::to_string(lcl.radios[selector].ptt)+","
                            //+ "VOL="+std::to_string(lcl.radios[selector].volume)+","
                            + "PWR="+std::to_string(lcl.radios[selector].pwr)+","
                            + "OPR="+std::to_string(lcl.radios[selector].operable);
                        // ^^ Save bandwith: We do not need all state on the other clients currently. Once we do, we can just uncomment this and the code to handle it is already implemented :)
                        // Ah yeah, and we must uncomment the change-detection down at fgcom_udp_parseMsg(), otherwise the changes get not detected
                } else {
                    // do not send data for local-only radios
                    return;
                }
            }
            
            break;
        
        case NTFY_ASK:
            // we ask all other clients to send us their data
            dataID  = "FGCOM:ICANHAZDATAPLZ";
            message = "allYourDataBelongsToUs!";
            break;
            
        case NTFY_USR:
            // userstate
            pluginDbg("[mum_pluginIO] notifyRemotes(): selected: userdata");
            dataID  = "FGCOM:UPD_USR:"+std::to_string(iid);
            message = "CALLSIGN="+fgcom_udp_escape(lcl.callsign);
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
            pluginDbg("[mum_pluginIO] notifyRemotes("+std::to_string(iid)+","+std::to_string(what)+","+std::to_string(selector)+","+std::to_string(tgtUser)+"): 'what' unknown");
            return;
    }
    
    
    // Now get all known FGCom users of the current channel.
    // to those we will push the update.
    size_t userCount;
	mumble_userid_t *userIDs;
    mumble_channelid_t localChannelID;
    if (mumAPI.getChannelOfUser(ownPluginID, activeConnection, localMumId, &localChannelID) != MUMBLE_STATUS_OK) {
        pluginLog("[mum_pluginIO] [ERROR]: Can't obtain channel of local user");
        return;
    }

    if (mumAPI.getUsersInChannel(ownPluginID, activeConnection, localChannelID, &userIDs, &userCount) != MUMBLE_STATUS_OK) {
        pluginLog("[mum_pluginIO] [ERROR]: Can't obtain user list");
        return;
    } else {
        pluginDbg("There are "+std::to_string(userCount)+" users on this channel.");
        if (userCount > 1) {
            if (tgtUser > 0) {
                // a specific user was requested
                // (note: 0 is usually the id of the superuser, ordinary users star with 1)
                if (tgtUser != lcl.mumid) {
                    pluginDbg("  sending message to targeted user: "+std::to_string(tgtUser));
                    int send_res = mumAPI.sendData(ownPluginID, activeConnection, &tgtUser, 1, reinterpret_cast<const uint8_t *>(message.c_str()), strlen(message.c_str()), dataID.c_str());
                    if (send_res != MUMBLE_STATUS_OK) {
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
            
                int send_res = mumAPI.sendData(ownPluginID, activeConnection, exclusiveUserIDs, userCount-1, reinterpret_cast<const uint8_t *>(message.c_str()), strlen(message.c_str()), dataID.c_str());
                if (send_res != MUMBLE_STATUS_OK) {
                    pluginDbg("  message sent ERROR: "+std::to_string(send_res));
                } else {
                    pluginDbg("  message sent to "+std::to_string(userCount-1)+" clients");
                }
            }

        }

        mumAPI.freeMemory(ownPluginID, userIDs);
        pluginDbg("[mum_pluginIO] message was: '"+message+"'");
        pluginDbg("[mum_pluginIO] notification for dataID='"+dataID+"' done.");
    }

}

// fgcom_remotecfg_mtx and fgcom_remote_clients are now defined in globalVars.cpp
bool handlePluginDataReceived(mumble_userid_t senderID, std::string dataID, std::string data) {
    // Handle the incoming data (if it belongs to us)
    setlocale(LC_NUMERIC,"C"); // decimal points always ".", not ","
    
    // Handle escaped data
    // the goal is that we want to support: `a,b\,c,d`=>['a', 'b,c', 'd']; we do this by replacing the escaped sequence
    // into a non-printable ASCII, so we can easily spit by ',' later on.
    const std::string delimEscPlaceholderC = "\x1A"; // for processing escaped `\,` sequences in UDP input string ('a,b' => 'a\x1Ab' )
    const std::string delimEscPlaceholderE = "\x1B"; // for processing escaped `\,` sequences in UDP input string ('a=b' => 'a\x1Bb' )
    replace_all(data, "\\,", delimEscPlaceholderC);
    replace_all(data, "\\=", delimEscPlaceholderE);
    
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
        bool clientAlreadyknown = true;
        auto search = fgcom_remote_clients.find(clientID);
        if (iid > -1 && search == fgcom_remote_clients.end()) {
            pluginDbg("[mum_pluginIO] registering new remote: Sender="+std::to_string(clientID)+" identity="+std::to_string(iid));
            fgcom_remote_clients[clientID][iid]       = fgcom_client();
            clientAlreadyknown = false;
        }
        
        // store that we have seen something for a valid identity
        if (iid > -1 ) {
            fgcom_remote_clients[clientID][iid].lastUpdate = std::chrono::system_clock::now();
            fgcom_remote_clients[clientID][iid].mumid = clientID; // update mumble client id for that identity
        }
        
        // Parse the data, depending on packet type
        if (dataID == "FGCOM:ICANHAZDATAPLZ") {
            // client asks for our current state
            pluginDbg("[mum_pluginIO] Data update requested: Sender="+std::to_string(clientID)+" DataID="+dataID);
            
            // Throttle answers per client per second (prevent https://github.com/hbeni/fgcom-mumble/issues/60)
            const std::chrono::milliseconds ntf_ask_answerInterval = std::chrono::milliseconds(MIN_NTFYANSWER_INTVAL);
            if (fgcom_remote_clients[clientID][iid].lastNotification + ntf_ask_answerInterval < std::chrono::system_clock::now()) {
                fgcom_remote_clients[clientID][iid].lastNotification = std::chrono::system_clock::now();
                notifyRemotes(NTFY_ALL, NTFY_ALL, -1, clientID); // notify the sender with all our data
            } else {
                pluginLog("[mum_pluginIO] <WARN> Dropped excess NTFY_ASK packet from sender="+std::to_string(clientID));
            }
        
        
        } else if (dataID == "FGCOM:PING") {
            // ping packet contains list of IIDs which are alive.
            pluginDbg("[mum_pluginIO] ping received, idtys="+data);
            if (clientAlreadyknown) {
                std::stringstream streambuffer(data);
                std::string segment;
                while(std::getline(streambuffer, segment, ',')) {
                    replace_all(segment, delimEscPlaceholderC, ","); // undo escaping of delim ('a\x1Ab' => 'a,b')
                    replace_all(segment, delimEscPlaceholderE, "="); // undo escaping of delim ('a\x1Bb' => 'a=b')
                    try {
                        int rmt_iid = stoi(segment);
                        if (fgcom_remote_clients[clientID].count(rmt_iid) > 0) {
                            fgcom_remote_clients[clientID][rmt_iid].lastUpdate = std::chrono::system_clock::now();
                        }
                    
                    } catch (const std::exception& e) {
                        pluginDbg("[mum_pluginIO] Parsing ping packet throw exception, ignoring token "+segment);
                    }
                }
            } else {
                // Technically this shouldn't happen, but request state from the unknown client
                notifyRemotes(NTFY_ALL, NTFY_ASK, clientID);
            }
            
        
        // Userdata and Location data update are treated the same
        } else if (dataID == "FGCOM:UPD_USR:"+iid_str
                || dataID == "FGCOM:UPD_LOC:"+iid_str) {
            pluginDbg("[mum_pluginIO] USR/LOC UPDATE: Sender="+std::to_string(clientID)+" DataID="+dataID+" DATA="+data);
            
            // update properties
            std::stringstream streambuffer(data);
            std::string segment;
            while(std::getline(streambuffer, segment, ',')) {
                // example: FRQ=1234,VLT=12,000000,PBT=1,SRV=1,PTT=0,VOL=1,000000,PWR=10,000000   segment=FRQ=1234
                replace_all(segment, delimEscPlaceholderC, ","); // undo escaping of delim ('a\x1Ab' => 'a,b')
                replace_all(segment, delimEscPlaceholderE, "="); // undo escaping of delim ('a\x1Bb' => 'a=b')
                pluginDbg("[mum_pluginIO] Segment="+segment);
                
                try {
                                
                    std::smatch sm;
                    if (std::regex_search(segment, sm, parse_key_value)) {
                        // this is a valid token. Lets parse it!
                        std::string token_key   = sm[1];
                        std::string token_value = sm[2];
                        pluginDbg("[mum_pluginIO] Parsing token: "+token_key+"="+token_value);
                        
                        // Ensure field content doesn't get overboard
                        int curlength = token_value.length();
                        if (curlength > MAX_PLUGINIO_FIELDLENGTH) {
                            token_value = token_value.substr(0, MAX_PLUGINIO_FIELDLENGTH); 
                            pluginLog("[mum_pluginIO] WARNING: supplied token "+token_key+" length="+std::to_string(curlength)+" is greater than allowed "+std::to_string(MAX_PLUGINIO_FIELDLENGTH)+": Field truncated!");
                        }
                        
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
            pluginDbg("[mum_pluginIO] COM UPDATE: Sender="+std::to_string(clientID)+" DataID="+dataID+" DATA="+data);
            long unsigned int radio_id = std::stoi(dataID.substr(15+iid_str.length())); // when segfault: indicates problem with the implemented udp protocol
            
            // if the selected radio does't exist, create it now
            if (fgcom_remote_clients[clientID][iid].radios.size() < radio_id+1) {
                for (long unsigned int cr = fgcom_remote_clients[clientID][iid].radios.size(); cr < radio_id+1; cr++) {
                    fgcom_remote_clients[clientID][iid].radios.push_back(fgcom_radio()); // add new radio instance with default values
                }
            }
            
            // update the radios properties
            std::stringstream streambuffer(data);
            std::string segment;
            while(std::getline(streambuffer, segment, ',')) {
                // example: FRQ=1234,VLT=12,000000,PBT=1,SRV=1,PTT=0,VOL=1,000000,PWR=10,000000   segment=FRQ=1234
                replace_all(segment, delimEscPlaceholderC, ","); // undo escaping of delim ('a\x1Ab' => 'a,b')
                replace_all(segment, delimEscPlaceholderE, "="); // undo escaping of delim ('a\x1Bb' => 'a=b')
                pluginDbg("[mum_pluginIO] Segment="+segment);
                
                try {        
                    std::smatch sm;
                    if (std::regex_search(segment, sm, parse_key_value)) {
                        // this is a valid token. Lets parse it!
                        //printf("Parsing token: %s=%s\n", token_key.c_str(), token_value.c_str());
                        std::string token_key   = sm[1];
                        std::string token_value = sm[2];
                        pluginDbg("[mum_pluginIO] Parsing token: "+token_key+"="+token_value);
                        
                        // Ensure field content doesn't get overboard
                        int curlength = token_value.length();
                        if (curlength > MAX_PLUGINIO_FIELDLENGTH) {
                            token_value = token_value.substr(0, MAX_PLUGINIO_FIELDLENGTH); 
                            pluginLog("[mum_pluginIO] WARNING: supplied token "+token_key+" length="+std::to_string(curlength)+" is greater than allowed "+std::to_string(MAX_PLUGINIO_FIELDLENGTH)+": Field truncated!");
                        }
                        
                        if (token_key == "FRQ") {
                            // expected is real wave carrier frequency, so something with at least 4 decimals
                            fgcom_remote_clients[clientID][iid].radios[radio_id].frequency = token_value;
                        }
                        if (token_key == "CHN") {
                            // expected is a raw channel selector (what was supplied from the remote client in COMn_FRQ=)
                            fgcom_remote_clients[clientID][iid].radios[radio_id].dialedFRQ = token_value;
                        }
                        if (token_key == "VLT") fgcom_remote_clients[clientID][iid].radios[radio_id].volts       = std::stof(token_value);
                        if (token_key == "PBT") fgcom_remote_clients[clientID][iid].radios[radio_id].power_btn   = (token_value == "1")? true : false;
                        if (token_key == "SRV") fgcom_remote_clients[clientID][iid].radios[radio_id].serviceable = (token_value == "1")? true : false;
                        if (token_key == "OPR") fgcom_remote_clients[clientID][iid].radios[radio_id].operable    = (token_value == "1")? true : false;
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
            pluginDbg("[mum_pluginIO] dataID='"+dataID+"' not known. Ignoring.");
        }
        
        fgcom_remotecfg_mtx.unlock();
        
        pluginDbg("[mum_pluginIO] Parsing done.");
        return true; // signal to other plugins that the data was handled already
        
    } else {
        return false; // packet does not belong to us. other plugins should also receive it
    }

}


std::map<int, fgcom_notificationState> lastNotifiedState;  // holds the last data we did sent out, so we can detect changes for notification (and how much)
const std::chrono::milliseconds notifyPingInterval = std::chrono::milliseconds(NOTIFYPINGINTERVAL);
void fgcom_notifyThread() {
    while (true) {
        if (fgcom_isPluginActive()) {
            // if plugin is active, check if we need to send notifications.
            fgcom_localcfg_mtx.lock();
            
            // Note: we are just looking at location and userdata. Radio data is "urgent" and notified directly.
            // Difference with 3 decimals is about 100m: http://wiki.gis.com/wiki/index.php/Decimal_degrees
            for (const auto &idty : fgcom_local_client) {
                int iid          = idty.first;
                fgcom_client lcl = idty.second;
                bool notifyUserData     = false;
                bool notifyLocationData = false;
                
                if (fabs(lcl.lat - lastNotifiedState[iid].data.lat) >= 0.0005) { // about 40-50m
                    lastNotifiedState[iid].data.lat = lcl.lat;
                    notifyLocationData = true;
                }
                if (fabs(lcl.lon - lastNotifiedState[iid].data.lon) >= 0.0005) { // about 40-50m
                    lastNotifiedState[iid].data.lon = lcl.lon;
                    notifyLocationData = true;
                }
                if (fabs(lcl.alt - lastNotifiedState[iid].data.alt) >= 5) {  // 5 meters
                    lastNotifiedState[iid].data.alt = lcl.alt;
                    notifyLocationData = true;
                }
                if (lcl.callsign != lastNotifiedState[iid].data.callsign) {
                    lastNotifiedState[iid].data.callsign = lcl.callsign;
                    notifyUserData = true;
                }
                
                
                // We did not have a change for several seconds.
                // We should send something so other clients know we are still alive!
                if (!notifyUserData && !notifyLocationData && std::chrono::system_clock::now() > lastNotifiedState[iid].lastPing + notifyPingInterval) {
                    pluginDbg("[mum_pluginIO] fgcom_notifyThread() Ping is due (IID="+std::to_string(iid)+").");
                    lastNotifiedState[iid].lastPing = std::chrono::system_clock::now();
                    notifyRemotes(iid, NTFY_PNG);
                }
                
                // Location has changed significantly: notify!
                if (notifyLocationData) {
                    pluginDbg("[mum_pluginIO] fgcom_notifyThread() locationdata was changed.");
                    lastNotifiedState[iid].lastPing = std::chrono::system_clock::now();
                    notifyRemotes(iid, NTFY_LOC);
                }
                
                // userdata has changed: notify!
                if (notifyUserData) {
                    pluginDbg("[mum_pluginIO] fgcom_notifyThread() userdata was changed.");
                    lastNotifiedState[iid].lastPing = std::chrono::system_clock::now();
                    notifyRemotes(iid, NTFY_USR);
                }
            }
            fgcom_localcfg_mtx.unlock();
            
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(NOTIFYINTERVAL));
    }
}
