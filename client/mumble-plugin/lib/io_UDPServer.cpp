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


// Plugin IO: UDP Server
//
// A simple udp input interface for the FGCom mumble plugin.
// It spawns an UDP server that accepts state inforamtion.
// The information is parsed and then put into a shared data
// structure, from where the plugin can read the current state.
// It is used for example from ATC clients or FlightSims to
// inform the plugin of local state.


#include <iostream>
#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sstream> 
#include <regex>
#include <sys/types.h> 
#include <math.h>

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
#include "radio_model.h"
#include "io_plugin.h"
#include "io_UDPServer.h"
#include "io_UDPClient.h"
#include "mumble/MumblePlugin_v_1_0_x.h"
#include "fgcom-mumble.h"

#ifdef DEBUG
    float fgcom_debug_signalstrength = -1;
#endif


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
std::map<std::pair<std::string,uint16_t>, int> fgcom_udp_portMap; // host,port2iid
bool fgcom_com_ptt_compatmode = false;
std::map<int, fgcom_udp_parseMsg_result> fgcom_udp_parseMsg(char buffer[MAXLINE], uint16_t clientPort, std::string clientHost) {
    pluginDbg("[UDP-server] received message (client="+clientHost+":"+std::to_string(clientPort)+"): "+std::string(buffer));
    //std::cout << "DBG: Stored local userID=" << localMumId <<std::endl;
    setlocale(LC_NUMERIC,"C"); // decimal points always ".", not ","
    
    // prepare return map
    std::map<int, fgcom_udp_parseMsg_result> parseResult;
    
    int iid = -1; // current IID selector for this message
    std::pair<std::string,uint16_t> clientHostPort(clientHost, clientPort); // connection pair for the portmapper
    
    // markers for ALT/HGT resolution
    // iid => new_value
    std::map<int, float> hgt_value;
    std::map<int, float> alt_value;
    std::map<int, std::pair<std::string, std::string>> parsed_frq_valAndToken; // last parsed frequency per radio-id (<value>,<token>)
    
    // marker for PTT change
    bool needToHandlePTT = false;

    // convert to stringstream so we can easily tokenize
    // TODO: why not simply refactor to strtok()?
    std::stringstream streambuffer(buffer); //std::string(buffer)
    std::string segment;
    std::regex parse_key_value ("^(\\w+)=(.+)");
    std::regex parse_COM ("^(COM)(\\d+)_(.+)");
    fgcom_localcfg_mtx.lock();
    while(std::getline(streambuffer, segment, ',')) {
        pluginDbg("[UDP-server] Segment='"+segment+"'");

        try {
            std::smatch sm;
            if (std::regex_search(segment, sm, parse_key_value)) {
                // this is a valid token. Lets parse it!
                std::string token_key   = sm[1];
                std::string token_value = sm[2];
                pluginDbg("[UDP-server] Parsing token: "+token_key+"="+token_value);
                
                // Ensure field content doesn't get overboard
                int curlength = token_value.length();
                if (curlength > MAX_UDPSRV_FIELDLENGTH) {
                    token_value = token_value.substr(0, MAX_UDPSRV_FIELDLENGTH); 
                    pluginLog("[UDP-server] WARNING: supplied token "+token_key+" length="+std::to_string(curlength)+" is greater than allowed "+std::to_string(MAX_UDPSRV_FIELDLENGTH)+": Field truncated!");
                }
                
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
                            clientHost = pm.first.first;
                            clientPort = pm.first.second;
                            clientHostPort = std::make_pair(clientHost, clientPort);
                            break;
                        }
                    }
                    if (!iid_port_found) {
                        // we did not see this iid so far so we need to establish it new.
                        // this happens automatically and defaults to the current client port.
                        // it may later be overridden by RDP_PORT= field.
                        fgcom_udp_portMap[clientHostPort] = iid;  // add info to portmapper, so it reports the right iid
                    }
                }


                // Get IID from client portmapper (if not overridden already)
                // This will map UDP client ports to identity IDs, so basicly we establish
                // that each UDP client is a unique identity (unless already overridden).
                if (iid == -1) {
                    if (fgcom_udp_portMap.count(clientHostPort) == 0) {
                        // register new client port to portmap.
                        // (IIDs are counted upwards from zero, so we save bandwith when transmitting packets)
                        int freeIID = 0;
                        for (const auto &fc : fgcom_udp_portMap) {
                            if (fc.second >= freeIID) freeIID = fc.second + 1;
                        }
                        fgcom_udp_portMap[clientHostPort] = freeIID;
                    }
                    iid = fgcom_udp_portMap[clientHostPort];
                    pluginDbg("[UDP-server] identity portmap result: clientHostPort("+clientHost+":"+std::to_string(clientPort)+") => iid("+std::to_string(iid)+")");
                }
                
                // see if we need to establish the local client state for the iid
                if (fgcom_local_client.count(iid) == 0 ) {
                    fgcom_local_client[iid]       = fgcom_client();
                    fgcom_local_client[iid].mumid = localMumId; // copy default id
                    fgcom_local_client[iid].clientHost = clientHost; // ensure valid and current clientHost
                    fgcom_local_client[iid].clientPort = clientPort; // ensure valid and current clientPort for portmapper
                    fgcom_local_client[iid].clientTgtPort = clientPort; // ensure valid starting clientTgtPort for udp client
                    pluginDbg("[UDP-server] new identity registered: iid="+std::to_string(iid)+"; clientHostPort="+clientHost+":"+std::to_string(clientPort));
                } else {
                    // Update that we have received some data
                    if (token_key != "IID") {
                        fgcom_local_client[iid].lastUpdate = std::chrono::system_clock::now();
                    }
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
                    long unsigned int radio_id = std::stoi(radio_nr.c_str());  // COM1 -> 1
                    if (radio_id < 1){
                        pluginLog("[UDP-server] Token ignored: radio_id outOfBounds (COM starts at 'COM1'!) "+token_key+"="+token_value);
                        continue; // if radio index not valid (ie. "COM0"): skip the token
                    }
                    if (fgcom_local_client[iid].radios.size() < radio_id) {
                        for (long unsigned int cr = fgcom_local_client[iid].radios.size(); cr < radio_id; cr++) {
                            pluginLog("[UDP-server]   create new local radio instance: "+std::to_string(cr));
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
                        fgcom_radiowave_freqConvRes frq_parsed = FGCom_radiowaveModel::splitFreqString(token_value);  // results in a cleaned frequency
                        std::unique_ptr<FGCom_radiowaveModel> radio_model = FGCom_radiowaveModel::selectModel(frq_parsed.frequency);
                        std::string finalParsedFRQ;
                        if (frq_parsed.isNumeric) {
                            // frequency is a numeric string.
                            // Let's check the decimals to decide if it is new or old format
                            if (std::regex_match(frq_parsed.frequency, std::regex("^\\d+\\.\\d{4,}$") )) {
                                // numeric frequency detected with >=4 decimals: treat as real wave frequency
                                pluginDbg("[UDP-server] detected real wave frequency format="+token_value);
                                finalParsedFRQ = frq_parsed.prefix + frq_parsed.frequency;
                                
                            } else {
                                // FGCom 3.0 compatibility mode:
                                // we expect 25kHz or 8.33 channel names here.
                                // So if we encounter such data, we probably need to convert the frequency part
                                pluginDbg("[UDP-server] detected old FGCom frequency format="+token_value);
                                finalParsedFRQ = frq_parsed.prefix + radio_model->conv_chan2freq(frq_parsed.frequency);
                                pluginDbg("[UDP-server] conversion result to realFreq="+finalParsedFRQ);
                            }
                        } else {
                            // not numeric: use as-is.
                            finalParsedFRQ = frq_parsed.frequency;  // already cleaned value
                            pluginDbg("[UDP-server] using FRQ as-is (non-numeric)");
                        }
                        
                        // handle final COMn_FRQ parsing result
                        // store parsing result for later comparison (only the last COMn_FRQ instance should be used)
                        parsed_frq_valAndToken[radio_id] = std::pair<std::string,std::string>(finalParsedFRQ, radio_model->conv_freq2chan(token_value));
                    }
                    if (radio_var == "VLT") {
                        float oldValue = fgcom_local_client[iid].radios[radio_id].volts;
                        if (token_value == "true" || token_value == "false") {
                            // support literal strings in case aircraft sends just a boolean as string
                            fgcom_local_client[iid].radios[radio_id].volts = (token_value == "true")? true : false;
                        } else {
                            fgcom_local_client[iid].radios[radio_id].volts       = std::stof(token_value);
                        }
                        if (fgcom_local_client[iid].radios[radio_id].volts != oldValue ) {
                            // send radio update in case of OPR change
                            pluginDbg("[UDP-server] recalculate operable state of radio "+radio_type+radio_nr+" (VLT changed)");
                            if (fgcom_radio_updateOperable(fgcom_local_client[iid].radios[radio_id])) parseResult[iid].radioData.insert(radio_id);
                        }
                    }
                    if (radio_var == "PBT") {
                        bool oldValue = fgcom_local_client[iid].radios[radio_id].power_btn;
                        fgcom_local_client[iid].radios[radio_id].power_btn   = (token_value == "1" || token_value == "true")? true : false;
                        if (fgcom_local_client[iid].radios[radio_id].power_btn != oldValue ) {
                            // send radio update in case of OPR change
                            pluginDbg("[UDP-server] recalculate operable state of radio "+radio_type+radio_nr+" (PBT changed)");
                            if (fgcom_radio_updateOperable(fgcom_local_client[iid].radios[radio_id])) parseResult[iid].radioData.insert(radio_id);
                        }
                    }
                    if (radio_var == "SRV") {
                        bool oldValue = fgcom_local_client[iid].radios[radio_id].serviceable;
                        fgcom_local_client[iid].radios[radio_id].serviceable = (token_value == "1" || token_value == "true")? true : false;
                        if (fgcom_local_client[iid].radios[radio_id].serviceable != oldValue ) {
                            // send radio update in case of OPR change
                            pluginDbg("[UDP-server] recalculate operable state of radio "+radio_type+radio_nr+" (SRV changed)");
                            if (fgcom_radio_updateOperable(fgcom_local_client[iid].radios[radio_id])) parseResult[iid].radioData.insert(radio_id);
                        }
                    }
                    if (radio_var == "PTT") {
                        // depends if we are previously have been in old compat mode (a single PTT property)
                        // if yes: we need to ignore the "PTT disabled" request, because it is probably always 0
                        bool parsedPTT = (token_value == "1" || token_value == "true")? true : false;
                        
                        // PTT was set to true with the new way: we disable compat mode and take it
                        if (parsedPTT && fgcom_com_ptt_compatmode) fgcom_com_ptt_compatmode = false; 
                        
                        if (!fgcom_com_ptt_compatmode) {
                            //bool oldValue = fgcom_local_client[iid].radios[radio_id].ptt_req;
                            fgcom_local_client[iid].radios[radio_id].ptt_req = parsedPTT;
                            //if (fgcom_local_client[iid].radios[radio_id].ptt_req != oldValue ) parseResult[iid].radioData.insert(radio_id);
                            needToHandlePTT = true;
                        }

                    }
                    if (radio_var == "VOL") {
                        //float oldValue = fgcom_local_client[iid].radios[radio_id].volume;
                        fgcom_local_client[iid].radios[radio_id].volume      = std::stof(token_value);
                        // do not send right now: if (fgcom_local_client[iid].radios[radio_id].volume != oldValue ) parseResult[iid].radioData.insert(radio_id);
                    }
                    if (radio_var == "PWR") {
                        float oldValue = fgcom_local_client[iid].radios[radio_id].pwr;
                        fgcom_local_client[iid].radios[radio_id].pwr = std::stof(token_value);
                        if (fgcom_local_client[iid].radios[radio_id].pwr != oldValue ) parseResult[iid].radioData.insert(radio_id);
                    }
                    if (radio_var == "SQC") {
                        //float oldValue = fgcom_local_client[iid].radios[radio_id].squelch;
                        fgcom_local_client[iid].radios[radio_id].squelch = std::stof(token_value);
                        // do not send right now: if (fgcom_local_client[iid].radios[radio_id].squelch != oldValue ) parseResult[iid].radioData.insert(radio_id);
                    }
                    if (radio_var == "RDF") {
                        //bool oldValue = fgcom_local_client[iid].radios[radio_id].rdfEnabled;
                        fgcom_local_client[iid].radios[radio_id].rdfEnabled = (token_value == "1" || token_value == "true")? true : false;
                        // do not send this: its only ever local state!  parseResult[iid].radioData.insert(radio_id);

                        // start new UDP client thread if requested
                        //pluginDbg("[UDP-server] UDP-client start thread check: registeredClientTgtPort="+std::to_string(fgcom_local_client[iid].clientTgtPort)+"; udpClientRunning="+std::to_string(udpClientRunning));
                        if (fgcom_local_client[iid].clientTgtPort > 0 && !udpClientRunning) {
                            pluginDbg("[UDP-server] UDP-client requested: "+std::to_string(fgcom_local_client[iid].clientTgtPort));
#ifndef NO_UDPCLIENT
                            std::thread udpClientThread(fgcom_spawnUDPClient);
                            udpClientThread.detach();
                            //std::cout << "FGCOM: udp client started; id=" << udpClientThread_id << std::endl;
                            pluginDbg("[UDP-server] UDP-client started");
#endif
                        }
                    }
                    if (radio_var == "CWKHZ") {
                        //float oldValue = fgcom_local_client[iid].radios[radio_id].channelWidth;
                        fgcom_local_client[iid].radios[radio_id].channelWidth = std::stof(token_value);
                        // do not send right now: if (fgcom_local_client[iid].radios[radio_id].channelWidth != oldValue ) parseResult[iid].radioData.insert(radio_id);
                    }
                    if (radio_var == "PUBLISH") {
                        fgcom_local_client[iid].radios[radio_id].publish = (token_value == "1" || token_value == "true")? true : false;
                        // must never be sended - it's a local config property
                    }
                    if (radio_var == "MAPMUMBLEPTT") {
                        fgcom_cfg.mapMumblePTT[radio_id] = (token_value == "1" || token_value == "true" || token_value == "on" || token_value == "yes")? true : false;
                        // must never be sended - it's a local config property
                    }
                    
                }
                
                
                /* 
                 * User client values.
                 */
                if (token_key == "LON") {
                    //float oldValue = fgcom_local_client[iid].lon;
                    fgcom_local_client[iid].lon = std::stof(token_value);
                    parseResult[iid].locationData = true;
                }
                if (token_key == "LAT") {
                    //float oldValue = fgcom_local_client[iid].lat;
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
                    long unsigned int ptt_id = std::stoi(token_value);
                    
                    // handle compat mode switch: if we receive PTT in the old way, we switch it on
                    if (ptt_id > 0) fgcom_com_ptt_compatmode = true;
                    
                    if (fgcom_com_ptt_compatmode) {
                        //pluginDbg("DBG_PTT:  ptt_id="+std::to_string(ptt_id));
                        for (long unsigned int i = 0; i<fgcom_local_client[iid].radios.size(); i++) {
                            //pluginDbg("DBG_PTT:    check i("+std::to_string(i)+")==ptt_id-1("+std::to_string(ptt_id-1)+")");
                            if (i == ptt_id - 1) {
                                if (fgcom_local_client[iid].radios[i].ptt_req != 1){
                                    //parseResult[iid].radioData.insert(i);
                                    fgcom_local_client[iid].radios[i].ptt_req = 1;
                                }
                            } else {
                                if (fgcom_local_client[iid].radios[i].ptt_req == 1){
                                    //parseResult[iid].radioData.insert(i);
                                    fgcom_local_client[iid].radios[i].ptt_req = 0;
                                }
                            }
                        }
                    }
                    needToHandlePTT = true;
                }
                if (token_key == "OUTPUT_VOL") {
                    // Set all radio instances to the selected volume
                    float comvol = std::stof(token_value);
                    for (long unsigned int i = 0; i<fgcom_local_client[iid].radios.size(); i++) {
                        fgcom_local_client[iid].radios[i].volume = comvol;
                    }
                }
                
                
                /*
                 * Plugin Configuration
                 */
                if (token_key == "UDP_TGT_PORT") {
                    // UDP client target Port change request
                    uint16_t oldValue = fgcom_local_client[iid].clientTgtPort;
                    fgcom_local_client[iid].clientTgtPort = std::stoi(token_value);
                    if (udpClientRunning && oldValue != fgcom_local_client[iid].clientTgtPort) {
                        pluginDbg("[UDP-server] client port info change: iid="+std::to_string(iid)+"; port="+std::to_string(fgcom_local_client[iid].clientTgtPort));
                        // running thread will handle the change to fgcom_local_client[iid].clientPort
                    }
                }
                
                
                // Enable/Disable radio audio effects
                if (token_key == "AUDIO_FX_RADIO") {
                    fgcom_cfg.radioAudioEffects = (token_value == "0" || token_value == "false" || token_value == "off")? false : true;
                }
                
                // Allow hearing of non-plugin users
                if (token_key == "AUDIO_HEAR_ALL") {
                    fgcom_cfg.allowHearingNonPluginUsers = (token_value == "1" || token_value == "true" || token_value == "on")? true : false;
                    pluginDbg("[UDP-server] override AUDIO_HEAR_ALL updated to "+std::to_string(fgcom_cfg.allowHearingNonPluginUsers));
                }
                
                
#ifdef DEBUG
                // DEBUG: allow override of signal quality for incoming transmissions
                if (token_key == "DEBUG_SIGQLY") {
                    fgcom_debug_signalstrength = std::stof(token_value);
                    if (fgcom_debug_signalstrength > 1) fgcom_debug_signalstrength = 1;
                    if (fgcom_debug_signalstrength < 0) fgcom_debug_signalstrength = -1;
                    pluginDbg("[UDP-server] debug override of signal quality updated to "+std::to_string(fgcom_debug_signalstrength));
                }
#endif
            
           
            } else {
                // this was an invalid token. skip it silently.
                pluginDbg("[UDP-server] segment invalid (is no key=value format): "+segment);
            }
            
        // done with parsing?
        } catch (const std::exception& e) {
            pluginDbg("[UDP-server] Parsing throw exception, ignoring segment "+segment);
        }
        
    }  //endwhile
    
    
    /*
     * Inspect COM frequency changes
     *
     * We may receive several COM_FRQ fields, but only the last one should be used.
     * Consecutive appearances are to be overwriting previous ones.
     * The parsed_frq_valAndToken contains the last seen successfully parsed token.
     */
    for (const auto &p : parsed_frq_valAndToken) { // parsed_frq_valAndToken=(finalParsedFRQ, token_value)
        int                                 radio_id      = p.first;
        std::pair<std::string, std::string> parsed_values = p.second;
        
        std::string oldValue = fgcom_local_client[iid].radios[radio_id].frequency;
        fgcom_radiowave_freqConvRes frq_ori = FGCom_radiowaveModel::splitFreqString(oldValue);
        fgcom_local_client[iid].radios[radio_id].frequency = parsed_values.first;  // already cleaned value
        fgcom_local_client[iid].radios[radio_id].dialedFRQ = parsed_values.second; // supplied raw value
        
        // see if we need to notify:
        // - for changed non-numeric, always if its different
        // - for change in numeric/non-numeric, also always if its different
        // - for numeric ones, if the prefix did change, or the frequency is different for more than rounding errors
        fgcom_radiowave_freqConvRes frq_new = FGCom_radiowaveModel::splitFreqString(parsed_values.first);
        if (frq_ori.isNumeric && frq_new.isNumeric && frq_ori.prefix == frq_new.prefix) {
            // both are numeric and the prefix did not change: only notify if frequency changed that much
            float frq_diff = std::fabs(std::stof(frq_ori.frequency) - std::stof(frq_new.frequency));
            //pluginDbg("[UDP-server] COMM frq diff="+std::to_string(frq_diff)+"; old="+oldValue+"; new="+parsed_values.first);
            if ( frq_diff > 0.000010 ) parseResult[iid].radioData.insert(radio_id);
        } else {
            if (fgcom_local_client[iid].radios[radio_id].frequency != oldValue ) parseResult[iid].radioData.insert(radio_id);
        }
    }

    
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
    
    /**
     * Handle PTT Change
     */
    if (needToHandlePTT) fgcom_handlePTT();
    
    pluginDbg("[UDP-server] packet fully processed");
    return parseResult;
}


int fgcom_udp_port_used = fgcom_cfg.udpServerPort;
bool fgcom_udp_shutdowncmd = false;
bool udpServerRunning = false;
void fgcom_spawnUDPServer() {
    pluginLog("[UDP-server] server starting");
    int  fgcom_UDPServer_sockfd;
    char buffer[MAXLINE];
    struct sockaddr_in servaddr, cliaddr; 
    
#if defined(MINGW_WIN64) || defined(MINGW_WIN32)
    // init WinSock
    WSADATA wsa;
    int winsockInitRC = WSAStartup(MAKEWORD(2,0),&wsa);
    if (winsockInitRC < 0 ) {
        pluginLog("[UDP-server] WinSock init  failed (code "+std::to_string(winsockInitRC)+")"); 
        mumAPI.log(ownPluginID, std::string("UDP server failed: winsock init failure (code "+std::to_string(winsockInitRC)+")").c_str());
        return;
    }
#endif
      
    // Creating socket file descriptor 
    if ( (fgcom_UDPServer_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        pluginLog("[UDP-server] socket creation failed (code "+std::to_string(fgcom_UDPServer_sockfd)+")"); 
        mumAPI.log(ownPluginID, std::string("UDP server failed: socket creation failed (code "+std::to_string(fgcom_UDPServer_sockfd)+")").c_str());
        return;
    } 
      
    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 
      
    // Filling server information
    servaddr.sin_family    = AF_INET; // IPv4 
    if (fgcom_cfg.udpServerHost == "*") {
        servaddr.sin_addr.s_addr = INADDR_ANY;
    } else {
        int a_s_addr = inet_addr(fgcom_cfg.udpServerHost.c_str());
        if (a_s_addr != -1) {
            servaddr.sin_addr.s_addr = a_s_addr;
        } else {
            pluginLog("[UDP-server] socket server address invalid: "+fgcom_cfg.udpServerHost);
            mumAPI.log(ownPluginID, std::string("UDP server failed: server address invalid: "+fgcom_cfg.udpServerHost).c_str());
            return;
//            exit(EXIT_FAILURE);
        }
    }
    

    // Bind the socket with the server address
    bool bind_ok = false;
    for (fgcom_udp_port_used = fgcom_cfg.udpServerPort; fgcom_udp_port_used < fgcom_cfg.udpServerPort + 10; fgcom_udp_port_used++) {
        servaddr.sin_port = htons(fgcom_udp_port_used); 
        if ( bind(fgcom_UDPServer_sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) >= 0 ) { 
            pluginLog("[UDP-server] udp socket bind succeeded");
            bind_ok = true;
            break;
        }
    }
    if (!bind_ok) {
        pluginLog("[UDP-server] udp socket bind to port failed");
        exit(EXIT_FAILURE); 
    }
    
    
    pluginLog("[UDP-server] server up and waiting for data at "+fgcom_cfg.udpServerHost+":"+std::to_string(fgcom_udp_port_used));
    mumAPI.log(ownPluginID, std::string("UDP server up and waiting for data at "+fgcom_cfg.udpServerHost+":"+std::to_string(fgcom_udp_port_used)).c_str());
    
    // wait for incoming data
    int n; 
    socklen_t len;
    std::map<uint16_t, bool> firstdata;
    char* clientHost;
    uint16_t clientPort;
    udpServerRunning = true;
    while (!fgcom_udp_shutdowncmd) {
        len = sizeof(cliaddr);  //len is value/result
#if defined(MINGW_WIN64) || defined(MINGW_WIN32)
        int recvfrom_flags = 0;  //MSG_WAITALL not supported with UDP on windows (gives error 10045 WSAEOPNOTSUPP)
#else
        int recvfrom_flags = MSG_WAITALL;
#endif

        // receive datagrams
        n = recvfrom(fgcom_UDPServer_sockfd, (char *)buffer, MAXLINE,
                     recvfrom_flags, ( struct sockaddr *) &cliaddr, &len);
        if (n < 0) {
            // SOCKET_ERROR returned
#if defined(MINGW_WIN64) || defined(MINGW_WIN32)
            //details for windows error codes: https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom
            wprintf(L"recvfrom failed with error %d\n", WSAGetLastError());
            pluginLog("[UDP-server] SOCKET_ERROR="+std::to_string(n)+" in nf-winsock-recvfrom()="+std::to_string(WSAGetLastError()));
            mumAPI.log(ownPluginID, std::string("UDP server encountered an internal error (recvfrom()="+std::to_string(n)+", WSAGetLastError()="+std::to_string(WSAGetLastError())+")").c_str());
#else
            // linux recvfrom has no further details
            pluginLog("[UDP-server] SOCKET_ERROR="+std::to_string(n)+" in recvfrom()");
            mumAPI.log(ownPluginID, std::string("UDP server encountered an internal error (recvfrom()="+std::to_string(n)+")").c_str());
#endif
            // abort further processing and stop the udp server
            close(fgcom_UDPServer_sockfd);
            mumAPI.log(ownPluginID, std::string("UDP server at port "+std::to_string(fgcom_udp_port_used)+" stopped forcefully").c_str());
            break;
        }
        
        buffer[n] = '\0';
        clientPort = ntohs(cliaddr.sin_port);
        clientHost = inet_ntoa(cliaddr.sin_addr);
        std::string clientHost_str = std::string(clientHost);
        
        // Allow the udp server to be shut down when receiving SHUTDOWN command
        if (strstr(buffer, "SHUTDOWN") && fgcom_udp_shutdowncmd) {
            pluginLog("[UDP-server] shutdown command recieved, server stopping now");
            fgcom_udp_shutdowncmd = false;
            close(fgcom_UDPServer_sockfd);
            //mumAPI.log(ownPluginID, std::string("UDP server at port "+std::to_string(fgcom_udp_port_used)+" stopped").c_str());
            // ^^ note: as long as the mumAPI is synchronuous/blocking, we cannot emit that message: it causes mumble's main thread to block/deadlock.
            break;
            
        } else {
            // let the incoming data be handled
            
            // Print info to client, so we know what ports are in use
            if (firstdata.count(clientPort) == 0 && sizeof(buffer) > 4) {
                firstdata[clientPort] = true;
                pluginLog("[UDP-server] server connection established from "+clientHost_str+":"+std::to_string(clientPort));
                mumAPI.log(ownPluginID, std::string("UDP server connection established from "+clientHost_str+":"+std::to_string(clientPort)).c_str());
            }
            
            std::map<int, fgcom_udp_parseMsg_result> updates; // so we can send updates to remotes
            updates = fgcom_udp_parseMsg(buffer, clientPort, clientHost_str);
            
            /* Process pending urgent notifications
             * (not-urgent updates are dealt from the notification thread) */
            for (const auto &p : updates) {
                int iid = p.first;
                fgcom_udp_parseMsg_result ures = p.second;
                
                // If we got userdata changed, notify immediately.
                if (ures.userData) {
                    pluginDbg("[UDP-server] userData for iid='"+std::to_string(iid)+"' has changed, notifying other clients");
                    notifyRemotes(iid, NTFY_USR);
                    fgcom_updateClientComment();
                }
                // See if we had a radio update. This is an "urgent" update: we must inform other clients instantly!
                for (std::set<int>::iterator it=ures.radioData.begin(); it!=ures.radioData.end(); ++it) {
                    // iterate trough changed radio instances
                    //std::cout << "ITERATOR: " << ' ' << *it;
                    pluginDbg("[UDP-server] radioData for iid='"+std::to_string(iid)+"', radio_id="+std::to_string(*it)+" has changed, notifying other clients");
                    notifyRemotes(iid, NTFY_COM, *it);
                    fgcom_updateClientComment();
                }
                // If we got locationdata changed, do NOT notify. This is handled asynchronusly from the notify thread.
                /*if (ures.locationData) {
                    pluginDbg("[UDP-server] locationData for iid='"+std::to_string(iid)+"' has changed, notifying other clients");
                    notifyRemotes(iid, 1);
                }*/
            }
            
            
        }
    }

    udpServerRunning = false;
    pluginDbg("[UDP-server] thread finished.");
    fgcom_udp_port_used = fgcom_cfg.udpServerPort;
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
	// see: https://beej.us/guide/bgnet/html/
    if (fgcom_cfg.udpServerHost == "*") {
#if defined(MINGW_WIN64) || defined(MINGW_WIN32)
        server_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
#else
        inet_pton(AF_INET, "127.0.0.1", &server_address.sin_addr);
#endif
    } else {
#if defined(MINGW_WIN64) || defined(MINGW_WIN32)
        server_address.sin_addr.s_addr = inet_addr(fgcom_cfg.udpServerHost.c_str());
#else
        inet_pton(AF_INET, fgcom_cfg.udpServerHost.c_str(), &server_address.sin_addr);
#endif
    }

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
    if (len == -1) {
        pluginLog("[UDP-server] error sending UDP shutdown packet");
        mumAPI.log(ownPluginID, std::string("error sending UDP shutdown packet").c_str());
        return;
    }
}
