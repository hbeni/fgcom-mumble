// An simple udp IO interface for the FGCom mumble plugin.
//
// It spawns an UDP server that accepts state inforamtion.
// The information is parsed and then put into a shared data
// structure, from where the plugin can read the current state.
//
#include <iostream>
#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sstream> 
#include <regex>
#include <sys/types.h> 
#include <sys/socket.h> 
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <thread>
#include <mutex>
#include <vector>
#include <set>
#include <map>
#include <clocale> // setlocale() 

#include "globalVars.h"
#include "plugin_io.h"
#include "MumblePlugin.h"


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


void notifyRemotes(int what, int selector, mumble_userid_t tgtUser) {
    std::string dataID("");  // FGCOM<something>
    std::string message(""); // the message as sting data (yeah, i'm lazy but it parses so easily and is human readable and therefore easy to debug)
    
    // check if we are connected and synchronized
    pluginDbg("notifyRemotes("+std::to_string(what)+","+std::to_string(selector)+","+std::to_string(tgtUser)+") called");
    if (!fgcom_isConnectedToServer()) {
        pluginDbg("notifyRemotes(): not connected, so not notifying.");
        return;
    } else {
        pluginDbg("notifyRemotes(): we are connected, so notifications will be sent.");
    }

    // @param what:  0=all local info; 1=location data; 2=comms
    // @param selector: ignored, when 'what'=2: id of radio (0=COM1,1=COM2,...); -1 sends all radios
    switch (what) {
        case 0:
            // notify all info
            pluginDbg("notifyRemotes(): selected: all");
            notifyRemotes(1, -1, tgtUser);
            notifyRemotes(2, -1, tgtUser);
            break;
            
        case 1:
            // Notify on location
            pluginDbg("notifyRemotes(): selected: location");
            dataID  = "FGCOM:UPD_LOC";
            message = "CALLSIGN="+fgcom_local_client.callsign+","
                     +"LAT="+std::to_string(fgcom_local_client.lat)+","
                     +"LON="+std::to_string(fgcom_local_client.lon)+","
                     +"ALT="+std::to_string(fgcom_local_client.alt)+",";
            break;
            
        case 2:
            // notify on radio state
            pluginDbg("notifyRemotes(): selected radio");            
            if (selector == -1) {
                pluginDbg("notifyRemotes():    all radios selected");
                for (int ri=0; ri < fgcom_local_client.radios.size(); ri++) {  
                    notifyRemotes(1,ri,tgtUser);
                }
            } else {
                pluginDbg("notifyRemotes():    send state of COM"+std::to_string(selector+1) );
                dataID  = "FGCOM:UPD_COM:"+std::to_string(selector);
                message = "FRQ="+fgcom_local_client.radios[selector].frequency+","
                        //+ "VLT="+std::to_string(fgcom_local_client.radios[selector].volts)+","
                        //+ "PBT="+std::to_string(fgcom_local_client.radios[selector].power_btn)+","
                        //+ "SRV="+std::to_string(fgcom_local_client.radios[selector].serviceable)+","
                        + "PTT="+std::to_string(fgcom_local_client.radios[selector].ptt)+","
                        //+ "VOL="+std::to_string(fgcom_local_client.radios[selector].volume)+","
                        + "PWR="+std::to_string(fgcom_local_client.radios[selector].pwr)+",";
                    // ^^ Save bandwith: We do not need all state on the other clients currently. Once we do, we can just uncomment this and the code to handle it is already implemented :)
                    // Ah yeah, and we must uncomment the change-detection down at fgcom_udp_parseMsg(), otherwise the changes get not detected
            }
            
            break;
            
        default: 
            pluginDbg("notifyRemotes("+std::to_string(what)+","+std::to_string(selector)+","+std::to_string(tgtUser)+"): 'what' unknown");
            return;
    }
    
    
    // Now get all known FGCom users of the current channel.
    // to those we will push the update.
    // TODO: maybe just resolve to known fgcom remotes? but that may not be updated yet...
    size_t userCount;
	mumble_userid_t *userIDs;

	if (mumAPI.getAllUsers(ownPluginID, activeConnection, &userIDs, &userCount) != STATUS_OK) {
        // ^TODO: currently all server users. We should strip this down to channel users, and then maybe just the ones known to have the plugin enabled for bandwith reasons...
		pluginLog("[ERROR]: Can't obtain user list");
		return;
	} else {
        pluginDbg("There are "+std::to_string(userCount)+" users on this server.");
        if (userCount > 1) {
            if (tgtUser > -1) {
                //a specific user was requested
                pluginDbg("  sending message to targeted user: "+std::to_string(tgtUser));
                int send_res = mumAPI.sendData(ownPluginID, activeConnection, &tgtUser, userCount-1, message.c_str(), strlen(message.c_str()), dataID.c_str());
                if (send_res != STATUS_OK) {
                    pluginDbg("  message sent ERROR: "+std::to_string(send_res));
                } else {
                    pluginDbg("  message sent to "+std::to_string(userCount-1)+" clients");
                }
            } else {
                // Notify all users;
                // remove local id from that array to prevent sending updates to ourselves
                mumble_userid_t exclusiveUserIDs[userCount-1];
                int o = 0;
                for(size_t i=0; i<userCount; i++) {
                    if (userIDs[i] != fgcom_local_client.mumid) {
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
        pluginDbg("  notification done.");
    }
    
    
}

std::mutex fgcom_remotecfg_mtx;  // mutex lock for remote data
std::map<int, fgcom_client> fgcom_remote_clients; // remote radio config
bool handlePluginDataReceived(mumble_userid_t senderID, std::string dataID, std::string data) {
    // Handle the incoming data (if it belongs to us)
    std::setlocale(LC_NUMERIC,"C"); // decial points always ".", not ","
    
    if (dataID.substr(0,5) == "FGCOM") {
        // Data is for our plugin
        int clientID = (int) senderID;  // get mumble client id
        std::regex parse_key_value ("^(\\w+)=(.+)"); // prepare a regex for simpler parsing
        
        fgcom_remotecfg_mtx.lock();
        
        // check if user is already known to us; if not add him to the local clients store
        auto search = fgcom_remote_clients.find(clientID);
        if (search == fgcom_remote_clients.end()) {
            fgcom_remote_clients[clientID] = fgcom_client();
            fgcom_remote_clients[clientID].mumid = clientID;
            /*std::cout << "   DBG: INSERTED NEW REMOTE CLIENT: " <<std::endl;
            for (const auto &p : fgcom_remote_clients) {
                std::cout << p.first << " => callsign=" << p.second.callsign << " id=" << p.second.mumid << ", #-radios: " << p.second.radios.size() << '\n';
            }*/
        }
        
        // Parse the data, depending on packet type
        if (dataID == "FGCOM:UPD_LOC") {
            // Location data update
            pluginDbg("LOC UPDATE: Sender="+std::to_string(clientID)+" DataID="+dataID+" DATA="+data);
            
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
                        
                        if (token_key == "LON")      fgcom_remote_clients[clientID].lon      = std::stof(token_value);
                        if (token_key == "LAT")      fgcom_remote_clients[clientID].lat      = std::stof(token_value);
                        if (token_key == "ALT")      fgcom_remote_clients[clientID].alt      = std::stoi(token_value);
                        if (token_key == "CALLSIGN") fgcom_remote_clients[clientID].callsign = token_value;
                        
                        
                    } else {
                        // ignore, segment was not in key=value format
                    }
                 
                // done with parsing?
                } catch (const std::exception& e) {
                    pluginDbg("[mum_pluginIO] Parsing throw exception, ignoring token "+segment);
                }
            }
            
        
        } else if (dataID.substr(0, 14) == "FGCOM:UPD_COM:") {
            // Radio data update. Here the radio in question was given in the dataid.
            pluginDbg("COM UPDATE: Sender="+std::to_string(clientID)+" DataID="+dataID+" DATA="+data);
            int radio_id = std::stoi(dataID.substr(14)); // segfault, indicates problem with the implemented udp protocol
            
            // if the selected radio does't exist, create it now
            if (fgcom_remote_clients[clientID].radios.size() < radio_id+1) {
                for (int cr = fgcom_remote_clients[clientID].radios.size(); cr < radio_id+1; cr++) {
                    fgcom_remote_clients[clientID].radios.push_back(fgcom_radio()); // add new radio instance with default values
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
                        
                        if (token_key == "FRQ") fgcom_remote_clients[clientID].radios[radio_id].frequency   = token_value;
                        if (token_key == "VLT") fgcom_remote_clients[clientID].radios[radio_id].volts       = std::stof(token_value);
                        if (token_key == "PBT") fgcom_remote_clients[clientID].radios[radio_id].power_btn   = (token_value == "1")? true : false;
                        if (token_key == "SRV") fgcom_remote_clients[clientID].radios[radio_id].serviceable = (token_value == "1")? true : false;
                        if (token_key == "PTT") fgcom_remote_clients[clientID].radios[radio_id].ptt         = (token_value == "1")? true : false;
                        if (token_key == "VOL") fgcom_remote_clients[clientID].radios[radio_id].volume      = std::stof(token_value);
                        if (token_key == "PWR") fgcom_remote_clients[clientID].radios[radio_id].pwr         = std::stof(token_value);      
                        
                    } else {
                        // ignore, segment was not in key=value format
                    }
                 
                // done with parsing?
                } catch (const std::exception& e) {
                    pluginLog("[mum_pluginIO] Parsing throw exception, ignoring token "+segment);
                }
            }
        }
        
        fgcom_remotecfg_mtx.unlock();
        
        pluginDbg("FGCom: [mum_pluginIO] Parsing done.");
        return true; // signal to other plugins that the data was handled already
        
    } else {
        return false; // packet does not belong to us. other plugins should also receive it
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
 * @todo: that should be changed, so the udp server instance gets initialized with pointers to these variables.
 *
 * @param buffer The char buffer to parse
 * @param userDataHashanged pointer to boolean that after call indicates if userdata had changed
 * @param radioDataHasChanged pointer to an set of ints that show which radios did change
 */
std::mutex fgcom_localcfg_mtx;
struct fgcom_client fgcom_local_client;
void fgcom_udp_parseMsg(char buffer[MAXLINE], bool *userDataHashanged, std::set<int> *radioDataHasChanged) {
    pluginDbg("[UDP] received message: "+std::string(buffer));
    //std::cout << "DBG: Stored local userID=" << fgcom_local_client.mumid <<std::endl;
    std::setlocale(LC_NUMERIC,"C"); // decial points always ".", not ","

    // convert to stringstream so we can easily tokenize
    // TODO: why not simply refactor to strtok()?
    std::stringstream streambuffer(buffer); //std::string(buffer)
    std::string segment;
    std::regex parse_key_value ("^(\\w+)=(.+)");
    std::regex parse_COM ("^(COM)(\\d)_(.+)");
    fgcom_localcfg_mtx.lock();
    while(std::getline(streambuffer, segment, ',')) {
        pluginDbg("[UDP] Segment='"+segment);

        try {
            std::smatch sm;
            if (std::regex_search(segment, sm, parse_key_value)) {
                // this is a valid token. Lets parse it!
                std::string token_key   = sm[1];
                std::string token_value = sm[2];
                pluginDbg("[UDP] Parsing token: "+token_key+"="+token_value);
                
                std::smatch smc;
                if (std::regex_search(token_key, smc, parse_COM)) {
                    // COM Radio mode detected
                    std::string radio_type = smc[1];
                    std::string radio_nr   = smc[2];
                    std::string radio_var  = smc[3];
                    
                    // if the selected radio does't exist, create it now
                    int radio_id = std::stoi(radio_nr.c_str());  // COM1 -> 1
                    if (fgcom_local_client.radios.size() < radio_id) {
                        for (int cr = fgcom_local_client.radios.size(); cr < radio_id; cr++) {
                            fgcom_local_client.radios.push_back(fgcom_radio()); // add new radio instance with default values
                            radioDataHasChanged->insert(radio_id-1);
                        }
                    }
                    radio_id--; // convert to array index
                    
                    if (radio_var == "FRQ") {
                        std::string oldValue = fgcom_local_client.radios[radio_id].frequency;
                        fgcom_local_client.radios[radio_id].frequency   = token_value;
                        if (fgcom_local_client.radios[radio_id].frequency != oldValue ) radioDataHasChanged->insert(radio_id);
                    }
                    if (radio_var == "VLT") {
                        float oldValue = fgcom_local_client.radios[radio_id].volts;
                        fgcom_local_client.radios[radio_id].volts       = std::stof(token_value);
                        // do not send right now: if (fgcom_local_client.radios[radio_id].volts != oldValue ) radioDataHasChanged->insert(radio_id);
                    }
                    if (radio_var == "PBT") {
                        bool oldValue = fgcom_local_client.radios[radio_id].power_btn;
                        fgcom_local_client.radios[radio_id].power_btn   = (token_value == "1")? true : false;
                        // do not send right now: if (fgcom_local_client.radios[radio_id].power_btn != oldValue ) radioDataHasChanged->insert(radio_id);
                    }
                    if (radio_var == "SRV") {
                        bool oldValue = fgcom_local_client.radios[radio_id].serviceable;
                        fgcom_local_client.radios[radio_id].serviceable = (token_value == "1")? true : false;
                        // do not send right now: if (fgcom_local_client.radios[radio_id].serviceable != oldValue ) radioDataHasChanged->insert(radio_id);
                    }
                    if (radio_var == "PTT") {
                        bool oldValue = fgcom_local_client.radios[radio_id].ptt;
                        fgcom_local_client.radios[radio_id].ptt         = (token_value == "1")? true : false;
                        if (fgcom_local_client.radios[radio_id].ptt != oldValue ) radioDataHasChanged->insert(radio_id);
                    }
                    if (radio_var == "VOL") {
                        float oldValue = fgcom_local_client.radios[radio_id].volume;
                        fgcom_local_client.radios[radio_id].volume      = std::stof(token_value);
                        // do not send right now: if (fgcom_local_client.radios[radio_id].volume != oldValue ) radioDataHasChanged->insert(radio_id);
                    }
                    if (radio_var == "PWR") {
                        float oldValue = fgcom_local_client.radios[radio_id].pwr;
                        fgcom_local_client.radios[radio_id].pwr = std::stof(token_value);
                        if (fgcom_local_client.radios[radio_id].pwr != oldValue ) radioDataHasChanged->insert(radio_id);
                    }

                }
                
                
                // User client values.
                // TODO: We should limit the update notification rate of positional data (The reason is that for example the UDP sending interface of flightgear may send new data several times per second.)
                if (token_key == "LON") {
                    float oldValue = fgcom_local_client.lon;
                    fgcom_local_client.lon = std::stof(token_value);;
                    if (fgcom_local_client.lon != oldValue ) *userDataHashanged = true;
                }
                if (token_key == "LAT") {
                    float oldValue = fgcom_local_client.lat;
                    fgcom_local_client.lat = std::stof(token_value);
                    if (fgcom_local_client.lat != oldValue ) *userDataHashanged = true;
                }
                if (token_key == "ALT") {
                    int oldValue = fgcom_local_client.alt;
                    // ALT comes in ft. We need meters however
                    fgcom_local_client.alt = std::stoi(token_value) / 3.2808;
                    if (fgcom_local_client.alt != oldValue ) *userDataHashanged = true;
                }
                if (token_key == "CALLSIGN") {
                    std::string oldValue = fgcom_local_client.callsign;
                    fgcom_local_client.callsign = token_value;
                    if (fgcom_local_client.callsign != oldValue ) *userDataHashanged = true;
                }
                
                
                // FGCom 3.0 compatibility
                if (token_key == "PTT") {
                    // PTT contains the ID of the used radio (0=none, 1=COM1, 2=COM2)
                    int ptt_id = std::stoi(token_value);
                    for (int i = 0; i<fgcom_local_client.radios.size(); i++) {
                        if (i == ptt_id - 1) {
                            fgcom_local_client.radios[i].ptt = 1;
                        } else {
                            fgcom_local_client.radios[i].ptt = 0;
                        }
                    }
                }
                if (token_key == "OUTPUT_VOL") {
                    // Set all radio instances to the selected volume
                    float comvol = std::stof(token_value);
                    for (int i = 0; i<fgcom_local_client.radios.size(); i++) {
                        fgcom_local_client.radios[i].volume = comvol;
                    }
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
    fgcom_localcfg_mtx.unlock();
}


int fgcom_udp_port_used = FGCOM_PORT; 
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
    for (fgcom_udp_port_used = FGCOM_PORT; fgcom_udp_port_used < FGCOM_PORT + 10; fgcom_udp_port_used++) {
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
    while (true) {
        len = sizeof(cliaddr);  //len is value/result 
        n = recvfrom(fgcom_UDPServer_sockfd, (char *)buffer, MAXLINE,  
                    MSG_WAITALL, ( struct sockaddr *) &cliaddr, &len); 
        buffer[n] = '\0';
        
        if (strstr(buffer, "SHUTDOWN")) {
            // Allow the udp server to be shut down when receiving SHUTDOWN command
            pluginLog("[UDP] shutdown command recieved, server stopping now");
            close(fgcom_UDPServer_sockfd);
            mumAPI.log(ownPluginID, std::string("UDP server at port "+std::to_string(fgcom_udp_port_used)+" stopped").c_str());
            break;
            
        } else {
            // let the incoming data be handled
            
            bool userDataHashanged = false;     // so we can send updates to remotes
            std::set<int> radioDataHasChanged;  // so we can send updates to remotes
            
            fgcom_udp_parseMsg(buffer, &userDataHashanged, &radioDataHasChanged);
            
            // if we got updates, we should publish them to other clients now
            if (userDataHashanged) {
                pluginDbg("[UDP] userData has changed, notifying other clients");
                notifyRemotes(1);
            }
            for (std::set<int>::iterator it=radioDataHasChanged.begin(); it!=radioDataHasChanged.end(); ++it) {
                // iterate trough changed radio instances
                //std::cout << "ITERATOR: " << ' ' << *it;
                pluginDbg("FGCom: [UDP] radioData id="+std::to_string(*it)+" has changed, notifying other clients");
                notifyRemotes(2, *it);
            }
        }
    }
      
    return;
}

void fgcom_shutdownUDPServer() {
    //  Trigger shutdown: this just sends some magic UDP message.
    pluginDbg("sending UDP shutdown request to port "+std::to_string(fgcom_udp_port_used));
    std::string message = "SHUTDOWN";
    
    const char* server_name = "localhost";

	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;

	// creates binary representation of server name
	// and stores it as sin_addr
	// http://beej.us/guide/bgnet/output/html/multipage/inet_ntopman.html
	inet_pton(AF_INET, server_name, &server_address.sin_addr);

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
