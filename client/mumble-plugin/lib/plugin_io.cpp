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


/*****************************************************
 *               Plugin communications               *
 ****************************************************/

void notifyRemotes(int what, int selector ) {
    std::string dataID("");  // FGCOM<something>
    std::string message(""); // the message as sting data (yeah, i'm lazy but it parses so easily and is human readable and therefore easy to debug)
    
    // check if we are connected and synchronized
    printf("notifyRemotes(%i,%i) called", what, selector);
    if (!connectionSynchronized) {
        std::cout << "notifyRemotes("<<what<<","<<selector<<"): not connected, so not notifying." << std::endl;
        return;
    }

    // @param what:  0=all local info; 1=location data; 2=comms
    // @param selector: ignored, when 'what'=2: id of radio (0=COM1,1=COM2,...); -1 sends all radios
    switch (what) {
        case 0:
            // notify all info
            std::cout << "notifyRemotes(): all status" << std::endl;
            notifyRemotes(1);
            notifyRemotes(2);
            break;
            
        case 1:
            // Notify on location
            std::cout << "notifyRemotes("<<what<<","<<selector<<"): location" << std::endl;
            dataID  = "FGCOM:UPD_LOC";
            message = "CALLSIGN="+fgcom_local_client.callsign+","
                     +"LAT="+std::to_string(fgcom_local_client.lat)+","
                     +"LON="+std::to_string(fgcom_local_client.lon)+","
                     +"ALT="+std::to_string(fgcom_local_client.alt)+",";
            break;
            
        case 2:
            // notify on radio state
            std::cout << "notifyRemotes(): radio" << std::endl;            
            if (selector == -1) {
                std::cout << "  all radios selected" << std::endl;
                for (int ri=0; ri < fgcom_local_client.radios.size(); ri++) {  
                    notifyRemotes(1,ri);
                }
            } else {
                std::cout << "  send state of COM" << selector+1 << std::endl;
                dataID  = "FGCOM:UPD_COM:"+std::to_string(selector);
                message = "FRQ="+fgcom_local_client.radios[selector].frequency+","
                        + "VLT="+std::to_string(fgcom_local_client.radios[selector].volts)+","
                        + "PBT="+std::to_string(fgcom_local_client.radios[selector].power_btn)+","
                        + "SRV="+std::to_string(fgcom_local_client.radios[selector].serviceable)+","
                        + "PTT="+std::to_string(fgcom_local_client.radios[selector].ptt)+","
                        + "VOL="+std::to_string(fgcom_local_client.radios[selector].volume)+","
                        + "PWR="+std::to_string(fgcom_local_client.radios[selector].pwr)+",";
            }
            
            break;
            
        default: 
            std::cout << "notifyRemotes("<<what<<","<<selector<<"): 'what' unknown" << std::endl;
            return;
    }
    
    
    // Now get all known FGCom users of the current channel.
    // to those we will push the update.
    // TODO: maybe just resolve to knopwn fgcom remotes? but that may not be updated yet...
    size_t userCount;
	mumble_userid_t *userIDs;

	if (mumAPI.getAllUsers(ownID, activeConnection, &userIDs, &userCount) != STATUS_OK) {
        // ^TODO: currently all server users. We should strip this down to channel users, and then maybe just the ones known to have the plugin enabled for bandwith reasons...
		std::cout << "[ERROR]: Can't obtain user list" << std::endl;
		return;
	} else {
        std::cout << "There are " << userCount << " users on this server." << std::endl;

        if (userCount >= 1) {
            // remove local id from that array to prevent sending updates to ourselves
            //TODO: auto arrayEnd = std::remove(std::begin(*userIDs), std::end(*userIDs), fgcom_local_client.mumid);
            
            for(size_t i=0; i<userCount; i++) {
                std::cout << "  sending message to: " << userIDs[i] << std::endl;
            }
            mumAPI.sendData(ownID, activeConnection, userIDs, userCount, message.c_str(), strlen(message.c_str()), dataID.c_str());
        }

        mumAPI.freeMemory(ownID, userIDs);
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
            std::cout << "LOC UPDATE: Sender=" << clientID << " DataID=" << dataID.c_str() << " DATA=" << data.c_str() << std::endl;
            
            // update properties
            std::stringstream streambuffer(data);
            std::string segment;
            while(std::getline(streambuffer, segment, ',')) {
                // example: FRQ=1234,VLT=12,000000,PBT=1,SRV=1,PTT=0,VOL=1,000000,PWR=10,000000   segment=FRQ=1234
                printf("FGCom: [mum_pluginIO] Segment=%s",segment);
                
                try {
                                
                    std::smatch sm;
                    if (std::regex_search(segment, sm, parse_key_value)) {
                        // this is a valid token. Lets parse it!
                        //printf("Parsing token: %s=%s\n", token_key.c_str(), token_value.c_str());
                        std::string token_key   = sm[1];
                        std::string token_value = sm[2];
                        printf("FGCom: [mum_pluginIO] Parsing token: %s=%s\n", token_key.c_str(), token_value.c_str());
                        
                        if (token_key == "LON")      fgcom_remote_clients[clientID].lon      = std::stof(token_value);
                        if (token_key == "LAT")      fgcom_remote_clients[clientID].lat      = std::stof(token_value);
                        if (token_key == "ALT")      fgcom_remote_clients[clientID].alt      = std::stoi(token_value);
                        if (token_key == "CALLSIGN") fgcom_remote_clients[clientID].callsign = token_value;
                        
                    } else {
                        // ignore, segment was not in key=value format
                    }
                 
                // done with parsing?
                } catch (const std::exception& e) {
                    std::cout << "FGCom: [mum_pluginIO] Parsing throw exception, ignoring token " << segment.c_str() << std::endl;
                }
            }
            
        
        } else if (dataID.substr(0, 14) == "FGCOM:UPD_COM:") {
            // Radio data update. Here the radio in question was given in the dataid.
            std::cout << "COM UPDATE: Sender=" << clientID << " DataID=" << dataID.c_str() << " DATA=" << data.c_str() << std::endl;
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
                printf("FGCom: [mum_pluginIO] Segment=%s",segment);
                
                try {        
                    std::smatch sm;
                    if (std::regex_search(segment, sm, parse_key_value)) {
                        // this is a valid token. Lets parse it!
                        //printf("Parsing token: %s=%s\n", token_key.c_str(), token_value.c_str());
                        std::string token_key   = sm[1];
                        std::string token_value = sm[2];
                        printf("FGCom: [mum_pluginIO] Parsing token: %s=%s\n", token_key.c_str(), token_value.c_str());
                        
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
                    std::cout << "FGCom: [mum_pluginIO] Parsing throw exception, ignoring token " << segment.c_str() << std::endl;
                }
            }
        }
        
        fgcom_remotecfg_mtx.unlock();
        
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
    printf("FGCOM: [UDP] received message: %s\n", buffer);
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
        printf("FGCom: [UDP] Segment=%s",segment);
        //printf("Parsing token: %s=%s\n", token_key.c_str(), token_value.c_str());

        try {
            std::smatch sm;
            if (std::regex_search(segment, sm, parse_key_value)) {
                // this is a valid token. Lets parse it!
                std::string token_key   = sm[1];
                std::string token_value = sm[2];
                printf("FGCom: [UDP] Parsing token: %s=%s\n", token_key.c_str(), token_value.c_str());
                
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
                        if (fgcom_local_client.radios[radio_id].volts != oldValue ) radioDataHasChanged->insert(radio_id);
                    }
                    if (radio_var == "PBT") {
                        bool oldValue = fgcom_local_client.radios[radio_id].power_btn;
                        fgcom_local_client.radios[radio_id].power_btn   = (token_value == "1")? true : false;
                        if (fgcom_local_client.radios[radio_id].power_btn != oldValue ) radioDataHasChanged->insert(radio_id);
                    }
                    if (radio_var == "SRV") {
                        bool oldValue = fgcom_local_client.radios[radio_id].serviceable;
                        fgcom_local_client.radios[radio_id].serviceable = (token_value == "1")? true : false;
                        if (fgcom_local_client.radios[radio_id].serviceable != oldValue ) radioDataHasChanged->insert(radio_id);
                    }
                    if (radio_var == "PTT") {
                        bool oldValue = fgcom_local_client.radios[radio_id].ptt;
                        fgcom_local_client.radios[radio_id].ptt         = (token_value == "1")? true : false;
                        if (fgcom_local_client.radios[radio_id].ptt != oldValue ) radioDataHasChanged->insert(radio_id);
                    }
                    if (radio_var == "VOL") {
                        float oldValue = fgcom_local_client.radios[radio_id].volume;
                        fgcom_local_client.radios[radio_id].volume      = std::stof(token_value);
                        if (fgcom_local_client.radios[radio_id].volume != oldValue ) radioDataHasChanged->insert(radio_id);
                    }
                    if (radio_var == "PWR") {
                        float oldValue = fgcom_local_client.radios[radio_id].pwr;
                        fgcom_local_client.radios[radio_id].pwr = std::stof(token_value);
                        if (fgcom_local_client.radios[radio_id].pwr != oldValue ) radioDataHasChanged->insert(radio_id);
                    }

                }
                
                
                // User client values
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
                printf("FGCom: [UDP] segment invalid (is no key=value format): %s\n", segment.c_str());
            }
            
        // done with parsing?
        } catch (const std::exception& e) {
            std::cout << "FGCom: [UDP] Parsing throw exception, ignoring token " << segment.c_str() << std::endl;
        }
        
    }  //endwhile
    fgcom_localcfg_mtx.unlock();
}



void fgcom_spawnUDPServer() {
    printf("FGCom: [UDP] server starting on port %i\n", FGCOM_PORT);
    int  fgcom_UDPServer_sockfd; 
    char buffer[MAXLINE]; 
    struct sockaddr_in servaddr, cliaddr; 
      
    // Creating socket file descriptor 
    if ( (fgcom_UDPServer_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) { 
        perror("FGCom: [UDP] socket creation failed"); 
        exit(EXIT_FAILURE); 
    } 
      
    memset(&servaddr, 0, sizeof(servaddr)); 
    memset(&cliaddr, 0, sizeof(cliaddr)); 
      
    // Filling server information 
    servaddr.sin_family    = AF_INET; // IPv4 
    servaddr.sin_addr.s_addr = INADDR_ANY; 
    servaddr.sin_port = htons(FGCOM_PORT); 
      
    // Bind the socket with the server address 
    if ( bind(fgcom_UDPServer_sockfd, (const struct sockaddr *)&servaddr,  
            sizeof(servaddr)) < 0 ) 
    { 
        perror("FGCom: [UDP] udp socket bind to port failed"); 
        exit(EXIT_FAILURE); 
    } 
    
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
            printf("FGCom: [UDP] shutdown command recieved, server stopping now");
            close(fgcom_UDPServer_sockfd);
            break;
            
        } else {
            // let the incoming data be handled
            
            bool userDataHashanged = false;     // so we can send updates to remotes
            std::set<int> radioDataHasChanged;  // so we can send updates to remotes
            
            fgcom_udp_parseMsg(buffer, &userDataHashanged, &radioDataHasChanged);
            
            // if we got updates, we should publish them to other clients now
            if (userDataHashanged) {
                printf("FGCom: [UDP] userDataHashanged, notifying other clients");
                notifyRemotes(1);
            }
            for (std::set<int>::iterator it=radioDataHasChanged.begin(); it!=radioDataHasChanged.end(); ++it) {
                // iterate trough changed radio instances
                //std::cout << "ITERATOR: " << ' ' << *it;
                printf("FGCom: [UDP] radioDataHashanged id=%i, notifying other clients", *it);
                notifyRemotes(2, *it);
            }
        }
    }
      
    return;
}

void fgcom_shutdownUDPServer() {
    //  Trigger shutdown: this just sends some magic UDP message.
    printf("FGCOM: sending UDP shutdown request\n");
    std::string message = "SHUTDOWN";
    
    const char* server_name = "localhost";
	const int server_port = FGCOM_PORT;

	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;

	// creates binary representation of server name
	// and stores it as sin_addr
	// http://beej.us/guide/bgnet/output/html/multipage/inet_ntopman.html
	inet_pton(AF_INET, server_name, &server_address.sin_addr);

	// htons: port in network order format
	server_address.sin_port = htons(server_port);

	// open socket
	int sock;
	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("could not create socket\n");
		return;
	}

	// send data
	int len = sendto(sock, message.c_str(), strlen(message.c_str()), 0,
	           (struct sockaddr*)&server_address, sizeof(server_address));

}
